//! Foreign-key dependency graph, Tarjan SCC cycle breaking, and deterministic topological scheduling.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use petgraph::algo::tarjan_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};

use crate::db::backend::DatabaseKind;
use crate::db::schema::ir::{ForeignKeyIr, SchemaIr, TableIr};

/// Directed edge `parent_table -> child_table` derived from a foreign key.
#[derive(Debug, Clone)]
pub struct FkDependencyEdge {
    pub child_table: String,
    pub parent_table: String,
    pub fk_name: String,
    pub columns: Vec<String>,
    pub nullable: bool,
    pub explicit_defer: bool,
}

/// Cycle-breaking and topological table ordering plan for a schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaGraphPlan {
    /// Forward dependency order (`CREATE TABLE` / data import order): parents before children.
    pub creation_order: Vec<String>,
    /// Reverse dependency order (`DROP TABLE` order): children before parents.
    pub drop_order: Vec<String>,
    /// Cycle-breaking FKs deferred to `ALTER TABLE ... ADD CONSTRAINT` (`table -> {fk_name}`).
    pub deferred_fks_by_table: BTreeMap<String, BTreeSet<String>>,
    /// Column names corresponding to deferred cyclic FKs (`table -> [col_names]`).
    pub deferred_columns_by_table: BTreeMap<String, Vec<String>>,
    /// All non-trivial strongly connected components broken during scheduling.
    pub cyclic_sccs: Vec<Vec<String>>,
}

/// Analyze table foreign-key dependencies using `petgraph::algo::tarjan_scc` and
/// produce a deterministic DAG creation order + deferred cycle-breaking foreign keys.
#[must_use]
pub fn plan_schema_graph(ir: &SchemaIr, dialect: DatabaseKind) -> SchemaGraphPlan {
    plan_table_subset(&ir.tables, dialect)
}

/// Analyze a subset/map of tables using `tarjan_scc` + deterministic Kahn topological sort.
#[must_use]
pub fn plan_table_subset(
    tables: &BTreeMap<String, TableIr>,
    dialect: DatabaseKind,
) -> SchemaGraphPlan {
    let table_names: Vec<String> = tables.keys().cloned().collect();
    let mut graph = DiGraph::<String, FkDependencyEdge>::new();
    let mut node_map: BTreeMap<String, NodeIndex> = BTreeMap::new();

    for name in &table_names {
        let idx = graph.add_node(name.clone());
        node_map.insert(name.clone(), idx);
    }

    for (child_name, table) in tables {
        let Some(&child_idx) = node_map.get(child_name) else {
            continue;
        };
        for fk in &table.foreign_keys {
            if fk.ref_table == *child_name {
                // Self-referencing FK (e.g. `document_revisions.parent_revision_id`) does not block CREATE TABLE.
                continue;
            }
            let Some(&parent_idx) = node_map.get(&fk.ref_table) else {
                continue;
            };
            let fk_name = fk.effective_name(child_name, dialect);
            let nullable = fk_columns_nullable(table, fk);
            graph.add_edge(
                parent_idx,
                child_idx,
                FkDependencyEdge {
                    child_table: child_name.clone(),
                    parent_table: fk.ref_table.clone(),
                    fk_name,
                    columns: fk.columns.clone(),
                    nullable,
                    explicit_defer: fk.defer_on_create,
                },
            );
        }
    }

    let mut deferred_fks_by_table: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut deferred_columns_by_table: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut cyclic_sccs: Vec<Vec<String>> = Vec::new();
    let mut recorded_sccs: BTreeSet<Vec<String>> = BTreeSet::new();

    // Iteratively find strongly connected components and remove the highest-priority
    // nullable/feedback edge inside each cycle until the graph is a strict DAG.
    loop {
        let sccs = tarjan_scc(&graph);
        let multi_sccs: Vec<Vec<NodeIndex>> = sccs
            .into_iter()
            .filter(|comp| comp.len() > 1)
            .collect();
        if multi_sccs.is_empty() {
            break;
        }

        for comp in multi_sccs {
            let comp_set: BTreeSet<NodeIndex> = comp.iter().copied().collect();
            let mut comp_names: Vec<String> =
                comp.iter().map(|idx| graph[*idx].clone()).collect();
            comp_names.sort();
            if recorded_sccs.insert(comp_names.clone()) {
                cyclic_sccs.push(comp_names);
            }

            let mut candidate_edges = Vec::new();
            for &u in &comp {
                for edge in graph.edges(u) {
                    use petgraph::visit::EdgeRef;
                    if comp_set.contains(&edge.target()) {
                        candidate_edges.push((edge.id(), edge.weight().clone()));
                    }
                }
            }

            // Deterministic priority for breaking cycles:
            // 1. Nullable FK columns first (can be NULL during data backfill)
            // 2. Explicit `defer_on_create` hint second
            // 3. Lexical `(child_table, fk_name)` ascending
            candidate_edges.sort_by(|(_, a), (_, b)| {
                b.nullable
                    .cmp(&a.nullable)
                    .then_with(|| b.explicit_defer.cmp(&a.explicit_defer))
                    .then_with(|| a.child_table.cmp(&b.child_table))
                    .then_with(|| a.fk_name.cmp(&b.fk_name))
            });

            if let Some((edge_id, chosen)) = candidate_edges.into_iter().next() {
                deferred_fks_by_table
                    .entry(chosen.child_table.clone())
                    .or_default()
                    .insert(chosen.fk_name.clone());
                let cols = deferred_columns_by_table
                    .entry(chosen.child_table)
                    .or_default();
                for col in chosen.columns {
                    cols.insert(col);
                }
                graph.remove_edge(edge_id);
            } else {
                break;
            }
        }
    }

    // Also include explicit defer flags marked directly on FKs even if already acyclic.
    for (child_name, table) in tables {
        for fk in &table.foreign_keys {
            if fk.defer_on_create && fk.ref_table != *child_name {
                deferred_fks_by_table
                    .entry(child_name.clone())
                    .or_default()
                    .insert(fk.effective_name(child_name, dialect));
                let cols = deferred_columns_by_table
                    .entry(child_name.clone())
                    .or_default();
                for col in &fk.columns {
                    cols.insert(col.clone());
                }
            }
        }
    }

    let creation_order = deterministic_toposort(&graph);
    let mut drop_order = creation_order.clone();
    drop_order.reverse();
    cyclic_sccs.sort();

    let deferred_cols_vec = deferred_columns_by_table
        .into_iter()
        .map(|(t, cols)| (t, cols.into_iter().collect()))
        .collect();

    SchemaGraphPlan {
        creation_order,
        drop_order,
        deferred_fks_by_table,
        deferred_columns_by_table: deferred_cols_vec,
        cyclic_sccs,
    }
}

fn fk_columns_nullable(table: &TableIr, fk: &ForeignKeyIr) -> bool {
    fk.columns
        .iter()
        .all(|col_name| table.column(col_name).is_some_and(|c| c.nullable))
}

/// Kahn's algorithm with a min-heap so independent tables follow sorted lexical order.
fn deterministic_toposort(graph: &DiGraph<String, FkDependencyEdge>) -> Vec<String> {
    let n = graph.node_count();
    let mut indegree = vec![0usize; n];
    for edge in graph.raw_edges() {
        indegree[edge.target().index()] += 1;
    }

    let mut ready: BinaryHeap<Reverse<(String, usize)>> = BinaryHeap::new();
    for idx in graph.node_indices() {
        let i = idx.index();
        if indegree[i] == 0 {
            ready.push(Reverse((graph[idx].clone(), i)));
        }
    }

    let mut order = Vec::with_capacity(n);
    while let Some(Reverse((name, u))) = ready.pop() {
        order.push(name);
        let u_idx = NodeIndex::new(u);
        for neighbor in graph.neighbors_directed(u_idx, petgraph::Direction::Outgoing) {
            let v = neighbor.index();
            indegree[v] = indegree[v].saturating_sub(1);
            if indegree[v] == 0 {
                ready.push(Reverse((graph[neighbor].clone(), v)));
            }
        }
    }

    // Fallback safety if graph had unexpected unremoved edge: append any unvisited deterministically.
    if order.len() < n {
        let placed: BTreeSet<String> = order.iter().cloned().collect();
        let mut remaining: Vec<String> = graph
            .node_indices()
            .map(|idx| graph[idx].clone())
            .filter(|name| !placed.contains(name))
            .collect();
        remaining.sort();
        order.extend(remaining);
    }

    order
}

/// Serial columns, deferred FK cycle columns per table, and safe table creation order.
pub type TransferMetadata = (Vec<(String, String)>, BTreeMap<String, Vec<String>>, Vec<String>);

/// Detect `SERIAL`/`BIGSERIAL` columns and deferred FK cycle backfill columns dynamically from a [`SchemaIr`].
#[must_use]
pub fn infer_transfer_metadata(
    ir: &SchemaIr,
    dialect: DatabaseKind,
) -> TransferMetadata {
    let graph_plan = plan_schema_graph(ir, dialect);
    let mut serial_cols = Vec::new();
    for table_name in &graph_plan.creation_order {
        if let Some(table) = ir.tables.get(table_name) {
            for col in &table.columns {
                if col.canonical_type.is_serial() {
                    serial_cols.push((table_name.clone(), col.name.clone()));
                }
            }
        }
    }
    (
        serial_cols,
        graph_plan.deferred_columns_by_table,
        graph_plan.creation_order,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::ddl::builtin_schema_ir;

    #[test]
    fn tarjan_scc_breaks_cfms_35_table_fk_cycles_and_produces_valid_dag_order() {
        let ir = builtin_schema_ir(false);
        let plan = plan_schema_graph(&ir, DatabaseKind::Postgresql);

        assert_eq!(plan.creation_order.len(), 35);
        assert!(plan.cyclic_sccs.len() >= 2);
        assert!(plan
            .cyclic_sccs
            .iter()
            .any(|c| c.contains(&"users".to_string()) && c.contains(&"keyrings".to_string())));
        assert!(plan
            .cyclic_sccs
            .iter()
            .any(|c| c.contains(&"documents".to_string())
                && c.contains(&"document_revisions".to_string())));

        let pos: BTreeMap<&str, usize> = plan
            .creation_order
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_str(), i))
            .collect();

        // Every non-deferred, non-self-referencing FK must point strictly backwards in creation_order.
        for (table_name, table) in &ir.tables {
            let deferred = plan.deferred_fks_by_table.get(table_name);
            for fk in &table.foreign_keys {
                if fk.ref_table == *table_name {
                    continue;
                }
                let fk_name = fk.effective_name(table_name, DatabaseKind::Postgresql);
                if deferred.is_some_and(|set| set.contains(&fk_name)) {
                    continue;
                }
                assert!(
                    pos[fk.ref_table.as_str()] < pos[table_name.as_str()],
                    "Parent {} must precede child {} (fk {})",
                    fk.ref_table,
                    table_name,
                    fk_name
                );
            }
        }

        assert!(pos["nodes"] < pos["dacl_rules"]);
        assert!(pos["dacl_rules"] < pos["dacl_rule_clauses"]);
        assert!(pos["dacl_rule_clauses"] < pos["dacl_rule_atoms"]);
    }
}
