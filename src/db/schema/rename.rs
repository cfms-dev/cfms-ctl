//! Multi-feature bipartite column rename detection using `strsim` and Kuhn-Munkres.

use std::collections::{BTreeMap, BTreeSet};

use pathfinding::kuhn_munkres::kuhn_munkres;
use pathfinding::matrix::Matrix;
use serde::{Deserialize, Serialize};

use crate::db::schema::ir::{ColumnIr, TableIr, TypeCompatibility};

/// Scoring weights and thresholds for rename detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameConfig {
    pub name_weight: f64,
    pub type_weight: f64,
    pub pos_weight: f64,
    pub accept_threshold: f64,
    pub ambiguous_threshold: f64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub explicit_column_overrides: BTreeMap<String, String>,
}

impl Default for RenameConfig {
    fn default() -> Self {
        Self {
            name_weight: 0.55,
            type_weight: 0.30,
            pos_weight: 0.15,
            accept_threshold: 0.78,
            ambiguous_threshold: 0.55,
            explicit_column_overrides: BTreeMap::new(),
        }
    }
}

impl RenameConfig {
    /// Parse `--rename table.old_col=new_col` specification cleanly.
    pub fn insert_override_spec(&mut self, spec: &str) -> std::result::Result<(), String> {
        let (lhs, new_col) = spec
            .split_once('=')
            .ok_or_else(|| format!("Invalid rename override '{spec}' (expected table.old=new)"))?;
        let (table, old_col) = lhs
            .split_once('.')
            .ok_or_else(|| format!("Invalid rename override '{spec}' (expected table.old=new)"))?;
        let key = format!("{}.{}", table.trim(), old_col.trim());
        let val = new_col.trim().to_string();
        if key == "." || val.is_empty() {
            return Err(format!(
                "Invalid rename override '{spec}' (expected non-empty table.old=new)"
            ));
        }
        self.explicit_column_overrides.insert(key, val);
        Ok(())
    }
}

/// Detailed score components stored for audit comments and JSON diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameScoreBreakdown {
    pub total: f64,
    pub name_score: f64,
    pub type_score: f64,
    pub pos_score: f64,
    pub damerau_levenshtein: f64,
    pub jaro_winkler: f64,
    pub token_jaccard: f64,
    pub compatibility: String,
    pub explicit_override: bool,
}

/// Accepted column rename mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedRename {
    pub old_column: String,
    pub new_column: String,
    pub score: RenameScoreBreakdown,
}

/// Low/medium-confidence rename candidate flagged for human confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmbiguousRenameCandidate {
    pub old_column: String,
    pub new_column: String,
    pub score: RenameScoreBreakdown,
    pub reason: String,
}

/// Complete column rename matching outcome for a single table.
#[derive(Debug, Clone, Default)]
pub struct ColumnRenameAnalysis {
    pub confirmed: Vec<ConfirmedRename>,
    pub ambiguous: Vec<AmbiguousRenameCandidate>,
    pub unmatched_dropped: Vec<String>,
    pub unmatched_added: Vec<String>,
}

/// Advisory table rename suspicion between unmatched dropped and added tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRenameCandidate {
    pub old_table: String,
    pub new_table: String,
    pub score: f64,
}

/// Analyze unmatched dropped vs added columns inside `old_table` -> `new_table`.
#[must_use]
pub fn detect_column_renames(
    old_table: &TableIr,
    new_table: &TableIr,
    exact_anchors: &[(usize, usize)],
    dropped_cols: &[&ColumnIr],
    added_cols: &[&ColumnIr],
    cfg: &RenameConfig,
) -> ColumnRenameAnalysis {
    let mut consumed_old = BTreeSet::new();
    let mut consumed_new = BTreeSet::new();
    let mut confirmed = Vec::new();

    // 1. Consume explicit operator `--rename table.old=new` overrides first.
    for (o_idx, old_col) in dropped_cols.iter().enumerate() {
        let key = format!("{}.{}", old_table.name, old_col.name);
        if let Some(target_new) = cfg.explicit_column_overrides.get(&key)
            && let Some((n_idx, new_col)) = added_cols
                .iter()
                .enumerate()
                .find(|(idx, c)| !consumed_new.contains(idx) && c.name == *target_new)
        {
            consumed_old.insert(o_idx);
            consumed_new.insert(n_idx);
            let mut score = compute_pair_score(
                old_col,
                new_col,
                old_table.columns.len(),
                new_table.columns.len(),
                exact_anchors,
                cfg,
            );
            score.explicit_override = true;
            confirmed.push(ConfirmedRename {
                old_column: old_col.name.clone(),
                new_column: new_col.name.clone(),
                score,
            });
        }
    }

    let rem_old: Vec<&ColumnIr> = dropped_cols
        .iter()
        .enumerate()
        .filter(|(i, _)| !consumed_old.contains(i))
        .map(|(_, c)| *c)
        .collect();
    let rem_new: Vec<&ColumnIr> = added_cols
        .iter()
        .enumerate()
        .filter(|(i, _)| !consumed_new.contains(i))
        .map(|(_, c)| *c)
        .collect();

    if rem_old.is_empty() || rem_new.is_empty() {
        return ColumnRenameAnalysis {
            confirmed,
            ambiguous: Vec::new(),
            unmatched_dropped: rem_old.into_iter().map(|c| c.name.clone()).collect(),
            unmatched_added: rem_new.into_iter().map(|c| c.name.clone()).collect(),
        };
    }

    // 2. Global 1-to-1 optimal assignment via Kuhn-Munkres on a zero-padded square matrix.
    let n = rem_old.len().max(rem_new.len());
    let mut breakdowns: Vec<Vec<Option<RenameScoreBreakdown>>> =
        vec![vec![None; rem_new.len()]; rem_old.len()];

    for (r, old_col) in rem_old.iter().enumerate() {
        for (c, new_col) in rem_new.iter().enumerate() {
            breakdowns[r][c] = Some(compute_pair_score(
                old_col,
                new_col,
                old_table.columns.len(),
                new_table.columns.len(),
                exact_anchors,
                cfg,
            ));
        }
    }

    let matrix = Matrix::from_fn(n, n, |(r, c)| {
        if r < rem_old.len() && c < rem_new.len() {
            let score = breakdowns[r][c].as_ref().map_or(0.0, |b| b.total);
            (score * 1_000_000.0).round() as i64
        } else {
            0
        }
    });

    let (_, assignments) = kuhn_munkres(&matrix);

    let mut matched_old = BTreeSet::new();
    let mut matched_new = BTreeSet::new();
    let mut ambiguous = Vec::new();

    for (r, &c) in assignments.iter().enumerate() {
        if r >= rem_old.len() || c >= rem_new.len() {
            continue;
        }
        let Some(score) = breakdowns[r][c].clone() else {
            continue;
        };
        let old_col = rem_old[r];
        let new_col = rem_new[c];
        let compat = old_col
            .canonical_type
            .classify_transition(&new_col.canonical_type);
        let incompatible_blocked =
            compat == TypeCompatibility::Incompatible && score.name_score < 0.90;

        if !incompatible_blocked && score.total >= cfg.accept_threshold {
            matched_old.insert(r);
            matched_new.insert(c);
            confirmed.push(ConfirmedRename {
                old_column: old_col.name.clone(),
                new_column: new_col.name.clone(),
                score,
            });
        } else if score.total >= cfg.ambiguous_threshold {
            let reason = if incompatible_blocked {
                format!(
                    "Score {:.2} but types {:?} -> {:?} are incompatible without explicit --rename",
                    score.total, old_col.canonical_type, new_col.canonical_type
                )
            } else {
                format!(
                    "Borderline rename candidate ({:.2} in [{:.2}, {:.2}))",
                    score.total, cfg.ambiguous_threshold, cfg.accept_threshold
                )
            };
            ambiguous.push(AmbiguousRenameCandidate {
                old_column: old_col.name.clone(),
                new_column: new_col.name.clone(),
                score,
                reason,
            });
        }
    }

    let unmatched_dropped = rem_old
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !matched_old.contains(i))
        .map(|(_, c)| c.name.clone())
        .collect();
    let unmatched_added = rem_new
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !matched_new.contains(i))
        .map(|(_, c)| c.name.clone())
        .collect();

    ColumnRenameAnalysis {
        confirmed,
        ambiguous,
        unmatched_dropped,
        unmatched_added,
    }
}

/// Detect potential table-level renames among unmatched tables using name + column set overlap.
#[must_use]
pub fn detect_table_rename_candidates(
    dropped_tables: &[&TableIr],
    added_tables: &[&TableIr],
) -> Vec<TableRenameCandidate> {
    if dropped_tables.is_empty() || added_tables.is_empty() {
        return Vec::new();
    }
    let n = dropped_tables.len().max(added_tables.len());
    let mut scores = vec![vec![0.0; added_tables.len()]; dropped_tables.len()];
    for (r, old_t) in dropped_tables.iter().enumerate() {
        let old_cols: BTreeSet<&str> = old_t.columns.iter().map(|c| c.name.as_str()).collect();
        for (c, new_t) in added_tables.iter().enumerate() {
            let new_cols: BTreeSet<&str> = new_t.columns.iter().map(|c| c.name.as_str()).collect();
            let col_jaccard = set_jaccard(&old_cols, &new_cols);
            let name_sim = combined_name_similarity(&old_t.name, &new_t.name).0;
            scores[r][c] = 0.50 * name_sim + 0.50 * col_jaccard;
        }
    }

    let matrix = Matrix::from_fn(n, n, |(r, c)| {
        if r < dropped_tables.len() && c < added_tables.len() {
            (scores[r][c] * 1_000_000.0).round() as i64
        } else {
            0
        }
    });
    let (_, assignments) = kuhn_munkres(&matrix);

    let mut out = Vec::new();
    for (r, &c) in assignments.iter().enumerate() {
        if r < dropped_tables.len() && c < added_tables.len() && scores[r][c] >= 0.65 {
            out.push(TableRenameCandidate {
                old_table: dropped_tables[r].name.clone(),
                new_table: added_tables[c].name.clone(),
                score: scores[r][c],
            });
        }
    }
    out
}

fn compute_pair_score(
    old_col: &ColumnIr,
    new_col: &ColumnIr,
    old_total_cols: usize,
    new_total_cols: usize,
    anchors: &[(usize, usize)],
    cfg: &RenameConfig,
) -> RenameScoreBreakdown {
    let (name_score, dl, jw, jaccard) = combined_name_similarity(&old_col.name, &new_col.name);
    let compat = old_col
        .canonical_type
        .classify_transition(&new_col.canonical_type);
    let type_score = compat.rename_score();
    let pos_score = anchor_relative_position_score(
        old_col.ordinal,
        new_col.ordinal,
        old_total_cols,
        new_total_cols,
        anchors,
    );

    let compat_str = match compat {
        TypeCompatibility::Exact => "exact",
        TypeCompatibility::Widening => "widening",
        TypeCompatibility::Narrowing => "narrowing",
        TypeCompatibility::CompatibleCrossFamily => "cross_family",
        TypeCompatibility::Incompatible => "incompatible",
    };

    let total = (cfg.name_weight * name_score
        + cfg.type_weight * type_score
        + cfg.pos_weight * pos_score)
        .clamp(0.0, 1.0);

    RenameScoreBreakdown {
        total,
        name_score,
        type_score,
        pos_score,
        damerau_levenshtein: dl,
        jaro_winkler: jw,
        token_jaccard: jaccard,
        compatibility: compat_str.to_string(),
        explicit_override: false,
    }
}

fn combined_name_similarity(a: &str, b: &str) -> (f64, f64, f64, f64) {
    let dl = strsim::normalized_damerau_levenshtein(a, b);
    let jw = strsim::jaro_winkler(a, b);
    let tokens_a: BTreeSet<&str> = a.split('_').filter(|t| !t.is_empty()).collect();
    let tokens_b: BTreeSet<&str> = b.split('_').filter(|t| !t.is_empty()).collect();
    let jaccard = set_jaccard(&tokens_a, &tokens_b);
    let min_len = tokens_a.len().min(tokens_b.len()) as f64;
    let overlap = if min_len == 0.0 {
        1.0
    } else {
        tokens_a.intersection(&tokens_b).count() as f64 / min_len
    };
    let token_sim = 0.75 * jaccard + 0.25 * overlap;
    let combined = 0.45 * dl + 0.30 * jw + 0.25 * token_sim;
    (combined, dl, jw, jaccard)
}

fn set_jaccard<T: Ord>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let inter = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 { 0.0 } else { inter / union }
}

fn anchor_relative_position_score(
    old_ord: usize,
    new_ord: usize,
    old_len: usize,
    new_len: usize,
    anchors: &[(usize, usize)],
) -> f64 {
    // Use bracketing exact-matched columns so insertions earlier/later in a class
    // don't unfairly shift ordinal similarity.
    let left_anchor = anchors.iter().rfind(|(o, _)| *o < old_ord).copied();
    let right_anchor = anchors.iter().find(|(o, _)| *o > old_ord).copied();

    if let (Some((ol, nl)), Some((or_pos, nr))) = (left_anchor, right_anchor)
        && or_pos > ol
        && nr > nl
    {
        let frac_old = (old_ord - ol) as f64 / (or_pos - ol) as f64;
        if new_ord >= nl && new_ord <= nr {
            let frac_new = (new_ord - nl) as f64 / (nr - nl) as f64;
            return (1.0 - (frac_old - frac_new).abs()).clamp(0.0, 1.0);
        }
        return 0.0;
    }

    let p_old = if old_len <= 1 {
        0.0
    } else {
        old_ord as f64 / (old_len - 1) as f64
    };
    let p_new = if new_len <= 1 {
        0.0
    } else {
        new_ord as f64 / (new_len - 1) as f64
    };
    (1.0 - (p_old - p_new).abs()).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::ir::{CanonicalType, ConfidenceLevel, PrimaryKeyIr, TableOwnership};

    fn col(name: &str, ordinal: usize, ty: CanonicalType) -> ColumnIr {
        ColumnIr {
            name: name.to_string(),
            ordinal,
            canonical_type: ty,
            dialect_types: BTreeMap::new(),
            nullable: false,
            autoincrement: false,
            server_default: None,
            computed: None,
            comment: None,
            confidence: ConfidenceLevel::High,
        }
    }

    fn dummy_table(name: &str, cols: Vec<ColumnIr>) -> TableIr {
        TableIr {
            name: name.to_string(),
            ownership: TableOwnership::Core,
            columns: cols,
            primary_key: PrimaryKeyIr::default(),
            foreign_keys: Vec::new(),
            uniques: Vec::new(),
            checks: Vec::new(),
            indexes: Vec::new(),
            comment: None,
            confidence: ConfidenceLevel::High,
        }
    }

    #[test]
    fn rename_detector_solves_global_optimal_with_prefix_shift() {
        let old = dummy_table(
            "users",
            vec![
                col("id", 0, CanonicalType::Uuid),
                col("display_name", 1, CanonicalType::Varchar { length: Some(64) }),
                col("email_addr", 2, CanonicalType::Varchar { length: Some(255) }),
                col("created_at", 3, CanonicalType::Double),
            ],
        );
        // Shifted ordinals due to column insertion at position 1!
        let new = dummy_table(
            "users",
            vec![
                col("id", 0, CanonicalType::Uuid),
                col("tenant_id", 1, CanonicalType::Uuid),
                col("full_display_name", 2, CanonicalType::Varchar { length: Some(128) }),
                col("email_address", 3, CanonicalType::Varchar { length: Some(255) }),
                col("created_at", 4, CanonicalType::Double),
            ],
        );

        let anchors = vec![(0, 0), (3, 4)];
        let dropped = vec![&old.columns[1], &old.columns[2]];
        let added = vec![&new.columns[1], &new.columns[2], &new.columns[3]];
        let res = detect_column_renames(&old, &new, &anchors, &dropped, &added, &RenameConfig::default());

        assert_eq!(
            res.confirmed.len(),
            2,
            "confirmed={:?}, ambiguous={:?}",
            res.confirmed,
            res.ambiguous
        );
        assert!(res
            .confirmed
            .iter()
            .any(|r| r.old_column == "display_name" && r.new_column == "full_display_name"));
        assert!(res
            .confirmed
            .iter()
            .any(|r| r.old_column == "email_addr" && r.new_column == "email_address"));
        assert_eq!(res.unmatched_added, vec!["tenant_id".to_string()]);
        assert!(res.unmatched_dropped.is_empty());
    }

    #[test]
    fn rename_detector_blocks_incompatible_type_unless_overridden() {
        let old = dummy_table(
            "items",
            vec![col("item_code", 0, CanonicalType::Boolean)],
        );
        let new = dummy_table(
            "items",
            vec![col("item_codes", 0, CanonicalType::Json)],
        );

        let dropped = vec![&old.columns[0]];
        let added = vec![&new.columns[0]];
        let res = detect_column_renames(&old, &new, &[], &dropped, &added, &RenameConfig::default());
        assert!(res.confirmed.is_empty());
        assert!(!res.ambiguous.is_empty());

        let mut cfg = RenameConfig::default();
        cfg.insert_override_spec("items.item_code=item_codes")
            .expect("valid spec");
        let res_override = detect_column_renames(&old, &new, &[], &dropped, &added, &cfg);
        assert_eq!(res_override.confirmed.len(), 1);
        assert!(res_override.confirmed[0].score.explicit_override);
    }

    #[test]
    fn rename_detector_flags_borderline_rename_as_ambiguous() {
        let old = dummy_table("notes", vec![col("summary", 0, CanonicalType::Text)]);
        let new = dummy_table(
            "notes",
            vec![col("brief_summary_text", 0, CanonicalType::Text)],
        );
        let dropped = vec![&old.columns[0]];
        let added = vec![&new.columns[0]];
        let res = detect_column_renames(&old, &new, &[], &dropped, &added, &RenameConfig::default());
        assert!(res.confirmed.is_empty(), "{:?}", res.confirmed);
        assert_eq!(res.ambiguous.len(), 1);
        assert_eq!(res.unmatched_dropped, vec!["summary".to_string()]);
        assert_eq!(res.unmatched_added, vec!["brief_summary_text".to_string()]);
    }
}
