//! Streaming encrypted `cfms-ctl backup export` implementation.
//!
//! Writes `ManifestHeader`, ordered database tables, deduplicated storage blobs, and
//! `IntegrityFooter` directly through `MessagePack -> Zstd -> Chunked AES-256-GCM` into a
//! sibling ciphertext temporary file before `persist_noclobber`, never writing plaintext
//! archives or extracted files to disk.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use bytes::Bytes;
use chrono::Utc;
use dialoguer::{Confirm, Input, MultiSelect};
use futures_util::StreamExt;
use indicatif::ProgressBar;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use zeroize::Zeroizing;
use crate::cli::backup::BackupExportArgs;
use crate::core::config::ConfigDocument;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::DbPool;
use crate::db::schema::{ExtractorMode, builtin_schema_ir, extract_code_schema_ir};
use crate::db::transfer::{
    NODE_BATCH_SIZE, SqlValue, TransferColumn, build_filtered_select_sql,
    build_node_hierarchy_cte_sql, count_table_rows, fetch_rows_by_str_ids, hash_canonical_row,
    stream_query,
};
use crate::ops::AppContext;
use crate::ops::extension::version::discover_server_version;
use crate::storage::{StorageBackend, resolve_storage, validate_storage_relative_path};
use crate::ui::{CommandReport, KeyValueTable, OutputFormat, UiConsole};
use super::backup_progress_bar;
use super::format::{
    BACKUP_FORMAT_VERSION, ChunkedEncryptWriter, DEFAULT_CHUNK_SIZE, EnvelopeHeaderSpec,
    encode_backup_key_base31, generate_backup_key, write_envelope_header, write_key_file_exclusive,
};
use super::selection::{
    BackupComponent, ComponentSelection, SourceExportPlan, fetch_active_rule_set_ids,
    partial_export_where_clause, prepare_source_export_plan,
};
use super::stream::{
    BlobEndPayload, BlobStartPayload, ConfigurationPayload, FileEntryPayload, IntegrityFooter,
    MAX_BLOB_CHUNK_BYTES, ManifestHeader, MissingInactiveFilePayload, StreamRecordWriter,
    TableDigestSummary, backup_rows_from_sql, sql_val_to_id,
};

const EXPORT_ROW_BATCH_SIZE: usize = 256;

/// Structured report emitted by `cfms-ctl backup export`.
#[derive(Debug, Clone, Serialize)]
pub struct BackupExportReport {
    pub archive_path: String,
    pub file_size: u64,
    pub format_version: u32,
    pub created_at: String,
    pub server_version: String,
    pub schema_revision: String,
    pub storage_provider: String,
    pub storage_target: String,
    pub components: Vec<String>,
    pub auto_added_components: Vec<String>,
    pub table_count: usize,
    pub total_rows: u64,
    pub file_entries: usize,
    pub unique_blobs: usize,
    pub blob_bytes: u64,
    pub missing_inactive_files: usize,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_out_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_key: Option<String>,
}

impl CommandReport for BackupExportReport {
    fn render_human(&self, ui: &UiConsole) {
        for warning in &self.warnings {
            ui.print_warning(warning);
        }

        let mut table = KeyValueTable::new("Backup Export Summary");
        table
            .row("Archive Path", self.archive_path.clone())
            .row("Archive Size (bytes)", self.file_size.to_string())
            .row("Format Version", self.format_version.to_string())
            .row("Server Version", self.server_version.clone())
            .row("Schema Revision", self.schema_revision.clone())
            .row(
                "Storage Backend",
                format!("{} ({})", self.storage_provider, self.storage_target),
            )
            .row("Components", self.components.join(", "));
        if !self.auto_added_components.is_empty() {
            table.row("Auto-Added Dependencies", self.auto_added_components.join(", "));
        }
        table
            .row("Tables Exported", self.table_count.to_string())
            .row("Total Rows Exported", self.total_rows.to_string())
            .row("File Entries", self.file_entries.to_string())
            .row("Unique Blobs", self.unique_blobs.to_string())
            .row("Blob Bytes (raw)", self.blob_bytes.to_string())
            .row("Missing Inactive Files", self.missing_inactive_files.to_string());
        if let Some(ref key_path) = self.key_out_path {
            table.row("Decryption Key File", key_path.clone());
        }
        table.print();

        println!();
        ui.print_success("Encrypted streaming backup archive created successfully.");
        if let Some(ref key) = self.generated_key {
            println!();
            ui.print_warning(
                "Store this decryption key safely. Without it, the backup archive CANNOT be decrypted:",
            );
            println!("  {key}");
        }
    }
}

struct ResolvedExportOptions {
    output_path: PathBuf,
    key_out: Option<PathBuf>,
    selection: ComponentSelection,
}

#[derive(Debug, Clone)]
struct ExportedFileMeta {
    id: String,
    storage_path: String,
    active: bool,
}

#[derive(Default)]
struct ExportStreamState {
    table_digests: BTreeMap<String, TableDigestSummary>,
    total_rows: u64,
    files_meta: Vec<ExportedFileMeta>,
    seen_file_ids: HashSet<String>,
    seen_paths_ci: HashMap<String, String>,
}

/// Execute `cfms-ctl backup export`.
pub async fn run_export(ctx: &AppContext, args: BackupExportArgs) -> Result<()> {
    let options = resolve_export_options(ctx, &args)?;
    validate_export_targets(&options)?;

    let paths = ctx.resolve_paths()?;
    let _lock = ctx.acquire_server_lock(&paths, false)?;
    let report = execute_export_locked(ctx, &paths, &options).await?;
    ctx.ui.render(&report);
    Ok(())
}

/// Create a full encrypted `.confbak` safety checkpoint when the caller already holds [`crate::core::ServerLockGuard`].
pub async fn export_pre_mutation_backup(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    output_path: PathBuf,
    key_out: Option<PathBuf>,
) -> Result<BackupExportReport> {
    let options = ResolvedExportOptions {
        output_path,
        key_out,
        selection: ComponentSelection::all(),
    };
    validate_export_targets(&options)?;
    execute_export_locked(ctx, paths, &options).await
}

async fn execute_export_locked(
    ctx: &AppContext,
    paths: &WorkspacePaths,
    options: &ResolvedExportOptions,
) -> Result<BackupExportReport> {
    let server_version = discover_server_version(paths)?.version.to_string();
    let config = ctx.load_config(paths)?;
    let storage = resolve_storage(paths, &config).await?;
    storage.preflight().await?;
    let configuration = extract_configuration_payload(
        &config,
        options.selection.contains(BackupComponent::Configuration),
    )?;

    let pool = ctx.connect_db(paths).await?;
    let base_ir = extract_code_schema_ir(paths, ExtractorMode::Auto, None, None, true, true)
        .await
        .unwrap_or_else(|_| builtin_schema_ir(true));
    let plan =
        prepare_source_export_plan(&pool, &base_ir, Some(paths), &options.selection).await?;
    let active_rule_set_ids = if plan.table_order.iter().any(|t| t == "nodes")
        && plan
            .table_order
            .iter()
            .any(|t| t == "compiled_access_rule_sets")
    {
        fetch_active_rule_set_ids(&pool).await?
    } else {
        HashSet::new()
    };

    let created_at = Utc::now().to_rfc3339();
    let component_names = options.selection.component_names();

    let master_key = generate_backup_key();
    let encoded_key = encode_backup_key_base31(&master_key);

    let parent_dir = archive_parent_dir(&options.output_path)?;
    std::fs::create_dir_all(parent_dir)?;
    let temp_archive = tempfile::Builder::new()
        .prefix(".cfms-backup-")
        .suffix(".confbak.part")
        .tempfile_in(parent_dir)?;

    let pb = backup_progress_bar(ctx.ui.format(), plan.table_order.len() as u64 + 1);
    let write_res = stream_archive_payload(
        &pool,
        &storage,
        &plan,
        &options.selection,
        &active_rule_set_ids,
        &configuration,
        &created_at,
        &server_version,
        &component_names,
        &master_key,
        temp_archive,
        &pb,
    )
    .await;
    pb.finish_and_clear();
    pool.close().await;

    let (temp_file, mut stats) = write_res?;
    for w in storage.collected_warnings() {
        if !stats.warnings.iter().any(|existing| existing == &w) {
            stats.warnings.push(w);
        }
    }
    temp_file.persist_noclobber(&options.output_path).map_err(|e| {
        CfmsError::Backup(format!(
            "Unable to persist backup archive '{}': {}",
            options.output_path.display(),
            e.error
        ))
    })?;

    if let Some(ref key_path) = options.key_out
        && let Err(err) = write_key_file_exclusive(key_path, &encoded_key)
    {
        let _ = std::fs::remove_file(&options.output_path);
        return Err(err);
    }

    let file_size = std::fs::metadata(&options.output_path)?.len();
    Ok(build_export_report(
        options,
        &plan,
        &created_at,
        &server_version,
        storage.kind(),
        storage.target_description(),
        file_size,
        stats,
        encoded_key,
    ))
}

struct ExportFinishStats {
    table_count: usize,
    total_rows: u64,
    file_entries: usize,
    unique_blobs: usize,
    blob_bytes: u64,
    missing_inactive_files: usize,
    warnings: Vec<String>,
}

type ExportRecordWriter = StreamRecordWriter<
    zstd::stream::write::Encoder<'static, ChunkedEncryptWriter<BufWriter<tempfile::NamedTempFile>>>,
>;

#[allow(clippy::too_many_arguments)]
async fn stream_archive_payload(
    pool: &DbPool,
    storage: &Arc<dyn StorageBackend>,
    plan: &SourceExportPlan,
    selection: &ComponentSelection,
    active_rule_set_ids: &HashSet<String>,
    configuration: &ConfigurationPayload,
    created_at: &str,
    server_version: &str,
    component_names: &[String],
    master_key: &Zeroizing<[u8; 32]>,
    temp_archive: tempfile::NamedTempFile,
    pb: &ProgressBar,
) -> Result<(tempfile::NamedTempFile, ExportFinishStats)> {
    let envelope = EnvelopeHeaderSpec::new(
        created_at.to_string(),
        server_version.to_string(),
        plan.schema_revision.clone(),
        component_names.to_vec(),
        storage.kind().to_string(),
        DEFAULT_CHUNK_SIZE,
    );

    let mut out_writer = BufWriter::with_capacity(256 * 1024, temp_archive);
    let header_sha256 = write_envelope_header(&mut out_writer, &envelope)?;
    let enc_writer =
        ChunkedEncryptWriter::new(out_writer, master_key, &envelope, header_sha256)?;
    let zstd_writer = zstd::stream::write::Encoder::new(enc_writer, 3)
        .map_err(|e| CfmsError::Backup(format!("Failed to initialize Zstd encoder: {e}")))?;
    let mut record_writer: ExportRecordWriter = StreamRecordWriter::new(zstd_writer);

    let manifest = ManifestHeader::new(
        created_at.to_string(),
        server_version.to_string(),
        plan.schema_revision.clone(),
        component_names.to_vec(),
        storage.kind().to_string(),
        plan.extension_tables.clone(),
        plan.table_order.clone(),
        plan.table_specs.clone(),
        plan.export_ir.clone(),
        configuration.clone(),
    );
    record_writer.write_manifest_header(&manifest)?;

    let mut state = ExportStreamState::default();
    let mut hierarchy_streamed = false;

    for table_name in &plan.table_order {
        if plan.use_node_hierarchy
            && matches!(table_name.as_str(), "nodes" | "folders" | "documents")
        {
            if !hierarchy_streamed {
                hierarchy_streamed = true;
                pb.set_message("Exporting node hierarchy (nodes, folders, documents)");
                stream_node_hierarchy(
                    pool,
                    plan,
                    active_rule_set_ids,
                    &mut record_writer,
                    &mut state,
                )
                .await?;
            }
            pb.inc(1);
            continue;
        }

        pb.set_message(format!("Exporting table '{table_name}'"));
        stream_regular_table(
            pool,
            plan,
            selection,
            table_name,
            &mut record_writer,
            &mut state,
        )
        .await?;
        pb.inc(1);
    }

    pb.set_message(format!(
        "Streaming {} storage file reference(s) from {}",
        state.files_meta.len(),
        storage.kind()
    ));
    let (mut record_writer, file_stats) =
        stream_storage_files(storage, &state.files_meta, record_writer).await?;
    pb.inc(1);

    let footer = IntegrityFooter {
        tables: state.table_digests.clone(),
        blobs: file_stats.blobs,
        files: file_stats.files,
        missing_inactive_files: file_stats.missing_inactive_files,
        warnings: file_stats.warnings.clone(),
    };
    record_writer.write_integrity_footer(&footer)?;
    record_writer.flush()?;

    let zstd_writer = record_writer.into_inner();
    let enc_writer = zstd_writer
        .finish()
        .map_err(|e| CfmsError::Backup(format!("Failed to finalize Zstd stream: {e}")))?;
    let mut out_writer = enc_writer.finish()?;
    out_writer.flush()?;
    let temp_file = out_writer.into_inner().map_err(|e| CfmsError::Io(e.into_error()))?;
    temp_file.as_file().sync_all()?;

    let stats = ExportFinishStats {
        table_count: state.table_digests.len(),
        total_rows: state.total_rows,
        file_entries: footer.files.len(),
        unique_blobs: footer.blobs.len(),
        blob_bytes: file_stats.blob_bytes,
        missing_inactive_files: footer.missing_inactive_files.len(),
        warnings: file_stats.warnings,
    };
    Ok((temp_file, stats))
}

async fn stream_node_hierarchy<W: Write>(
    pool: &DbPool,
    plan: &SourceExportPlan,
    active_rule_set_ids: &HashSet<String>,
    writer: &mut StreamRecordWriter<W>,
    state: &mut ExportStreamState,
) -> Result<()> {
    let nodes_def = plan.transfer_tables.get("nodes").ok_or_else(|| {
        CfmsError::Backup("Missing 'nodes' metadata for hierarchy export".to_string())
    })?;
    let folders_def = plan.transfer_tables.get("folders").ok_or_else(|| {
        CfmsError::Backup("Missing 'folders' metadata for hierarchy export".to_string())
    })?;
    let docs_def = plan.transfer_tables.get("documents").ok_or_else(|| {
        CfmsError::Backup("Missing 'documents' metadata for hierarchy export".to_string())
    })?;

    let node_cols: Vec<TransferColumn> = nodes_def.data_columns().cloned().collect();
    let folder_cols: Vec<TransferColumn> = folders_def.data_columns().cloned().collect();
    let doc_cols: Vec<TransferColumn> = docs_def.data_columns().cloned().collect();

    let node_id_idx = col_index(&node_cols, "id", "nodes")?;
    let ars_idx = node_cols.iter().position(|c| c.name == "access_rule_set_id");
    let check_ars = plan.table_specs.contains_key("compiled_access_rule_sets");

    for tbl in ["nodes", "folders", "documents"] {
        writer.write_table_start(tbl)?;
    }

    let expected_node_count = count_table_rows(pool, "nodes").await?;
    let mut node_rows_exported = 0u64;
    let mut nodes_hasher = Sha256::new();
    let mut folders_hasher = Sha256::new();
    let mut docs_hasher = Sha256::new();
    let mut folders_count = 0u64;
    let mut docs_count = 0u64;

    let (cte_cols, cte_sql) = build_node_hierarchy_cte_sql(pool.kind(), &node_cols);
    let mut stream = stream_query(pool, &cte_sql, &cte_cols).await?;
    let mut current_depth: Option<i64> = None;
    let mut batch_nodes: Vec<Vec<SqlValue>> = Vec::with_capacity(NODE_BATCH_SIZE);
    let mut batch_ids: Vec<String> = Vec::with_capacity(NODE_BATCH_SIZE);

    while let Some(row_res) = stream.next().await {
        let row = row_res?;
        let depth = match &row[0] {
            SqlValue::I64(d) => *d,
            other => {
                return Err(CfmsError::Database(format!(
                    "Unexpected CTE migration_depth value: {other:?}"
                )));
            }
        };
        let should_flush = match current_depth {
            Some(prev) if prev != depth => true,
            _ => batch_nodes.len() >= NODE_BATCH_SIZE,
        };
        if should_flush && !batch_nodes.is_empty() {
            flush_hierarchy_batch(
                pool,
                &batch_nodes,
                &batch_ids,
                &folder_cols,
                &doc_cols,
                writer,
                &mut nodes_hasher,
                &mut folders_hasher,
                &mut docs_hasher,
                &mut folders_count,
                &mut docs_count,
            )
            .await?;
            node_rows_exported += batch_nodes.len() as u64;
            batch_nodes.clear();
            batch_ids.clear();
        }
        current_depth = Some(depth);

        let mut node_row = row.into_iter().skip(1).collect::<Vec<_>>();
        normalize_node_row(
            &mut node_row,
            ars_idx,
            check_ars,
            active_rule_set_ids,
        );
        let id = sql_val_to_id(&node_row[node_id_idx], "nodes.id")?;
        batch_nodes.push(node_row);
        batch_ids.push(id);
    }
    drop(stream);

    if !batch_nodes.is_empty() {
        flush_hierarchy_batch(
            pool,
            &batch_nodes,
            &batch_ids,
            &folder_cols,
            &doc_cols,
            writer,
            &mut nodes_hasher,
            &mut folders_hasher,
            &mut docs_hasher,
            &mut folders_count,
            &mut docs_count,
        )
        .await?;
        node_rows_exported += batch_nodes.len() as u64;
    }

    if node_rows_exported != expected_node_count {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Node hierarchy export visited {node_rows_exported} node(s), expected {expected_node_count} (possible parent cycle or dangling parent_id)"
        )));
    }

    let summaries = [
        ("nodes", node_rows_exported, hex::encode(nodes_hasher.finalize())),
        ("folders", folders_count, hex::encode(folders_hasher.finalize())),
        ("documents", docs_count, hex::encode(docs_hasher.finalize())),
    ];
    for (name, count, sha) in summaries {
        writer.write_table_end(&super::stream::TableEndPayload {
            table_name: name.to_string(),
            row_count: count,
            canonical_sha256: sha.clone(),
        })?;
        state.table_digests.insert(
            name.to_string(),
            TableDigestSummary {
                rows: count,
                sha256: sha,
            },
        );
        state.total_rows += count;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn flush_hierarchy_batch<W: Write>(
    pool: &DbPool,
    node_rows: &[Vec<SqlValue>],
    node_ids: &[String],
    folder_cols: &[TransferColumn],
    doc_cols: &[TransferColumn],
    writer: &mut StreamRecordWriter<W>,
    nodes_hasher: &mut Sha256,
    folders_hasher: &mut Sha256,
    docs_hasher: &mut Sha256,
    folders_count: &mut u64,
    docs_count: &mut u64,
) -> Result<()> {
    for row in node_rows {
        hash_canonical_row(nodes_hasher, row)?;
    }
    writer.write_table_row_batch("nodes", backup_rows_from_sql(node_rows)?)?;

    let folder_rows = fetch_rows_by_str_ids(pool, "folders", folder_cols, node_ids).await?;
    if !folder_rows.is_empty() {
        for row in &folder_rows {
            hash_canonical_row(folders_hasher, row)?;
        }
        *folders_count += folder_rows.len() as u64;
        writer.write_table_row_batch("folders", backup_rows_from_sql(&folder_rows)?)?;
    }

    let doc_rows = fetch_rows_by_str_ids(pool, "documents", doc_cols, node_ids).await?;
    if !doc_rows.is_empty() {
        for row in &doc_rows {
            hash_canonical_row(docs_hasher, row)?;
        }
        *docs_count += doc_rows.len() as u64;
        writer.write_table_row_batch("documents", backup_rows_from_sql(&doc_rows)?)?;
    }

    Ok(())
}

async fn stream_regular_table<W: Write>(
    pool: &DbPool,
    plan: &SourceExportPlan,
    selection: &ComponentSelection,
    table_name: &str,
    writer: &mut StreamRecordWriter<W>,
    state: &mut ExportStreamState,
) -> Result<()> {
    let table_def = plan.transfer_tables.get(table_name).ok_or_else(|| {
        CfmsError::Backup(format!("Missing transfer metadata for table '{table_name}'"))
    })?;
    let cols: Vec<TransferColumn> = table_def.data_columns().cloned().collect();
    let has_userblock_entries = plan.export_ir.tables.contains_key("userblock_entries");
    let where_clause =
        partial_export_where_clause(table_name, &selection.selected, has_userblock_entries);
    let sql = build_filtered_select_sql(pool.kind(), table_def, &cols, where_clause, true);

    let file_indices = if table_name == "files" {
        Some((
            col_index(&cols, "id", "files")?,
            col_index(&cols, "path", "files")?,
            col_index(&cols, "active", "files")?,
        ))
    } else {
        None
    };

    writer.write_table_start(table_name)?;

    let mut hasher = Sha256::new();
    let mut row_count = 0u64;
    let mut batch: Vec<Vec<SqlValue>> = Vec::with_capacity(EXPORT_ROW_BATCH_SIZE);

    let mut stream = stream_query(pool, &sql, &cols).await?;
    while let Some(row_res) = stream.next().await {
        let row = row_res?;
        if let Some((id_idx, path_idx, active_idx)) = file_indices {
            record_exported_file_meta(state, &row[id_idx], &row[path_idx], &row[active_idx])?;
        }
        hash_canonical_row(&mut hasher, &row)?;
        row_count += 1;
        batch.push(row);

        if batch.len() >= EXPORT_ROW_BATCH_SIZE {
            writer.write_table_row_batch(table_name, backup_rows_from_sql(&batch)?)?;
            batch.clear();
        }
    }
    drop(stream);

    if !batch.is_empty() {
        writer.write_table_row_batch(table_name, backup_rows_from_sql(&batch)?)?;
    }

    let sha256 = hex::encode(hasher.finalize());
    writer.write_table_end(&super::stream::TableEndPayload {
        table_name: table_name.to_string(),
        row_count,
        canonical_sha256: sha256.clone(),
    })?;

    state.table_digests.insert(
        table_name.to_string(),
        TableDigestSummary {
            rows: row_count,
            sha256,
        },
    );
    state.total_rows += row_count;
    Ok(())
}

struct FileExportStreamStats {
    blobs: Vec<BlobEndPayload>,
    files: Vec<FileEntryPayload>,
    missing_inactive_files: Vec<MissingInactiveFilePayload>,
    warnings: Vec<String>,
    blob_bytes: u64,
}

enum UniqueBlobMsg {
    Missing,
    Begin,
    Chunk(Bytes),
    End,
}

fn spawn_storage_prefetch_slot(
    storage: Arc<dyn StorageBackend>,
    path: String,
) -> mpsc::Receiver<Result<UniqueBlobMsg>> {
    let (tx, rx) = mpsc::channel::<Result<UniqueBlobMsg>>(4);
    tokio::spawn(async move {
        match storage.open_read_optional(&path).await {
            Ok(None) => {
                let _ = tx.send(Ok(UniqueBlobMsg::Missing)).await;
            }
            Ok(Some(mut stream)) => {
                if tx.send(Ok(UniqueBlobMsg::Begin)).await.is_err() {
                    return;
                }
                while let Some(chunk_res) = stream.next().await {
                    match chunk_res {
                        Ok(bytes) => {
                            let mut offset = 0usize;
                            while offset < bytes.len() {
                                let end = (offset + MAX_BLOB_CHUNK_BYTES).min(bytes.len());
                                let slice = bytes.slice(offset..end);
                                if tx.send(Ok(UniqueBlobMsg::Chunk(slice))).await.is_err() {
                                    return;
                                }
                                offset = end;
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            return;
                        }
                    }
                }
                let _ = tx.send(Ok(UniqueBlobMsg::End)).await;
            }
            Err(e) => {
                let _ = tx.send(Err(e)).await;
            }
        }
    });
    rx
}

fn handle_missing_file_meta(
    meta: &ExportedFileMeta,
    writer: &mut ExportRecordWriter,
    warnings: &mut Vec<String>,
    missing_inactive_files: &mut Vec<MissingInactiveFilePayload>,
) -> Result<()> {
    if !meta.active {
        let missing = MissingInactiveFilePayload {
            file_id: meta.id.clone(),
            storage_path: meta.storage_path.clone(),
        };
        warnings.push(format!(
            "Inactive file '{}' missing from storage path '{}'; omitted from archive.",
            meta.id, meta.storage_path
        ));
        writer.write_missing_inactive_file(&missing)?;
        missing_inactive_files.push(missing);
        return Ok(());
    }
    Err(CfmsError::ArchiveIntegrity(format!(
        "Active storage file '{}' is missing at '{}'",
        meta.id, meta.storage_path
    )))
}

fn consume_storage_blobs_blocking(
    files_meta: &[ExportedFileMeta],
    mut writer: ExportRecordWriter,
    mut rx: mpsc::Receiver<UniqueBlobMsg>,
) -> Result<(ExportRecordWriter, FileExportStreamStats)> {
    let mut path_to_blob: HashMap<String, BlobEndPayload> = HashMap::new();
    let mut missing_paths: HashSet<String> = HashSet::new();
    let mut blobs = Vec::new();
    let mut files = Vec::new();
    let mut missing_inactive_files = Vec::new();
    let mut warnings = Vec::new();
    let mut next_blob_id = 0u64;
    let mut total_blob_bytes = 0u64;

    for meta in files_meta {
        if let Some(existing_blob) = path_to_blob.get(&meta.storage_path) {
            let entry = FileEntryPayload {
                file_id: meta.id.clone(),
                storage_path: meta.storage_path.clone(),
                blob_id: existing_blob.blob_id,
                size: existing_blob.size,
                sha256: existing_blob.sha256.clone(),
            };
            writer.write_file_entry(&entry)?;
            files.push(entry);
            continue;
        }

        if missing_paths.contains(&meta.storage_path) {
            handle_missing_file_meta(
                meta,
                &mut writer,
                &mut warnings,
                &mut missing_inactive_files,
            )?;
            continue;
        }

        match rx.blocking_recv() {
            Some(UniqueBlobMsg::Missing) => {
                missing_paths.insert(meta.storage_path.clone());
                handle_missing_file_meta(
                    meta,
                    &mut writer,
                    &mut warnings,
                    &mut missing_inactive_files,
                )?;
            }
            Some(UniqueBlobMsg::Begin) => {
                let blob_id = next_blob_id;
                next_blob_id += 1;

                writer.write_blob_start(&BlobStartPayload {
                    blob_id,
                    storage_path: meta.storage_path.clone(),
                })?;

                let mut hasher = Sha256::new();
                let mut size = 0u64;
                loop {
                    match rx.blocking_recv() {
                        Some(UniqueBlobMsg::Chunk(bytes)) => {
                            hasher.update(&bytes);
                            size += bytes.len() as u64;
                            writer.write_blob_chunk(blob_id, &bytes)?;
                        }
                        Some(UniqueBlobMsg::End) => break,
                        Some(other) => {
                            let label = match other {
                                UniqueBlobMsg::Missing => "Missing",
                                UniqueBlobMsg::Begin => "Begin",
                                _ => "Unknown",
                            };
                            return Err(CfmsError::ArchiveIntegrity(format!(
                                "Unexpected prefetch state '{label}' while streaming '{}'",
                                meta.storage_path
                            )));
                        }
                        None => {
                            return Err(CfmsError::Backup(format!(
                                "Storage stream terminated prematurely while reading '{}'",
                                meta.storage_path
                            )));
                        }
                    }
                }

                let blob_end = BlobEndPayload {
                    blob_id,
                    size,
                    sha256: hex::encode(hasher.finalize()),
                };
                writer.write_blob_end(&blob_end)?;

                total_blob_bytes += size;
                path_to_blob.insert(meta.storage_path.clone(), blob_end.clone());
                blobs.push(blob_end.clone());

                let entry = FileEntryPayload {
                    file_id: meta.id.clone(),
                    storage_path: meta.storage_path.clone(),
                    blob_id,
                    size: blob_end.size,
                    sha256: blob_end.sha256,
                };
                writer.write_file_entry(&entry)?;
                files.push(entry);
            }
            Some(UniqueBlobMsg::Chunk(_)) | Some(UniqueBlobMsg::End) | None => {
                return Err(CfmsError::Backup(format!(
                    "Storage prefetch stream closed before delivering '{}'",
                    meta.storage_path
                )));
            }
        }
    }

    Ok((
        writer,
        FileExportStreamStats {
            blobs,
            files,
            missing_inactive_files,
            warnings,
            blob_bytes: total_blob_bytes,
        },
    ))
}

async fn stream_storage_files(
    storage: &Arc<dyn StorageBackend>,
    files_meta: &[ExportedFileMeta],
    writer: ExportRecordWriter,
) -> Result<(ExportRecordWriter, FileExportStreamStats)> {
    let mut seen_unique = HashSet::with_capacity(files_meta.len());
    let mut unique_paths = Vec::with_capacity(files_meta.len());
    for meta in files_meta {
        if seen_unique.insert(meta.storage_path.clone()) {
            unique_paths.push(meta.storage_path.clone());
        }
    }

    let (event_tx, event_rx) = mpsc::channel::<UniqueBlobMsg>(8);
    let files_meta_owned = files_meta.to_vec();
    let consumer_handle = tokio::task::spawn_blocking(move || {
        consume_storage_blobs_blocking(&files_meta_owned, writer, event_rx)
    });

    let concurrency = storage.recommended_concurrency().max(1);
    let mut next_to_spawn = 0usize;
    let mut window: VecDeque<mpsc::Receiver<Result<UniqueBlobMsg>>> =
        VecDeque::with_capacity(concurrency);

    while next_to_spawn < unique_paths.len() && window.len() < concurrency {
        window.push_back(spawn_storage_prefetch_slot(
            Arc::clone(storage),
            unique_paths[next_to_spawn].clone(),
        ));
        next_to_spawn += 1;
    }

    let mut producer_err: Option<CfmsError> = None;
    while let Some(mut slot_rx) = window.pop_front() {
        while next_to_spawn < unique_paths.len() && window.len() < concurrency {
            window.push_back(spawn_storage_prefetch_slot(
                Arc::clone(storage),
                unique_paths[next_to_spawn].clone(),
            ));
            next_to_spawn += 1;
        }

        while let Some(item_res) = slot_rx.recv().await {
            match item_res {
                Ok(msg) => {
                    if event_tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    producer_err = Some(e);
                    break;
                }
            }
        }
        if producer_err.is_some() {
            break;
        }
    }

    // Cancel all remaining prefetch slots and close consumer channel.
    drop(window);
    drop(event_tx);

    let consumer_res = consumer_handle
        .await
        .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))?;

    if let Some(err) = producer_err {
        return Err(err);
    }

    consumer_res
}

fn record_exported_file_meta(
    state: &mut ExportStreamState,
    id_val: &SqlValue,
    path_val: &SqlValue,
    active_val: &SqlValue,
) -> Result<()> {
    let id = sql_val_to_id(id_val, "files.id")?;
    if !state.seen_file_ids.insert(id.clone()) {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Duplicate file ID '{id}' encountered while exporting 'files'"
        )));
    }

    let raw_path = sql_val_to_id(path_val, "files.path")?;
    let storage_path = validate_storage_relative_path(&raw_path)?.to_string();

    let lower = storage_path.to_ascii_lowercase();
    if let Some(prev) = state.seen_paths_ci.get(&lower) {
        if prev != &storage_path {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Case-colliding storage paths '{prev}' and '{storage_path}' cannot be safely exported"
            )));
        }
    } else {
        state.seen_paths_ci.insert(lower, storage_path.clone());
    }

    let active = match active_val {
        SqlValue::Bool(b) => *b,
        SqlValue::I64(n) => *n != 0,
        other => {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Unexpected non-boolean value for files.active: {other:?}"
            )));
        }
    };

    state.files_meta.push(ExportedFileMeta {
        id,
        storage_path,
        active,
    });
    Ok(())
}

fn resolve_export_options(ctx: &AppContext, args: &BackupExportArgs) -> Result<ResolvedExportOptions> {
    if !args.interactive {
        let output_path = args.output_path.clone().ok_or_else(|| {
            CfmsError::InvalidArgument(
                "Missing OUTPUT_PATH (provide output path or pass `--interactive`)".to_string(),
            )
        })?;
        let selection = if args.components.is_empty() {
            ComponentSelection::all()
        } else {
            let requested: Vec<BackupComponent> = args
                .components
                .iter()
                .copied()
                .map(BackupComponent::from)
                .collect();
            ComponentSelection::resolve(&requested)?
        };
        return Ok(ResolvedExportOptions {
            output_path,
            key_out: args.key_out.clone(),
            selection,
        });
    }

    if ctx.ui.format() == OutputFormat::Json {
        return Err(CfmsError::InvalidArgument(
            "Interactive backup wizard (`--interactive`) cannot be used with `--output json`"
                .to_string(),
        ));
    }

    run_interactive_wizard()
}

fn run_interactive_wizard() -> Result<ResolvedExportOptions> {
    let labels: Vec<String> = BackupComponent::ALL
        .iter()
        .map(|c| format!("{:<15} — {}", c.as_str(), c.description()))
        .collect();
    let defaults = vec![true; labels.len()];

    let chosen_indices = MultiSelect::new()
        .with_prompt("Select backup components to include (space to toggle, enter to confirm)")
        .items(&labels)
        .defaults(&defaults)
        .interact()
        .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))?;

    if chosen_indices.is_empty() {
        return Err(CfmsError::InvalidArgument(
            "At least one backup component must be selected".to_string(),
        ));
    }

    let requested: Vec<BackupComponent> = chosen_indices
        .into_iter()
        .map(|idx| BackupComponent::ALL[idx])
        .collect();
    let selection = ComponentSelection::resolve(&requested)?;
    if !selection.auto_added.is_empty() {
        let added: Vec<&str> = selection.auto_added.iter().map(|c| c.as_str()).collect();
        eprintln!(
            "Automatically added required dependency component(s): {}",
            added.join(", ")
        );
    }

    let default_filename = format!(
        "cfms-backup-{}.confbak",
        Utc::now().format("%Y%m%d-%H%M%S")
    );
    let output_str: String = Input::new()
        .with_prompt("Destination backup archive path (.confbak)")
        .default(default_filename)
        .interact_text()
        .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))?;
    let output_path = PathBuf::from(output_str.trim());

    let save_key_file = Confirm::new()
        .with_prompt("Write the generated decryption key to a dedicated file (`--key-out`)?")
        .default(true)
        .interact()
        .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))?;

    let key_out = if save_key_file {
        let default_key_path = format!("{}.key", output_path.display());
        let key_str: String = Input::new()
            .with_prompt("Destination decryption key file path")
            .default(default_key_path)
            .interact_text()
            .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))?;
        let trimmed = key_str.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        }
    } else {
        None
    };

    Ok(ResolvedExportOptions {
        output_path,
        key_out,
        selection,
    })
}

fn validate_export_targets(options: &ResolvedExportOptions) -> Result<()> {
    if options.output_path.as_os_str().is_empty() {
        return Err(CfmsError::InvalidArgument(
            "Backup output path must not be empty".to_string(),
        ));
    }
    if std::fs::symlink_metadata(&options.output_path).is_ok() {
        return Err(CfmsError::Backup(format!(
            "Refusing to overwrite existing output archive '{}'",
            options.output_path.display()
        )));
    }
    if let Some(ref key_path) = options.key_out {
        if key_path.as_os_str().is_empty() {
            return Err(CfmsError::InvalidArgument(
                "Key output path must not be empty".to_string(),
            ));
        }
        if key_path == &options.output_path {
            return Err(CfmsError::InvalidArgument(
                "`--key-out` must differ from backup archive output path".to_string(),
            ));
        }
        if std::fs::symlink_metadata(key_path).is_ok() {
            return Err(CfmsError::Backup(format!(
                "Refusing to overwrite existing key file '{}'",
                key_path.display()
            )));
        }
    }
    Ok(())
}

fn extract_configuration_payload(
    config: &ConfigDocument,
    include_config: bool,
) -> Result<ConfigurationPayload> {
    if !include_config {
        return Ok(ConfigurationPayload::default());
    }
    let pepper = config
        .document()
        .get("security")
        .and_then(|v| v.as_table_like())
        .and_then(|t| t.get("pepper"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| {
            CfmsError::Config(
                "Component 'configuration' requires `[security].pepper` to be configured as a string in `config.toml`"
                    .to_string(),
            )
        })?;
    let secret_key = config
        .document()
        .get("server")
        .and_then(|v| v.as_table_like())
        .and_then(|t| t.get("secret_key"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| {
            CfmsError::Config(
                "Component 'configuration' requires `[server].secret_key` to be configured as a string in `config.toml`"
                    .to_string(),
            )
        })?;
    Ok(ConfigurationPayload {
        pepper: Some(pepper),
        secret_key: Some(secret_key),
    })
}

fn archive_parent_dir(output_path: &Path) -> Result<&Path> {
    match output_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => Ok(p),
        _ => Ok(Path::new(".")),
    }
}

fn normalize_node_row(
    row: &mut [SqlValue],
    ars_idx: Option<usize>,
    check_ars: bool,
    active_rule_set_ids: &HashSet<String>,
) {
    if !check_ars {
        return;
    }
    if let Some(idx) = ars_idx
        && let SqlValue::Str(ref id) = row[idx]
        && !active_rule_set_ids.contains(id)
    {
        row[idx] = SqlValue::Null;
    }
}

fn col_index(cols: &[TransferColumn], name: &str, table: &str) -> Result<usize> {
    cols.iter().position(|c| c.name == name).ok_or_else(|| {
        CfmsError::SchemaDrift(format!("Table '{table}' is missing required column '{name}'"))
    })
}

#[allow(clippy::too_many_arguments)]
fn build_export_report(
    options: &ResolvedExportOptions,
    plan: &SourceExportPlan,
    created_at: &str,
    server_version: &str,
    storage_provider: &str,
    storage_target: String,
    file_size: u64,
    stats: ExportFinishStats,
    encoded_key: Zeroizing<String>,
) -> BackupExportReport {
    let auto_added_components: Vec<String> = options
        .selection
        .auto_added
        .iter()
        .map(|c| c.as_str().to_string())
        .collect();
    let (key_out_path, generated_key) = match &options.key_out {
        Some(p) => (Some(p.display().to_string()), None),
        None => (None, Some(encoded_key.to_string())),
    };
    BackupExportReport {
        archive_path: options.output_path.display().to_string(),
        file_size,
        format_version: BACKUP_FORMAT_VERSION,
        created_at: created_at.to_string(),
        server_version: server_version.to_string(),
        schema_revision: plan.schema_revision.clone(),
        storage_provider: storage_provider.to_string(),
        storage_target,
        components: options.selection.component_names(),
        auto_added_components,
        table_count: stats.table_count,
        total_rows: stats.total_rows,
        file_entries: stats.file_entries,
        unique_blobs: stats.unique_blobs,
        blob_bytes: stats.blob_bytes,
        missing_inactive_files: stats.missing_inactive_files,
        warnings: stats.warnings,
        key_out_path,
        generated_key,
    }
}
