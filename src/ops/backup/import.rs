//! Streaming transactional `cfms-ctl backup import` implementation.
//!
//! Decrypts Chunk 0 upfront to validate header/schema compatibility, initializes blank targets
//! or enforces an empty existing schema, streams rows into a single [`TargetTx`] and blobs
//! directly through `.cfms-import-part-*` staged writes, and performs multi-resource rollback
//! across database schema, storage files, `config.toml`, and `init` marker on any failure.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use crate::cli::backup::BackupImportArgs;
use crate::core::atomic::atomic_write;
use crate::core::config::ConfigDocument;
use crate::core::error::{CfmsError, Result};
use crate::db::DbPool;
use crate::db::options::encode_option_value;
use crate::db::schema::ddl::execute_ddl_statements;
use crate::db::schema::{
    DEFERRED_COLUMNS, DEFERRED_UPDATE_ORDER, ExtractorMode, LATEST_SCHEMA_REVISION,
    SERIAL_IDENTITY_COLUMNS, SchemaInspector, SchemaIr, builtin_schema_ir,
    compile_full_schema_ddl, drop_all_cfms_tables, extract_code_schema_ir,
    infer_transfer_metadata, set_alembic_version,
};
use crate::db::transfer::{
    DEFERRED_UPDATE_BATCH_SIZE, SqlValue, TargetTx, TransferColumn, active_schema_subset,
    apply_deferred_update_batch, count_table_rows, insert_batch, insert_batch_size,
    sync_target_sequences,
};
use crate::ops::AppContext;
use crate::storage::{LocalFsStorage, StagedStorageFile, StorageBackend, resolve_local_storage};
use crate::ui::{CommandReport, KeyValueTable, OutputFormat, UiConsole, confirm_or_abort};
use super::format::read_key_from_args;
use super::stream::{
    ConfigurationPayload, IntegrityFooter, ManifestHeader, TableSchemaSpec, is_coupled_node_group,
    sql_val_to_id,
};
use super::verify::{VerifiedArchiveEvent, VerifiedArchiveReader};
use super::backup_progress_bar;

const INIT_MARKER_BYTES: &[u8] = b"This file indicates that the database has been initialized.\n";
const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;

/// Structured report emitted by `cfms-ctl backup import`.
#[derive(Debug, Clone, Serialize)]
pub struct BackupImportReport {
    pub archive_path: String,
    pub target_endpoint: String,
    pub target_dialect: String,
    pub format_version: u32,
    pub schema_revision: String,
    pub components: Vec<String>,
    pub blank_target_initialized: bool,
    pub table_count: usize,
    pub total_rows: u64,
    pub restored_files: usize,
    pub unique_blobs: usize,
    pub blob_bytes: u64,
    pub missing_inactive_files: usize,
    pub configuration_restored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_backup_path: Option<String>,
    pub warnings: Vec<String>,
}

impl CommandReport for BackupImportReport {
    fn render_human(&self, ui: &UiConsole) {
        for warning in &self.warnings {
            ui.print_warning(warning);
        }

        let mut table = KeyValueTable::new("Backup Import Summary");
        table
            .row("Archive Path", self.archive_path.clone())
            .row(
                "Target Database",
                format!("{} ({})", self.target_endpoint, self.target_dialect),
            )
            .row("Format Version", self.format_version.to_string())
            .row("Schema Revision", self.schema_revision.clone())
            .row("Components", self.components.join(", "))
            .row(
                "Blank Target Initialized",
                if self.blank_target_initialized {
                    "yes"
                } else {
                    "no (existing empty schema)"
                },
            )
            .row("Tables Restored", self.table_count.to_string())
            .row("Total Rows Restored", self.total_rows.to_string())
            .row("Restored File Entries", self.restored_files.to_string())
            .row("Unique Blobs Written", self.unique_blobs.to_string())
            .row("Blob Bytes (raw)", self.blob_bytes.to_string())
            .row("Missing Inactive Files", self.missing_inactive_files.to_string())
            .row(
                "Config Secrets Restored",
                if self.configuration_restored { "yes" } else { "no" },
            );
        if let Some(ref bak) = self.config_backup_path {
            table.row("Config Backup", bak.clone());
        }
        table.print();

        println!();
        ui.print_success("Encrypted streaming backup restored cleanly.");
    }
}

struct RollbackGuard {
    created_schema_tables: Vec<String>,
    written_storage_paths: Vec<String>,
    config_path: std::path::PathBuf,
    config_snapshot: Option<Vec<u8>>,
    config_backup_path: Option<std::path::PathBuf>,
    init_path: std::path::PathBuf,
    init_snapshot: Option<Option<Vec<u8>>>,
    armed: bool,
}

impl RollbackGuard {
    fn new(config_path: std::path::PathBuf, init_path: std::path::PathBuf) -> Self {
        Self {
            created_schema_tables: Vec::new(),
            written_storage_paths: Vec::new(),
            config_path,
            config_snapshot: None,
            config_backup_path: None,
            init_path,
            init_snapshot: None,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    async fn rollback(mut self, pool: &DbPool, storage: &LocalFsStorage) {
        if !self.armed {
            return;
        }
        self.armed = false;

        if let Some(prev_init) = self.init_snapshot.take() {
            match prev_init {
                Some(bytes) => {
                    let _ = atomic_write(&self.init_path, &bytes);
                }
                None => {
                    let _ = std::fs::remove_file(&self.init_path);
                }
            }
        }

        if let Some(bak) = self.config_backup_path.take() {
            let _ = std::fs::remove_file(bak);
        }
        if let Some(prev_cfg) = self.config_snapshot.take() {
            let _ = atomic_write(&self.config_path, &prev_cfg);
        }

        for path in self.written_storage_paths.iter().rev() {
            let _ = storage.remove_file(path);
        }

        if !self.created_schema_tables.is_empty() {
            let _ = drop_all_cfms_tables(pool, &self.created_schema_tables).await;
        }
    }
}

/// Execute `cfms-ctl backup import`.
pub async fn run_import(ctx: &AppContext, args: BackupImportArgs) -> Result<()> {
    let master_key = read_key_from_args(args.key.as_deref(), args.key_file.as_deref())?;
    let paths = ctx.resolve_paths()?;
    let _lock = ctx.acquire_server_lock(&paths, false)?;
    let mut config = ctx.load_config(&paths)?;
    let db_cfg = config.database_config()?;
    let target_endpoint = db_cfg.display_endpoint(&paths);
    let storage = resolve_local_storage(&paths, &config)?;

    let (envelope, manifest, archive) =
        VerifiedArchiveReader::open_file(&args.backup_path, &master_key)?;

    if manifest.storage_provider != storage.kind() {
        return Err(CfmsError::Config(format!(
            "Backup storage provider '{}' is incompatible with active storage provider '{}'",
            manifest.storage_provider,
            storage.kind()
        )));
    }

    if ctx.ui.format() == OutputFormat::Human && !ctx.global.yes {
        let mut preview = KeyValueTable::new("Backup Import Plan");
        preview
            .row("Archive Path", envelope.path.clone())
            .row("Target Database", format!("{target_endpoint} ({})", db_cfg.kind))
            .row("Schema Revision", manifest.schema_revision.clone())
            .row("Components", manifest.components.join(", "))
            .row("Tables in Archive", manifest.table_order.len().to_string());
        preview.print();
    }

    confirm_or_abort(
        &format!(
            "Restore backup '{}' ({}) into target {} ({})?",
            envelope.path,
            manifest.components.join(", "),
            target_endpoint,
            db_cfg.kind
        ),
        ctx.global.yes,
    )?;

    if manifest.components.iter().any(|c| c == "configuration") {
        validate_config_sections_mutable(&config, &manifest.configuration)?;
    }

    if db_cfg.kind == crate::db::DatabaseKind::Sqlite {
        let sqlite_path = paths.resolve_sqlite_path(&db_cfg.file);
        if let Some(parent) = sqlite_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
    }

    let pool = ctx.connect_db(&paths).await?;
    let code_base_ir = extract_code_schema_ir(&paths, ExtractorMode::Auto, None, None, true, true)
        .await
        .unwrap_or_else(|_| builtin_schema_ir(true));

    let mut guard = RollbackGuard::new(paths.config_path.clone(), paths.server_root.join("init"));
    let (target_ir, created_tables) =
        prepare_target_database(&pool, &manifest, &code_base_ir).await?;
    let blank_target_initialized = !created_tables.is_empty();
    guard.created_schema_tables = created_tables;

    let pb = backup_progress_bar(ctx.ui.format(), manifest.table_order.len() as u64 + 1);
    let import_res = execute_transactional_import(
        &pool,
        &storage,
        &mut config,
        &target_ir,
        &manifest,
        archive,
        &mut guard,
        &pb,
    )
    .await;
    pb.finish_and_clear();

    match import_res {
        Ok(stats) => {
            guard.disarm();
            pool.close().await;
            let report = BackupImportReport {
                archive_path: envelope.path,
                target_endpoint,
                target_dialect: pool.kind().to_string(),
                format_version: manifest.version,
                schema_revision: manifest.schema_revision,
                components: manifest.components,
                blank_target_initialized,
                table_count: stats.table_count,
                total_rows: stats.total_rows,
                restored_files: stats.restored_files,
                unique_blobs: stats.unique_blobs,
                blob_bytes: stats.blob_bytes,
                missing_inactive_files: stats.missing_inactive_files,
                configuration_restored: stats.configuration_restored,
                config_backup_path: stats.config_backup_path,
                warnings: stats.warnings,
            };
            ctx.ui.render(&report);
            Ok(())
        }
        Err(err) => {
            guard.rollback(&pool, &storage).await;
            pool.close().await;
            Err(err)
        }
    }
}

struct ImportStats {
    table_count: usize,
    total_rows: u64,
    restored_files: usize,
    unique_blobs: usize,
    blob_bytes: u64,
    missing_inactive_files: usize,
    configuration_restored: bool,
    config_backup_path: Option<String>,
    warnings: Vec<String>,
}

type DeferredPairMap = BTreeMap<(String, String), Vec<(SqlValue, SqlValue)>>;

#[allow(clippy::too_many_arguments)]
async fn execute_transactional_import<R: std::io::Read>(
    pool: &DbPool,
    storage: &LocalFsStorage,
    config: &mut ConfigDocument,
    target_ir: &SchemaIr,
    manifest: &ManifestHeader,
    mut archive: VerifiedArchiveReader<R>,
    guard: &mut RollbackGuard,
    pb: &indicatif::ProgressBar,
) -> Result<ImportStats> {
    let mut tx = TargetTx::begin(pool).await?;
    let outcome: Result<ImportStats> = async {
        let coupled = is_coupled_node_group(manifest);
        let import_subset_ir = build_import_subset_ir(target_ir, manifest)?;
        let deferred_cols_by_table =
            build_deferred_column_map(&import_subset_ir, pool.kind(), coupled);

        let transfer_cols_map = build_transfer_columns_map(manifest)?;
        let mut deferred_pairs: DeferredPairMap = BTreeMap::new();
        let mut saw_server_name_option = false;

        let mut active_staged_blob: Option<(u64, String, Box<dyn StagedStorageFile>)> = None;
        let mut completed_blob_paths: HashMap<u64, String> = HashMap::new();
        let mut restored_files_count = 0usize;
        let mut blob_bytes = 0u64;
        let mut total_rows = 0u64;
        let mut footer_opt: Option<IntegrityFooter> = None;

        while let Some(event) = archive.next_event()? {
            match event {
                VerifiedArchiveEvent::TableStart { table_name } => {
                    pb.set_message(format!("Importing table '{table_name}'"));
                }
                VerifiedArchiveEvent::TableBatch { table_name, rows } => {
                    if table_name == "files" {
                        ensure_storage_paths_available(
                            storage,
                            manifest.tables.get("files"),
                            &rows,
                        )?;
                    }
                    if table_name == "options" && !saw_server_name_option {
                        saw_server_name_option =
                            batch_has_server_name_option(manifest.tables.get("options"), &rows)?;
                    }

                    let (cols, pk_idx, deferred_meta) =
                        table_insert_metadata(&table_name, manifest, &transfer_cols_map, &deferred_cols_by_table)?;

                    insert_table_rows_into_tx(
                        &mut tx,
                        &table_name,
                        cols,
                        pk_idx,
                        &deferred_meta,
                        rows,
                        &mut deferred_pairs,
                    )
                    .await?;
                }
                VerifiedArchiveEvent::TableEnd { row_count, .. } => {
                    total_rows += row_count;
                    pb.inc(1);
                }
                VerifiedArchiveEvent::BlobStart {
                    blob_id,
                    storage_path,
                } => {
                    pb.set_message(format!("Restoring blob '{storage_path}'"));
                    let staged = storage.begin_staged_write(&storage_path)?;
                    active_staged_blob = Some((blob_id, storage_path, staged));
                }
                VerifiedArchiveEvent::BlobChunk { blob_id, data } => {
                    let Some((active_id, _, ref mut staged)) = active_staged_blob else {
                        return Err(CfmsError::ArchiveIntegrity(
                            "BlobChunk arrived without open staged storage file".to_string(),
                        ));
                    };
                    if active_id != blob_id {
                        return Err(CfmsError::ArchiveIntegrity(
                            "Staged blob_id mismatch".to_string(),
                        ));
                    }
                    staged.write_all(&data)?;
                }
                VerifiedArchiveEvent::BlobEnd {
                    blob_id,
                    storage_path,
                    size,
                    ..
                } => {
                    let Some((active_id, active_path, staged)) = active_staged_blob.take() else {
                        return Err(CfmsError::ArchiveIntegrity(
                            "BlobEnd arrived without open staged storage file".to_string(),
                        ));
                    };
                    if active_id != blob_id || active_path != storage_path {
                        return Err(CfmsError::ArchiveIntegrity(
                            "BlobEnd identity mismatch".to_string(),
                        ));
                    }
                    staged.finish()?;
                    guard.written_storage_paths.push(storage_path.clone());
                    completed_blob_paths.insert(blob_id, storage_path);
                    blob_bytes += size;
                }
                VerifiedArchiveEvent::MissingInactiveFile => {}
                VerifiedArchiveEvent::FileEntry(entry) => {
                    let src_path = completed_blob_paths.get(&entry.blob_id).ok_or_else(|| {
                        CfmsError::ArchiveIntegrity(format!(
                            "FileEntry '{}' references missing blob {}",
                            entry.file_id, entry.blob_id
                        ))
                    })?;
                    if src_path != &entry.storage_path {
                        storage.copy_within(src_path, &entry.storage_path)?;
                        guard.written_storage_paths.push(entry.storage_path);
                    }
                    restored_files_count += 1;
                }
                VerifiedArchiveEvent::IntegrityFooter(footer) => {
                    footer_opt = Some(footer);
                }
            }
        }

        let footer = footer_opt.ok_or_else(|| {
            CfmsError::ArchiveIntegrity("Backup stream ended without IntegrityFooter".to_string())
        })?;

        pb.set_message("Restoring deferred references and configuration");
        restore_deferred_pairs(&mut tx, &transfer_cols_map, manifest, &deferred_pairs).await?;

        let include_config = manifest.components.iter().any(|c| c == "configuration");
        if include_config && !saw_server_name_option {
            insert_default_server_name_option(&mut tx, manifest).await?;
        }

        let config_backup_path = if include_config {
            guard.config_snapshot = Some(read_bounded_snapshot(config.path())?);
            apply_configuration_secrets(config, &manifest.configuration)?;
            let bak = config.save_with_backup()?;
            guard.config_backup_path = Some(bak.clone());
            Some(bak.display().to_string())
        } else {
            None
        };

        let init_prev = if guard.init_path.exists() {
            Some(read_bounded_snapshot(&guard.init_path)?)
        } else {
            None
        };
        guard.init_snapshot = Some(init_prev);
        atomic_write(&guard.init_path, INIT_MARKER_BYTES)?;

        Ok(ImportStats {
            table_count: footer.tables.len(),
            total_rows,
            restored_files: restored_files_count,
            unique_blobs: footer.blobs.len(),
            blob_bytes,
            missing_inactive_files: footer.missing_inactive_files.len(),
            configuration_restored: include_config,
            config_backup_path,
            warnings: footer.warnings,
        })
    }
    .await;

    match outcome {
        Ok(stats) => {
            tx.commit().await?;
            let serial_cols: Vec<(String, String)> = SERIAL_IDENTITY_COLUMNS
                .iter()
                .filter(|(tbl, _)| manifest.tables.contains_key(*tbl))
                .map(|(tbl, col)| ((*tbl).to_string(), (*col).to_string()))
                .collect();
            sync_target_sequences(pool, &serial_cols).await?;
            pb.inc(1);
            Ok(stats)
        }
        Err(err) => {
            rollback_tx(tx).await;
            Err(err)
        }
    }
}

async fn rollback_tx(tx: TargetTx<'_>) {
    match tx {
        TargetTx::Sqlite(inner) => {
            let _ = inner.rollback().await;
        }
        TargetTx::Mysql(inner) => {
            let _ = inner.rollback().await;
        }
        TargetTx::Postgres(inner) => {
            let _ = inner.rollback().await;
        }
    }
}

async fn prepare_target_database(
    pool: &DbPool,
    manifest: &ManifestHeader,
    code_base_ir: &SchemaIr,
) -> Result<(SchemaIr, Vec<String>)> {
    let expected_code_revision = code_base_ir
        .schema_revision
        .as_deref()
        .unwrap_or(LATEST_SCHEMA_REVISION);
    if manifest.schema_revision != expected_code_revision {
        return Err(CfmsError::SchemaDrift(format!(
            "Backup schema revision '{}' does not match workspace schema revision '{expected_code_revision}'",
            manifest.schema_revision
        )));
    }

    let ext_names: Vec<String> = manifest
        .extension_tables
        .iter()
        .map(|e| e.table_name.clone())
        .collect();
    let mut full_target_ir = active_schema_subset(code_base_ir, &ext_names);
    for ext in &manifest.extension_tables {
        if !full_target_ir.tables.contains_key(&ext.table_name)
            && let Some(ext_tbl) = manifest.schema_ir.tables.get(&ext.table_name)
        {
            full_target_ir
                .tables
                .insert(ext.table_name.clone(), ext_tbl.clone());
        }
    }

    let report = SchemaInspector::inspect_against_ir(pool, &full_target_ir).await?;
    if report.is_empty_database {
        let stmts = compile_full_schema_ddl(&full_target_ir, pool.kind());
        execute_ddl_statements(pool, &stmts).await?;
        if let Err(err) = set_alembic_version(pool, &manifest.schema_revision).await {
            let created: Vec<String> = full_target_ir.tables.keys().cloned().collect();
            let _ = drop_all_cfms_tables(pool, &created).await;
            return Err(err);
        }
        let created: Vec<String> = full_target_ir.tables.keys().cloned().collect();
        return Ok((full_target_ir, created));
    }

    if report.current_revision.as_deref() != Some(manifest.schema_revision.as_str()) {
        return Err(CfmsError::SchemaDrift(format!(
            "Target database schema revision {:?} does not match backup schema revision '{}'",
            report.current_revision, manifest.schema_revision
        )));
    }
    if !report.missing_tables.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Target database is missing required tables: {}",
            report.missing_tables.join(", ")
        )));
    }
    if !report.column_mismatches.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Target database schema differs from expected layout: {}",
            report.column_mismatches.join("; ")
        )));
    }

    let (known_extra_exts, unknown_extra) = report.partition_extra_tables();
    if !unknown_extra.is_empty() {
        return Err(CfmsError::SchemaDrift(format!(
            "Target database contains unsupported extra tables: {}",
            unknown_extra.join(", ")
        )));
    }

    let mut tables_to_check_empty: BTreeSet<String> =
        full_target_ir.tables.keys().cloned().collect();
    tables_to_check_empty.extend(known_extra_exts);
    for tbl in tables_to_check_empty {
        let cnt = count_table_rows(pool, &tbl).await?;
        if cnt > 0 {
            return Err(CfmsError::Backup(format!(
                "Target database must be completely empty before import (table '{tbl}' already contains {cnt} row(s))"
            )));
        }
    }

    Ok((full_target_ir, Vec::new()))
}

fn build_import_subset_ir(target_ir: &SchemaIr, manifest: &ManifestHeader) -> Result<SchemaIr> {
    let mut sub = SchemaIr::new(target_ir.source, Some(manifest.schema_revision.clone()));
    for table_name in &manifest.table_order {
        let tbl = target_ir
            .tables
            .get(table_name)
            .or_else(|| manifest.schema_ir.tables.get(table_name))
            .ok_or_else(|| {
                CfmsError::SchemaDrift(format!(
                    "Schema definition missing for archived table '{table_name}'"
                ))
            })?;
        sub.tables.insert(table_name.clone(), tbl.clone());
    }
    Ok(sub)
}

fn build_deferred_column_map(
    import_ir: &SchemaIr,
    dialect: crate::db::DatabaseKind,
    coupled: bool,
) -> BTreeMap<String, Vec<String>> {
    let (_, mut deferred, _) = infer_transfer_metadata(import_ir, dialect);
    for (tbl, cols) in DEFERRED_COLUMNS {
        if import_ir.tables.contains_key(*tbl) {
            let entry = deferred.entry((*tbl).to_string()).or_default();
            for col in *cols {
                if !entry.iter().any(|c| c == col) {
                    entry.push((*col).to_string());
                }
            }
        }
    }
    if coupled && let Some(node_def) = deferred.get_mut("nodes") {
        node_def.retain(|c| c != "parent_id");
        if node_def.is_empty() {
            deferred.remove("nodes");
        }
    }
    deferred
}

fn build_transfer_columns_map(
    manifest: &ManifestHeader,
) -> Result<BTreeMap<String, Vec<TransferColumn>>> {
    let mut map = BTreeMap::new();
    for (name, spec) in &manifest.tables {
        let cols = spec
            .columns
            .iter()
            .map(super::stream::TableColumnSpec::to_transfer_column)
            .collect();
        map.insert(name.clone(), cols);
    }
    Ok(map)
}

type TableInsertMetadata<'a> = (&'a [TransferColumn], Option<usize>, Vec<(usize, String)>);

fn table_insert_metadata<'a>(
    table_name: &str,
    manifest: &ManifestHeader,
    transfer_cols_map: &'a BTreeMap<String, Vec<TransferColumn>>,
    deferred_cols_by_table: &BTreeMap<String, Vec<String>>,
) -> Result<TableInsertMetadata<'a>> {
    let cols = transfer_cols_map
        .get(table_name)
        .map(Vec::as_slice)
        .ok_or_else(|| {
            CfmsError::ArchiveIntegrity(format!("Missing columns for table '{table_name}'"))
        })?;
    let spec = manifest.tables.get(table_name).ok_or_else(|| {
        CfmsError::ArchiveIntegrity(format!("Missing schema spec for table '{table_name}'"))
    })?;

    let deferred_names = deferred_cols_by_table
        .get(table_name)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    if deferred_names.is_empty() {
        return Ok((cols, None, Vec::new()));
    }

    if spec.pk_columns.len() != 1 {
        return Err(CfmsError::SchemaDrift(format!(
            "Table '{table_name}' with deferred FK columns requires a single-column primary key"
        )));
    }
    let pk_idx = cols
        .iter()
        .position(|c| c.name == spec.pk_columns[0])
        .ok_or_else(|| {
            CfmsError::ArchiveIntegrity(format!(
                "Primary key column '{}' missing from '{table_name}'",
                spec.pk_columns[0]
            ))
        })?;

    let mut deferred_meta = Vec::with_capacity(deferred_names.len());
    for def_name in deferred_names {
        let idx = cols.iter().position(|c| &c.name == def_name).ok_or_else(|| {
            CfmsError::ArchiveIntegrity(format!(
                "Deferred column '{def_name}' missing from '{table_name}'"
            ))
        })?;
        deferred_meta.push((idx, def_name.clone()));
    }
    Ok((cols, Some(pk_idx), deferred_meta))
}

async fn insert_table_rows_into_tx(
    tx: &mut TargetTx<'_>,
    table_name: &str,
    cols: &[TransferColumn],
    pk_idx: Option<usize>,
    deferred_meta: &[(usize, String)],
    mut rows: Vec<Vec<SqlValue>>,
    deferred_pairs: &mut DeferredPairMap,
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }

    if !deferred_meta.is_empty() {
        let pk_col_idx = pk_idx.expect("validated pk index");
        for row in &mut rows {
            let pk_val = row[pk_col_idx].clone();
            for (col_idx, col_name) in deferred_meta {
                if !matches!(row[*col_idx], SqlValue::Null) {
                    let deferred_val = std::mem::replace(&mut row[*col_idx], SqlValue::Null);
                    deferred_pairs
                        .entry((table_name.to_string(), col_name.clone()))
                        .or_default()
                        .push((pk_val.clone(), deferred_val));
                }
            }
        }
    }

    let batch_size = insert_batch_size(cols.len());
    for chunk in rows.chunks(batch_size) {
        insert_batch(tx, table_name, cols, chunk).await?;
    }
    Ok(())
}

async fn restore_deferred_pairs(
    tx: &mut TargetTx<'_>,
    transfer_cols_map: &BTreeMap<String, Vec<TransferColumn>>,
    manifest: &ManifestHeader,
    deferred_pairs: &DeferredPairMap,
) -> Result<()> {
    let mut visited: BTreeSet<(String, String)> = BTreeSet::new();

    for (table_name, _, cols) in DEFERRED_UPDATE_ORDER {
        for col_name in *cols {
            let key = ((*table_name).to_string(), (*col_name).to_string());
            if let Some(pairs) = deferred_pairs.get(&key) {
                visited.insert(key);
                apply_single_deferred_column(
                    tx,
                    transfer_cols_map,
                    manifest,
                    table_name,
                    col_name,
                    pairs,
                )
                .await?;
            }
        }
    }

    for ((table_name, col_name), pairs) in deferred_pairs {
        let key = (table_name.clone(), col_name.clone());
        if visited.contains(&key) {
            continue;
        }
        apply_single_deferred_column(
            tx,
            transfer_cols_map,
            manifest,
            table_name,
            col_name,
            pairs,
        )
        .await?;
    }

    Ok(())
}

async fn apply_single_deferred_column(
    tx: &mut TargetTx<'_>,
    transfer_cols_map: &BTreeMap<String, Vec<TransferColumn>>,
    manifest: &ManifestHeader,
    table_name: &str,
    col_name: &str,
    pairs: &[(SqlValue, SqlValue)],
) -> Result<()> {
    if pairs.is_empty() {
        return Ok(());
    }
    let cols = transfer_cols_map.get(table_name).ok_or_else(|| {
        CfmsError::ArchiveIntegrity(format!("Missing columns for deferred table '{table_name}'"))
    })?;
    let spec = manifest.tables.get(table_name).ok_or_else(|| {
        CfmsError::ArchiveIntegrity(format!("Missing schema spec for deferred table '{table_name}'"))
    })?;
    let pk_col = cols
        .iter()
        .find(|c| c.name == spec.pk_columns[0])
        .ok_or_else(|| CfmsError::ArchiveIntegrity("Missing PK column".to_string()))?;
    let val_col = cols
        .iter()
        .find(|c| c.name == col_name)
        .ok_or_else(|| CfmsError::ArchiveIntegrity("Missing deferred column".to_string()))?;

    for chunk in pairs.chunks(DEFERRED_UPDATE_BATCH_SIZE) {
        apply_deferred_update_batch(tx, table_name, pk_col, val_col, chunk).await?;
    }
    Ok(())
}

fn ensure_storage_paths_available(
    storage: &LocalFsStorage,
    files_spec: Option<&TableSchemaSpec>,
    rows: &[Vec<SqlValue>],
) -> Result<()> {
    let Some(spec) = files_spec else {
        return Ok(());
    };
    let path_idx = spec
        .columns
        .iter()
        .position(|c| c.name == "path")
        .ok_or_else(|| CfmsError::ArchiveIntegrity("Missing files.path column".to_string()))?;

    for row in rows {
        let storage_path = sql_val_to_id(&row[path_idx], "files.path")?;
        if storage.exists(&storage_path)? {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Refusing to overwrite pre-existing storage object '{storage_path}'"
            )));
        }
    }
    Ok(())
}

fn batch_has_server_name_option(
    options_spec: Option<&TableSchemaSpec>,
    rows: &[Vec<SqlValue>],
) -> Result<bool> {
    let Some(spec) = options_spec else {
        return Ok(false);
    };
    let ns_idx = spec
        .columns
        .iter()
        .position(|c| c.name == "namespace")
        .ok_or_else(|| CfmsError::ArchiveIntegrity("Missing options.namespace".to_string()))?;
    let key_idx = spec
        .columns
        .iter()
        .position(|c| c.name == "option_key")
        .ok_or_else(|| CfmsError::ArchiveIntegrity("Missing options.option_key".to_string()))?;

    for row in rows {
        if let (SqlValue::Str(ns), SqlValue::Str(key)) = (&row[ns_idx], &row[key_idx])
            && ns == "server"
            && key == "name"
        {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn insert_default_server_name_option(
    tx: &mut TargetTx<'_>,
    manifest: &ManifestHeader,
) -> Result<()> {
    let spec = manifest.tables.get("options").ok_or_else(|| {
        CfmsError::ArchiveIntegrity("Missing 'options' schema in archive manifest".to_string())
    })?;
    let (val_type, encoded_val) = encode_option_value(&json!("CFMS WebSocket Server"))?;
    let now = Utc::now().timestamp() as f64;

    let mut cols = Vec::with_capacity(spec.columns.len());
    let mut row = Vec::with_capacity(spec.columns.len());
    for col_spec in &spec.columns {
        cols.push(col_spec.to_transfer_column());
        let val = match col_spec.name.as_str() {
            "namespace" => SqlValue::Str("server".to_string()),
            "owner" => SqlValue::Str("core".to_string()),
            "option_key" => SqlValue::Str("name".to_string()),
            "schema_version" => SqlValue::I64(1),
            "revision" => SqlValue::I64(1),
            "value_type" => SqlValue::Str(val_type.as_str().to_string()),
            "option_value" => SqlValue::Str(encoded_val.clone()),
            "updated_at" => SqlValue::F64(now),
            other => {
                return Err(CfmsError::SchemaDrift(format!(
                    "Unexpected column '{other}' in 'options' table when inserting default server.name"
                )));
            }
        };
        row.push(val);
    }
    insert_batch(tx, "options", &cols, &[row]).await?;
    Ok(())
}

fn validate_config_sections_mutable(
    config: &ConfigDocument,
    payload: &ConfigurationPayload,
) -> Result<()> {
    if payload.pepper.is_none() || payload.secret_key.is_none() {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive with 'configuration' component is missing security secrets".to_string(),
        ));
    }
    if let Some(sec) = config.document().get("security")
        && !sec.is_table_like()
    {
        return Err(CfmsError::Config(
            "Configuration entry 'security' in `config.toml` must be a table".to_string(),
        ));
    }
    if let Some(srv) = config.document().get("server")
        && !srv.is_table_like()
    {
        return Err(CfmsError::Config(
            "Configuration entry 'server' in `config.toml` must be a table".to_string(),
        ));
    }
    Ok(())
}

fn apply_configuration_secrets(
    config: &mut ConfigDocument,
    payload: &ConfigurationPayload,
) -> Result<()> {
    let pepper = payload.pepper.as_deref().ok_or_else(|| {
        CfmsError::ArchiveIntegrity("Missing security.pepper in archive manifest".to_string())
    })?;
    let secret_key = payload.secret_key.as_deref().ok_or_else(|| {
        CfmsError::ArchiveIntegrity("Missing server.secret_key in archive manifest".to_string())
    })?;

    set_table_string_preserving_decor(config.document_mut(), "security", "pepper", pepper)?;
    set_table_string_preserving_decor(config.document_mut(), "server", "secret_key", secret_key)?;
    Ok(())
}

fn set_table_string_preserving_decor(
    doc: &mut toml_edit::DocumentMut,
    section: &str,
    key: &str,
    new_val: &str,
) -> Result<()> {
    let item = doc
        .entry(section)
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let tbl = item.as_table_like_mut().ok_or_else(|| {
        CfmsError::Config(format!("Configuration section '{section}' must be a table"))
    })?;
    let mut replacement = toml_edit::Value::from(new_val);
    if let Some(existing) = tbl.get_mut(key) {
        if let Some(old_val) = existing.as_value() {
            *replacement.decor_mut() = old_val.decor().clone();
        }
        *existing = toml_edit::Item::Value(replacement);
    } else {
        tbl.insert(key, toml_edit::Item::Value(replacement));
    }
    Ok(())
}

fn read_bounded_snapshot(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_SNAPSHOT_BYTES {
        return Err(CfmsError::Backup(format!(
            "File '{}' exceeds 16 MiB snapshot limit",
            path.display()
        )));
    }
    Ok(std::fs::read(path)?)
}
