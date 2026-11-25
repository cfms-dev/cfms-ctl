//! Shared streaming integrity verification state machine and `cfms-ctl backup verify`.
//!
//! Reads `.confbak` archives once through `ChunkedDecryptReader -> Zstd -> StreamRecordReader`,
//! validating every chunk tag, Zstd frame, manifest invariant, schema column type, node hierarchy
//! parent ordering, canonical table digest, blob SHA-256/size, file inventory completeness,
//! integrity footer, and clean authenticated EOF without touching any database or storage directory.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zstd::stream::read::Decoder as ZstdDecoder;
use crate::cli::backup::BackupVerifyArgs;
use crate::core::error::{CfmsError, Result};
use crate::db::schema::ir::TableOwnership;
use crate::db::transfer::{SqlValue, hash_canonical_row, validate_oidc_binding};
use crate::ops::AppContext;
use crate::storage::validate_storage_relative_path;
use crate::ui::{CommandReport, KeyValueTable, UiConsole};
use super::backup_progress_bar;
use super::format::{
    BackupHeaderReport, ChunkedDecryptReader, read_envelope_and_hash, read_key_from_args,
};
use super::selection::{expected_tables_for_schema, parse_and_validate_manifest_components};
use super::stream::{
    BackupValue, BlobEndPayload, FileEntryPayload, IntegrityFooter, ManifestHeader,
    MissingInactiveFilePayload, StreamRecord, StreamRecordReader, TableDigestSummary,
    TableSchemaSpec, is_coupled_node_group, sql_val_to_id, validate_manifest_header,
};

/// Structured verification report emitted by `cfms-ctl backup verify`.
#[derive(Debug, Clone, Serialize)]
pub struct BackupVerifyReport {
    pub archive_path: String,
    pub file_size: u64,
    pub format_version: u32,
    pub created_at: String,
    pub server_version: String,
    pub schema_revision: String,
    pub components: Vec<String>,
    pub table_count: usize,
    pub total_rows: u64,
    pub file_entries: usize,
    pub unique_blobs: usize,
    pub blob_bytes: u64,
    pub missing_inactive_files: usize,
    pub warnings: Vec<String>,
    pub tables: BTreeMap<String, TableDigestSummary>,
}

impl CommandReport for BackupVerifyReport {
    fn render_human(&self, ui: &UiConsole) {
        for warning in &self.warnings {
            ui.print_warning(warning);
        }

        let mut table = KeyValueTable::new("Backup Archive Verification");
        table
            .row("Archive Path", self.archive_path.clone())
            .row("Archive Size (bytes)", self.file_size.to_string())
            .row("Format Version", self.format_version.to_string())
            .row("Created At", self.created_at.clone())
            .row("Server Version", self.server_version.clone())
            .row("Schema Revision", self.schema_revision.clone())
            .row("Components", self.components.join(", "))
            .row("Tables Verified", self.table_count.to_string())
            .row("Total Rows Verified", self.total_rows.to_string())
            .row("File Entries", self.file_entries.to_string())
            .row("Unique Blobs Verified", self.unique_blobs.to_string())
            .row("Blob Bytes (raw)", self.blob_bytes.to_string())
            .row("Missing Inactive Files", self.missing_inactive_files.to_string());
        table.print();

        println!();
        ui.print_success("Encrypted streaming backup archive passed all cryptographic and structural checks.");
    }
}

/// Decoded and integrity-verified event emitted sequentially by [`VerifiedArchiveReader`].
#[derive(Debug)]
pub(crate) enum VerifiedArchiveEvent {
    TableStart {
        table_name: String,
    },
    TableBatch {
        table_name: String,
        rows: Vec<Vec<SqlValue>>,
    },
    TableEnd {
        table_name: String,
        row_count: u64,
        canonical_sha256: String,
    },
    BlobStart {
        blob_id: u64,
        storage_path: String,
    },
    BlobChunk {
        blob_id: u64,
        data: Vec<u8>,
    },
    BlobEnd {
        blob_id: u64,
        storage_path: String,
        size: u64,
    },
    MissingInactiveFile,
    FileEntry(FileEntryPayload),
    IntegrityFooter(IntegrityFooter),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TableSlot {
    Single(String),
    CoupledNodesGroup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoupledPhase {
    OpeningNodes,
    OpeningFolders,
    OpeningDocuments,
    Streaming,
}

struct ActiveTableTracker {
    hasher: Sha256,
    row_count: u64,
}

struct ActiveBlobTracker {
    blob_id: u64,
    storage_path: String,
    bytes: u64,
    hasher: Sha256,
}

struct NodeColumnIndices {
    id_idx: usize,
    parent_id_idx: usize,
}

struct FileColumnIndices {
    id_idx: usize,
    path_idx: usize,
    active_idx: usize,
}

struct OidcColumnIndices {
    id_idx: usize,
    issuer_idx: usize,
    subject_idx: usize,
    digest_idx: usize,
}

type InnerRecordReader<R> =
    StreamRecordReader<ZstdDecoder<'static, BufReader<ChunkedDecryptReader<R>>>>;

/// Streaming archive reader enforcing full cryptographic and structural consistency on every frame.
pub(crate) struct VerifiedArchiveReader<R: Read> {
    manifest: ManifestHeader,
    reader: Option<InnerRecordReader<R>>,
    slots: Vec<TableSlot>,
    slot_idx: usize,
    coupled_phase: CoupledPhase,
    active_tables: BTreeMap<String, ActiveTableTracker>,
    completed_tables: BTreeMap<String, TableDigestSummary>,
    node_col_indices: Option<NodeColumnIndices>,
    seen_node_ids: HashSet<String>,
    seen_folder_ids: HashSet<String>,
    file_col_indices: Option<FileColumnIndices>,
    oidc_col_indices: Option<OidcColumnIndices>,
    files_meta: HashMap<String, (String, bool)>,
    seen_paths_ci: HashMap<String, String>,
    accounted_file_ids: HashSet<String>,
    active_blob: Option<ActiveBlobTracker>,
    completed_blobs: HashMap<u64, (String, BlobEndPayload)>,
    blobs_order: Vec<BlobEndPayload>,
    referenced_blob_ids: HashSet<u64>,
    files_order: Vec<FileEntryPayload>,
    missing_order: Vec<MissingInactiveFilePayload>,
    saw_footer: bool,
}

impl VerifiedArchiveReader<BufReader<File>> {
    /// Open an encrypted `.confbak` file from disk, authenticate the outer header & Chunk 0,
    /// and parse and validate [`ManifestHeader`].
    pub fn open_file(
        path: &Path,
        master_key: &Zeroizing<[u8; 32]>,
    ) -> Result<(BackupHeaderReport, ManifestHeader, Self)> {
        let file = File::open(path).map_err(|e| {
            CfmsError::Backup(format!("Unable to open backup '{}': {e}", path.display()))
        })?;
        let file_size = file.metadata()?.len();
        let reader = BufReader::with_capacity(256 * 1024, file);
        Self::open(reader, master_key, &path.display().to_string(), file_size)
    }
}

impl<R: Read> VerifiedArchiveReader<R> {
    /// Wrap any `Read` source, verify outer envelope + HKDF/AES-256-GCM Chunk 0 + Zstd header,
    /// and validate the decrypted [`ManifestHeader`].
    pub fn open(
        mut source: R,
        master_key: &Zeroizing<[u8; 32]>,
        path_display: &str,
        file_size: u64,
    ) -> Result<(BackupHeaderReport, ManifestHeader, Self)> {
        let (envelope, header_sha256) =
            read_envelope_and_hash(&mut source, path_display, file_size)?;
        let decrypt_reader =
            ChunkedDecryptReader::new(source, master_key, &envelope, header_sha256)?;
        let zstd_decoder = ZstdDecoder::new(decrypt_reader)
            .map_err(|e| CfmsError::ArchiveIntegrity(format!("Failed to initialize Zstd decoder: {e}")))?;
        let (manifest, record_reader) = StreamRecordReader::open(zstd_decoder)?;

        validate_open_manifest(&manifest, &envelope)?;

        let coupled = is_coupled_node_group(&manifest);
        let slots = build_table_slots(&manifest.table_order, coupled);
        let node_col_indices = if coupled {
            let spec = manifest.tables.get("nodes").ok_or_else(|| {
                CfmsError::ArchiveIntegrity("Missing 'nodes' table schema".to_string())
            })?;
            Some(NodeColumnIndices {
                id_idx: spec_col_idx(spec, "id", "nodes")?,
                parent_id_idx: spec_col_idx(spec, "parent_id", "nodes")?,
            })
        } else {
            None
        };
        let file_col_indices = if let Some(spec) = manifest.tables.get("files") {
            Some(FileColumnIndices {
                id_idx: spec_col_idx(spec, "id", "files")?,
                path_idx: spec_col_idx(spec, "path", "files")?,
                active_idx: spec_col_idx(spec, "active", "files")?,
            })
        } else {
            None
        };
        let oidc_col_indices = if let Some(spec) = manifest.tables.get("user_oidc_credentials") {
            Some(OidcColumnIndices {
                id_idx: spec_col_idx(spec, "id", "user_oidc_credentials")?,
                issuer_idx: spec_col_idx(spec, "issuer", "user_oidc_credentials")?,
                subject_idx: spec_col_idx(spec, "subject", "user_oidc_credentials")?,
                digest_idx: spec_col_idx(spec, "identity_digest", "user_oidc_credentials")?,
            })
        } else {
            None
        };

        let manifest_clone = manifest.clone();
        let verifier = Self {
            manifest,
            reader: Some(record_reader),
            slots,
            slot_idx: 0,
            coupled_phase: CoupledPhase::OpeningNodes,
            active_tables: BTreeMap::new(),
            completed_tables: BTreeMap::new(),
            node_col_indices,
            seen_node_ids: HashSet::new(),
            seen_folder_ids: HashSet::new(),
            file_col_indices,
            oidc_col_indices,
            files_meta: HashMap::new(),
            seen_paths_ci: HashMap::new(),
            accounted_file_ids: HashSet::new(),
            active_blob: None,
            completed_blobs: HashMap::new(),
            blobs_order: Vec::new(),
            referenced_blob_ids: HashSet::new(),
            files_order: Vec::new(),
            missing_order: Vec::new(),
            saw_footer: false,
        };
        Ok((envelope, manifest_clone, verifier))
    }

    /// Read and fully verify the next sequential event (`Ok(None)` at authenticated EOF).
    pub fn next_event(&mut self) -> Result<Option<VerifiedArchiveEvent>> {
        let Some(ref mut reader) = self.reader else {
            return Ok(None);
        };
        let Some(record) = reader.next_record()? else {
            if !self.saw_footer {
                return Err(CfmsError::ArchiveIntegrity(
                    "Backup stream ended without integrity footer".to_string(),
                ));
            }
            let record_reader = self.reader.take().unwrap();
            finalize_decrypted_stream(record_reader)?;
            return Ok(None);
        };

        match record {
            StreamRecord::TableStart(p) => self.on_table_start(p.table_name),
            StreamRecord::TableRowBatch(p) => self.on_table_batch(p.table_name, p.rows),
            StreamRecord::TableEnd(p) => self.on_table_end(p),
            StreamRecord::BlobStart(p) => self.on_blob_start(p.blob_id, p.storage_path),
            StreamRecord::BlobChunk { blob_id, data } => self.on_blob_chunk(blob_id, data),
            StreamRecord::BlobEnd(p) => self.on_blob_end(p),
            StreamRecord::MissingInactiveFile(p) => self.on_missing_inactive(p),
            StreamRecord::FileEntry(p) => self.on_file_entry(p),
            StreamRecord::IntegrityFooter(footer) => self.on_integrity_footer(footer),
        }
        .map(Some)
    }

    fn on_table_start(&mut self, table_name: String) -> Result<VerifiedArchiveEvent> {
        let Some(slot) = self.slots.get(self.slot_idx) else {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Unexpected TableStart('{table_name}') after all manifest tables finished"
            )));
        };
        match slot {
            TableSlot::Single(expected) => {
                if &table_name != expected {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Expected table '{expected}', got TableStart('{table_name}')"
                    )));
                }
                if !self.active_tables.is_empty() {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "TableStart('{table_name}') arrived while previous table is still open"
                    )));
                }
            }
            TableSlot::CoupledNodesGroup => match self.coupled_phase {
                CoupledPhase::OpeningNodes => {
                    if table_name != "nodes" {
                        return Err(CfmsError::ArchiveIntegrity(format!(
                            "Expected coupled hierarchy TableStart('nodes'), got '{table_name}'"
                        )));
                    }
                    self.coupled_phase = CoupledPhase::OpeningFolders;
                }
                CoupledPhase::OpeningFolders => {
                    if table_name != "folders" {
                        return Err(CfmsError::ArchiveIntegrity(format!(
                            "Expected coupled hierarchy TableStart('folders'), got '{table_name}'"
                        )));
                    }
                    self.coupled_phase = CoupledPhase::OpeningDocuments;
                }
                CoupledPhase::OpeningDocuments => {
                    if table_name != "documents" {
                        return Err(CfmsError::ArchiveIntegrity(format!(
                            "Expected coupled hierarchy TableStart('documents'), got '{table_name}'"
                        )));
                    }
                    self.coupled_phase = CoupledPhase::Streaming;
                }
                CoupledPhase::Streaming => {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Unexpected TableStart('{table_name}') during coupled node hierarchy stream"
                    )));
                }
            },
        }

        if self.completed_tables.contains_key(&table_name)
            || self.active_tables.contains_key(&table_name)
        {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Duplicate TableStart for '{table_name}'"
            )));
        }
        self.active_tables.insert(
            table_name.clone(),
            ActiveTableTracker {
                hasher: Sha256::new(),
                row_count: 0,
            },
        );
        Ok(VerifiedArchiveEvent::TableStart { table_name })
    }

    fn on_table_batch(
        &mut self,
        table_name: String,
        rows: Vec<Vec<BackupValue>>,
    ) -> Result<VerifiedArchiveEvent> {
        if self.slots.get(self.slot_idx) == Some(&TableSlot::CoupledNodesGroup)
            && self.coupled_phase != CoupledPhase::Streaming
        {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "TableRowBatch('{table_name}') arrived before all coupled hierarchy tables opened"
            )));
        }
        if !self.active_tables.contains_key(&table_name) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "TableRowBatch for inactive or unopened table '{table_name}'"
            )));
        }
        let spec = self.manifest.tables.get(&table_name).ok_or_else(|| {
            CfmsError::ArchiveIntegrity(format!(
                "TableRowBatch references unknown manifest table '{table_name}'"
            ))
        })?;

        let mut converted_rows = Vec::with_capacity(rows.len());
        for raw_row in rows {
            if raw_row.len() != spec.columns.len() {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Row in table '{table_name}' has {} columns, expected {}",
                    raw_row.len(),
                    spec.columns.len()
                )));
            }
            let mut sql_row = Vec::with_capacity(raw_row.len());
            for (val, col) in raw_row.into_iter().zip(spec.columns.iter()) {
                if !val.matches_column_type(col.col_type) {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Cell in '{}.{}' failed column type check ({:?})",
                        table_name, col.name, col.col_type
                    )));
                }
                sql_row.push(val.into_sql()?);
            }

            if table_name == "nodes"
                && let Some(ref indices) = self.node_col_indices
            {
                let node_id = sql_val_to_id(&sql_row[indices.id_idx], "nodes.id")?;
                if !self.seen_node_ids.insert(node_id.clone()) {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Duplicate node ID '{node_id}' in 'nodes' table stream"
                    )));
                }
                match &sql_row[indices.parent_id_idx] {
                    SqlValue::Null => {}
                    parent_val => {
                        let parent_id = sql_val_to_id(parent_val, "nodes.parent_id")?;
                        if parent_id == node_id {
                            return Err(CfmsError::ArchiveIntegrity(format!(
                                "Node '{node_id}' has self-referential parent_id"
                            )));
                        }
                        if !self.seen_folder_ids.contains(&parent_id) {
                            return Err(CfmsError::ArchiveIntegrity(format!(
                                "Node '{node_id}' references parent folder '{parent_id}' before it appeared in hierarchy stream"
                            )));
                        }
                    }
                }
            } else if table_name == "folders"
                && let Some(ref indices) = self.node_col_indices
            {
                let folder_id = sql_val_to_id(&sql_row[indices.id_idx], "folders.id")?;
                if !self.seen_folder_ids.insert(folder_id.clone()) {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Duplicate folder ID '{folder_id}' in 'folders' table stream"
                    )));
                }
            } else if table_name == "files"
                && let Some(ref indices) = self.file_col_indices
            {
                let id = sql_val_to_id(&sql_row[indices.id_idx], "files.id")?;
                let raw_path = sql_val_to_id(&sql_row[indices.path_idx], "files.path")?;
                let path = validate_storage_relative_path(&raw_path)?.to_string();
                let lower = path.to_ascii_lowercase();
                if let Some(prev) = self.seen_paths_ci.get(&lower) {
                    if prev != &path {
                        return Err(CfmsError::ArchiveIntegrity(format!(
                            "Archive contains case-colliding file paths '{prev}' and '{path}'"
                        )));
                    }
                } else {
                    self.seen_paths_ci.insert(lower, path.clone());
                }
                let active = match &sql_row[indices.active_idx] {
                    SqlValue::Bool(b) => *b,
                    SqlValue::I64(n) => *n != 0,
                    other => {
                        return Err(CfmsError::ArchiveIntegrity(format!(
                            "Invalid files.active value {other:?}"
                        )));
                    }
                };
                if self.files_meta.insert(id.clone(), (path, active)).is_some() {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Duplicate file ID '{id}' in 'files' table stream"
                    )));
                }
            } else if table_name == "user_oidc_credentials"
                && let Some(ref indices) = self.oidc_col_indices
            {
                let cred_id = sql_val_to_id(&sql_row[indices.id_idx], "user_oidc_credentials.id")?;
                let issuer =
                    sql_val_to_id(&sql_row[indices.issuer_idx], "user_oidc_credentials.issuer")?;
                let subject = sql_val_to_id(
                    &sql_row[indices.subject_idx],
                    "user_oidc_credentials.subject",
                )?;
                let digest = match &sql_row[indices.digest_idx] {
                    SqlValue::Bytes(b) => b.as_slice(),
                    other => {
                        return Err(CfmsError::ArchiveIntegrity(format!(
                            "Invalid user_oidc_credentials.identity_digest value {other:?}"
                        )));
                    }
                };
                validate_oidc_binding(&cred_id, &issuer, &subject, digest)?;
            }

            let tracker = self.active_tables.get_mut(&table_name).unwrap();
            hash_canonical_row(&mut tracker.hasher, &sql_row)?;
            tracker.row_count += 1;
            converted_rows.push(sql_row);
        }

        Ok(VerifiedArchiveEvent::TableBatch {
            table_name,
            rows: converted_rows,
        })
    }

    fn on_table_end(
        &mut self,
        end: super::stream::TableEndPayload,
    ) -> Result<VerifiedArchiveEvent> {
        let Some(tracker) = self.active_tables.remove(&end.table_name) else {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Unexpected TableEnd for unopened table '{}'",
                end.table_name
            )));
        };
        let actual_sha = hex::encode(tracker.hasher.finalize());
        if tracker.row_count != end.row_count {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Row count mismatch in table '{}': stream delivered {}, header/end recorded {}",
                end.table_name, tracker.row_count, end.row_count
            )));
        }
        if actual_sha != end.canonical_sha256 {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Canonical content digest mismatch in table '{}'",
                end.table_name
            )));
        }

        self.completed_tables.insert(
            end.table_name.clone(),
            TableDigestSummary {
                rows: end.row_count,
                sha256: end.canonical_sha256.clone(),
            },
        );

        let advance_slot = match self.slots.get(self.slot_idx) {
            Some(TableSlot::Single(expected)) => expected == &end.table_name,
            Some(TableSlot::CoupledNodesGroup) => {
                self.coupled_phase == CoupledPhase::Streaming && self.active_tables.is_empty()
            }
            None => false,
        };
        if advance_slot {
            self.slot_idx += 1;
        }

        Ok(VerifiedArchiveEvent::TableEnd {
            table_name: end.table_name,
            row_count: end.row_count,
            canonical_sha256: end.canonical_sha256,
        })
    }

    fn ensure_tables_complete(&self, op: &str) -> Result<()> {
        if self.slot_idx < self.slots.len() || !self.active_tables.is_empty() {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Received {op} before all manifest tables completed"
            )));
        }
        Ok(())
    }

    fn on_blob_start(&mut self, blob_id: u64, storage_path: String) -> Result<VerifiedArchiveEvent> {
        self.ensure_tables_complete("BlobStart")?;
        if self.active_blob.is_some() {
            return Err(CfmsError::ArchiveIntegrity(
                "Received nested BlobStart while previous blob is still open".to_string(),
            ));
        }
        if self.completed_blobs.contains_key(&blob_id) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Duplicate blob_id {blob_id} in archive stream"
            )));
        }
        let valid_path = validate_storage_relative_path(&storage_path)?.to_string();
        if self
            .completed_blobs
            .values()
            .any(|(existing_path, _)| existing_path == &valid_path)
        {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Duplicate blob storage_path '{valid_path}' in archive stream"
            )));
        }
        self.active_blob = Some(ActiveBlobTracker {
            blob_id,
            storage_path: valid_path.clone(),
            bytes: 0,
            hasher: Sha256::new(),
        });
        Ok(VerifiedArchiveEvent::BlobStart {
            blob_id,
            storage_path: valid_path,
        })
    }

    fn on_blob_chunk(&mut self, blob_id: u64, data: Vec<u8>) -> Result<VerifiedArchiveEvent> {
        let Some(ref mut active) = self.active_blob else {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Received BlobChunk for unopened blob {blob_id}"
            )));
        };
        if active.blob_id != blob_id {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "BlobChunk id mismatch: active {}, got {blob_id}",
                active.blob_id
            )));
        }
        active.bytes = active
            .bytes
            .checked_add(data.len() as u64)
            .ok_or_else(|| CfmsError::ArchiveIntegrity("Blob byte counter overflow".to_string()))?;
        active.hasher.update(&data);
        Ok(VerifiedArchiveEvent::BlobChunk { blob_id, data })
    }

    fn on_blob_end(&mut self, end: BlobEndPayload) -> Result<VerifiedArchiveEvent> {
        let Some(active) = self.active_blob.take() else {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Received BlobEnd for unopened blob {}",
                end.blob_id
            )));
        };
        if active.blob_id != end.blob_id {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "BlobEnd id mismatch: expected {}, got {}",
                active.blob_id, end.blob_id
            )));
        }
        if active.bytes != end.size {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Blob {} byte count mismatch: streamed {}, recorded {}",
                end.blob_id, active.bytes, end.size
            )));
        }
        let actual_sha = hex::encode(active.hasher.finalize());
        if actual_sha != end.sha256 {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Blob {} SHA-256 checksum mismatch",
                end.blob_id
            )));
        }
        let storage_path = active.storage_path;
        self.completed_blobs
            .insert(end.blob_id, (storage_path.clone(), end.clone()));
        self.blobs_order.push(end.clone());
        Ok(VerifiedArchiveEvent::BlobEnd {
            blob_id: end.blob_id,
            storage_path,
            size: end.size,
        })
    }

    fn on_missing_inactive(
        &mut self,
        missing: MissingInactiveFilePayload,
    ) -> Result<VerifiedArchiveEvent> {
        self.ensure_tables_complete("MissingInactiveFile")?;
        if self.active_blob.is_some() {
            return Err(CfmsError::ArchiveIntegrity(
                "MissingInactiveFile appeared inside an active blob stream".to_string(),
            ));
        }
        validate_storage_relative_path(&missing.storage_path)?;
        let Some((expected_path, active)) = self.files_meta.get(&missing.file_id) else {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "MissingInactiveFile references unknown file_id '{}'",
                missing.file_id
            )));
        };
        if *active {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Archive omitted an active storage file '{}'",
                missing.file_id
            )));
        }
        if expected_path != &missing.storage_path {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "MissingInactiveFile path mismatch for '{}'",
                missing.file_id
            )));
        }
        if !self.accounted_file_ids.insert(missing.file_id.clone()) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Duplicate file accounting entry for '{}'",
                missing.file_id
            )));
        }
        self.missing_order.push(missing);
        Ok(VerifiedArchiveEvent::MissingInactiveFile)
    }

    fn on_file_entry(&mut self, entry: FileEntryPayload) -> Result<VerifiedArchiveEvent> {
        self.ensure_tables_complete("FileEntry")?;
        if self.active_blob.is_some() {
            return Err(CfmsError::ArchiveIntegrity(
                "FileEntry appeared inside an active blob stream".to_string(),
            ));
        }
        validate_storage_relative_path(&entry.storage_path)?;
        let Some((expected_path, _)) = self.files_meta.get(&entry.file_id) else {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "FileEntry references unknown file_id '{}'",
                entry.file_id
            )));
        };
        if expected_path != &entry.storage_path {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "FileEntry path mismatch for '{}'",
                entry.file_id
            )));
        }
        let Some((_, blob_end)) = self.completed_blobs.get(&entry.blob_id) else {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "FileEntry '{}' references non-existent or unfinished blob_id {}",
                entry.file_id, entry.blob_id
            )));
        };
        if blob_end.size != entry.size || blob_end.sha256 != entry.sha256 {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "FileEntry '{}' metadata does not match blob {}",
                entry.file_id, entry.blob_id
            )));
        }
        if !self.accounted_file_ids.insert(entry.file_id.clone()) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Duplicate file accounting entry for '{}'",
                entry.file_id
            )));
        }
        self.referenced_blob_ids.insert(entry.blob_id);
        self.files_order.push(entry.clone());
        Ok(VerifiedArchiveEvent::FileEntry(entry))
    }

    fn on_integrity_footer(&mut self, footer: IntegrityFooter) -> Result<VerifiedArchiveEvent> {
        self.ensure_tables_complete("IntegrityFooter")?;
        if self.active_blob.is_some() {
            return Err(CfmsError::ArchiveIntegrity(
                "IntegrityFooter arrived while a blob stream is still open".to_string(),
            ));
        }
        if self.accounted_file_ids.len() != self.files_meta.len() {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Archive accounted for {} of {} file record(s)",
                self.accounted_file_ids.len(),
                self.files_meta.len()
            )));
        }
        if self.referenced_blob_ids.len() != self.completed_blobs.len() {
            return Err(CfmsError::ArchiveIntegrity(
                "Archive contains unreferenced orphan blob payload(s)".to_string(),
            ));
        }
        if footer.tables != self.completed_tables {
            return Err(CfmsError::ArchiveIntegrity(
                "IntegrityFooter table digests do not match streamed table contents".to_string(),
            ));
        }
        if footer.blobs != self.blobs_order {
            return Err(CfmsError::ArchiveIntegrity(
                "IntegrityFooter blob list does not match streamed blobs".to_string(),
            ));
        }
        if footer.files != self.files_order {
            return Err(CfmsError::ArchiveIntegrity(
                "IntegrityFooter file entries do not match streamed entries".to_string(),
            ));
        }
        if footer.missing_inactive_files != self.missing_order {
            return Err(CfmsError::ArchiveIntegrity(
                "IntegrityFooter missing-inactive-file list does not match stream".to_string(),
            ));
        }
        self.saw_footer = true;
        Ok(VerifiedArchiveEvent::IntegrityFooter(footer))
    }
}

/// Execute `cfms-ctl backup verify`.
pub async fn run_verify(ctx: &AppContext, args: BackupVerifyArgs) -> Result<()> {
    let master_key = read_key_from_args(args.key.as_deref(), args.key_file.as_deref())?;
    let (envelope, manifest, mut archive) =
        VerifiedArchiveReader::open_file(&args.backup_path, &master_key)?;

    let pb = backup_progress_bar(ctx.ui.format(), manifest.table_order.len() as u64);
    let mut verified_tables = BTreeMap::new();
    let mut total_rows = 0u64;
    let mut blob_bytes = 0u64;
    let mut final_footer: Option<IntegrityFooter> = None;

    while let Some(event) = archive.next_event()? {
        match event {
            VerifiedArchiveEvent::TableStart { table_name } => {
                pb.set_message(format!("Verifying table '{table_name}'"));
            }
            VerifiedArchiveEvent::TableBatch { .. } => {}
            VerifiedArchiveEvent::TableEnd {
                table_name,
                row_count,
                canonical_sha256,
            } => {
                total_rows += row_count;
                verified_tables.insert(
                    table_name,
                    TableDigestSummary {
                        rows: row_count,
                        sha256: canonical_sha256,
                    },
                );
                pb.inc(1);
            }
            VerifiedArchiveEvent::BlobStart { storage_path, .. } => {
                pb.set_message(format!("Verifying blob '{storage_path}'"));
            }
            VerifiedArchiveEvent::BlobChunk { .. } => {}
            VerifiedArchiveEvent::BlobEnd { size, .. } => {
                blob_bytes += size;
            }
            VerifiedArchiveEvent::MissingInactiveFile | VerifiedArchiveEvent::FileEntry(_) => {}
            VerifiedArchiveEvent::IntegrityFooter(footer) => {
                final_footer = Some(footer);
            }
        }
    }
    pb.finish_and_clear();

    let footer = final_footer.ok_or_else(|| {
        CfmsError::ArchiveIntegrity("Archive verification completed without footer".to_string())
    })?;

    let report = BackupVerifyReport {
        archive_path: envelope.path,
        file_size: envelope.file_size,
        format_version: manifest.version,
        created_at: manifest.created_at,
        server_version: manifest.server_version,
        schema_revision: manifest.schema_revision,
        components: manifest.components,
        table_count: verified_tables.len(),
        total_rows,
        file_entries: footer.files.len(),
        unique_blobs: footer.blobs.len(),
        blob_bytes,
        missing_inactive_files: footer.missing_inactive_files.len(),
        warnings: footer.warnings,
        tables: verified_tables,
    };
    ctx.ui.render(&report);
    Ok(())
}

fn validate_open_manifest(manifest: &ManifestHeader, envelope: &BackupHeaderReport) -> Result<()> {
    let components = parse_and_validate_manifest_components(&manifest.components)?;
    let expected_tables = expected_tables_for_schema(
        &components,
        &manifest.extension_tables,
        Some(&manifest.schema_ir),
    );
    validate_manifest_header(manifest, envelope, &expected_tables)?;

    for ext in &manifest.extension_tables {
        let Some(tbl_ir) = manifest.schema_ir.tables.get(&ext.table_name) else {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Archive extension table '{}' is missing from embedded schema_ir",
                ext.table_name
            )));
        };
        match &tbl_ir.ownership {
            TableOwnership::Extension(owner) if owner == &ext.owner => {}
            other => {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Archive extension table '{}' ownership mismatch ({other:?})",
                    ext.table_name
                )));
            }
        }
    }
    Ok(())
}

fn build_table_slots(table_order: &[String], coupled: bool) -> Vec<TableSlot> {
    let mut slots = Vec::with_capacity(table_order.len());
    let mut emitted_coupled = false;
    for name in table_order {
        if coupled && matches!(name.as_str(), "nodes" | "folders" | "documents") {
            if !emitted_coupled {
                emitted_coupled = true;
                slots.push(TableSlot::CoupledNodesGroup);
            }
            continue;
        }
        slots.push(TableSlot::Single(name.clone()));
    }
    slots
}

fn spec_col_idx(spec: &TableSchemaSpec, col: &str, table: &str) -> Result<usize> {
    spec.columns
        .iter()
        .position(|c| c.name == col)
        .ok_or_else(|| {
            CfmsError::ArchiveIntegrity(format!(
                "Manifest schema for '{table}' is missing required column '{col}'"
            ))
        })
}

fn finalize_decrypted_stream<R: Read>(reader: InnerRecordReader<R>) -> Result<()> {
    // Finish Zstd frame epilogue cleanly, verify zero trailing decompressed bytes,
    // then verify ChunkedDecryptReader hit the final chunk & EOF.
    let mut zstd_decoder = reader.into_inner();
    zstd_decoder.finish_frame().map_err(|e| {
        CfmsError::ArchiveIntegrity(format!("Compressed backup stream failed epilogue check: {e}"))
    })?;
    let mut probe = [0u8; 1];
    match zstd_decoder.read(&mut probe) {
        Ok(0) => {}
        Ok(_) => {
            return Err(CfmsError::ArchiveIntegrity(
                "Unexpected trailing compressed stream data after integrity footer".to_string(),
            ));
        }
        Err(e) => {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Compressed backup trailing stream error: {e}"
            )));
        }
    }
    let buf_reader = zstd_decoder.into_inner();
    if !buf_reader.buffer().is_empty() {
        return Err(CfmsError::ArchiveIntegrity(
            "Unexpected trailing plaintext data left in decompression buffer".to_string(),
        ));
    }
    let mut decrypt_reader = buf_reader.into_inner();
    decrypt_reader.verify_eof()?;
    Ok(())
}
