//! `cfms-ctl audit`: Audit log inspection, canonical JSONL/Zstd export, verified archive-before-delete purging, and offline archive verification.

pub mod archive;
pub mod db;
pub mod filter;
pub mod policy;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use serde::Serialize;
use crate::cli::audit::{
    AuditCommand, AuditExportArgs, AuditInspectArgs, AuditPurgeArgs, AuditVerifyArgs,
};
use crate::core::error::{CfmsError, Result};
use crate::ops::AppContext;
use crate::ui::{
    CommandReport, KeyValueTable, OutputFormat, UiConsole, confirm_or_abort, styled_table,
};
use archive::{
    ArchiveIdBatchReader, StagedArchiveWriter, preflight_new_archive_path, verify_archive_file,
};
use db::{
    AuditDbInspectStats, CompiledAuditFilter, compile_filter, delete_id_batch,
    dialect_delete_chunk_cap, inspect_audit_entries, preflight_audit_schema, stream_export_entries,
};
use filter::{CutoffMode, ResolvedAuditFilter, format_unix_utc, validate_filter_syntax};
use policy::AuditRetentionPolicy;

const SENSITIVE_ARCHIVE_NOTICE: &str = "Audit archives preserve target/data/remote_address metadata as plaintext JSONL (or Zstd-compressed JSONL); protect exported files accordingly.";

/// Report for `cfms-ctl audit inspect`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditInspectReport {
    pub matched_entries: u64,
    pub cutoff_mode: CutoffMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cutoff_timestamp: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cutoff_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_timestamp: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u64>,
    pub batch_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_logged_time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_logged_time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_utc: Option<String>,
    pub by_action: BTreeMap<String, u64>,
    pub by_result: BTreeMap<i32, u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_usernames: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Report for `cfms-ctl audit export`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditExportReport {
    pub output_path: String,
    pub compressed: bool,
    pub exported_entries: u64,
    pub archive_bytes: u64,
    pub archive_sha256: String,
    pub cutoff_mode: CutoffMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cutoff_timestamp: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cutoff_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_timestamp: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_logged_time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_logged_time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_usernames: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub sensitive_data_notice: String,
}

/// Report for `cfms-ctl audit purge`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditPurgeReport {
    pub dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_path: Option<String>,
    pub compressed: bool,
    pub matched_entries: u64,
    pub archived_entries: u64,
    pub deleted_entries: u64,
    pub batches_executed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_sha256: Option<String>,
    pub cutoff_mode: CutoffMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cutoff_timestamp: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cutoff_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_timestamp: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u64>,
    pub batch_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_logged_time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_logged_time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_utc: Option<String>,
    pub by_action: BTreeMap<String, u64>,
    pub by_result: BTreeMap<i32, u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_usernames: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub sensitive_data_notice: String,
}

/// Report for `cfms-ctl audit verify`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditVerifyReport {
    pub archive_path: String,
    pub compressed: bool,
    pub verified_entries: u64,
    pub archive_bytes: u64,
    pub archive_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_logged_time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_logged_time: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest_utc: Option<String>,
    pub by_action: BTreeMap<String, u64>,
    pub by_result: BTreeMap<i32, u64>,
}

impl CommandReport for AuditInspectReport {
    fn render_human(&self, ui: &UiConsole) {
        for w in &self.warnings {
            ui.print_warning(w);
        }

        let mut kv = KeyValueTable::new("Audit Log Inspection");
        kv.row("Matched Entries", self.matched_entries.to_string()).row(
            "Cutoff Policy",
            format_cutoff_summary(
                self.cutoff_mode,
                self.cutoff_utc.as_deref(),
                self.retention_days,
                true,
            ),
        );
        if let Some(after) = &self.after_utc {
            kv.row("After (>=)", after.clone());
        }
        kv.row(
            "Retention Policy (days)",
            self.retention_days
                .map_or_else(|| "n/a".to_string(), |d| d.to_string()),
        )
        .row("Batch Size", self.batch_size.to_string());
        if let Some(oldest) = &self.oldest_utc {
            kv.row("Oldest Match", oldest.clone());
        }
        if let Some(newest) = &self.newest_utc {
            kv.row("Newest Match", newest.clone());
        }
        kv.print();
        render_histograms(ui, &self.by_action, &self.by_result);
    }
}

impl CommandReport for AuditExportReport {
    fn render_human(&self, ui: &UiConsole) {
        for w in &self.warnings {
            ui.print_warning(w);
        }
        let mut kv = KeyValueTable::new("Audit Log Export");
        kv.row("Output Path", self.output_path.clone())
            .row(
                "Format",
                if self.compressed {
                    "Zstd-compressed JSONL"
                } else {
                    "JSONL (UTF-8)"
                },
            )
            .row("Exported Entries", self.exported_entries.to_string())
            .row("Archive Bytes", self.archive_bytes.to_string())
            .row("Archive SHA-256", self.archive_sha256.clone())
            .row(
                "Cutoff Policy",
                format_cutoff_summary(self.cutoff_mode, self.cutoff_utc.as_deref(), None, true),
            );
        if let Some(after) = &self.after_utc {
            kv.row("After (>=)", after.clone());
        }
        if let Some(oldest) = &self.oldest_utc {
            kv.row("Oldest Entry", oldest.clone());
        }
        if let Some(newest) = &self.newest_utc {
            kv.row("Newest Entry", newest.clone());
        }
        kv.row("Security Notice", self.sensitive_data_notice.clone());
        kv.print();
    }
}

impl CommandReport for AuditPurgeReport {
    fn render_human(&self, ui: &UiConsole) {
        for w in &self.warnings {
            ui.print_warning(w);
        }
        let title = if self.dry_run {
            "Audit Log Purge Preview (dry-run)"
        } else {
            "Audit Log Purge Summary"
        };
        let mut kv = KeyValueTable::new(title);
        kv.row(
            "Mode",
            if self.dry_run {
                "dry-run"
            } else {
                "archive-before-delete"
            },
        )
        .row("Matched Entries", self.matched_entries.to_string())
        .row("Archived Entries", self.archived_entries.to_string())
        .row("Deleted Entries", self.deleted_entries.to_string())
        .row("Batches Executed", self.batches_executed.to_string())
        .row(
            "Cutoff Policy",
            format_cutoff_summary(
                self.cutoff_mode,
                self.cutoff_utc.as_deref(),
                self.retention_days,
                false,
            ),
        );
        if let Some(after) = &self.after_utc {
            kv.row("After (>=)", after.clone());
        }
        if let Some(path) = &self.archive_path {
            kv.row("Archive Path", path.clone());
            kv.row(
                "Archive Format",
                if self.compressed {
                    "Zstd-compressed JSONL"
                } else {
                    "JSONL (UTF-8)"
                },
            );
        }
        if let Some(bytes) = self.archive_bytes {
            kv.row("Archive Bytes", bytes.to_string());
        }
        if let Some(sha) = &self.archive_sha256 {
            kv.row("Archive SHA-256", sha.clone());
        }
        kv.row("Batch Size", self.batch_size.to_string());
        if let Some(oldest) = &self.oldest_utc {
            kv.row("Oldest Match", oldest.clone());
        }
        if let Some(newest) = &self.newest_utc {
            kv.row("Newest Match", newest.clone());
        }
        kv.row("Security Notice", self.sensitive_data_notice.clone());
        kv.print();
        render_histograms(ui, &self.by_action, &self.by_result);
    }
}

impl CommandReport for AuditVerifyReport {
    fn render_human(&self, ui: &UiConsole) {
        let mut kv = KeyValueTable::new("Audit Archive Verification");
        kv.row("Archive Path", self.archive_path.clone())
            .row(
                "Format",
                if self.compressed {
                    "Zstd-compressed JSONL"
                } else {
                    "JSONL (UTF-8)"
                },
            )
            .row("Verified Entries", self.verified_entries.to_string())
            .row("Archive Bytes", self.archive_bytes.to_string())
            .row("Archive SHA-256", self.archive_sha256.clone());
        if let Some(oldest) = &self.oldest_utc {
            kv.row("Oldest Entry", oldest.clone());
        }
        if let Some(newest) = &self.newest_utc {
            kv.row("Newest Entry", newest.clone());
        }
        kv.print();
        render_histograms(ui, &self.by_action, &self.by_result);
    }
}

fn format_cutoff_summary(
    mode: CutoffMode,
    cutoff_utc: Option<&str>,
    retention_days: Option<u64>,
    suggest_all: bool,
) -> String {
    match mode {
        CutoffMode::AllTime => "all-time (no --before cutoff)".to_string(),
        CutoffMode::ExplicitBefore => format!(
            "explicit --before < {}",
            cutoff_utc.unwrap_or("<unknown>")
        ),
        CutoffMode::RetentionPolicy => {
            let base = format!(
                "retention policy ({} days, < {})",
                retention_days.map_or_else(|| "configured".to_string(), |d| d.to_string()),
                cutoff_utc.unwrap_or("<unknown>")
            );
            if suggest_all {
                format!("{base} — pass `--all` to include newer entries")
            } else {
                base
            }
        }
    }
}

fn render_histograms(
    ui: &UiConsole,
    by_action: &BTreeMap<String, u64>,
    by_result: &BTreeMap<i32, u64>,
) {
    if !by_action.is_empty() {
        let mut table = styled_table(&["Action", "Count"]);
        for (action, count) in by_action {
            table.add_row(vec![action.clone(), count.to_string()]);
        }
        ui.print_section("Entries by Action");
        println!("{table}");
    }
    if !by_result.is_empty() {
        let mut table = styled_table(&["Result Code", "Count"]);
        for (code, count) in by_result {
            table.add_row(vec![code.to_string(), count.to_string()]);
        }
        ui.print_section("Entries by Result");
        println!("{table}");
    }
}

/// Dispatch `cfms-ctl audit` subcommands.
pub async fn handle(ctx: &AppContext, cmd: AuditCommand) -> Result<()> {
    match cmd {
        AuditCommand::Inspect(args) => {
            let report = inspect_audit(ctx, &args).await?;
            ctx.ui.render(&report);
            Ok(())
        }
        AuditCommand::Export(args) => {
            let report = export_audit(ctx, &args).await?;
            ctx.ui.render(&report);
            Ok(())
        }
        AuditCommand::Purge(args) => {
            let report = purge_audit(ctx, &args).await?;
            ctx.ui.render(&report);
            Ok(())
        }
        AuditCommand::Verify(args) => {
            let report = verify_audit(&args).await?;
            ctx.ui.render(&report);
            Ok(())
        }
    }
}

/// Run `cfms-ctl audit inspect` without acquiring `server.lock` or mutating state.
pub async fn inspect_audit(ctx: &AppContext, args: &AuditInspectArgs) -> Result<AuditInspectReport> {
    validate_filter_syntax(&args.filter)?;

    let paths = ctx.resolve_paths()?;
    let pool = ctx.connect_db(&paths).await?;
    preflight_audit_schema(&pool).await?;

    let policy = AuditRetentionPolicy::load(&pool).await?;
    let filter = ResolvedAuditFilter::from_args(
        &args.filter,
        args.all,
        Some(policy),
        now_unix_seconds(),
    )?;
    let compiled = compile_filter(&pool, &filter).await?;
    let stats = inspect_audit_entries(&pool, &compiled).await?;
    let warnings = build_warnings(&compiled, None);

    Ok(AuditInspectReport {
        matched_entries: stats.matched_entries,
        cutoff_mode: filter.cutoff_mode,
        cutoff_timestamp: filter.before_unix,
        cutoff_utc: filter.before_utc,
        after_timestamp: filter.after_unix,
        after_utc: filter.after_utc,
        retention_days: Some(policy.retention_days),
        batch_size: policy.batch_size,
        oldest_logged_time: stats.oldest_logged_time,
        oldest_utc: stats.oldest_logged_time.map(format_unix_utc),
        newest_logged_time: stats.newest_logged_time,
        newest_utc: stats.newest_logged_time.map(format_unix_utc),
        by_action: stats.by_action,
        by_result: stats.by_result,
        unresolved_usernames: compiled.unresolved_usernames,
        warnings,
    })
}

/// Stream matching entries to a new atomic JSONL/Zstd export file without acquiring `server.lock`.
pub async fn export_audit(ctx: &AppContext, args: &AuditExportArgs) -> Result<AuditExportReport> {
    validate_filter_syntax(&args.filter)?;
    preflight_new_archive_path(&args.output_path)?;

    let paths = ctx.resolve_paths()?;
    let pool = ctx.connect_db(&paths).await?;
    preflight_audit_schema(&pool).await?;

    let policy = if args.all || args.filter.before.is_some() {
        None
    } else {
        Some(AuditRetentionPolicy::load(&pool).await?)
    };
    let filter = ResolvedAuditFilter::from_args(
        &args.filter,
        args.all,
        policy,
        now_unix_seconds(),
    )?;
    let compiled = compile_filter(&pool, &filter).await?;
    let warnings = build_warnings(&compiled, None);

    let mut writer = StagedArchiveWriter::new(&args.output_path, args.compress)?;
    let pb = export_progress_bar(ctx.ui.format(), None);
    stream_export_entries(&pool, &compiled, &mut writer, Some(&pb)).await?;
    pb.finish_and_clear();

    let stats = tokio::task::spawn_blocking(move || writer.finish_and_persist(None))
        .await
        .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))??;

    Ok(AuditExportReport {
        output_path: args.output_path.display().to_string(),
        compressed: stats.compressed,
        exported_entries: stats.record_count,
        archive_bytes: stats.archive_bytes,
        archive_sha256: stats.archive_sha256,
        cutoff_mode: filter.cutoff_mode,
        cutoff_timestamp: filter.before_unix,
        cutoff_utc: filter.before_utc,
        after_timestamp: filter.after_unix,
        after_utc: filter.after_utc,
        oldest_logged_time: stats.oldest_logged_time,
        oldest_utc: stats.oldest_logged_time.map(format_unix_utc),
        newest_logged_time: stats.newest_logged_time,
        newest_utc: stats.newest_logged_time.map(format_unix_utc),
        unresolved_usernames: compiled.unresolved_usernames,
        warnings,
        sensitive_data_notice: SENSITIVE_ARCHIVE_NOTICE.to_string(),
    })
}

/// Preview (`--dry-run`) or lock-protected archive-then-purge expired `audit_entries` rows.
pub async fn purge_audit(ctx: &AppContext, args: &AuditPurgeArgs) -> Result<AuditPurgeReport> {
    validate_filter_syntax(&args.filter)?;

    let archive_path: Option<PathBuf> = if args.dry_run {
        None
    } else {
        let p = args.archive.clone().ok_or_else(|| {
            CfmsError::InvalidArgument(
                "`--archive` is required unless `--dry-run` is specified".to_string(),
            )
        })?;
        preflight_new_archive_path(&p)?;
        Some(p)
    };

    let paths = ctx.resolve_paths()?;
    let _server_lock = if args.dry_run {
        None
    } else {
        Some(ctx.acquire_server_lock(&paths, false)?)
    };

    let pool = ctx.connect_db(&paths).await?;
    preflight_audit_schema(&pool).await?;

    let policy = AuditRetentionPolicy::load(&pool).await?;
    let filter = ResolvedAuditFilter::from_args(
        &args.filter,
        false,
        Some(policy),
        now_unix_seconds(),
    )?;
    let compiled = compile_filter(&pool, &filter).await?;
    let inspect = inspect_audit_entries(&pool, &compiled).await?;
    let effective_chunk_size = usize::try_from(policy.batch_size)
        .unwrap_or(usize::MAX)
        .min(dialect_delete_chunk_cap(pool.kind()));
    let mut warnings = build_warnings(
        &compiled,
        if effective_chunk_size as u64 != policy.batch_size {
            Some(format!(
                "Configured retention batch_size ({}) exceeds safe bind cap for {}; deleting in batches of {effective_chunk_size}.",
                policy.batch_size,
                pool.kind()
            ))
        } else {
            None
        },
    );

    if args.dry_run || inspect.matched_entries == 0 {
        if !args.dry_run && inspect.matched_entries == 0 {
            warnings.push(
                "No audit entries matched; archive file was not created and no rows were deleted."
                    .to_string(),
            );
        }
        return Ok(AuditPurgeReport {
            dry_run: args.dry_run,
            archive_path: None,
            compressed: args.compress,
            matched_entries: inspect.matched_entries,
            archived_entries: 0,
            deleted_entries: 0,
            batches_executed: 0,
            archive_bytes: None,
            archive_sha256: None,
            cutoff_mode: filter.cutoff_mode,
            cutoff_timestamp: filter.before_unix,
            cutoff_utc: filter.before_utc,
            after_timestamp: filter.after_unix,
            after_utc: filter.after_utc,
            retention_days: Some(policy.retention_days),
            batch_size: policy.batch_size,
            oldest_logged_time: inspect.oldest_logged_time,
            oldest_utc: inspect.oldest_logged_time.map(format_unix_utc),
            newest_logged_time: inspect.newest_logged_time,
            newest_utc: inspect.newest_logged_time.map(format_unix_utc),
            by_action: inspect.by_action,
            by_result: inspect.by_result,
            unresolved_usernames: compiled.unresolved_usernames,
            warnings,
            sensitive_data_notice: SENSITIVE_ARCHIVE_NOTICE.to_string(),
        });
    }

    let archive_path = archive_path.expect("checked above when not dry-run");
    confirm_purge(&ctx.ui, &inspect, &filter, &archive_path, ctx.global.yes)?;

    let mut writer = StagedArchiveWriter::new(&archive_path, args.compress)?;
    let pb = export_progress_bar(ctx.ui.format(), Some(inspect.matched_entries));
    pb.set_message("Archiving audit entries");
    stream_export_entries(&pool, &compiled, &mut writer, Some(&pb)).await?;
    pb.finish_and_clear();

    let expected = inspect.matched_entries;
    let write_stats = tokio::task::spawn_blocking(move || writer.finish_and_persist(Some(expected)))
        .await
        .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))??;

    // Verify full persisted archive readability & digest before deleting any DB rows.
    let verify_path = archive_path.clone();
    let verified = tokio::task::spawn_blocking(move || verify_archive_file(&verify_path))
        .await
        .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))??;
    if verified.verified_entries != write_stats.record_count
        || verified.archive_sha256 != write_stats.archive_sha256
    {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Archive verification mismatch on '{}'; aborting purge before deleting database rows",
            archive_path.display()
        )));
    }

    let mut id_reader = ArchiveIdBatchReader::open(&archive_path)?;
    let del_pb = export_progress_bar(ctx.ui.format(), Some(write_stats.record_count));
    del_pb.set_message("Deleting archived audit entries");
    let mut deleted_entries: u64 = 0;
    let mut batches_executed: u64 = 0;
    while let Some(id_batch) = id_reader.next_batch(effective_chunk_size)? {
        let deleted = delete_id_batch(&pool, &id_batch).await?;
        deleted_entries = deleted_entries.saturating_add(deleted);
        batches_executed = batches_executed.saturating_add(1);
        del_pb.inc(id_batch.len() as u64);
    }
    del_pb.finish_and_clear();

    if deleted_entries != write_stats.record_count {
        return Err(CfmsError::Database(format!(
            "Expected to delete {} archived audit entries, deleted {deleted_entries}; archive '{}' was preserved",
            write_stats.record_count,
            archive_path.display()
        )));
    }

    Ok(AuditPurgeReport {
        dry_run: false,
        archive_path: Some(archive_path.display().to_string()),
        compressed: write_stats.compressed,
        matched_entries: inspect.matched_entries,
        archived_entries: write_stats.record_count,
        deleted_entries,
        batches_executed,
        archive_bytes: Some(write_stats.archive_bytes),
        archive_sha256: Some(write_stats.archive_sha256),
        cutoff_mode: filter.cutoff_mode,
        cutoff_timestamp: filter.before_unix,
        cutoff_utc: filter.before_utc,
        after_timestamp: filter.after_unix,
        after_utc: filter.after_utc,
        retention_days: Some(policy.retention_days),
        batch_size: policy.batch_size,
        oldest_logged_time: inspect.oldest_logged_time,
        oldest_utc: inspect.oldest_logged_time.map(format_unix_utc),
        newest_logged_time: inspect.newest_logged_time,
        newest_utc: inspect.newest_logged_time.map(format_unix_utc),
        by_action: inspect.by_action,
        by_result: inspect.by_result,
        unresolved_usernames: compiled.unresolved_usernames,
        warnings,
        sensitive_data_notice: SENSITIVE_ARCHIVE_NOTICE.to_string(),
    })
}

/// Offline integrity, schema, ordering, and SHA-256 verification for an audit archive.
pub async fn verify_audit(args: &AuditVerifyArgs) -> Result<AuditVerifyReport> {
    let path = args.archive_path.clone();
    let summary = tokio::task::spawn_blocking(move || verify_archive_file(&path))
        .await
        .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))??;

    Ok(AuditVerifyReport {
        archive_path: summary.archive_path,
        compressed: summary.compressed,
        verified_entries: summary.verified_entries,
        archive_bytes: summary.archive_bytes,
        archive_sha256: summary.archive_sha256,
        oldest_logged_time: summary.oldest_logged_time,
        oldest_utc: summary.oldest_logged_time.map(format_unix_utc),
        newest_logged_time: summary.newest_logged_time,
        newest_utc: summary.newest_logged_time.map(format_unix_utc),
        by_action: summary.by_action,
        by_result: summary.by_result,
    })
}

fn build_warnings(compiled: &CompiledAuditFilter, extra: Option<String>) -> Vec<String> {
    let mut warnings = Vec::new();
    if !compiled.unresolved_usernames.is_empty() {
        warnings.push(format!(
            "Requested username(s) not found in `users` table: {}",
            compiled.unresolved_usernames.join(", ")
        ));
    }
    if let Some(msg) = extra {
        warnings.push(msg);
    }
    warnings
}

fn confirm_purge(
    ui: &UiConsole,
    inspect: &AuditDbInspectStats,
    filter: &ResolvedAuditFilter,
    archive_path: &Path,
    yes: bool,
) -> Result<()> {
    if !yes && ui.format() == OutputFormat::Json {
        return Err(CfmsError::OperationAborted);
    }
    let cutoff_desc = filter.before_utc.as_deref().unwrap_or("configured cutoff");
    let prompt = format!(
        "Archive {} audit log entries (logged before {cutoff_desc}) to '{}' and purge them from the database?",
        inspect.matched_entries,
        archive_path.display()
    );
    confirm_or_abort(&prompt, yes)
}

fn export_progress_bar(format: OutputFormat, len: Option<u64>) -> ProgressBar {
    match format {
        OutputFormat::Human => {
            let bar = ProgressBar::with_draw_target(len, ProgressDrawTarget::stderr());
            let style = if len.is_some() {
                ProgressStyle::with_template(
                    "{spinner:.cyan} [{elapsed_precise}] [{bar:32.cyan/blue}] {pos}/{len} ({msg})",
                )
            } else {
                ProgressStyle::with_template(
                    "{spinner:.cyan} [{elapsed_precise}] {pos} entries ({msg})",
                )
            }
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=>-");
            bar.set_style(style);
            bar.set_message("Streaming audit entries");
            bar
        }
        OutputFormat::Json => ProgressBar::hidden(),
    }
}

fn now_unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::GlobalOpts;
    use crate::cli::audit::AuditFilterArgs;
    use crate::core::config::ConfigDocument;
    use crate::core::lock::RuntimeLock;
    use crate::core::paths::WorkspacePaths;
    use crate::db::backend::DbPool;
    use crate::db::options::{OptionUpdateInput, write_options_batch};
    use crate::db::schema::LATEST_SCHEMA_REVISION;
    use crate::db::schema::ddl::{create_head_schema, set_alembic_version};
    use serde_json::{Value, json};
    use sqlx::Row;
    use uuid::Uuid;

    struct AuditTestEnv {
        _dir: tempfile::TempDir,
        root: PathBuf,
        paths: WorkspacePaths,
        pool: DbPool,
    }

    impl AuditTestEnv {
        async fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let src = dir.path().join("src");
            let cfg_dir = src.join("include").join("config");
            std::fs::create_dir_all(&cfg_dir).expect("cfg dir");
            std::fs::write(src.join("main.py"), "# cfms").expect("main.py");
            std::fs::write(
                cfg_dir.join("constants.py"),
                "CORE_VERSION = Version(\"0.14.0\")\n",
            )
            .expect("constants.py");
            std::fs::write(
                src.join("config.toml"),
                "[database]\ntype = \"sqlite\"\nfile = \"cfms.db\"\n",
            )
            .expect("config.toml");

            let paths = WorkspacePaths::discover(Some(dir.path()), None).expect("paths");
            let config = ConfigDocument::load(&paths.config_path).expect("load config");
            let db_cfg = config.database_config().expect("db config");
            let pool = DbPool::connect(&db_cfg, &paths).await.expect("connect sqlite");
            create_head_schema(&pool, false).await.expect("head schema");
            set_alembic_version(&pool, LATEST_SCHEMA_REVISION)
                .await
                .expect("alembic version");

            Self {
                _dir: dir,
                root: paths.project_root.clone(),
                paths,
                pool,
            }
        }

        fn sqlite(&self) -> &sqlx::SqlitePool {
            match &self.pool {
                DbPool::Sqlite(p) => p,
                _ => panic!("expected sqlite pool"),
            }
        }

        fn ctx(&self, format: OutputFormat, yes: bool) -> AppContext {
            AppContext::new(
                GlobalOpts {
                    root: Some(self.root.clone()),
                    config: None,
                    output: format,
                    yes,
                    verbose: false,
                },
                UiConsole::new(format),
            )
        }

        async fn insert_user(&self, username: &str) -> Uuid {
            let uid = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO users (id, username, nickname, created_time, status, secret_key) VALUES (?, ?, ?, 1.0, 0, 'sk')",
            )
            .bind(uid.simple().to_string())
            .bind(username)
            .bind(username)
            .execute(self.sqlite())
            .await
            .expect("insert user");
            uid
        }

        #[allow(clippy::too_many_arguments)]
        async fn insert_entry(
            &self,
            id: &str,
            action: &str,
            user_id: Option<Uuid>,
            target: Option<&str>,
            data: Option<Value>,
            result: i32,
            remote_address: Option<&str>,
            logged_time: f64,
        ) {
            let data_text = data.map(|v| serde_json::to_string(&v).unwrap());
            sqlx::query(
                "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(action)
            .bind(user_id.map(|u| u.simple().to_string()))
            .bind(target)
            .bind(data_text)
            .bind(result)
            .bind(remote_address)
            .bind(logged_time)
            .execute(self.sqlite())
            .await
            .expect("insert audit entry");
        }
    }

    fn empty_filter() -> AuditFilterArgs {
        AuditFilterArgs {
            before: None,
            after: None,
            actions: vec![],
            exclude_actions: vec![],
            usernames: vec![],
            user_ids: vec![],
            targets: vec![],
            results: vec![],
            remote_addresses: vec![],
        }
    }

    #[tokio::test]
    async fn inspect_and_export_filters_retention_and_canonical_jsonl() {
        let env = AuditTestEnv::new().await;
        let alice = env.insert_user("alice").await;
        let bob = env.insert_user("bob").await;
        let ghost_uid = Uuid::new_v4();
        let now = now_unix_seconds();
        let old_ts = now - 400.0 * 86_400.0;
        let recent_ts = now - 5.0 * 86_400.0;

        // Two entries sharing exact `logged_time` to verify deterministic `(logged_time, id)` tie-break.
        env.insert_entry(
            "id_b",
            "core.auth.login",
            Some(alice),
            Some("alice"),
            Some(json!({"z": 1, "a": 9007199254740993_i64})),
            200,
            Some("10.0.0.1"),
            old_ts,
        )
        .await;
        env.insert_entry(
            "id_a",
            "core.auth.login",
            Some(alice),
            Some("alice"),
            None,
            403,
            Some("10.0.0.2"),
            old_ts,
        )
        .await;
        env.insert_entry(
            "id_bob",
            "core.file.download",
            Some(bob),
            Some("doc-1"),
            Some(json!({"size": 42})),
            200,
            Some("10.0.0.3"),
            old_ts + 10.0,
        )
        .await;
        // Deleted user (user_id preserved as NULL by FK or orphan UUID manually present).
        env.insert_entry(
            "id_recent",
            "core.auth.login",
            None,
            Some("recent-target"),
            Some(json!({"note": "recent"})),
            200,
            Some("10.0.0.1"),
            recent_ts,
        )
        .await;
        // Note: SQLite schema enforces FK user_id -> users.id ON DELETE SET NULL, so insert with FK off only if testing orphan; instead test deleted user via `user_id` of an existing-then-deleted or keep active alice `--user-id`.
        let _ = ghost_uid;

        let ctx = env.ctx(OutputFormat::Json, false);

        // Default inspect applies 365-day retention -> excludes `id_recent`
        let default_report = inspect_audit(
            &ctx,
            &AuditInspectArgs {
                all: false,
                filter: empty_filter(),
            },
        )
        .await
        .unwrap();
        assert_eq!(default_report.matched_entries, 3);
        assert_eq!(default_report.cutoff_mode, CutoffMode::RetentionPolicy);
        assert_eq!(default_report.retention_days, Some(365));
        assert_eq!(default_report.by_action.get("core.auth.login"), Some(&2));
        assert_eq!(default_report.by_action.get("core.file.download"), Some(&1));

        // Inspect with `--all` + `--exclude-action` + unresolved username warning
        let mut f = empty_filter();
        f.exclude_actions = vec!["core.file.download".to_string()];
        f.usernames = vec!["alice".to_string(), "missing_user".to_string()];
        let all_filtered = inspect_audit(
            &ctx,
            &AuditInspectArgs {
                all: true,
                filter: f,
            },
        )
        .await
        .unwrap();
        assert_eq!(all_filtered.matched_entries, 2);
        assert_eq!(all_filtered.cutoff_mode, CutoffMode::AllTime);
        assert_eq!(all_filtered.unresolved_usernames, vec!["missing_user"]);
        assert!(!all_filtered.warnings.is_empty());

        // Inspect using `--after` + `retention_days = 1` DB option (verifies no premature dummy-policy error!)
        let mut updates = BTreeMap::new();
        updates.insert(
            "retention_days".to_string(),
            OptionUpdateInput {
                value: json!(1),
                expected_revision: 0,
            },
        );
        write_options_batch(&env.pool, "maintenance.audit_retention", updates)
            .await
            .unwrap();
        let mut f_window = empty_filter();
        f_window.after = Some(format_unix_utc(recent_ts - 60.0));
        let window_report = inspect_audit(
            &ctx,
            &AuditInspectArgs {
                all: false,
                filter: f_window,
            },
        )
        .await
        .unwrap();
        assert_eq!(window_report.matched_entries, 1);
        assert_eq!(window_report.retention_days, Some(1));

        // Reset retention_days back to 365 for export test
        let mut restore = BTreeMap::new();
        restore.insert(
            "retention_days".to_string(),
            OptionUpdateInput {
                value: json!(365),
                expected_revision: 1,
            },
        );
        write_options_batch(&env.pool, "maintenance.audit_retention", restore)
            .await
            .unwrap();

        // Export with `--user-id` directly for alice & check exact JSONL output
        let export_path = env.root.join("alice.jsonl");
        let mut f_uid = empty_filter();
        f_uid.user_ids = vec![alice.hyphenated().to_string()];
        let export_rep = export_audit(
            &ctx,
            &AuditExportArgs {
                output_path: export_path.clone(),
                all: true,
                compress: false,
                filter: f_uid,
            },
        )
        .await
        .unwrap();
        assert_eq!(export_rep.exported_entries, 2);
        let raw = std::fs::read_to_string(&export_path).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2);
        // Tie-break puts id_a before id_b, and hyphenated UUID matches lowercase RFC 4122
        let parsed0: Value = serde_json::from_str(lines[0]).unwrap();
        let parsed1: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed0["id"], "id_a");
        assert_eq!(parsed1["id"], "id_b");
        assert_eq!(parsed0["user_id"], alice.hyphenated().to_string());
        // Sorted keys inside nested `data` and exact 64-bit precision integer
        assert!(
            lines[1].contains(r#""data":{"a":9007199254740993,"z":1}"#),
            "line was: {}",
            lines[1]
        );

        // Refuses overwrite on existing export target
        let clobber_err = export_audit(
            &ctx,
            &AuditExportArgs {
                output_path: export_path.clone(),
                all: true,
                compress: false,
                filter: empty_filter(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(clobber_err, CfmsError::InvalidArgument(_)));

        // Verify exported file offline
        let verify_rep = verify_audit(&AuditVerifyArgs {
            archive_path: export_path,
        })
        .await
        .unwrap();
        assert_eq!(verify_rep.verified_entries, 2);
        assert_eq!(verify_rep.archive_sha256, export_rep.archive_sha256);
    }

    #[tokio::test]
    async fn purge_enforces_lock_json_yes_no_clobber_and_large_sqlite_batching() {
        let env = AuditTestEnv::new().await;
        let now = now_unix_seconds();
        let expired_ts = now - 500.0 * 86_400.0;

        // Configure batch_size = 2000 (> SQLite 999 host param cap) & retention_days = 365
        let mut updates = BTreeMap::new();
        updates.insert(
            "batch_size".to_string(),
            OptionUpdateInput {
                value: json!(2000),
                expected_revision: 0,
            },
        );
        write_options_batch(&env.pool, "maintenance.audit_retention", updates)
            .await
            .unwrap();

        // Seed 1,250 expired entries + 2 fresh entries inside one fast tx
        {
            let mut tx = env.sqlite().begin().await.unwrap();
            for i in 0..1250 {
                sqlx::query(
                    "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, 'core.test.event', NULL, 'bulk', NULL, 0, NULL, ?)",
                )
                .bind(format!("exp_{i:04}"))
                .bind(expired_ts + (i as f64) * 0.001)
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            for i in 0..2 {
                sqlx::query(
                    "INSERT INTO audit_entries (id, action, user_id, target, data, result, remote_address, logged_time) VALUES (?, 'core.test.fresh', NULL, 'keep', NULL, 0, NULL, ?)",
                )
                .bind(format!("fresh_{i}"))
                .bind(now - 60.0)
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            tx.commit().await.unwrap();
        }

        // Empty match exits cleanly without creating archive
        let json_no_ctx = env.ctx(OutputFormat::Json, false);
        let empty_archive = env.root.join("should-not-exist.jsonl");
        let mut empty_f = empty_filter();
        empty_f.actions = vec!["nonexistent.action".to_string()];
        let empty_rep = purge_audit(
            &json_no_ctx,
            &AuditPurgeArgs {
                archive: Some(empty_archive.clone()),
                dry_run: false,
                compress: false,
                filter: empty_f,
            },
        )
        .await
        .unwrap();
        assert_eq!(empty_rep.matched_entries, 0);
        assert_eq!(empty_rep.deleted_entries, 0);
        assert!(!empty_archive.exists());

        // Live server.lock blocks live purge, while dry-run succeeds
        let lock = RuntimeLock::acquire(&env.paths, false).unwrap();
        let locked_err = purge_audit(
            &env.ctx(OutputFormat::Json, true),
            &AuditPurgeArgs {
                archive: Some(env.root.join("blocked.jsonl")),
                dry_run: false,
                compress: false,
                filter: empty_filter(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(locked_err, CfmsError::RuntimeLocked(_)));

        let dry_rep = purge_audit(
            &json_no_ctx,
            &AuditPurgeArgs {
                archive: None,
                dry_run: true,
                compress: false,
                filter: empty_filter(),
            },
        )
        .await
        .unwrap();
        assert!(dry_rep.dry_run);
        assert_eq!(dry_rep.matched_entries, 1250);
        assert_eq!(dry_rep.deleted_entries, 0);
        drop(lock);

        // JSON mode without --yes refuses destructive purge before writing archive or deleting rows
        let zst_archive = env.root.join("purged.jsonl.zst");
        let abort_err = purge_audit(
            &json_no_ctx,
            &AuditPurgeArgs {
                archive: Some(zst_archive.clone()),
                dry_run: false,
                compress: true,
                filter: empty_filter(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(abort_err, CfmsError::OperationAborted));
        assert!(!zst_archive.exists());

        // Live purge with `--compress` and `--yes`: chunks 1250 -> 500 + 500 + 250 batches safely
        let yes_ctx = env.ctx(OutputFormat::Json, true);
        let purge_rep = purge_audit(
            &yes_ctx,
            &AuditPurgeArgs {
                archive: Some(zst_archive.clone()),
                dry_run: false,
                compress: true,
                filter: empty_filter(),
            },
        )
        .await
        .unwrap();
        assert!(!purge_rep.dry_run);
        assert!(purge_rep.compressed);
        assert_eq!(purge_rep.matched_entries, 1250);
        assert_eq!(purge_rep.archived_entries, 1250);
        assert_eq!(purge_rep.deleted_entries, 1250);
        assert_eq!(purge_rep.batches_executed, 3);
        assert!(!purge_rep.warnings.is_empty());

        // Only the 2 fresh entries + 1 `update_options` entry from setup remain (no self-inserted purge row!)
        let remaining: i64 = sqlx::query("SELECT COUNT(*) AS cnt FROM audit_entries")
            .fetch_one(env.sqlite())
            .await
            .unwrap()
            .try_get("cnt")
            .unwrap();
        assert_eq!(remaining, 3);
        let purge_self_rows: i64 = sqlx::query(
            "SELECT COUNT(*) AS cnt FROM audit_entries WHERE action LIKE '%purge%'",
        )
        .fetch_one(env.sqlite())
        .await
        .unwrap()
        .try_get("cnt")
        .unwrap();
        assert_eq!(purge_self_rows, 0);

        // Persisted compressed archive verifies cleanly
        let verify_rep = verify_audit(&AuditVerifyArgs {
            archive_path: zst_archive,
        })
        .await
        .unwrap();
        assert!(verify_rep.compressed);
        assert_eq!(verify_rep.verified_entries, 1250);
        assert_eq!(Some(verify_rep.archive_sha256), purge_rep.archive_sha256);
    }

    #[tokio::test]
    async fn export_empty_and_multi_field_and_or_filters_work_via_handle() {
        let env = AuditTestEnv::new().await;
        let now = now_unix_seconds();

        env.insert_entry(
            "m1",
            "login",
            None,
            Some("t1"),
            Some(json!({"k": "v"})),
            200,
            Some("10.0.0.1"),
            100.0,
        )
        .await;
        env.insert_entry(
            "m2",
            "logout",
            None,
            Some("t2"),
            None,
            403,
            Some("10.0.0.2"),
            200.0,
        )
        .await;
        env.insert_entry(
            "m3",
            "login",
            None,
            Some("t2"),
            None,
            404,
            Some("10.0.0.1"),
            now - 10.0,
        )
        .await;

        let ctx = env.ctx(OutputFormat::Json, false);

        // Empty selection export writes valid empty archive
        let empty_path = env.root.join("empty.jsonl");
        let mut no_match = empty_filter();
        no_match.actions = vec!["nonexistent".to_string()];
        handle(
            &ctx,
            AuditCommand::Export(AuditExportArgs {
                output_path: empty_path.clone(),
                all: true,
                compress: false,
                filter: no_match,
            }),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::metadata(&empty_path).unwrap().len(), 0);
        let verified_empty = verify_audit(&AuditVerifyArgs {
            archive_path: empty_path,
        })
        .await
        .unwrap();
        assert_eq!(verified_empty.verified_entries, 0);

        // Combined OR within field + AND across fields + explicit `--before`
        let mut combo = empty_filter();
        combo.actions = vec!["login".to_string(), "logout".to_string()];
        combo.targets = vec!["t1".to_string(), "t2".to_string()];
        combo.results = vec![200, 403];
        combo.remote_addresses = vec!["10.0.0.1".to_string()];
        combo.before = Some("1970-01-01T00:05:00Z".to_string());
        let rep = inspect_audit(
            &ctx,
            &AuditInspectArgs {
                all: false,
                filter: combo,
            },
        )
        .await
        .unwrap();
        assert_eq!(rep.matched_entries, 1);
        assert_eq!(rep.by_action.get("login"), Some(&1));
        assert_eq!(rep.by_result.get(&200), Some(&1));
        assert_eq!(rep.cutoff_mode, CutoffMode::ExplicitBefore);
    }
}
