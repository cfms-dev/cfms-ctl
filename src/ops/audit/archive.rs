//! Atomic canonical JSONL / Zstd archive staging, no-clobber persistence, and verification.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use uuid::Uuid;
use crate::core::error::{CfmsError, Result};

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const AUDIT_RECORD_KEYS: [&str; 8] = [
    "action",
    "data",
    "id",
    "logged_time",
    "remote_address",
    "result",
    "target",
    "user_id",
];

/// In-memory representation of a decoded `audit_entries` row.
#[derive(Debug, Clone)]
pub struct AuditEntryRow {
    pub id: String,
    pub action: String,
    pub user_id: Option<String>,
    pub target: Option<String>,
    pub data: Option<Value>,
    pub result: i32,
    pub remote_address: Option<String>,
    pub logged_time: f64,
}

/// Statistics produced when persisting an archive file.
#[derive(Debug, Clone, Serialize)]
pub struct ArchiveWriteStats {
    pub record_count: u64,
    pub compressed: bool,
    pub archive_bytes: u64,
    pub archive_sha256: String,
    pub oldest_logged_time: Option<f64>,
    pub newest_logged_time: Option<f64>,
}

/// Verification summary computed by streaming and validating an archive file offline.
#[derive(Debug, Clone)]
pub struct ArchiveVerificationSummary {
    pub archive_path: String,
    pub compressed: bool,
    pub verified_entries: u64,
    pub archive_bytes: u64,
    pub archive_sha256: String,
    pub oldest_logged_time: Option<f64>,
    pub newest_logged_time: Option<f64>,
    pub by_action: BTreeMap<String, u64>,
    pub by_result: BTreeMap<i32, u64>,
}

/// Strict alphabetical field declaration matching sorted-key JSONL output (`OPT_SORT_KEYS` parity).
#[derive(Serialize)]
struct AuditJsonlRecord<'a> {
    action: &'a str,
    data: &'a Option<Value>,
    id: &'a str,
    logged_time: f64,
    remote_address: &'a Option<String>,
    result: i32,
    target: &'a Option<String>,
    user_id: Option<&'a str>,
}

/// Validate destination path before querying or prompting: parent exists and destination does not exist.
pub fn preflight_new_archive_path(output_path: &Path) -> Result<PathBuf> {
    if output_path.file_name().is_none() {
        return Err(CfmsError::InvalidArgument(format!(
            "Archive output path '{}' must include a filename",
            output_path.display()
        )));
    }
    let parent = match output_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let parent_meta = std::fs::metadata(&parent).map_err(|e| {
        CfmsError::InvalidArgument(format!(
            "Archive parent directory '{}' is not accessible: {e}",
            parent.display()
        ))
    })?;
    if !parent_meta.is_dir() {
        return Err(CfmsError::InvalidArgument(format!(
            "Archive parent '{}' is not a directory",
            parent.display()
        )));
    }

    match std::fs::symlink_metadata(output_path) {
        Ok(_) => Err(CfmsError::InvalidArgument(format!(
            "Refusing to overwrite existing archive file '{}'",
            output_path.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(parent),
        Err(e) => Err(CfmsError::Io(e)),
    }
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    bytes_written: u64,
}

impl<W> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_written: 0,
        }
    }

    fn finish(self) -> (W, u64, String) {
        let digest = hex::encode(self.hasher.finalize());
        (self.inner, self.bytes_written, digest)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes_written = self.bytes_written.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

enum StageSink {
    Plain(BufWriter<HashingWriter<NamedTempFile>>),
    Zstd(BufWriter<zstd::stream::write::Encoder<'static, HashingWriter<NamedTempFile>>>),
}

impl StageSink {
    fn as_write_mut(&mut self) -> &mut dyn Write {
        match self {
            Self::Plain(w) => w,
            Self::Zstd(w) => w,
        }
    }

    fn finish_and_sync(self) -> Result<(NamedTempFile, u64, String)> {
        let hashing = match self {
            Self::Plain(mut buf) => {
                buf.flush()?;
                buf.into_inner().map_err(|e| e.into_error())?
            }
            Self::Zstd(mut buf) => {
                buf.flush()?;
                let encoder = buf.into_inner().map_err(|e| e.into_error())?;
                encoder.finish()?
            }
        };
        let (mut temp_file, bytes_written, sha256) = hashing.finish();
        temp_file.flush()?;
        temp_file.as_file().sync_all()?;
        Ok((temp_file, bytes_written, sha256))
    }
}

/// Stages an archive inside a sibling [`NamedTempFile`] and persists it with no-clobber semantics.
pub struct StagedArchiveWriter {
    target_path: PathBuf,
    sink: StageSink,
    compressed: bool,
    record_count: u64,
    oldest_logged_time: Option<f64>,
    newest_logged_time: Option<f64>,
}

impl StagedArchiveWriter {
    /// Create a temporary staging file in the target's parent directory after preflight checks.
    pub fn new(output_path: &Path, compress: bool) -> Result<Self> {
        let parent_dir = preflight_new_archive_path(output_path)?;
        let temp_file = tempfile::Builder::new()
            .prefix(".cfms-audit-")
            .suffix(".tmp")
            .tempfile_in(&parent_dir)?;
        let hashing = HashingWriter::new(temp_file);
        let sink = if compress {
            let encoder = zstd::stream::write::Encoder::new(hashing, 3).map_err(|e| {
                CfmsError::ArchiveIntegrity(format!("Failed to initialize Zstd encoder: {e}"))
            })?;
            StageSink::Zstd(BufWriter::with_capacity(128 * 1024, encoder))
        } else {
            StageSink::Plain(BufWriter::with_capacity(128 * 1024, hashing))
        };

        Ok(Self {
            target_path: output_path.to_path_buf(),
            sink,
            compressed: compress,
            record_count: 0,
            oldest_logged_time: None,
            newest_logged_time: None,
        })
    }

    /// Return how many entries have been written so far.
    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Encode one `audit_entries` row as compact canonical JSON followed by `\n`.
    pub fn write_entry(&mut self, entry: &AuditEntryRow) -> Result<()> {
        if !entry.logged_time.is_finite() {
            return Err(CfmsError::Database(format!(
                "Audit entry '{}' has non-finite logged_time ({})",
                entry.id, entry.logged_time
            )));
        }

        let record = AuditJsonlRecord {
            action: &entry.action,
            data: &entry.data,
            id: &entry.id,
            logged_time: entry.logged_time,
            remote_address: &entry.remote_address,
            result: entry.result,
            target: &entry.target,
            user_id: entry.user_id.as_deref(),
        };

        let w = self.sink.as_write_mut();
        serde_json::to_writer(&mut *w, &record).map_err(|e| {
            CfmsError::ArchiveIntegrity(format!(
                "Failed to serialize audit entry '{}': {e}",
                entry.id
            ))
        })?;
        w.write_all(b"\n")?;

        self.record_count = self.record_count.saturating_add(1);
        self.oldest_logged_time = Some(match self.oldest_logged_time {
            Some(prev) if prev <= entry.logged_time => prev,
            _ => entry.logged_time,
        });
        self.newest_logged_time = Some(match self.newest_logged_time {
            Some(prev) if prev >= entry.logged_time => prev,
            _ => entry.logged_time,
        });
        Ok(())
    }

    /// Finish writing and verify `expected_count` (if supplied) BEFORE atomically publishing the file.
    pub fn finish_and_persist(
        self,
        expected_count: Option<u64>,
    ) -> Result<ArchiveWriteStats> {
        let target_path = self.target_path;
        let compressed = self.compressed;
        let record_count = self.record_count;
        let oldest_logged_time = self.oldest_logged_time;
        let newest_logged_time = self.newest_logged_time;

        let (temp_file, archive_bytes, archive_sha256) = self.sink.finish_and_sync()?;

        if let Some(expected) = expected_count
            && record_count != expected
        {
            drop(temp_file);
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Refusing to publish archive '{}': expected {expected} audit entries, staged {record_count}",
                target_path.display()
            )));
        }

        temp_file.persist_noclobber(&target_path).map_err(|err| {
            if err.error.kind() == io::ErrorKind::AlreadyExists {
                CfmsError::InvalidArgument(format!(
                    "Refusing to overwrite existing archive file '{}'",
                    target_path.display()
                ))
            } else {
                CfmsError::Io(err.error)
            }
        })?;

        Ok(ArchiveWriteStats {
            record_count,
            compressed,
            archive_bytes,
            archive_sha256,
            oldest_logged_time,
            newest_logged_time,
        })
    }
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes_read: u64,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_read: 0,
        }
    }

    fn finish_digest(mut self) -> Result<(u64, String)> {
        io::copy(&mut self, &mut io::sink())?;
        Ok((self.bytes_read, hex::encode(self.hasher.finalize())))
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes_read = self.bytes_read.saturating_add(n as u64);
        Ok(n)
    }
}

type HeaderChainedFile = io::Chain<Cursor<[u8; 4]>, HashingReader<File>>;
type ZstdArchiveBufReader =
    BufReader<zstd::stream::read::Decoder<'static, BufReader<HeaderChainedFile>>>;

enum ArchiveReaderKind {
    Plain(BufReader<HeaderChainedFile>),
    ShortPlain {
        cursor: BufReader<Cursor<Vec<u8>>>,
        tail_hasher: HashingReader<File>,
    },
    Zstd(ZstdArchiveBufReader),
    Empty(HashingReader<File>),
}

impl ArchiveReaderKind {
    fn open(path: &Path) -> Result<(Self, bool)> {
        let meta = std::fs::metadata(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                CfmsError::InvalidArgument(format!("Archive file '{}' not found", path.display()))
            } else {
                CfmsError::Io(e)
            }
        })?;
        if !meta.is_file() {
            return Err(CfmsError::InvalidArgument(format!(
                "Archive path '{}' is not a regular file",
                path.display()
            )));
        }

        let file = File::open(path)?;
        let mut hashing = HashingReader::new(file);
        let mut header = [0u8; 4];
        let mut read_len = 0usize;
        while read_len < 4 {
            let n = hashing.read(&mut header[read_len..])?;
            if n == 0 {
                break;
            }
            read_len += n;
        }

        if read_len == 0 {
            return Ok((Self::Empty(hashing), false));
        }

        if read_len == 4 && header == ZSTD_MAGIC {
            let chained = Cursor::new(header).chain(hashing);
            let decoder = zstd::stream::read::Decoder::new(chained).map_err(|e| {
                CfmsError::ArchiveIntegrity(format!(
                    "Failed to initialize Zstd decoder for '{}': {e}",
                    path.display()
                ))
            })?;
            return Ok((Self::Zstd(BufReader::with_capacity(128 * 1024, decoder)), true));
        }

        if read_len < 4 {
            return Ok((
                Self::ShortPlain {
                    cursor: BufReader::new(Cursor::new(header[..read_len].to_vec())),
                    tail_hasher: hashing,
                },
                false,
            ));
        }

        let chained = Cursor::new(header).chain(hashing);
        Ok((Self::Plain(BufReader::with_capacity(128 * 1024, chained)), false))
    }

    fn read_line_raw(&mut self, buf: &mut String) -> io::Result<usize> {
        match self {
            Self::Plain(r) => r.read_line(buf),
            Self::ShortPlain { cursor, .. } => cursor.read_line(buf),
            Self::Zstd(r) => r.read_line(buf),
            Self::Empty(_) => Ok(0),
        }
    }

    fn finish_digest(self) -> Result<(u64, String)> {
        match self {
            Self::Plain(r) => {
                let (_prefix, tail) = r.into_inner().into_inner();
                tail.finish_digest()
            }
            Self::ShortPlain { tail_hasher, .. } => tail_hasher.finish_digest(),
            Self::Zstd(r) => {
                let decoder = r.into_inner();
                let buf_chained = decoder.finish();
                let (_prefix, tail) = buf_chained.into_inner().into_inner();
                tail.finish_digest()
            }
            Self::Empty(h) => h.finish_digest(),
        }
    }
}

struct ParsedLineMeta {
    id: String,
    action: String,
    result: i32,
    logged_time: f64,
}

#[derive(Default)]
struct MonotonicOrderChecker {
    prev_ts: Option<f64>,
    same_ts_ids: HashSet<String>,
}

impl MonotonicOrderChecker {
    fn observe(&mut self, path: &Path, line_no: u64, logged_time: f64, id: &str) -> Result<()> {
        let norm_ts = if logged_time == 0.0 { 0.0 } else { logged_time };
        match self.prev_ts {
            None => {
                self.prev_ts = Some(norm_ts);
                self.same_ts_ids.insert(id.to_string());
            }
            Some(prev) if norm_ts < prev => {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Archive '{}' line {line_no} is out of chronological order ({norm_ts} < {prev})",
                    path.display()
                )));
            }
            Some(prev) if norm_ts > prev => {
                self.prev_ts = Some(norm_ts);
                self.same_ts_ids.clear();
                self.same_ts_ids.insert(id.to_string());
            }
            Some(_) => {
                if !self.same_ts_ids.insert(id.to_string()) {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Archive '{}' line {line_no} contains duplicate audit entry id '{id}'",
                        path.display()
                    )));
                }
            }
        }
        Ok(())
    }
}

fn parse_and_validate_archive_line(path: &Path, line_no: u64, raw_line: &str) -> Result<ParsedLineMeta> {
    let trimmed = raw_line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Archive '{}' contains an unexpected blank line at line {line_no}",
            path.display()
        )));
    }

    let val: Value = serde_json::from_str(trimmed).map_err(|e| {
        CfmsError::ArchiveIntegrity(format!(
            "Archive '{}' line {line_no} is not valid JSON: {e}",
            path.display()
        ))
    })?;
    let obj = val.as_object().ok_or_else(|| {
        CfmsError::ArchiveIntegrity(format!(
            "Archive '{}' line {line_no} must be a JSON object",
            path.display()
        ))
    })?;

    if obj.len() != AUDIT_RECORD_KEYS.len()
        || !AUDIT_RECORD_KEYS.iter().all(|k| obj.contains_key(*k))
    {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Archive '{}' line {line_no} does not match the 8-field canonical audit record schema",
            path.display()
        )));
    }

    let id = match obj.get("id") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Archive '{}' line {line_no} has invalid or empty `id`",
                path.display()
            )));
        }
    };

    let action = match obj.get("action") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Archive '{}' line {line_no} has invalid or empty `action`",
                path.display()
            )));
        }
    };

    match obj.get("user_id") {
        Some(Value::Null) => {}
        Some(Value::String(s)) if Uuid::parse_str(s).is_ok() => {}
        _ => {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Archive '{}' line {line_no} has invalid `user_id` UUID",
                path.display()
            )));
        }
    }

    match obj.get("target") {
        Some(Value::Null | Value::String(_)) => {}
        _ => {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Archive '{}' line {line_no} has invalid `target` (expected string or null)",
                path.display()
            )));
        }
    }

    match obj.get("remote_address") {
        Some(Value::Null | Value::String(_)) => {}
        _ => {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Archive '{}' line {line_no} has invalid `remote_address` (expected string or null)",
                path.display()
            )));
        }
    }

    let result = obj
        .get("result")
        .and_then(Value::as_i64)
        .and_then(|v| i32::try_from(v).ok())
        .ok_or_else(|| {
            CfmsError::ArchiveIntegrity(format!(
                "Archive '{}' line {line_no} has invalid `result` (expected 32-bit integer)",
                path.display()
            ))
        })?;

    let logged_time = obj
        .get("logged_time")
        .and_then(Value::as_f64)
        .filter(|v| v.is_finite())
        .ok_or_else(|| {
            CfmsError::ArchiveIntegrity(format!(
                "Archive '{}' line {line_no} has invalid `logged_time`",
                path.display()
            ))
        })?;

    Ok(ParsedLineMeta {
        id,
        action,
        result,
        logged_time,
    })
}

/// Stream, validate, and summarize an exported `.jsonl` or `.jsonl.zst` archive offline.
pub fn verify_archive_file(path: &Path) -> Result<ArchiveVerificationSummary> {
    let (mut reader, compressed) = ArchiveReaderKind::open(path)?;
    let mut order = MonotonicOrderChecker::default();
    let mut by_action: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_result: BTreeMap<i32, u64> = BTreeMap::new();
    let mut oldest_logged_time: Option<f64> = None;
    let mut newest_logged_time: Option<f64> = None;
    let mut verified_entries: u64 = 0;

    let mut line = String::new();
    let mut line_no: u64 = 0;
    loop {
        line.clear();
        let n = reader.read_line_raw(&mut line).map_err(|e| {
            CfmsError::ArchiveIntegrity(format!(
                "Failed to read archive '{}' at line {}: {e}",
                path.display(),
                line_no + 1
            ))
        })?;
        if n == 0 {
            break;
        }
        line_no = line_no.saturating_add(1);
        let parsed = parse_and_validate_archive_line(path, line_no, &line)?;
        order.observe(path, line_no, parsed.logged_time, &parsed.id)?;

        *by_action.entry(parsed.action).or_insert(0) += 1;
        *by_result.entry(parsed.result).or_insert(0) += 1;
        oldest_logged_time = Some(match oldest_logged_time {
            Some(prev) if prev <= parsed.logged_time => prev,
            _ => parsed.logged_time,
        });
        newest_logged_time = Some(match newest_logged_time {
            Some(prev) if prev >= parsed.logged_time => prev,
            _ => parsed.logged_time,
        });
        verified_entries = verified_entries.saturating_add(1);
    }

    let (archive_bytes, archive_sha256) = reader.finish_digest()?;
    Ok(ArchiveVerificationSummary {
        archive_path: path.display().to_string(),
        compressed,
        verified_entries,
        archive_bytes,
        archive_sha256,
        oldest_logged_time,
        newest_logged_time,
        by_action,
        by_result,
    })
}

/// Bounded-memory streaming batch reader returning verified audit `id` chunks from an archive file.
pub struct ArchiveIdBatchReader {
    path: PathBuf,
    reader: ArchiveReaderKind,
    line_no: u64,
    line_buf: String,
    order: MonotonicOrderChecker,
    exhausted: bool,
}

impl ArchiveIdBatchReader {
    /// Open a persisted archive file for streaming `id` batch extraction.
    pub fn open(path: &Path) -> Result<Self> {
        let (reader, _) = ArchiveReaderKind::open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            reader,
            line_no: 0,
            line_buf: String::new(),
            order: MonotonicOrderChecker::default(),
            exhausted: false,
        })
    }

    /// Read at most `batch_size` verified audit IDs, returning `None` cleanly on EOF.
    pub fn next_batch(&mut self, batch_size: usize) -> Result<Option<Vec<String>>> {
        if self.exhausted || batch_size == 0 {
            return Ok(None);
        }
        let mut ids = Vec::with_capacity(batch_size.min(4096));
        while ids.len() < batch_size {
            self.line_buf.clear();
            let n = self.reader.read_line_raw(&mut self.line_buf).map_err(|e| {
                CfmsError::ArchiveIntegrity(format!(
                    "Failed to read archive '{}' at line {}: {e}",
                    self.path.display(),
                    self.line_no + 1
                ))
            })?;
            if n == 0 {
                self.exhausted = true;
                break;
            }
            self.line_no = self.line_no.saturating_add(1);
            let parsed =
                parse_and_validate_archive_line(&self.path, self.line_no, &self.line_buf)?;
            self.order
                .observe(&self.path, self.line_no, parsed.logged_time, &parsed.id)?;
            ids.push(parsed.id);
        }
        if ids.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ids))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn sample_row(id: &str, ts: f64) -> AuditEntryRow {
        AuditEntryRow {
            id: id.to_string(),
            action: "core.auth.login".to_string(),
            user_id: Some("12345678-1234-4234-9234-123456789abc".to_string()),
            target: Some("alice".to_string()),
            data: Some(json!({
                "z_key": 1,
                "a_key": 9007199254740993_i64,
            })),
            result: 200,
            remote_address: Some("127.0.0.1".to_string()),
            logged_time: ts,
        }
    }

    #[test]
    fn staged_archive_writes_canonical_sorted_keys_and_refuses_clobber() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("audit.jsonl");

        let mut writer = StagedArchiveWriter::new(&target, false).unwrap();
        writer.write_entry(&sample_row("e1", 100.0)).unwrap();
        writer.write_entry(&sample_row("e2", 200.25)).unwrap();
        let stats = writer.finish_and_persist(Some(2)).unwrap();
        assert_eq!(stats.record_count, 2);
        assert!(!stats.compressed);
        assert_eq!(stats.oldest_logged_time, Some(100.0));
        assert_eq!(stats.newest_logged_time, Some(200.25));

        let contents = std::fs::read_to_string(&target).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            r#"{"action":"core.auth.login","data":{"a_key":9007199254740993,"z_key":1},"id":"e1","logged_time":100.0,"remote_address":"127.0.0.1","result":200,"target":"alice","user_id":"12345678-1234-4234-9234-123456789abc"}"#
        );

        let verify = verify_archive_file(&target).unwrap();
        assert_eq!(verify.verified_entries, 2);
        assert_eq!(verify.archive_sha256, stats.archive_sha256);
        assert_eq!(verify.archive_bytes, stats.archive_bytes);

        let err = StagedArchiveWriter::new(&target, false)
            .err()
            .expect("existing target must be rejected");
        assert!(matches!(err, CfmsError::InvalidArgument(_)));
    }

    #[test]
    fn compressed_archive_round_trips_verification_and_id_batches() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("audit.jsonl.zst");

        let mut writer = StagedArchiveWriter::new(&target, true).unwrap();
        writer.write_entry(&sample_row("a1", 10.0)).unwrap();
        writer.write_entry(&sample_row("a2", 10.0)).unwrap();
        writer.write_entry(&sample_row("a3", 20.0)).unwrap();
        let stats = writer.finish_and_persist(Some(3)).unwrap();
        assert!(stats.compressed);

        let verify = verify_archive_file(&target).unwrap();
        assert!(verify.compressed);
        assert_eq!(verify.verified_entries, 3);
        assert_eq!(verify.archive_sha256, stats.archive_sha256);

        let mut reader = ArchiveIdBatchReader::open(&target).unwrap();
        assert_eq!(
            reader.next_batch(2).unwrap(),
            Some(vec!["a1".to_string(), "a2".to_string()])
        );
        assert_eq!(reader.next_batch(2).unwrap(), Some(vec!["a3".to_string()]));
        assert_eq!(reader.next_batch(2).unwrap(), None);
    }

    #[test]
    fn count_mismatch_aborts_without_publishing_destination() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("should-not-exist.jsonl");
        let mut writer = StagedArchiveWriter::new(&target, false).unwrap();
        writer.write_entry(&sample_row("e1", 10.0)).unwrap();
        let err = writer.finish_and_persist(Some(2)).unwrap_err();
        assert!(matches!(err, CfmsError::ArchiveIntegrity(_)));
        assert!(!target.exists());
    }

    #[test]
    fn verify_detects_corruption_and_out_of_order_entries() {
        let dir = TempDir::new().unwrap();
        let bad_order = dir.path().join("bad-order.jsonl");
        std::fs::write(
            &bad_order,
            concat!(
                r#"{"action":"a","data":null,"id":"e2","logged_time":200.0,"remote_address":null,"result":0,"target":null,"user_id":null}"#,
                "\n",
                r#"{"action":"a","data":null,"id":"e1","logged_time":100.0,"remote_address":null,"result":0,"target":null,"user_id":null}"#,
                "\n",
            ),
        )
        .unwrap();
        assert!(matches!(
            verify_archive_file(&bad_order).unwrap_err(),
            CfmsError::ArchiveIntegrity(_)
        ));

        let bad_schema = dir.path().join("bad-schema.jsonl");
        std::fs::write(&bad_schema, r#"{"action":"a","id":"e1"}"#.to_string() + "\n").unwrap();
        assert!(matches!(
            verify_archive_file(&bad_schema).unwrap_err(),
            CfmsError::ArchiveIntegrity(_)
        ));
    }
}
