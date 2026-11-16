//! Encrypted backup outer envelope framing, Base31/Base64url key management,
//! and HKDF-SHA256 + chunked `AES-256-GCM` streaming reader/writer.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::Path;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{AeadInOut, KeyInit, Tag, inout::InOutBuf},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::DateTime;
use hkdf::Hkdf;
use rand::Rng;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};
use crate::core::error::{CfmsError, Result};
use crate::ui::{CommandReport, KeyValueTable, UiConsole};
use super::selection::parse_and_validate_manifest_components;

/// Magic prefix identifying `cfms-ctl` v2 encrypted streaming backup containers.
pub const BACKUP_MAGIC: &[u8; 8] = b"CFMSCBK2";
/// Self-describing CRLSet-style content type marker inside the JSON envelope header.
pub const BACKUP_CONTENT_TYPE: &str = "cfms-backup";
pub const BACKUP_FORMAT_VERSION: u32 = 2;
pub const BACKUP_CIPHER: &str = "aes-256-gcm-hkdf-sha256-chunked-v2";
pub const BACKUP_COMPRESSION: &str = "zstd";
pub const BACKUP_CONTAINER: &str = "cfms-stream-v2";
pub const BACKUP_KDF: &str = "hkdf-sha256";
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
pub const MIN_CHUNK_SIZE: usize = 64;
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_HEADER_BYTES: usize = 1024 * 1024;
pub const MAX_KEY_FILE_BYTES: usize = 4096;

const AES_GCM_TAG_LEN: usize = 16;
const HKDF_INFO_PREFIX: &[u8] = b"cfms-ctl-backup-v2:";
const BASE31_ALPHABET: &[u8; 31] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const ENCODED_BASE31_CHARS: usize = 52;
const SUPPORTED_STORAGE_PROVIDERS: &[&str] = &["local", "s3"];

#[must_use]
pub(crate) fn is_supported_storage_provider(provider: &str) -> bool {
    SUPPORTED_STORAGE_PROVIDERS.contains(&provider)
}

const MANDATORY_ENVELOPE_FIELDS: &[&str] = &[
    "content_type",
    "version",
    "cipher",
    "compression",
    "container",
    "kdf",
    "chunk_size",
    "kdf_salt",
    "nonce_prefix",
    "components",
    "schema_revision",
];

const KNOWN_ENVELOPE_FIELDS: &[&str] = &[
    "content_type",
    "version",
    "cipher",
    "compression",
    "container",
    "kdf",
    "chunk_size",
    "kdf_salt",
    "nonce_prefix",
    "components",
    "schema_revision",
    "storage_provider",
    "created_at",
    "server_version",
];

/// Validate a RFC 7515/9052-style `"critical"` header field list against present and known keys.
pub(super) fn validate_critical_key_list(
    critical: Option<&[String]>,
    present_keys: &BTreeSet<String>,
    mandatory_fields: &[&str],
    known_fields: &[&str],
    header_label: &str,
) -> std::result::Result<BTreeSet<String>, String> {
    let Some(critical) = critical else {
        return Err(format!(
            "Missing required 'critical' field list in {header_label}"
        ));
    };

    let mut crit_set = BTreeSet::new();
    for key in critical {
        if key.trim().is_empty() || key != key.trim() {
            return Err(format!(
                "{header_label} 'critical' list contains an empty or padded field name '{key}'"
            ));
        }
        if key == "critical" {
            return Err(format!(
                "{header_label} 'critical' list must not self-reference 'critical'"
            ));
        }
        if !crit_set.insert(key.clone()) {
            return Err(format!(
                "{header_label} 'critical' list contains duplicate field '{key}'"
            ));
        }
    }

    let missing_declared: Vec<&str> = crit_set
        .iter()
        .map(String::as_str)
        .filter(|k| !present_keys.contains(*k))
        .collect();
    if !missing_declared.is_empty() {
        return Err(format!(
            "CRITICAL field(s) declared in {header_label} are missing from header: {}",
            missing_declared.join(", ")
        ));
    }

    let unsupported_critical: Vec<&str> = crit_set
        .iter()
        .map(String::as_str)
        .filter(|k| !known_fields.contains(k))
        .collect();
    if !unsupported_critical.is_empty() {
        return Err(format!(
            "Unsupported CRITICAL {header_label} field(s): {}",
            unsupported_critical.join(", ")
        ));
    }

    let missing_mandatory: Vec<&str> = mandatory_fields
        .iter()
        .copied()
        .filter(|k| !present_keys.contains(*k))
        .collect();
    if !missing_mandatory.is_empty() {
        return Err(format!(
            "Missing required baseline {header_label} field(s): {}",
            missing_mandatory.join(", ")
        ));
    }

    Ok(crit_set)
}

/// Unencrypted outer header stored at the start of a `.confbak` archive and rendered by `backup info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupHeaderReport {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default)]
    pub file_size: u64,
    pub content_type: String,
    pub version: u32,
    #[serde(default)]
    pub critical: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_version: String,
    pub schema_revision: String,
    pub components: Vec<String>,
    pub cipher: String,
    pub compression: String,
    pub container: String,
    pub kdf: String,
    pub chunk_size: usize,
    pub kdf_salt: String,
    pub nonce_prefix: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub storage_provider: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub non_critical_fields: BTreeMap<String, serde_json::Value>,
}

impl CommandReport for BackupHeaderReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("CFMS Backup Archive Info");
        let components = if self.components.is_empty() {
            "(unspecified)".to_string()
        } else {
            self.components.join(", ")
        };
        let critical = if self.critical.is_empty() {
            "(none)".to_string()
        } else {
            self.critical.join(", ")
        };
        table
            .row("Archive Path", self.path.clone())
            .row("File Size (bytes)", self.file_size.to_string())
            .row("Content Type", self.content_type.clone())
            .row("Format Version", self.version.to_string())
            .row("Critical Fields", critical)
            .row(
                "Created At",
                if self.created_at.is_empty() {
                    "(unspecified)".to_string()
                } else {
                    self.created_at.clone()
                },
            )
            .row(
                "Server Version",
                if self.server_version.is_empty() {
                    "(unspecified)".to_string()
                } else {
                    self.server_version.clone()
                },
            )
            .row("Schema Revision", self.schema_revision.clone())
            .row("Components", components)
            .row("Cipher", self.cipher.clone())
            .row("Compression", self.compression.clone())
            .row("Container", self.container.clone())
            .row("KDF", self.kdf.clone())
            .row("Chunk Size (bytes)", self.chunk_size.to_string())
            .row(
                "Storage Provider",
                if self.storage_provider.is_empty() {
                    "(unspecified)".to_string()
                } else {
                    self.storage_provider.clone()
                },
            );
        if !self.non_critical_fields.is_empty() {
            let ignored_keys: Vec<&str> = self
                .non_critical_fields
                .keys()
                .map(String::as_str)
                .collect();
            table.row("Ignored Non-Critical Fields", ignored_keys.join(", "));
        }
        table.print();
    }
}

/// Canonical JSON envelope written immediately after `BACKUP_MAGIC` + `u32 LE header_len`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeHeaderSpec {
    pub content_type: String,
    pub version: u32,
    pub critical: Vec<String>,
    pub created_at: String,
    pub server_version: String,
    pub schema_revision: String,
    pub components: Vec<String>,
    pub cipher: String,
    pub compression: String,
    pub container: String,
    pub kdf: String,
    pub chunk_size: usize,
    pub kdf_salt: String,
    pub nonce_prefix: String,
    pub storage_provider: String,
}

impl EnvelopeHeaderSpec {
    /// Construct a fresh envelope header specification with CSPRNG salt, nonce prefix,
    /// and canonical CRLSet/JWS-style `critical` declaration.
    pub fn new(
        created_at: String,
        server_version: String,
        schema_revision: String,
        components: Vec<String>,
        storage_provider: String,
        chunk_size: usize,
    ) -> Self {
        let mut salt = [0u8; 16];
        let mut nonce_prefix = [0u8; 7];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce_prefix);
        let mut critical: Vec<String> = MANDATORY_ENVELOPE_FIELDS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        critical.push("storage_provider".to_string());
        Self {
            content_type: BACKUP_CONTENT_TYPE.to_string(),
            version: BACKUP_FORMAT_VERSION,
            critical,
            created_at,
            server_version,
            schema_revision,
            components,
            cipher: BACKUP_CIPHER.to_string(),
            compression: BACKUP_COMPRESSION.to_string(),
            container: BACKUP_CONTAINER.to_string(),
            kdf: BACKUP_KDF.to_string(),
            chunk_size,
            kdf_salt: general_purpose::URL_SAFE_NO_PAD.encode(salt),
            nonce_prefix: general_purpose::URL_SAFE_NO_PAD.encode(nonce_prefix),
            storage_provider,
        }
    }
}

/// Generate a cryptographically random 256-bit backup master key.
#[must_use]
pub fn generate_backup_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *key);
    key
}

/// Encode a 32-byte key as 13 groups of 4 unambiguous Base31 characters separated by `-`.
#[must_use]
pub fn encode_backup_key_base31(key: &[u8; 32]) -> Zeroizing<String> {
    let mut num = Zeroizing::new(*key);
    let mut digits = [0u8; ENCODED_BASE31_CHARS];
    for digit in &mut digits {
        let mut rem: u16 = 0;
        for byte in &mut *num {
            let acc = (rem << 8) | u16::from(*byte);
            *byte = (acc / 31) as u8;
            rem = acc % 31;
        }
        *digit = BASE31_ALPHABET[usize::from(rem)];
    }

    let mut out = Zeroizing::new(String::with_capacity(ENCODED_BASE31_CHARS + 12));
    for (idx, ch) in digits.iter().rev().enumerate() {
        if idx > 0 && idx % 4 == 0 {
            out.push('-');
        }
        out.push(*ch as char);
    }
    digits.zeroize();
    out
}

/// Encode a 32-byte key as unpadded URL-safe Base64.
#[must_use]
pub fn encode_backup_key_base64url(key: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(general_purpose::URL_SAFE_NO_PAD.encode(key))
}

/// Decode a grouped/ungrouped Base31 key or 32-byte URL-safe Base64 key.
pub fn decode_backup_key(raw: &str) -> Result<Zeroizing<[u8; 32]>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CfmsError::InvalidArgument(
            "Backup decryption key must not be empty".to_string(),
        ));
    }

    let mut base31_stripped = Zeroizing::new(String::with_capacity(trimmed.len()));
    for ch in trimmed.chars() {
        if ch.is_ascii_whitespace() || ch == '-' {
            continue;
        }
        base31_stripped.push(ch.to_ascii_uppercase());
    }

    if base31_stripped.len() == ENCODED_BASE31_CHARS
        && base31_stripped
            .bytes()
            .all(|b| BASE31_ALPHABET.contains(&b))
    {
        return decode_base31_str(&base31_stripped);
    }

    if trimmed.bytes().all(|b| !b.is_ascii_whitespace()) {
        let engine = if trimmed.contains('=') {
            &general_purpose::URL_SAFE
        } else {
            &general_purpose::URL_SAFE_NO_PAD
        };
        if let Ok(decoded) = engine.decode(trimmed) {
            let mut decoded = Zeroizing::new(decoded);
            if decoded.len() == 32 {
                let mut key = Zeroizing::new([0u8; 32]);
                key.copy_from_slice(&decoded);
                decoded.zeroize();
                return Ok(key);
            }
        }
    }

    Err(CfmsError::InvalidArgument(
        "Invalid backup decryption key format (expected 52-char Base31 key or 32-byte base64url key)"
            .to_string(),
    ))
}

fn decode_base31_str(digits: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut num = Zeroizing::new([0u8; 32]);
    for b in digits.bytes() {
        let digit_val = BASE31_ALPHABET
            .iter()
            .position(|&candidate| candidate == b)
            .ok_or_else(|| CfmsError::InvalidArgument("Invalid Base31 character".to_string()))?
            as u16;
        let mut carry = digit_val;
        for byte in num.iter_mut().rev() {
            let acc = u16::from(*byte) * 31 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        if carry != 0 {
            return Err(CfmsError::InvalidArgument(
                "Backup decryption key exceeds 256-bit key range".to_string(),
            ));
        }
    }
    Ok(num)
}

/// Resolve a decryption key from either `--key` or `--key-file` CLI options.
pub fn read_key_from_args(key: Option<&str>, key_file: Option<&Path>) -> Result<Zeroizing<[u8; 32]>> {
    match (key, key_file) {
        (Some(raw), None) => decode_backup_key(raw),
        (None, Some(path)) => read_key_file(path),
        _ => Err(CfmsError::InvalidArgument(
            "Provide either `--key` or `--key-file`".to_string(),
        )),
    }
}

/// Read and decode a backup decryption key from disk with strict file-size bounds.
pub fn read_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let file = File::open(path).map_err(|e| {
        CfmsError::InvalidArgument(format!("Unable to open key file '{}': {e}", path.display()))
    })?;
    let meta = file.metadata()?;
    if meta.len() > MAX_KEY_FILE_BYTES as u64 {
        return Err(CfmsError::InvalidArgument(format!(
            "Key file '{}' exceeds maximum allowed size ({MAX_KEY_FILE_BYTES} bytes)",
            path.display()
        )));
    }
    let mut raw = Zeroizing::new(String::new());
    let mut limited = file.take((MAX_KEY_FILE_BYTES + 1) as u64);
    limited.read_to_string(&mut raw).map_err(|e| {
        CfmsError::InvalidArgument(format!("Unable to read UTF-8 key file '{}': {e}", path.display()))
    })?;
    if raw.len() > MAX_KEY_FILE_BYTES {
        return Err(CfmsError::InvalidArgument(format!(
            "Key file '{}' exceeds maximum allowed size ({MAX_KEY_FILE_BYTES} bytes)",
            path.display()
        )));
    }
    decode_backup_key(&raw)
}

/// Create a new key file exclusively (never overwriting existing files) with restrictive permissions.
pub fn write_key_file_exclusive(path: &Path, encoded_key: &str) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| {
        CfmsError::Backup(format!(
            "Unable to create key output file '{}': {e}",
            path.display()
        ))
    })?;
    writeln!(file, "{encoded_key}")?;
    file.flush()?;
    file.sync_data()?;
    Ok(())
}

/// Write the unencrypted envelope header and return `SHA256(magic || len_le || json_bytes)`.
pub fn write_envelope_header(
    writer: &mut impl Write,
    header: &EnvelopeHeaderSpec,
) -> Result<[u8; 32]> {
    let json_bytes = serde_json::to_vec(header)
        .map_err(|e| CfmsError::Backup(format!("Failed to serialize backup header: {e}")))?;
    if json_bytes.is_empty() || json_bytes.len() > MAX_HEADER_BYTES {
        return Err(CfmsError::Backup(format!(
            "Backup header size ({} bytes) outside valid bounds (1..={MAX_HEADER_BYTES})",
            json_bytes.len()
        )));
    }
    let len_le = u32::try_from(json_bytes.len())
        .map_err(|_| CfmsError::Backup("Backup header exceeds u32 length".to_string()))?
        .to_le_bytes();

    writer.write_all(BACKUP_MAGIC)?;
    writer.write_all(&len_le)?;
    writer.write_all(&json_bytes)?;

    Ok(compute_envelope_digest(&len_le, &json_bytes))
}

/// Read only the unencrypted outer header from a backup file for `cfms-ctl backup info`.
pub fn read_backup_header(path: &Path) -> Result<BackupHeaderReport> {
    let file = File::open(path)
        .map_err(|e| CfmsError::Backup(format!("Unable to open backup '{}': {e}", path.display())))?;
    let file_size = file.metadata()?.len();
    let mut reader = BufReader::new(file);
    let path_display = path.display().to_string();
    let (report, _) = read_envelope_and_hash(&mut reader, &path_display, file_size)?;
    Ok(report)
}

/// Read the unencrypted outer header from an already-opened reader, returning both the validated
/// report and `SHA256(magic || len_le || json_bytes)` used to bind chunk AEAD keys and AAD.
pub fn read_envelope_and_hash(
    reader: &mut impl Read,
    path_display: &str,
    file_size: u64,
) -> Result<(BackupHeaderReport, [u8; 32])> {
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            CfmsError::Backup(format!("File '{path_display}' is too short to be a CFMS backup"))
        } else {
            CfmsError::Backup(format!(
                "Unable to read backup header from '{path_display}': {e}"
            ))
        }
    })?;
    if &magic != BACKUP_MAGIC {
        return Err(CfmsError::Backup(format!(
            "File '{path_display}' does not have the expected CFMS backup magic header"
        )));
    }

    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).map_err(|e| {
        CfmsError::Backup(format!(
            "Truncated backup header length in '{path_display}': {e}"
        ))
    })?;
    let header_len = u32::from_le_bytes(len_buf) as usize;
    if header_len == 0 || header_len > MAX_HEADER_BYTES {
        return Err(CfmsError::Backup(format!(
            "Invalid backup header length ({header_len} bytes) in '{path_display}'"
        )));
    }

    let mut header_buf = vec![0u8; header_len];
    reader.read_exact(&mut header_buf).map_err(|e| {
        CfmsError::Backup(format!("Truncated backup header in '{path_display}': {e}"))
    })?;

    let report = parse_and_validate_envelope_header(&header_buf, path_display, file_size)?;
    let digest = compute_envelope_digest(&len_buf, &header_buf);
    Ok((report, digest))
}

struct StrictJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct StrictJsonVisitor;

        impl<'de> Visitor<'de> for StrictJsonVisitor {
            type Value = StrictJsonValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("any valid JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Bool(v)))
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Number(v.into())))
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Number(v.into())))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StrictJsonValue(serde_json::Value::Number(n)))
                    .ok_or_else(|| de::Error::custom("Non-finite JSON number"))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::String(v.to_owned())))
            }

            fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::String(v)))
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Null))
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Null))
            }

            fn visit_some<D2: Deserializer<'de>>(
                self,
                deserializer: D2,
            ) -> std::result::Result<Self::Value, D2::Error> {
                StrictJsonValue::deserialize(deserializer)
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut vec = Vec::new();
                while let Some(elem) = seq.next_element::<StrictJsonValue>()? {
                    vec.push(elem.0);
                }
                Ok(StrictJsonValue(serde_json::Value::Array(vec)))
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let Some(first_key) = map.next_key::<String>()? else {
                    return Ok(StrictJsonValue(serde_json::Value::Object(
                        serde_json::Map::new(),
                    )));
                };
                if first_key == "$serde_json::private::Number" {
                    let raw = map.next_value::<String>()?;
                    if map.next_key::<String>()?.is_some() {
                        return Err(de::Error::custom(
                            "Unexpected extra field inside arbitrary-precision JSON number",
                        ));
                    }
                    let num: serde_json::Number = raw.parse().map_err(de::Error::custom)?;
                    return Ok(StrictJsonValue(serde_json::Value::Number(num)));
                }

                let mut obj = serde_json::Map::new();
                let first_val = map.next_value::<StrictJsonValue>()?;
                obj.insert(first_key, first_val.0);
                while let Some(key) = map.next_key::<String>()? {
                    if obj.contains_key(&key) {
                        return Err(de::Error::custom(format!("Duplicate JSON key '{key}'")));
                    }
                    let val = map.next_value::<StrictJsonValue>()?;
                    obj.insert(key, val.0);
                }
                Ok(StrictJsonValue(serde_json::Value::Object(obj)))
            }
        }

        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

fn parse_strict_json_object(
    bytes: &[u8],
    path_display: &str,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let root = StrictJsonValue::deserialize(&mut de).map_err(|e| {
        CfmsError::Backup(format!("Malformed JSON header in backup '{path_display}': {e}"))
    })?;
    de.end().map_err(|e| {
        CfmsError::Backup(format!(
            "Trailing non-JSON bytes inside header of backup '{path_display}': {e}"
        ))
    })?;
    match root.0 {
        serde_json::Value::Object(map) => Ok(map),
        _ => Err(CfmsError::Backup(format!(
            "Envelope header in backup '{path_display}' must be a JSON object"
        ))),
    }
}

fn json_required_str(map: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<String> {
    match map.get(key) {
        Some(serde_json::Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(CfmsError::Backup(format!(
            "Envelope header field '{key}' must be a string"
        ))),
        None => Err(CfmsError::Backup(format!(
            "Missing required envelope header field '{key}'"
        ))),
    }
}

fn json_optional_str(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String> {
    match map.get(key) {
        None => Ok(String::new()),
        Some(serde_json::Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(CfmsError::Backup(format!(
            "Envelope header field '{key}' must be a string"
        ))),
    }
}

fn json_required_usize(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<usize> {
    let val = map.get(key).ok_or_else(|| {
        CfmsError::Backup(format!("Missing required envelope header field '{key}'"))
    })?;
    let n = val
        .as_u64()
        .ok_or_else(|| CfmsError::Backup(format!("Envelope header field '{key}' must be an unsigned integer")))?;
    usize::try_from(n).map_err(|_| {
        CfmsError::Backup(format!("Envelope header field '{key}' exceeds usize range"))
    })
}

fn json_required_u32(map: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<u32> {
    let val = map.get(key).ok_or_else(|| {
        CfmsError::Backup(format!("Missing required envelope header field '{key}'"))
    })?;
    let n = val
        .as_u64()
        .ok_or_else(|| CfmsError::Backup(format!("Envelope header field '{key}' must be an unsigned integer")))?;
    u32::try_from(n).map_err(|_| {
        CfmsError::Backup(format!("Envelope header field '{key}' exceeds u32 range"))
    })
}

fn json_required_string_array(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Vec<String>> {
    let val = map.get(key).ok_or_else(|| {
        CfmsError::Backup(format!("Missing required envelope header field '{key}'"))
    })?;
    let arr = val.as_array().ok_or_else(|| {
        CfmsError::Backup(format!(
            "Envelope header field '{key}' must be an array of strings"
        ))
    })?;
    arr.iter()
        .map(|item| {
            item.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                CfmsError::Backup(format!(
                    "Envelope header field '{key}' must contain only strings"
                ))
            })
        })
        .collect()
}

fn parse_and_validate_envelope_header(
    header_buf: &[u8],
    path_display: &str,
    file_size: u64,
) -> Result<BackupHeaderReport> {
    let map = parse_strict_json_object(header_buf, path_display)?;
    let present_keys: BTreeSet<String> = map.keys().cloned().collect();
    let critical_raw = if map.contains_key("critical") {
        Some(json_required_string_array(&map, "critical")?)
    } else {
        None
    };
    let crit_set = validate_critical_key_list(
        critical_raw.as_deref(),
        &present_keys,
        MANDATORY_ENVELOPE_FIELDS,
        KNOWN_ENVELOPE_FIELDS,
        "envelope header",
    )
    .map_err(CfmsError::Backup)?;

    let mut non_critical_fields = BTreeMap::new();
    for (key, value) in &map {
        if key != "critical" && !KNOWN_ENVELOPE_FIELDS.contains(&key.as_str()) {
            non_critical_fields.insert(key.clone(), value.clone());
        }
    }

    let report = BackupHeaderReport {
        path: path_display.to_string(),
        file_size,
        content_type: json_required_str(&map, "content_type")?,
        version: json_required_u32(&map, "version")?,
        critical: critical_raw.unwrap_or_default(),
        created_at: json_optional_str(&map, "created_at")?,
        server_version: json_optional_str(&map, "server_version")?,
        schema_revision: json_required_str(&map, "schema_revision")?,
        components: json_required_string_array(&map, "components")?,
        cipher: json_required_str(&map, "cipher")?,
        compression: json_required_str(&map, "compression")?,
        container: json_required_str(&map, "container")?,
        kdf: json_required_str(&map, "kdf")?,
        chunk_size: json_required_usize(&map, "chunk_size")?,
        kdf_salt: json_required_str(&map, "kdf_salt")?,
        nonce_prefix: json_required_str(&map, "nonce_prefix")?,
        storage_provider: json_optional_str(&map, "storage_provider")?,
        non_critical_fields,
    };

    validate_envelope_semantics(&report, &crit_set)?;
    Ok(report)
}

fn validate_envelope_semantics(
    header: &BackupHeaderReport,
    crit_set: &BTreeSet<String>,
) -> Result<(usize, [u8; 16], [u8; 7])> {
    if header.content_type != BACKUP_CONTENT_TYPE {
        return Err(CfmsError::Backup(format!(
            "Unsupported backup content_type '{}' (expected '{BACKUP_CONTENT_TYPE}')",
            header.content_type
        )));
    }
    if header.version != BACKUP_FORMAT_VERSION {
        return Err(CfmsError::Backup(format!(
            "Unsupported backup format version {} (expected {BACKUP_FORMAT_VERSION})",
            header.version
        )));
    }
    if header.cipher != BACKUP_CIPHER {
        return Err(CfmsError::Backup(format!(
            "Unsupported backup cipher '{}' (expected '{BACKUP_CIPHER}')",
            header.cipher
        )));
    }
    if header.compression != BACKUP_COMPRESSION {
        return Err(CfmsError::Backup(format!(
            "Unsupported backup compression '{}' (expected '{BACKUP_COMPRESSION}')",
            header.compression
        )));
    }
    if header.container != BACKUP_CONTAINER {
        return Err(CfmsError::Backup(format!(
            "Unsupported backup container '{}' (expected '{BACKUP_CONTAINER}')",
            header.container
        )));
    }
    if header.kdf != BACKUP_KDF {
        return Err(CfmsError::Backup(format!(
            "Unsupported backup KDF '{}' (expected '{BACKUP_KDF}')",
            header.kdf
        )));
    }
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&header.chunk_size) {
        return Err(CfmsError::Backup(format!(
            "Invalid backup chunk_size {} (expected {MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE})",
            header.chunk_size
        )));
    }
    if header.schema_revision.trim().is_empty() {
        return Err(CfmsError::Backup(
            "Envelope header field 'schema_revision' must not be empty".to_string(),
        ));
    }
    parse_and_validate_manifest_components(&header.components)?;

    if crit_set.contains("storage_provider") && !is_supported_storage_provider(&header.storage_provider)
    {
        return Err(CfmsError::Backup(format!(
            "Unsupported CRITICAL backup storage_provider '{}' (expected one of: {})",
            header.storage_provider,
            SUPPORTED_STORAGE_PROVIDERS.join(", ")
        )));
    }
    if crit_set.contains("created_at") && DateTime::parse_from_rfc3339(&header.created_at).is_err() {
        return Err(CfmsError::Backup(format!(
            "Invalid CRITICAL envelope header field 'created_at' timestamp '{}'",
            header.created_at
        )));
    }
    if crit_set.contains("server_version") && header.server_version.trim().is_empty() {
        return Err(CfmsError::Backup(
            "CRITICAL envelope header field 'server_version' must not be empty".to_string(),
        ));
    }

    let salt_vec = general_purpose::URL_SAFE_NO_PAD
        .decode(header.kdf_salt.as_bytes())
        .map_err(|e| CfmsError::ArchiveIntegrity(format!("Invalid kdf_salt encoding: {e}")))?;
    let salt: [u8; 16] = salt_vec.try_into().map_err(|_| {
        CfmsError::ArchiveIntegrity("Invalid kdf_salt length (expected 16 bytes)".to_string())
    })?;

    let prefix_vec = general_purpose::URL_SAFE_NO_PAD
        .decode(header.nonce_prefix.as_bytes())
        .map_err(|e| CfmsError::ArchiveIntegrity(format!("Invalid nonce_prefix encoding: {e}")))?;
    let nonce_prefix: [u8; 7] = prefix_vec.try_into().map_err(|_| {
        CfmsError::ArchiveIntegrity("Invalid nonce_prefix length (expected 7 bytes)".to_string())
    })?;

    Ok((header.chunk_size, salt, nonce_prefix))
}

/// Validate header `CRITICAL` declarations and cryptographic parameters before decryption.
pub fn validate_archive_crypto_header(
    header: &BackupHeaderReport,
) -> Result<(usize, [u8; 16], [u8; 7])> {
    let mut present_keys: BTreeSet<String> = MANDATORY_ENVELOPE_FIELDS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if !header.storage_provider.is_empty() {
        present_keys.insert("storage_provider".to_string());
    }
    if !header.created_at.is_empty() {
        present_keys.insert("created_at".to_string());
    }
    if !header.server_version.is_empty() {
        present_keys.insert("server_version".to_string());
    }
    present_keys.extend(header.non_critical_fields.keys().cloned());

    let crit_set = validate_critical_key_list(
        Some(&header.critical),
        &present_keys,
        MANDATORY_ENVELOPE_FIELDS,
        KNOWN_ENVELOPE_FIELDS,
        "envelope header",
    )
    .map_err(CfmsError::Backup)?;

    validate_envelope_semantics(header, &crit_set)
}

fn compute_envelope_digest(len_le: &[u8; 4], json_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BACKUP_MAGIC);
    hasher.update(len_le);
    hasher.update(json_bytes);
    hasher.finalize().into()
}

fn derive_chunk_cipher(
    master_key: &[u8; 32],
    salt: &[u8; 16],
    header_sha256: &[u8; 32],
) -> Result<Aes256Gcm> {
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 32);
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(header_sha256);

    let mut subkey = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), master_key)
        .expand(&info, &mut *subkey)
        .map_err(|_| CfmsError::Backup("HKDF subkey derivation failed".to_string()))?;

    let key = Key::<Aes256Gcm>::from(*subkey);
    Ok(Aes256Gcm::new(&key))
}

fn build_chunk_nonce(nonce_prefix: &[u8; 7], chunk_idx: u32, is_final: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..7].copy_from_slice(nonce_prefix);
    nonce[7..11].copy_from_slice(&chunk_idx.to_be_bytes());
    nonce[11] = u8::from(is_final);
    nonce
}

fn build_chunk_aad(header_sha256: &[u8; 32], chunk_idx: u32, is_final: bool) -> [u8; 37] {
    let mut aad = [0u8; 37];
    aad[..32].copy_from_slice(header_sha256);
    aad[32..36].copy_from_slice(&chunk_idx.to_be_bytes());
    aad[36] = u8::from(is_final);
    aad
}

/// Streaming writer that encrypts plaintext in bounded chunks using `AES-256-GCM` with
/// counter-and-final-flag nonces and header-hash-bound AAD.
pub struct ChunkedEncryptWriter<W: Write> {
    inner: Option<W>,
    cipher: Aes256Gcm,
    header_sha256: [u8; 32],
    nonce_prefix: [u8; 7],
    chunk_size: usize,
    chunk_idx: u32,
    buf: Vec<u8>,
}

impl<W: Write> Drop for ChunkedEncryptWriter<W> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl<W: Write> ChunkedEncryptWriter<W> {
    pub fn new(
        inner: W,
        master_key: &[u8; 32],
        header: &EnvelopeHeaderSpec,
        header_sha256: [u8; 32],
    ) -> Result<Self> {
        let salt_vec = general_purpose::URL_SAFE_NO_PAD
            .decode(header.kdf_salt.as_bytes())
            .map_err(|e| CfmsError::Backup(format!("Invalid kdf_salt: {e}")))?;
        let salt: [u8; 16] = salt_vec
            .try_into()
            .map_err(|_| CfmsError::Backup("Invalid kdf_salt length".to_string()))?;

        let prefix_vec = general_purpose::URL_SAFE_NO_PAD
            .decode(header.nonce_prefix.as_bytes())
            .map_err(|e| CfmsError::Backup(format!("Invalid nonce_prefix: {e}")))?;
        let nonce_prefix: [u8; 7] = prefix_vec
            .try_into()
            .map_err(|_| CfmsError::Backup("Invalid nonce_prefix length".to_string()))?;

        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&header.chunk_size) {
            return Err(CfmsError::Backup(format!(
                "Invalid chunk size {}",
                header.chunk_size
            )));
        }

        let cipher = derive_chunk_cipher(master_key, &salt, &header_sha256)?;
        Ok(Self {
            inner: Some(inner),
            cipher,
            header_sha256,
            nonce_prefix,
            chunk_size: header.chunk_size,
            chunk_idx: 0,
            buf: Vec::with_capacity(header.chunk_size),
        })
    }

    fn flush_chunk(&mut self, is_final: bool) -> std::io::Result<()> {
        let Some(inner) = self.inner.as_mut() else {
            return Err(std::io::Error::other("ChunkedEncryptWriter already finished"));
        };
        let pt_len = self.buf.len();
        let ct_len = pt_len + AES_GCM_TAG_LEN;
        let ct_len_le = u32::try_from(ct_len)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk overflow"))?
            .to_le_bytes();
        let nonce = Nonce::from(build_chunk_nonce(
            &self.nonce_prefix,
            self.chunk_idx,
            is_final,
        ));
        let aad = build_chunk_aad(&self.header_sha256, self.chunk_idx, is_final);
        let tag: Tag<Aes256Gcm> = self
            .cipher
            .encrypt_inout_detached(&nonce, &aad, InOutBuf::from(self.buf.as_mut_slice()))
            .map_err(|_| std::io::Error::other("AES-256-GCM encryption failed"))?;

        inner.write_all(&ct_len_le)?;
        inner.write_all(&[u8::from(is_final)])?;
        inner.write_all(&self.buf)?;
        inner.write_all(tag.as_slice())?;

        self.buf.zeroize();
        self.buf.clear();

        if !is_final {
            self.chunk_idx = self.chunk_idx.checked_add(1).ok_or_else(|| {
                std::io::Error::other("Encrypted backup chunk index exhausted u32 range")
            })?;
        }
        Ok(())
    }

    /// Emit the authenticated final chunk (`is_final = true`), flush, and return the inner writer.
    pub fn finish(mut self) -> Result<W> {
        self.flush_chunk(true)?;
        let mut inner = self
            .inner
            .take()
            .ok_or_else(|| CfmsError::Backup("ChunkedEncryptWriter already finished".to_string()))?;
        inner.flush()?;
        Ok(inner)
    }
}

impl<W: Write> Write for ChunkedEncryptWriter<W> {
    fn write(&mut self, mut src: &[u8]) -> std::io::Result<usize> {
        let total = src.len();
        while !src.is_empty() {
            let space = self.chunk_size - self.buf.len();
            let take = space.min(src.len());
            self.buf.extend_from_slice(&src[..take]);
            src = &src[take..];
            if self.buf.len() == self.chunk_size {
                self.flush_chunk(false)?;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(inner) = self.inner.as_mut() {
            inner.flush()?;
        }
        Ok(())
    }
}

/// Streaming reader that verifies and decrypts chunked `AES-256-GCM` frames before exposing any
/// plaintext bytes to downstream decompressors or parsers.
pub struct ChunkedDecryptReader<R: Read> {
    inner: R,
    cipher: Aes256Gcm,
    header_sha256: [u8; 32],
    nonce_prefix: [u8; 7],
    chunk_size: usize,
    chunk_idx: u32,
    saw_final: bool,
    pt_buf: Vec<u8>,
    pt_pos: usize,
    pt_len: usize,
}

impl<R: Read> Drop for ChunkedDecryptReader<R> {
    fn drop(&mut self) {
        self.pt_buf.zeroize();
    }
}

impl<R: Read> ChunkedDecryptReader<R> {
    pub fn new(
        inner: R,
        master_key: &[u8; 32],
        header: &BackupHeaderReport,
        header_sha256: [u8; 32],
    ) -> Result<Self> {
        let (chunk_size, salt, nonce_prefix) = validate_archive_crypto_header(header)?;
        let cipher = derive_chunk_cipher(master_key, &salt, &header_sha256)?;
        Ok(Self {
            inner,
            cipher,
            header_sha256,
            nonce_prefix,
            chunk_size,
            chunk_idx: 0,
            saw_final: false,
            pt_buf: vec![0u8; chunk_size + AES_GCM_TAG_LEN],
            pt_pos: 0,
            pt_len: 0,
        })
    }

    fn read_next_chunk(&mut self) -> std::io::Result<bool> {
        if self.saw_final {
            return Ok(false);
        }

        let mut frame_hdr = [0u8; 5];
        match read_exact_or_eof(&mut self.inner, &mut frame_hdr)? {
            ReadHeaderOutcome::Eof => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Encrypted backup stream ended prematurely without a final chunk",
                ));
            }
            ReadHeaderOutcome::Partial => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Truncated encrypted chunk header in backup stream",
                ));
            }
            ReadHeaderOutcome::Complete => {}
        }

        let ct_len = u32::from_le_bytes([frame_hdr[0], frame_hdr[1], frame_hdr[2], frame_hdr[3]])
            as usize;
        let final_flag = frame_hdr[4];
        if final_flag > 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid chunk final flag {final_flag} in encrypted backup stream"),
            ));
        }
        let is_final = final_flag == 1;
        if ct_len < AES_GCM_TAG_LEN || ct_len > self.chunk_size + AES_GCM_TAG_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid encrypted chunk length {ct_len} bytes"),
            ));
        }

        let payload_slice = &mut self.pt_buf[..ct_len];
        self.inner.read_exact(payload_slice).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Truncated encrypted chunk payload: {e}"),
            )
        })?;

        let pt_len = ct_len - AES_GCM_TAG_LEN;
        let (ct_slice, tag_slice) = payload_slice.split_at_mut(pt_len);
        let tag_arr: [u8; AES_GCM_TAG_LEN] = tag_slice
            .try_into()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "tag size"))?;
        let tag = Tag::<Aes256Gcm>::from(tag_arr);

        let nonce = Nonce::from(build_chunk_nonce(
            &self.nonce_prefix,
            self.chunk_idx,
            is_final,
        ));
        let aad = build_chunk_aad(&self.header_sha256, self.chunk_idx, is_final);

        self.cipher
            .decrypt_inout_detached(&nonce, &aad, InOutBuf::from(ct_slice), &tag)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Backup authentication failed (wrong decryption key or tampered/corrupted chunk)",
                )
            })?;

        self.pt_pos = 0;
        self.pt_len = pt_len;

        if is_final {
            self.saw_final = true;
            // Reject any trailing unauthenticated bytes after the final chunk.
            let mut trailing = [0u8; 1];
            loop {
                match self.inner.read(&mut trailing) {
                    Ok(0) => break,
                    Ok(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Unexpected trailing data after final encrypted chunk",
                        ));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
        } else {
            self.chunk_idx = self.chunk_idx.checked_add(1).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Encrypted backup chunk index exhausted u32 range",
                )
            })?;
        }

        Ok(true)
    }
}

impl<R: Read> Read for ChunkedDecryptReader<R> {
    fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        while self.pt_pos == self.pt_len {
            if !self.read_next_chunk()? {
                return Ok(0);
            }
        }
        let avail = self.pt_len - self.pt_pos;
        let copy_len = avail.min(dst.len());
        dst[..copy_len].copy_from_slice(&self.pt_buf[self.pt_pos..self.pt_pos + copy_len]);
        self.pt_pos += copy_len;
        Ok(copy_len)
    }
}

impl<R: Read> ChunkedDecryptReader<R> {
    /// Drain and authenticate any final chunk and verify zero unauthenticated trailing bytes remain.
    pub fn verify_eof(&mut self) -> Result<()> {
        if self.pt_pos < self.pt_len {
            return Err(CfmsError::ArchiveIntegrity(
                "Unexpected trailing plaintext bytes after backup stream".to_string(),
            ));
        }
        let mut probe = [0u8; 16];
        let n = self.read(&mut probe).map_err(|e| {
            CfmsError::ArchiveIntegrity(format!("Encrypted backup stream EOF verification failed: {e}"))
        })?;
        if n > 0 {
            return Err(CfmsError::ArchiveIntegrity(
                "Unexpected trailing plaintext bytes after backup stream".to_string(),
            ));
        }
        if !self.saw_final {
            return Err(CfmsError::ArchiveIntegrity(
                "Encrypted backup stream missing final authenticated chunk".to_string(),
            ));
        }
        Ok(())
    }
}

enum ReadHeaderOutcome {
    Eof,
    Partial,
    Complete,
}

fn read_exact_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<ReadHeaderOutcome> {
    let mut read = 0usize;
    while read < buf.len() {
        match reader.read(&mut buf[read..]) {
            Ok(0) => {
                return Ok(if read == 0 {
                    ReadHeaderOutcome::Eof
                } else {
                    ReadHeaderOutcome::Partial
                });
            }
            Ok(n) => read += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(ReadHeaderOutcome::Complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn roundtrip_bytes(data: &[u8], chunk_size: usize) {
        let key = generate_backup_key();
        let header = EnvelopeHeaderSpec::new(
            "2026-11-14T15:45:00Z".to_string(),
            "0.14.0".to_string(),
            "e952c02c1454".to_string(),
            vec!["accounts".to_string()],
            "local".to_string(),
            chunk_size,
        );
        let mut wire = Vec::new();
        let digest = write_envelope_header(&mut wire, &header).unwrap();
        let mut enc = ChunkedEncryptWriter::new(&mut wire, &key, &header, digest).unwrap();
        enc.write_all(data).unwrap();
        enc.finish().unwrap();

        let mut cursor = Cursor::new(&wire);
        let (parsed_hdr, parsed_digest) =
            read_envelope_and_hash(&mut cursor, "mem.confbak", wire.len() as u64).unwrap();
        assert_eq!(parsed_digest, digest);

        let mut dec = ChunkedDecryptReader::new(cursor, &key, &parsed_hdr, parsed_digest).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn key_encoding_and_decoding_roundtrip_and_rejects_malformed() {
        for seed in [
            [0u8; 32],
            [0xffu8; 32],
            *generate_backup_key(),
            [0x5au8; 32],
        ] {
            let b31 = encode_backup_key_base31(&seed);
            assert_eq!(b31.len(), 52 + 12);
            let dec1 = decode_backup_key(&b31).unwrap();
            assert_eq!(*dec1, seed);

            let lowercase_nodash = b31.replace('-', " ").to_ascii_lowercase();
            let dec2 = decode_backup_key(&lowercase_nodash).unwrap();
            assert_eq!(*dec2, seed);

            let b64 = encode_backup_key_base64url(&seed);
            let dec3 = decode_backup_key(&b64).unwrap();
            assert_eq!(*dec3, seed);
        }

        assert!(decode_backup_key("").is_err());
        assert!(decode_backup_key("invalid-key").is_err());
        // Overflow 31^52 > 2^256
        let overflow = "Z".repeat(52);
        assert!(decode_backup_key(&overflow).is_err());

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), vec![b'a'; MAX_KEY_FILE_BYTES + 1]).unwrap();
        assert!(read_key_file(tmp.path()).is_err());
    }

    #[test]
    fn chunked_aead_handles_boundaries_and_rejects_tampering() {
        for size in [0usize, 1, 63, 64, 65, 128, 300] {
            let payload: Vec<u8> = (0..size).map(|i| (i * 7 + 3) as u8).collect();
            roundtrip_bytes(&payload, 64);
        }

        // Verify tamper protections on a multi-chunk stream
        let key = generate_backup_key();
        let header = EnvelopeHeaderSpec::new(
            "2026-11-14T15:45:00Z".to_string(),
            "0.14.0".to_string(),
            "e952c02c1454".to_string(),
            vec!["accounts".to_string(), "audit".to_string()],
            "local".to_string(),
            64,
        );
        let mut wire = Vec::new();
        let digest = write_envelope_header(&mut wire, &header).unwrap();
        let mut enc = ChunkedEncryptWriter::new(&mut wire, &key, &header, digest).unwrap();
        enc.write_all(&[0x42u8; 200]).unwrap();
        enc.finish().unwrap();

        // 1. Wrong key fails
        let wrong_key = generate_backup_key();
        let mut cur = Cursor::new(&wire);
        let (h, d) = read_envelope_and_hash(&mut cur, "test", wire.len() as u64).unwrap();
        let mut dec = ChunkedDecryptReader::new(cur, &wrong_key, &h, d).unwrap();
        let mut tmp = Vec::new();
        assert!(dec.read_to_end(&mut tmp).is_err());

        // 2. Trailing bytes after final chunk fail
        let mut with_trailing = wire.clone();
        with_trailing.push(0x99);
        let mut cur = Cursor::new(&with_trailing);
        let (h, d) = read_envelope_and_hash(&mut cur, "test", with_trailing.len() as u64).unwrap();
        let mut dec = ChunkedDecryptReader::new(cur, &key, &h, d).unwrap();
        assert!(dec.read_to_end(&mut tmp).is_err());

        // 3. Premature truncation (remove final chunk) fails
        let header_end = 12 + u32::from_le_bytes([wire[8], wire[9], wire[10], wire[11]]) as usize;
        // First chunk is 5 + 64 + 16 = 85 bytes
        let truncated = wire[..header_end + 85].to_vec();
        let mut cur = Cursor::new(&truncated);
        let (h, d) = read_envelope_and_hash(&mut cur, "test", truncated.len() as u64).unwrap();
        let mut dec = ChunkedDecryptReader::new(cur, &key, &h, d).unwrap();
        assert!(dec.read_to_end(&mut tmp).is_err());

        // 4. Envelope header tampering (even preserving valid JSON length) fails AAD check
        let mut tampered_hdr = wire.clone();
        let pos = wire.windows(12).position(|w| w == b"e952c02c1454").unwrap();
        tampered_hdr[pos] = b'X';
        let mut cur = Cursor::new(&tampered_hdr);
        let (h, d) = read_envelope_and_hash(&mut cur, "test", tampered_hdr.len() as u64).unwrap();
        let mut dec = ChunkedDecryptReader::new(cur, &key, &h, d).unwrap();
        assert!(dec.read_to_end(&mut tmp).is_err());
    }

    fn envelope_wire_from_json_bytes(json_bytes: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(BACKUP_MAGIC);
        wire.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
        wire.extend_from_slice(json_bytes);
        wire
    }

    fn base_envelope_json_value() -> serde_json::Value {
        let spec = EnvelopeHeaderSpec::new(
            "2026-11-15T00:00:00Z".to_string(),
            "0.14.0".to_string(),
            "e952c02c1454".to_string(),
            vec!["accounts".to_string()],
            "local".to_string(),
            DEFAULT_CHUNK_SIZE,
        );
        serde_json::to_value(spec).unwrap()
    }

    #[test]
    fn envelope_header_critical_rules_reject_unknown_and_tolerate_non_critical() {
        // 1. Unknown non-critical field is tolerated and surfaced in non_critical_fields
        let mut non_crit_val = base_envelope_json_value();
        non_crit_val
            .as_object_mut()
            .unwrap()
            .insert("backup_note".to_string(), serde_json::json!("nightly"));
        let wire = envelope_wire_from_json_bytes(&serde_json::to_vec(&non_crit_val).unwrap());
        let (parsed, _) =
            read_envelope_and_hash(&mut Cursor::new(&wire), "ok.confbak", wire.len() as u64)
                .unwrap();
        assert_eq!(parsed.content_type, BACKUP_CONTENT_TYPE);
        assert_eq!(parsed.version, BACKUP_FORMAT_VERSION);
        assert_eq!(
            parsed.non_critical_fields.get("backup_note"),
            Some(&serde_json::json!("nightly"))
        );

        // 2. Unknown field marked CRITICAL must be rejected
        let mut unknown_crit = base_envelope_json_value();
        let obj = unknown_crit.as_object_mut().unwrap();
        obj.insert(
            "pq_kem_envelope".to_string(),
            serde_json::json!({"alg": "ml-kem-1024"}),
        );
        obj.get_mut("critical")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("pq_kem_envelope"));
        let wire = envelope_wire_from_json_bytes(&serde_json::to_vec(&unknown_crit).unwrap());
        let err = read_envelope_and_hash(&mut Cursor::new(&wire), "crit.confbak", wire.len() as u64)
            .unwrap_err();
        assert!(err.to_string().contains("Unsupported CRITICAL envelope header field"));
        assert!(err.to_string().contains("pq_kem_envelope"));

        // 3. Dangling CRITICAL field (declared in `critical` but missing from JSON object) is rejected
        let mut dangling = base_envelope_json_value();
        dangling
            .as_object_mut()
            .unwrap()
            .get_mut("critical")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("missing_critical_ext"));
        let wire = envelope_wire_from_json_bytes(&serde_json::to_vec(&dangling).unwrap());
        let err = read_envelope_and_hash(&mut Cursor::new(&wire), "dangling.confbak", wire.len() as u64)
            .unwrap_err();
        assert!(err.to_string().contains("missing from header"));

        // 4. Known CRITICAL field with valid `"s3"` provider succeeds, while unsupported provider or bad timestamp fails
        let mut s3_provider = base_envelope_json_value();
        s3_provider
            .as_object_mut()
            .unwrap()
            .insert("storage_provider".to_string(), serde_json::json!("s3"));
        let wire = envelope_wire_from_json_bytes(&serde_json::to_vec(&s3_provider).unwrap());
        let (parsed_s3, _) =
            read_envelope_and_hash(&mut Cursor::new(&wire), "s3.confbak", wire.len() as u64)
                .unwrap();
        assert_eq!(parsed_s3.storage_provider, "s3");

        let mut bad_provider = base_envelope_json_value();
        bad_provider.as_object_mut().unwrap().insert(
            "storage_provider".to_string(),
            serde_json::json!("s3-external"),
        );
        let wire = envelope_wire_from_json_bytes(&serde_json::to_vec(&bad_provider).unwrap());
        assert!(
            read_envelope_and_hash(&mut Cursor::new(&wire), "bad_provider.confbak", wire.len() as u64)
                .is_err()
        );

        let mut bad_ts = base_envelope_json_value();
        let obj = bad_ts.as_object_mut().unwrap();
        obj.insert("created_at".to_string(), serde_json::json!("not-rfc3339"));
        obj.get_mut("critical")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("created_at"));
        let wire = envelope_wire_from_json_bytes(&serde_json::to_vec(&bad_ts).unwrap());
        assert!(
            read_envelope_and_hash(&mut Cursor::new(&wire), "ts.confbak", wire.len() as u64)
                .is_err()
        );

        // 5. Missing `critical` array, self-referential `"critical"`, or duplicate JSON keys are rejected
        let mut no_crit = base_envelope_json_value();
        no_crit.as_object_mut().unwrap().remove("critical");
        let wire = envelope_wire_from_json_bytes(&serde_json::to_vec(&no_crit).unwrap());
        assert!(
            read_envelope_and_hash(&mut Cursor::new(&wire), "nocrit.confbak", wire.len() as u64)
                .is_err()
        );

        let mut self_crit = base_envelope_json_value();
        self_crit
            .as_object_mut()
            .unwrap()
            .get_mut("critical")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("critical"));
        let wire = envelope_wire_from_json_bytes(&serde_json::to_vec(&self_crit).unwrap());
        assert!(
            read_envelope_and_hash(&mut Cursor::new(&wire), "selfcrit.confbak", wire.len() as u64)
                .is_err()
        );

        let raw_base = serde_json::to_string(&base_envelope_json_value()).unwrap();
        let dup_json = format!(r#"{{"critical":["unknown_crit"],{}"#, &raw_base[1..]);
        let wire = envelope_wire_from_json_bytes(dup_json.as_bytes());
        let err = read_envelope_and_hash(&mut Cursor::new(&wire), "dup.confbak", wire.len() as u64)
            .unwrap_err();
        assert!(err.to_string().contains("Duplicate JSON key"));
    }
}