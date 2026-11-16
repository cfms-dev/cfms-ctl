//! Typed single-pass streaming container codec (`cfms-stream-v2`) wrapped inside Zstd +
//! chunked AEAD, eliminating intermediate plaintext staging files and upfront size requirements.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use chrono::DateTime;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use crate::core::error::{CfmsError, Result};
use crate::db::schema::ddl::ColumnType;
use crate::db::schema::ir::{SCHEMA_IR_VERSION, SchemaIr};
use crate::db::transfer::{SqlValue, TransferColumn};
use crate::ops::backup::format::{
    BACKUP_FORMAT_VERSION, BackupHeaderReport, validate_critical_key_list,
};

pub const MANIFEST_CONTENT_TYPE: &str = "cfms-manifest";
const SUPPORTED_MANIFEST_STORAGE_PROVIDERS: &[&str] = &["local", "s3"];

const MANDATORY_MANIFEST_FIELDS: &[&str] = &[
    "content_type",
    "version",
    "schema_revision",
    "components",
    "storage_provider",
    "extension_tables",
    "table_order",
    "tables",
    "schema_ir",
    "configuration",
];

const KNOWN_MANIFEST_FIELDS: &[&str] = &[
    "content_type",
    "version",
    "schema_revision",
    "components",
    "storage_provider",
    "extension_tables",
    "table_order",
    "tables",
    "schema_ir",
    "configuration",
    "created_at",
    "server_version",
];

pub const MAX_HEADER_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TABLE_BATCH_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_ROW_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BLOB_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_FOOTER_FRAME_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SMALL_FRAME_BYTES: usize = 1024 * 1024;

const TAG_MANIFEST_HEADER: u8 = 0x01;
const TAG_TABLE_START: u8 = 0x10;
const TAG_TABLE_ROW_BATCH: u8 = 0x11;
const TAG_TABLE_END: u8 = 0x12;
const TAG_BLOB_START: u8 = 0x20;
const TAG_BLOB_CHUNK: u8 = 0x21;
const TAG_BLOB_END: u8 = 0x22;
const TAG_MISSING_INACTIVE_FILE: u8 = 0x23;
const TAG_FILE_ENTRY: u8 = 0x24;
const TAG_INTEGRITY_FOOTER: u8 = 0xFF;

mod msgpack_bytes {
    use serde::{Deserializer, Serializer, de::Error as _, de::Visitor};
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct BytesVisitor;
        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("binary byte buffer")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(BytesVisitor).map_err(D::Error::custom)
    }
}

/// Lossless canonical SQL value serialized directly inside `cfms-stream-v2` row batches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupValue {
    Null,
    Bool(bool),
    I64(i64),
    F64Bits(u64),
    Str(String),
    Uuid([u8; 16]),
    Bytes(#[serde(with = "msgpack_bytes")] Vec<u8>),
    JsonText(String),
}

impl BackupValue {
    pub(crate) fn from_sql(val: &SqlValue) -> Result<Self> {
        match val {
            SqlValue::Null => Ok(Self::Null),
            SqlValue::Bool(b) => Ok(Self::Bool(*b)),
            SqlValue::I64(n) => Ok(Self::I64(*n)),
            SqlValue::F64(f) => {
                if !f.is_finite() {
                    return Err(CfmsError::ArchiveIntegrity(format!(
                        "Non-finite floating point value {f} cannot be serialized in backup"
                    )));
                }
                Ok(Self::F64Bits(f.to_bits()))
            }
            SqlValue::Str(s) => Ok(Self::Str(s.clone())),
            SqlValue::Uuid(u) => Ok(Self::Uuid(*u)),
            SqlValue::Bytes(b) => Ok(Self::Bytes(b.clone())),
            SqlValue::Json(v) => Ok(Self::JsonText(serde_json::to_string(v).map_err(|e| {
                CfmsError::Backup(format!("Failed to serialize JSON cell value: {e}"))
            })?)),
        }
    }

    pub(crate) fn into_sql(self) -> Result<SqlValue> {
        match self {
            Self::Null => Ok(SqlValue::Null),
            Self::Bool(b) => Ok(SqlValue::Bool(b)),
            Self::I64(n) => Ok(SqlValue::I64(n)),
            Self::F64Bits(bits) => {
                let f = f64::from_bits(bits);
                if !f.is_finite() {
                    return Err(CfmsError::ArchiveIntegrity(
                        "Non-finite floating point value in backup row".to_string(),
                    ));
                }
                Ok(SqlValue::F64(f))
            }
            Self::Str(s) => Ok(SqlValue::Str(s)),
            Self::Uuid(u) => Ok(SqlValue::Uuid(u)),
            Self::Bytes(b) => Ok(SqlValue::Bytes(b)),
            Self::JsonText(raw) => {
                let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
                    CfmsError::ArchiveIntegrity(format!("Invalid JSON payload in backup cell: {e}"))
                })?;
                Ok(SqlValue::Json(v))
            }
        }
    }

    /// Validate that a backed-up value matches the expected column schema (allowing `Null`).
    pub fn matches_column_type(&self, col_type: BackupColumnType) -> bool {
        match (self, col_type) {
            (Self::Null, _) => true,
            (Self::Bool(_), BackupColumnType::Boolean) => true,
            (
                Self::I64(_),
                BackupColumnType::SmallInt
                | BackupColumnType::Integer
                | BackupColumnType::BigInt
                | BackupColumnType::SqliteIntElseBigInt
                | BackupColumnType::Serial
                | BackupColumnType::BigSerial,
            ) => true,
            (Self::F64Bits(bits), BackupColumnType::Double) => f64::from_bits(*bits).is_finite(),
            (
                Self::Str(_),
                BackupColumnType::Varchar(_) | BackupColumnType::Text | BackupColumnType::LongText,
            ) => true,
            (Self::Uuid(_), BackupColumnType::Uuid) => true,
            (Self::Bytes(_), BackupColumnType::Blob) => true,
            (Self::Bytes(b), BackupColumnType::FixedBinary32) => b.len() == 32,
            (Self::JsonText(_), BackupColumnType::Json) => true,
            _ => false,
        }
    }
}

/// Serializable counterpart to [`ColumnType`] stored inside [`TableSchemaSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupColumnType {
    Varchar(u16),
    Text,
    LongText,
    SmallInt,
    Integer,
    BigInt,
    SqliteIntElseBigInt,
    Serial,
    BigSerial,
    Double,
    Boolean,
    Uuid,
    Blob,
    FixedBinary32,
    Json,
}

impl From<ColumnType> for BackupColumnType {
    fn from(ct: ColumnType) -> Self {
        match ct {
            ColumnType::Varchar(n) => Self::Varchar(n),
            ColumnType::Text => Self::Text,
            ColumnType::LongText => Self::LongText,
            ColumnType::SmallInt => Self::SmallInt,
            ColumnType::Integer => Self::Integer,
            ColumnType::BigInt => Self::BigInt,
            ColumnType::SqliteIntElseBigInt => Self::SqliteIntElseBigInt,
            ColumnType::Serial => Self::Serial,
            ColumnType::BigSerial => Self::BigSerial,
            ColumnType::Double => Self::Double,
            ColumnType::Boolean => Self::Boolean,
            ColumnType::Uuid => Self::Uuid,
            ColumnType::Blob => Self::Blob,
            ColumnType::FixedBinary32 => Self::FixedBinary32,
            ColumnType::Json => Self::Json,
        }
    }
}

impl From<BackupColumnType> for ColumnType {
    fn from(ct: BackupColumnType) -> Self {
        match ct {
            BackupColumnType::Varchar(n) => Self::Varchar(n),
            BackupColumnType::Text => Self::Text,
            BackupColumnType::LongText => Self::LongText,
            BackupColumnType::SmallInt => Self::SmallInt,
            BackupColumnType::Integer => Self::Integer,
            BackupColumnType::BigInt => Self::BigInt,
            BackupColumnType::SqliteIntElseBigInt => Self::SqliteIntElseBigInt,
            BackupColumnType::Serial => Self::Serial,
            BackupColumnType::BigSerial => Self::BigSerial,
            BackupColumnType::Double => Self::Double,
            BackupColumnType::Boolean => Self::Boolean,
            BackupColumnType::Uuid => Self::Uuid,
            BackupColumnType::Blob => Self::Blob,
            BackupColumnType::FixedBinary32 => Self::FixedBinary32,
            BackupColumnType::Json => Self::Json,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableColumnSpec {
    pub name: String,
    pub col_type: BackupColumnType,
}

impl From<&TransferColumn> for TableColumnSpec {
    fn from(c: &TransferColumn) -> Self {
        Self {
            name: c.name.clone(),
            col_type: c.col_type.into(),
        }
    }
}

impl TableColumnSpec {
    pub(crate) fn to_transfer_column(&self) -> TransferColumn {
        TransferColumn {
            name: self.name.clone(),
            col_type: self.col_type.into(),
            is_generated: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableSchemaSpec {
    pub columns: Vec<TableColumnSpec>,
    pub pk_columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionTableBackupSpec {
    pub table_name: String,
    pub owner: String,
    pub backup_component: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigurationPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pepper: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
}

/// Lossless representation of unknown non-critical MessagePack metadata inside [`ManifestHeader`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum MsgPackMetaValue {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64Bits(u64),
    Str(String),
    Bytes(#[serde(with = "msgpack_bytes")] Vec<u8>),
    Array(Vec<Self>),
    Map(BTreeMap<String, Self>),
}

impl<'de> Deserialize<'de> for MsgPackMetaValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct MetaVisitor;

        impl<'de> Visitor<'de> for MetaVisitor {
            type Value = MsgPackMetaValue;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any valid MessagePack metadata value")
            }

            fn visit_bool<E>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(MsgPackMetaValue::Bool(v))
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(MsgPackMetaValue::I64(v))
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(MsgPackMetaValue::U64(v))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                if !v.is_finite() {
                    return Err(de::Error::custom("Non-finite float in manifest metadata"));
                }
                Ok(MsgPackMetaValue::F64Bits(v.to_bits()))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(MsgPackMetaValue::Str(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(MsgPackMetaValue::Str(v))
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> std::result::Result<Self::Value, E> {
                Ok(MsgPackMetaValue::Bytes(v.to_vec()))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> std::result::Result<Self::Value, E> {
                Ok(MsgPackMetaValue::Bytes(v))
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(MsgPackMetaValue::Null)
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(MsgPackMetaValue::Null)
            }

            fn visit_some<D2: Deserializer<'de>>(
                self,
                deserializer: D2,
            ) -> std::result::Result<Self::Value, D2::Error> {
                MsgPackMetaValue::deserialize(deserializer)
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(item) = seq.next_element::<MsgPackMetaValue>()? {
                    out.push(item);
                }
                Ok(MsgPackMetaValue::Array(out))
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if out.contains_key(&key) {
                        return Err(de::Error::custom(format!(
                            "Duplicate manifest metadata key '{key}'"
                        )));
                    }
                    let val = map.next_value::<MsgPackMetaValue>()?;
                    out.insert(key, val);
                }
                Ok(MsgPackMetaValue::Map(out))
            }
        }

        deserializer.deserialize_any(MetaVisitor)
    }
}

/// First stream frame inside the encrypted/compressed archive (`0x01`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestHeader {
    pub content_type: String,
    pub version: u32,
    pub critical: Vec<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub server_version: String,
    pub schema_revision: String,
    pub components: Vec<String>,
    pub storage_provider: String,
    pub extension_tables: Vec<ExtensionTableBackupSpec>,
    pub table_order: Vec<String>,
    pub tables: BTreeMap<String, TableSchemaSpec>,
    pub schema_ir: SchemaIr,
    pub configuration: ConfigurationPayload,
    #[serde(skip)]
    pub non_critical_fields: BTreeMap<String, MsgPackMetaValue>,
}

impl ManifestHeader {
    /// Construct a new [`ManifestHeader`] populated with the canonical `content_type`,
    /// `version`, and `critical` declarations.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        created_at: String,
        server_version: String,
        schema_revision: String,
        components: Vec<String>,
        storage_provider: String,
        extension_tables: Vec<ExtensionTableBackupSpec>,
        table_order: Vec<String>,
        tables: BTreeMap<String, TableSchemaSpec>,
        schema_ir: SchemaIr,
        configuration: ConfigurationPayload,
    ) -> Self {
        Self {
            content_type: MANIFEST_CONTENT_TYPE.to_string(),
            version: BACKUP_FORMAT_VERSION,
            critical: MANDATORY_MANIFEST_FIELDS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            created_at,
            server_version,
            schema_revision,
            components,
            storage_provider,
            extension_tables,
            table_order,
            tables,
            schema_ir,
            configuration,
            non_critical_fields: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableStartPayload {
    pub table_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRowBatchPayload {
    pub table_name: String,
    pub rows: Vec<Vec<BackupValue>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableEndPayload {
    pub table_name: String,
    pub row_count: u64,
    pub canonical_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobStartPayload {
    pub blob_id: u64,
    pub storage_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobEndPayload {
    pub blob_id: u64,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingInactiveFilePayload {
    pub file_id: String,
    pub storage_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntryPayload {
    pub file_id: String,
    pub storage_path: String,
    pub blob_id: u64,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityFooter {
    pub tables: BTreeMap<String, TableDigestSummary>,
    pub blobs: Vec<BlobEndPayload>,
    pub files: Vec<FileEntryPayload>,
    pub missing_inactive_files: Vec<MissingInactiveFilePayload>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableDigestSummary {
    pub rows: u64,
    pub sha256: String,
}

/// Decoded sequential record from [`StreamRecordReader`].
#[derive(Debug)]
pub enum StreamRecord {
    TableStart(TableStartPayload),
    TableRowBatch(TableRowBatchPayload),
    TableEnd(TableEndPayload),
    BlobStart(BlobStartPayload),
    BlobChunk { blob_id: u64, data: Vec<u8> },
    BlobEnd(BlobEndPayload),
    MissingInactiveFile(MissingInactiveFilePayload),
    FileEntry(FileEntryPayload),
    IntegrityFooter(IntegrityFooter),
}

/// Validates internal structural invariants on [`ManifestHeader`] against the outer envelope header.
pub fn validate_manifest_header(
    manifest: &ManifestHeader,
    envelope: &BackupHeaderReport,
    expected_tables_for_selection: &BTreeSet<String>,
) -> Result<()> {
    let mut present_keys: BTreeSet<String> = MANDATORY_MANIFEST_FIELDS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if !manifest.created_at.is_empty() {
        present_keys.insert("created_at".to_string());
    }
    if !manifest.server_version.is_empty() {
        present_keys.insert("server_version".to_string());
    }
    for extra_key in manifest.non_critical_fields.keys() {
        present_keys.insert(extra_key.clone());
    }

    let critical_set = validate_critical_key_list(
        Some(&manifest.critical),
        &present_keys,
        MANDATORY_MANIFEST_FIELDS,
        KNOWN_MANIFEST_FIELDS,
        "manifest header",
    )
    .map_err(CfmsError::ArchiveIntegrity)?;

    if manifest.content_type != MANIFEST_CONTENT_TYPE {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Unsupported manifest content_type '{}' (expected '{}')",
            manifest.content_type, MANIFEST_CONTENT_TYPE
        )));
    }
    if manifest.version != BACKUP_FORMAT_VERSION {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Unsupported manifest format version {} (expected {})",
            manifest.version, BACKUP_FORMAT_VERSION
        )));
    }
    if manifest.version != envelope.version {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Archive manifest version {} does not match envelope version {}",
            manifest.version, envelope.version
        )));
    }
    if manifest.schema_ir.ir_version != SCHEMA_IR_VERSION {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Unsupported manifest schema IR version {} (expected {SCHEMA_IR_VERSION})",
            manifest.schema_ir.ir_version
        )));
    }
    if !SUPPORTED_MANIFEST_STORAGE_PROVIDERS.contains(&manifest.storage_provider.as_str()) {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Unsupported manifest storage_provider '{}' (expected one of: {})",
            manifest.storage_provider,
            SUPPORTED_MANIFEST_STORAGE_PROVIDERS.join(", ")
        )));
    }
    if !envelope.storage_provider.is_empty()
        && manifest.storage_provider != envelope.storage_provider
    {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive manifest storage_provider does not match unencrypted envelope header"
                .to_string(),
        ));
    }
    if critical_set.contains("created_at") {
        if manifest.created_at.trim().is_empty() {
            return Err(CfmsError::ArchiveIntegrity(
                "Critical manifest header field 'created_at' cannot be empty".to_string(),
            ));
        }
        DateTime::parse_from_rfc3339(&manifest.created_at).map_err(|e| {
            CfmsError::ArchiveIntegrity(format!(
                "Critical manifest header field 'created_at' is not valid RFC 3339: {e}"
            ))
        })?;
    }
    if !envelope.created_at.is_empty()
        && !manifest.created_at.is_empty()
        && manifest.created_at != envelope.created_at
    {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive manifest created_at does not match unencrypted envelope header".to_string(),
        ));
    }
    if critical_set.contains("server_version") && manifest.server_version.trim().is_empty() {
        return Err(CfmsError::ArchiveIntegrity(
            "Critical manifest header field 'server_version' cannot be empty".to_string(),
        ));
    }
    if !envelope.server_version.is_empty()
        && !manifest.server_version.is_empty()
        && manifest.server_version != envelope.server_version
    {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive manifest server_version does not match unencrypted envelope header".to_string(),
        ));
    }
    if manifest.schema_revision.trim().is_empty() {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive manifest has empty `schema_revision`".to_string(),
        ));
    }
    if manifest.components != envelope.components {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive manifest components do not match unencrypted envelope header".to_string(),
        ));
    }
    if manifest.schema_revision != envelope.schema_revision {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive manifest schema_revision does not match unencrypted envelope header".to_string(),
        ));
    }

    if manifest.components.is_empty() {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive manifest has invalid empty components list".to_string(),
        ));
    }
    let mut comp_set = BTreeSet::new();
    for c in &manifest.components {
        if !comp_set.insert(c.as_str()) {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Archive manifest contains duplicate component '{c}'"
            )));
        }
    }

    let has_config = comp_set.contains("configuration");
    if has_config {
        let pepper = manifest.configuration.pepper.as_deref().unwrap_or("");
        let secret = manifest.configuration.secret_key.as_deref().unwrap_or("");
        if manifest.configuration.pepper.is_none() || manifest.configuration.secret_key.is_none() {
            return Err(CfmsError::ArchiveIntegrity(
                "Archive includes 'configuration' component but is missing `security.pepper` or `server.secret_key`".to_string(),
            ));
        }
        // Empty strings are rejected as invalid restored secrets only if completely absent? Wait:
        // allow configured strings (note CFMS config could have pepper empty before fill-pepper, OR enforce non-empty? Let Option presence + String type be required, matching schema!)
        let _ = (pepper, secret);
    } else if manifest.configuration.pepper.is_some() || manifest.configuration.secret_key.is_some()
    {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive includes configuration secrets even though 'configuration' component is not selected"
                .to_string(),
        ));
    }

    let order_set: BTreeSet<&str> = manifest.table_order.iter().map(String::as_str).collect();
    if order_set.len() != manifest.table_order.len() {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive manifest contains duplicate tables in `table_order`".to_string(),
        ));
    }
    let schema_set: BTreeSet<&str> = manifest.tables.keys().map(String::as_str).collect();
    if order_set != schema_set {
        return Err(CfmsError::ArchiveIntegrity(
            "Archive manifest `table_order` does not match `tables` schema definitions"
                .to_string(),
        ));
    }
    let expected_ref: BTreeSet<&str> = expected_tables_for_selection
        .iter()
        .map(String::as_str)
        .collect();
    if order_set != expected_ref {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Archive manifest tables {:?} do not match expected component closure {:?}",
            order_set, expected_ref
        )));
    }

    Ok(())
}

/// Encode a batch of typed SQL rows into canonical [`BackupValue`] rows for streaming.
pub(crate) fn backup_rows_from_sql(rows: &[Vec<SqlValue>]) -> Result<Vec<Vec<BackupValue>>> {
    rows.iter()
        .map(|row| row.iter().map(BackupValue::from_sql).collect())
        .collect()
}

/// Whether `nodes`, `folders`, and `documents` stream interleaved as one depth-ordered hierarchy group.
#[must_use]
pub fn is_coupled_node_group(manifest: &ManifestHeader) -> bool {
    manifest
        .tables
        .get("nodes")
        .is_some_and(|t| t.columns.iter().any(|c| c.name == "parent_id"))
        && manifest.tables.contains_key("folders")
        && manifest.tables.contains_key("documents")
}

/// Extract a canonical string identifier from a typed [`SqlValue`] (`Str` or `Uuid`).
pub(crate) fn sql_val_to_id(val: &SqlValue, field: &str) -> Result<String> {
    match val {
        SqlValue::Str(s) => Ok(s.clone()),
        SqlValue::Uuid(u) => Ok(uuid::Uuid::from_bytes(*u).to_string()),
        other => Err(CfmsError::ArchiveIntegrity(format!(
            "Expected string identifier for '{field}', got {other:?}"
        ))),
    }
}

/// Streaming writer for `cfms-stream-v2` records.
pub struct StreamRecordWriter<W: Write> {
    inner: W,
}

impl<W: Write> StreamRecordWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }

    fn write_msgpack_frame<T: Serialize>(
        &mut self,
        tag: u8,
        max_bytes: usize,
        value: &T,
    ) -> Result<()> {
        let payload = rmp_serde::to_vec_named(value)
            .map_err(|e| CfmsError::Backup(format!("MessagePack encode failed: {e}")))?;
        if payload.len() > max_bytes {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Encoded record (tag 0x{tag:02x}, {} bytes) exceeds backup limit ({max_bytes} bytes)",
                payload.len()
            )));
        }
        let len_le = u32::try_from(payload.len())
            .map_err(|_| CfmsError::Backup("Frame length exceeds u32".to_string()))?
            .to_le_bytes();
        self.inner.write_all(&[tag])?;
        self.inner.write_all(&len_le)?;
        self.inner.write_all(&payload)?;
        Ok(())
    }

    pub fn write_manifest_header(&mut self, header: &ManifestHeader) -> Result<()> {
        self.write_msgpack_frame(TAG_MANIFEST_HEADER, MAX_HEADER_FRAME_BYTES, header)
    }

    pub fn write_table_start(&mut self, table_name: &str) -> Result<()> {
        self.write_msgpack_frame(
            TAG_TABLE_START,
            MAX_SMALL_FRAME_BYTES,
            &TableStartPayload {
                table_name: table_name.to_string(),
            },
        )
    }

    pub fn write_table_row_batch(
        &mut self,
        table_name: &str,
        rows: Vec<Vec<BackupValue>>,
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        // Validate per-row limit cleanly before combining into batch frame
        for row in &rows {
            let encoded = rmp_serde::to_vec_named(row)
                .map_err(|e| CfmsError::Backup(format!("Row MessagePack encode failed: {e}")))?;
            if encoded.len() > MAX_ROW_BYTES {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Serialized row in table '{table_name}' ({} bytes) exceeds backup row limit ({MAX_ROW_BYTES} bytes)",
                    encoded.len()
                )));
            }
        }
        self.write_msgpack_frame(
            TAG_TABLE_ROW_BATCH,
            MAX_TABLE_BATCH_BYTES,
            &TableRowBatchPayload {
                table_name: table_name.to_string(),
                rows,
            },
        )
    }

    pub fn write_table_end(&mut self, end: &TableEndPayload) -> Result<()> {
        self.write_msgpack_frame(TAG_TABLE_END, MAX_SMALL_FRAME_BYTES, end)
    }

    pub fn write_blob_start(&mut self, start: &BlobStartPayload) -> Result<()> {
        self.write_msgpack_frame(TAG_BLOB_START, MAX_SMALL_FRAME_BYTES, start)
    }

    pub fn write_blob_chunk(&mut self, blob_id: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if data.len() > MAX_BLOB_CHUNK_BYTES {
            return Err(CfmsError::Backup(format!(
                "Blob chunk size {} exceeds limit {MAX_BLOB_CHUNK_BYTES}",
                data.len()
            )));
        }
        let payload_len = 8 + data.len();
        let len_le = u32::try_from(payload_len)
            .map_err(|_| CfmsError::Backup("Blob chunk exceeds u32".to_string()))?
            .to_le_bytes();
        self.inner.write_all(&[TAG_BLOB_CHUNK])?;
        self.inner.write_all(&len_le)?;
        self.inner.write_all(&blob_id.to_le_bytes())?;
        self.inner.write_all(data)?;
        Ok(())
    }

    pub fn write_blob_end(&mut self, end: &BlobEndPayload) -> Result<()> {
        self.write_msgpack_frame(TAG_BLOB_END, MAX_SMALL_FRAME_BYTES, end)
    }

    pub fn write_missing_inactive_file(&mut self, missing: &MissingInactiveFilePayload) -> Result<()> {
        self.write_msgpack_frame(TAG_MISSING_INACTIVE_FILE, MAX_SMALL_FRAME_BYTES, missing)
    }

    pub fn write_file_entry(&mut self, entry: &FileEntryPayload) -> Result<()> {
        self.write_msgpack_frame(TAG_FILE_ENTRY, MAX_SMALL_FRAME_BYTES, entry)
    }

    pub fn write_integrity_footer(&mut self, footer: &IntegrityFooter) -> Result<()> {
        self.write_msgpack_frame(TAG_INTEGRITY_FOOTER, MAX_FOOTER_FRAME_BYTES, footer)
    }

    pub fn flush(&mut self) -> Result<()> {
        self.inner.flush()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum StrictMapKey {
    Null,
    Bool(bool),
    I64(i64),
    U64(u64),
    F64Bits(u64),
    Str(String),
    Bytes(Vec<u8>),
}

impl<'de> Deserialize<'de> for StrictMapKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct KeyVisitor;

        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = StrictMapKey;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("primitive MessagePack map key")
            }

            fn visit_bool<E>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictMapKey::Bool(v))
            }

            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictMapKey::I64(v))
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictMapKey::U64(v))
            }

            fn visit_f64<E>(self, v: f64) -> std::result::Result<Self::Value, E> {
                Ok(StrictMapKey::F64Bits(v.to_bits()))
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictMapKey::Str(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(StrictMapKey::Str(v))
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E> {
                Ok(StrictMapKey::Bytes(v.to_vec()))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> std::result::Result<Self::Value, E> {
                Ok(StrictMapKey::Bytes(v))
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictMapKey::Null)
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictMapKey::Null)
            }
        }

        deserializer.deserialize_any(KeyVisitor)
    }
}

struct StrictSkipValue;

impl<'de> Deserialize<'de> for StrictSkipValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct SkipVisitor;

        impl<'de> Visitor<'de> for SkipVisitor {
            type Value = StrictSkipValue;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any valid MessagePack value without duplicate map keys")
            }

            fn visit_bool<E>(self, _v: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictSkipValue)
            }

            fn visit_i64<E>(self, _v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictSkipValue)
            }

            fn visit_u64<E>(self, _v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictSkipValue)
            }

            fn visit_f64<E>(self, _v: f64) -> std::result::Result<Self::Value, E> {
                Ok(StrictSkipValue)
            }

            fn visit_str<E>(self, _v: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictSkipValue)
            }

            fn visit_string<E>(self, _v: String) -> std::result::Result<Self::Value, E> {
                Ok(StrictSkipValue)
            }

            fn visit_bytes<E>(self, _v: &[u8]) -> std::result::Result<Self::Value, E> {
                Ok(StrictSkipValue)
            }

            fn visit_byte_buf<E>(self, _v: Vec<u8>) -> std::result::Result<Self::Value, E> {
                Ok(StrictSkipValue)
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictSkipValue)
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictSkipValue)
            }

            fn visit_some<D2: Deserializer<'de>>(
                self,
                deserializer: D2,
            ) -> std::result::Result<Self::Value, D2::Error> {
                StrictSkipValue::deserialize(deserializer)
            }

            fn visit_newtype_struct<D2: Deserializer<'de>>(
                self,
                deserializer: D2,
            ) -> std::result::Result<Self::Value, D2::Error> {
                StrictSkipValue::deserialize(deserializer)
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                while seq.next_element::<StrictSkipValue>()?.is_some() {}
                Ok(StrictSkipValue)
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut seen = BTreeSet::new();
                while let Some(key) = map.next_key::<StrictMapKey>()? {
                    if !seen.insert(key) {
                        return Err(de::Error::custom(
                            "Duplicate map key inside manifest header payload",
                        ));
                    }
                    let _ = map.next_value::<StrictSkipValue>()?;
                }
                Ok(StrictSkipValue)
            }
        }

        deserializer.deserialize_any(SkipVisitor)
    }
}

struct ManifestPreScan {
    critical: Option<Vec<String>>,
    present_keys: BTreeSet<String>,
    non_critical_fields: BTreeMap<String, MsgPackMetaValue>,
}

fn scan_manifest_header_bytes(bytes: &[u8]) -> Result<ManifestPreScan> {
    struct TopMapSeed;

    impl<'de> de::DeserializeSeed<'de> for TopMapSeed {
        type Value = ManifestPreScan;

        fn deserialize<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> std::result::Result<Self::Value, D::Error> {
            struct TopMapVisitor;

            impl<'de> Visitor<'de> for TopMapVisitor {
                type Value = ManifestPreScan;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("MessagePack manifest header map")
                }

                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> std::result::Result<Self::Value, A::Error> {
                    let mut critical: Option<Vec<String>> = None;
                    let mut present_keys = BTreeSet::new();
                    let mut non_critical_fields = BTreeMap::new();

                    while let Some(key) = map.next_key::<String>()? {
                        if key == "critical" {
                            if critical.is_some() {
                                return Err(de::Error::custom(
                                    "Duplicate 'critical' key in manifest header",
                                ));
                            }
                            critical = Some(map.next_value::<Vec<String>>()?);
                            continue;
                        }
                        if !present_keys.insert(key.clone()) {
                            return Err(de::Error::custom(format!(
                                "Duplicate manifest header key '{key}'"
                            )));
                        }
                        if KNOWN_MANIFEST_FIELDS.contains(&key.as_str()) {
                            let _ = map.next_value::<StrictSkipValue>()?;
                        } else {
                            let val = map.next_value::<MsgPackMetaValue>()?;
                            non_critical_fields.insert(key, val);
                        }
                    }

                    Ok(ManifestPreScan {
                        critical,
                        present_keys,
                        non_critical_fields,
                    })
                }
            }

            deserializer.deserialize_map(TopMapVisitor)
        }
    }

    let mut cursor = Cursor::new(bytes);
    let scan = {
        let mut de = rmp_serde::Deserializer::new(&mut cursor);
        de::DeserializeSeed::deserialize(TopMapSeed, &mut de).map_err(|e| {
            CfmsError::ArchiveIntegrity(format!("Malformed manifest header payload: {e}"))
        })?
    };
    if cursor.position() as usize != bytes.len() {
        return Err(CfmsError::ArchiveIntegrity(format!(
            "Manifest header payload contains {} trailing bytes",
            bytes.len() - cursor.position() as usize
        )));
    }
    Ok(scan)
}

/// Streaming reader for `cfms-stream-v2` records that validates record lengths before allocation
/// and reads `ManifestHeader` upfront before exposing subsequent records.
#[derive(Debug)]
pub struct StreamRecordReader<R: Read> {
    inner: R,
    saw_footer: bool,
}

impl<R: Read> StreamRecordReader<R> {
    /// Open a stream reader and parse the mandatory leading [`ManifestHeader`], enforcing
    /// `CRITICAL` field semantics before full struct decoding.
    pub fn open(mut inner: R) -> Result<(ManifestHeader, Self)> {
        let mut hdr_tag = [0u8; 5];
        inner.read_exact(&mut hdr_tag).map_err(|e| {
            CfmsError::ArchiveIntegrity(format!(
                "Failed to read manifest header record from backup stream: {e}"
            ))
        })?;
        if hdr_tag[0] != TAG_MANIFEST_HEADER {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Expected manifest header record (0x{TAG_MANIFEST_HEADER:02x}), got 0x{:02x}",
                hdr_tag[0]
            )));
        }
        let len = u32::from_le_bytes([hdr_tag[1], hdr_tag[2], hdr_tag[3], hdr_tag[4]]) as usize;
        if len == 0 || len > MAX_HEADER_FRAME_BYTES {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Invalid manifest header frame size {len} bytes"
            )));
        }
        let mut buf = vec![0u8; len];
        inner.read_exact(&mut buf).map_err(|e| {
            CfmsError::ArchiveIntegrity(format!("Truncated manifest header frame: {e}"))
        })?;

        let pre_scan = scan_manifest_header_bytes(&buf)?;
        validate_critical_key_list(
            pre_scan.critical.as_deref(),
            &pre_scan.present_keys,
            MANDATORY_MANIFEST_FIELDS,
            KNOWN_MANIFEST_FIELDS,
            "manifest header",
        )
        .map_err(CfmsError::ArchiveIntegrity)?;

        let mut header: ManifestHeader = rmp_serde::from_slice(&buf).map_err(|e| {
            CfmsError::ArchiveIntegrity(format!("Malformed manifest header payload: {e}"))
        })?;
        header.non_critical_fields = pre_scan.non_critical_fields;
        Ok((
            header,
            Self {
                inner,
                saw_footer: false,
            },
        ))
    }

    /// Read the next stream record (`Ok(None)` strictly once after `IntegrityFooter` at clean EOF).
    pub fn next_record(&mut self) -> Result<Option<StreamRecord>> {
        let mut hdr = [0u8; 5];
        let mut read = 0usize;
        while read < hdr.len() {
            match self.inner.read(&mut hdr[read..]) {
                Ok(0) => {
                    if read == 0 {
                        if self.saw_footer {
                            return Ok(None);
                        }
                        return Err(CfmsError::ArchiveIntegrity(
                            "Backup stream ended unexpectedly before integrity footer".to_string(),
                        ));
                    }
                    return Err(CfmsError::ArchiveIntegrity(
                        "Truncated record frame header in backup stream".to_string(),
                    ));
                }
                Ok(n) => read += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(CfmsError::ArchiveIntegrity(format!("Stream read error: {e}"))),
            }
        }

        if self.saw_footer {
            return Err(CfmsError::ArchiveIntegrity(
                "Unexpected trailing records after archive integrity footer".to_string(),
            ));
        }

        let tag = hdr[0];
        let len = u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        let max_len = match tag {
            TAG_TABLE_ROW_BATCH => MAX_TABLE_BATCH_BYTES,
            TAG_BLOB_CHUNK => 8 + MAX_BLOB_CHUNK_BYTES,
            TAG_INTEGRITY_FOOTER => MAX_FOOTER_FRAME_BYTES,
            TAG_TABLE_START
            | TAG_TABLE_END
            | TAG_BLOB_START
            | TAG_BLOB_END
            | TAG_MISSING_INACTIVE_FILE
            | TAG_FILE_ENTRY => MAX_SMALL_FRAME_BYTES,
            other => {
                return Err(CfmsError::ArchiveIntegrity(format!(
                    "Unknown stream record tag 0x{other:02x}"
                )));
            }
        };
        if len == 0 || len > max_len {
            return Err(CfmsError::ArchiveIntegrity(format!(
                "Record frame (tag 0x{tag:02x}) length {len} outside valid range (1..={max_len})"
            )));
        }

        let mut payload = vec![0u8; len];
        self.inner.read_exact(&mut payload).map_err(|e| {
            CfmsError::ArchiveIntegrity(format!(
                "Truncated record payload (tag 0x{tag:02x}): {e}"
            ))
        })?;

        let record = match tag {
            TAG_TABLE_START => StreamRecord::TableStart(decode_msgpack(&payload, "TableStart")?),
            TAG_TABLE_ROW_BATCH => {
                let batch: TableRowBatchPayload = decode_msgpack(&payload, "TableRowBatch")?;
                for row in &batch.rows {
                    let row_encoded = rmp_serde::to_vec(row).map_err(|e| {
                        CfmsError::ArchiveIntegrity(format!("Invalid row batch item: {e}"))
                    })?;
                    if row_encoded.len() > MAX_ROW_BYTES {
                        return Err(CfmsError::ArchiveIntegrity(format!(
                            "Row in table '{}' exceeds limit ({MAX_ROW_BYTES} bytes)",
                            batch.table_name
                        )));
                    }
                }
                StreamRecord::TableRowBatch(batch)
            }
            TAG_TABLE_END => StreamRecord::TableEnd(decode_msgpack(&payload, "TableEnd")?),
            TAG_BLOB_START => StreamRecord::BlobStart(decode_msgpack(&payload, "BlobStart")?),
            TAG_BLOB_CHUNK => {
                if payload.len() < 8 {
                    return Err(CfmsError::ArchiveIntegrity(
                        "BlobChunk payload shorter than 8-byte blob_id header".to_string(),
                    ));
                }
                let blob_id = u64::from_le_bytes(payload[..8].try_into().unwrap());
                StreamRecord::BlobChunk {
                    blob_id,
                    data: payload[8..].to_vec(),
                }
            }
            TAG_BLOB_END => StreamRecord::BlobEnd(decode_msgpack(&payload, "BlobEnd")?),
            TAG_MISSING_INACTIVE_FILE => {
                StreamRecord::MissingInactiveFile(decode_msgpack(&payload, "MissingInactiveFile")?)
            }
            TAG_FILE_ENTRY => StreamRecord::FileEntry(decode_msgpack(&payload, "FileEntry")?),
            TAG_INTEGRITY_FOOTER => {
                self.saw_footer = true;
                StreamRecord::IntegrityFooter(decode_msgpack(&payload, "IntegrityFooter")?)
            }
            _ => unreachable!(),
        };

        Ok(Some(record))
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

fn decode_msgpack<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|e| {
        CfmsError::ArchiveIntegrity(format!("Malformed {label} record payload: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use crate::db::schema::ddl::builtin_schema_ir;

    #[test]
    fn backup_value_preserves_binary_uuid_float_and_arbitrary_precision_json() {
        let json_val: serde_json::Value =
            serde_json::from_str(r#"{"big": 99999999999999999999999999, "flag": true}"#).unwrap();
        let samples = vec![
            SqlValue::Null,
            SqlValue::Bool(true),
            SqlValue::I64(-42),
            SqlValue::F64(-0.0),
            SqlValue::F64(std::f64::consts::PI),
            SqlValue::Str("hello".to_string()),
            SqlValue::Uuid([0x11; 16]),
            SqlValue::Bytes(vec![0, 1, 255, 128]),
            SqlValue::Json(json_val.clone()),
        ];

        let encoded_vals: Vec<BackupValue> = samples
            .iter()
            .map(|v| BackupValue::from_sql(v).unwrap())
            .collect();
        let raw = rmp_serde::to_vec(&encoded_vals).unwrap();
        let decoded_vals: Vec<BackupValue> = rmp_serde::from_slice(&raw).unwrap();
        assert_eq!(encoded_vals, decoded_vals);

        let sql_back: Vec<SqlValue> = decoded_vals
            .into_iter()
            .map(|v| v.into_sql().unwrap())
            .collect();
        assert_eq!(sql_back[0..8], samples[0..8]);
        assert_eq!(
            serde_json::to_string(&match &sql_back[8] {
                SqlValue::Json(v) => v,
                _ => unreachable!(),
            })
            .unwrap(),
            serde_json::to_string(&json_val).unwrap()
        );
    }

    fn test_manifest_header() -> ManifestHeader {
        let ir = builtin_schema_ir(false);
        ManifestHeader::new(
            "2026-11-14T00:00:00Z".to_string(),
            "0.14.0".to_string(),
            "e952c02c1454".to_string(),
            vec!["accounts".to_string(), "audit".to_string()],
            "local".to_string(),
            vec![],
            vec![
                "accounts".to_string(),
                "audit_entries".to_string(),
            ],
            BTreeMap::new(),
            ir,
            ConfigurationPayload::default(),
        )
    }

    fn encode_msgpack_frame(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + payload.len());
        out.push(tag);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn encode_custom_manifest_map(
        base: &ManifestHeader,
        mutate: impl FnOnce(&mut Vec<(String, MsgPackMetaValue)>),
    ) -> Vec<u8> {
        let raw = rmp_serde::to_vec_named(base).unwrap();
        let map: BTreeMap<String, MsgPackMetaValue> = rmp_serde::from_slice(&raw).unwrap();
        let mut entries: Vec<(String, MsgPackMetaValue)> = map.into_iter().collect();
        mutate(&mut entries);

        let mut payload = Vec::new();
        let count = entries.len();
        if count <= 15 {
            payload.push(0x80 | (count as u8));
        } else {
            payload.push(0xde);
            payload.extend_from_slice(&(count as u16).to_be_bytes());
        }
        for (k, v) in entries {
            payload.extend_from_slice(&rmp_serde::to_vec_named(&k).unwrap());
            payload.extend_from_slice(&rmp_serde::to_vec_named(&v).unwrap());
        }
        payload
    }

    #[test]
    fn stream_codec_rejects_oversized_or_unterminated_frames() {
        // Frame claiming 1 GiB length must be rejected before allocating buffer
        let mut buf = Vec::new();
        let manifest = test_manifest_header();
        let mut w = StreamRecordWriter::new(&mut buf);
        w.write_manifest_header(&manifest).unwrap();
        buf.push(TAG_TABLE_ROW_BATCH);
        buf.extend_from_slice(&(u32::MAX - 10).to_le_bytes());

        let (_, mut r) = StreamRecordReader::open(Cursor::new(&buf)).unwrap();
        let err = r.next_record().unwrap_err();
        assert!(err.to_string().contains("outside valid range"));
    }

    #[test]
    fn manifest_header_tolerates_unknown_non_critical_fields() {
        let base = test_manifest_header();
        let payload = encode_custom_manifest_map(&base, |entries| {
            entries.push((
                "future_note".to_string(),
                MsgPackMetaValue::Str("tolerated-v2".to_string()),
            ));
            entries.push((
                "future_blob".to_string(),
                MsgPackMetaValue::Bytes(vec![0xca, 0xfe, 0xba, 0xbe]),
            ));
            let mut nested = BTreeMap::new();
            nested.insert("flag".to_string(), MsgPackMetaValue::Bool(true));
            entries.push(("future_map".to_string(), MsgPackMetaValue::Map(nested)));
        });
        let frame = encode_msgpack_frame(TAG_MANIFEST_HEADER, &payload);

        let (header, _) = StreamRecordReader::open(Cursor::new(&frame)).unwrap();
        assert_eq!(header.content_type, MANIFEST_CONTENT_TYPE);
        assert_eq!(header.version, BACKUP_FORMAT_VERSION);
        assert_eq!(
            header.non_critical_fields.get("future_note"),
            Some(&MsgPackMetaValue::Str("tolerated-v2".to_string()))
        );
        assert_eq!(
            header.non_critical_fields.get("future_blob"),
            Some(&MsgPackMetaValue::Bytes(vec![0xca, 0xfe, 0xba, 0xbe]))
        );
        assert!(header.non_critical_fields.contains_key("future_map"));
    }

    fn push_critical_field(entries: &mut [(String, MsgPackMetaValue)], field: &str) {
        for (k, v) in entries.iter_mut() {
            if k == "critical"
                && let MsgPackMetaValue::Array(arr) = v
            {
                arr.push(MsgPackMetaValue::Str(field.to_string()));
            }
        }
    }

    #[test]
    fn manifest_header_rejects_unknown_critical_and_malformed_declarations() {
        let base = test_manifest_header();

        // 1. Unknown critical field (even when its value is present in MessagePack)
        let payload_unknown = encode_custom_manifest_map(&base, |entries| {
            push_critical_field(entries, "future_critical_ext");
            entries.push((
                "future_critical_ext".to_string(),
                MsgPackMetaValue::Bool(true),
            ));
        });
        let err = StreamRecordReader::open(Cursor::new(&encode_msgpack_frame(
            TAG_MANIFEST_HEADER,
            &payload_unknown,
        )))
        .unwrap_err();
        assert!(matches!(err, CfmsError::ArchiveIntegrity(_)));
        assert!(err.to_string().contains("future_critical_ext"));

        // 2. Dangling critical optional field (`created_at` in `critical`, omitted from map)
        let payload_dangling = encode_custom_manifest_map(&base, |entries| {
            entries.retain(|(k, _)| k != "created_at");
            push_critical_field(entries, "created_at");
        });
        let err = StreamRecordReader::open(Cursor::new(&encode_msgpack_frame(
            TAG_MANIFEST_HEADER,
            &payload_dangling,
        )))
        .unwrap_err();
        assert!(matches!(err, CfmsError::ArchiveIntegrity(_)));
        assert!(err.to_string().contains("created_at"));

        // 3. Omitting `critical` key completely must fail
        let payload_no_critical = encode_custom_manifest_map(&base, |entries| {
            entries.retain(|(k, _)| k != "critical");
        });
        let err = StreamRecordReader::open(Cursor::new(&encode_msgpack_frame(
            TAG_MANIFEST_HEADER,
            &payload_no_critical,
        )))
        .unwrap_err();
        assert!(matches!(err, CfmsError::ArchiveIntegrity(_)));
        assert!(err.to_string().contains("critical"));

        // 4. Omitting a mandatory baseline field (`schema_revision`) from the map must fail
        let payload_missing_mandatory = encode_custom_manifest_map(&base, |entries| {
            entries.retain(|(k, _)| k != "schema_revision");
        });
        let err = StreamRecordReader::open(Cursor::new(&encode_msgpack_frame(
            TAG_MANIFEST_HEADER,
            &payload_missing_mandatory,
        )))
        .unwrap_err();
        assert!(matches!(err, CfmsError::ArchiveIntegrity(_)));
        assert!(err.to_string().contains("schema_revision"));

        // 4b. Self-referential `critical` array must fail
        let payload_self_critical = encode_custom_manifest_map(&base, |entries| {
            push_critical_field(entries, "critical");
        });
        let err = StreamRecordReader::open(Cursor::new(&encode_msgpack_frame(
            TAG_MANIFEST_HEADER,
            &payload_self_critical,
        )))
        .unwrap_err();
        assert!(matches!(err, CfmsError::ArchiveIntegrity(_)));
        assert!(err.to_string().contains("self-reference"));

        // 5. Duplicate MessagePack top-level key must fail
        let payload_dup = encode_custom_manifest_map(&base, |entries| {
            entries.push((
                "future_note".to_string(),
                MsgPackMetaValue::Str("first".to_string()),
            ));
            entries.push((
                "future_note".to_string(),
                MsgPackMetaValue::Str("second".to_string()),
            ));
        });
        let err = StreamRecordReader::open(Cursor::new(&encode_msgpack_frame(
            TAG_MANIFEST_HEADER,
            &payload_dup,
        )))
        .unwrap_err();
        assert!(matches!(err, CfmsError::ArchiveIntegrity(_)));
        assert!(err.to_string().contains("Duplicate"));

        // 6. Trailing bytes after MessagePack map must fail
        let mut payload_trailing = rmp_serde::to_vec_named(&base).unwrap();
        payload_trailing.extend_from_slice(&[0x01, 0x02]);
        let err = StreamRecordReader::open(Cursor::new(&encode_msgpack_frame(
            TAG_MANIFEST_HEADER,
            &payload_trailing,
        )))
        .unwrap_err();
        assert!(matches!(err, CfmsError::ArchiveIntegrity(_)));
        assert!(err.to_string().contains("trailing bytes"));
    }

    #[test]
    fn validate_manifest_header_checks_content_type_version_ir_and_critical_semantics() {
        let base = test_manifest_header();
        let envelope = BackupHeaderReport {
            path: "test.confbak".to_string(),
            file_size: 1024,
            content_type: crate::ops::backup::format::BACKUP_CONTENT_TYPE.to_string(),
            version: BACKUP_FORMAT_VERSION,
            critical: vec![],
            created_at: base.created_at.clone(),
            server_version: base.server_version.clone(),
            schema_revision: base.schema_revision.clone(),
            components: base.components.clone(),
            cipher: crate::ops::backup::format::BACKUP_CIPHER.to_string(),
            compression: "zstd".to_string(),
            container: crate::ops::backup::format::BACKUP_CONTAINER.to_string(),
            kdf: crate::ops::backup::format::BACKUP_KDF.to_string(),
            chunk_size: 1024,
            kdf_salt: "salt".to_string(),
            nonce_prefix: "prefix".to_string(),
            storage_provider: "local".to_string(),
            non_critical_fields: BTreeMap::new(),
        };
        let expected_tables = BTreeSet::new();

        // Wrong content_type
        let mut bad_ct = base.clone();
        bad_ct.content_type = "wrong-type".to_string();
        assert!(validate_manifest_header(&bad_ct, &envelope, &expected_tables).is_err());

        // Unsupported schema_ir.ir_version
        let mut bad_ir = base.clone();
        bad_ir.schema_ir.ir_version = SCHEMA_IR_VERSION + 1;
        let err = validate_manifest_header(&bad_ir, &envelope, &expected_tables).unwrap_err();
        assert!(err.to_string().contains("schema IR version"));

        // Critical optional field `created_at` set to invalid timestamp must fail
        let mut bad_created = base.clone();
        bad_created.critical.push("created_at".to_string());
        bad_created.created_at = "not-an-rfc3339-time".to_string();
        let mut env_bad_created = envelope.clone();
        env_bad_created.created_at = bad_created.created_at.clone();
        let err =
            validate_manifest_header(&bad_created, &env_bad_created, &expected_tables).unwrap_err();
        assert!(err.to_string().contains("RFC 3339"));
    }
}