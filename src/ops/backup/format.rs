//! Encrypted backup outer envelope framing, Base31/Base64url key management,
//! and HKDF-SHA256 + chunked `AES-256-GCM` streaming reader/writer.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::Path;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{AeadInOut, KeyInit, Tag, inout::InOutBuf},
};
use base64::{Engine as _, engine::general_purpose};
use hkdf::Hkdf;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};
use crate::core::error::{CfmsError, Result};
use crate::ui::{CommandReport, KeyValueTable, UiConsole};

/// Magic prefix identifying `cfms-ctl` encrypted streaming backup containers.
pub const BACKUP_MAGIC: &[u8; 8] = b"CFMSCBK1";
pub const BACKUP_FORMAT_VERSION: u32 = 1;
pub const BACKUP_CIPHER: &str = "aes-256-gcm-hkdf-sha256-chunked-v1";
pub const BACKUP_COMPRESSION: &str = "zstd";
pub const BACKUP_CONTAINER: &str = "cfms-stream-v1";
pub const BACKUP_KDF: &str = "hkdf-sha256";
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
pub const MIN_CHUNK_SIZE: usize = 64;
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_HEADER_BYTES: usize = 1024 * 1024;
pub const MAX_KEY_FILE_BYTES: usize = 4096;

const AES_GCM_TAG_LEN: usize = 16;
const HKDF_INFO_PREFIX: &[u8] = b"cfms-ctl-backup-v1:";
const BASE31_ALPHABET: &[u8; 31] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const ENCODED_BASE31_CHARS: usize = 52;

/// Unencrypted outer header stored at the start of a `.confbak` archive and rendered by `backup info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupHeaderReport {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default)]
    pub file_size: u64,
    #[serde(default)]
    pub format_version: u32,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub server_version: String,
    #[serde(default)]
    pub schema_revision: String,
    #[serde(default)]
    pub components: Vec<String>,
    #[serde(default)]
    pub cipher: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compression: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub container: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kdf: String,
    #[serde(default)]
    pub chunk_size: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kdf_salt: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nonce_prefix: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub storage_provider: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl CommandReport for BackupHeaderReport {
    fn render_human(&self, _ui: &UiConsole) {
        let mut table = KeyValueTable::new("CFMS Backup Archive Info");
        let components = if self.components.is_empty() {
            "(unspecified)".to_string()
        } else {
            self.components.join(", ")
        };
        table
            .row("Archive Path", self.path.clone())
            .row("File Size (bytes)", self.file_size.to_string())
            .row("Format Version", self.format_version.to_string())
            .row("Created At", self.created_at.clone())
            .row("Server Version", self.server_version.clone())
            .row("Schema Revision", self.schema_revision.clone())
            .row("Components", components)
            .row("Cipher", self.cipher.clone())
            .row(
                "Compression",
                if self.compression.is_empty() {
                    "(unspecified)".to_string()
                } else {
                    self.compression.clone()
                },
            )
            .row(
                "Container",
                if self.container.is_empty() {
                    "(unspecified)".to_string()
                } else {
                    self.container.clone()
                },
            );
        table.print();
    }
}

/// Canonical JSON envelope written immediately after `BACKUP_MAGIC` + `u32 BE header_len`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeHeaderSpec {
    pub format_version: u32,
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
    /// Construct a fresh envelope header specification with CSPRNG salt and nonce prefix.
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
        Self {
            format_version: BACKUP_FORMAT_VERSION,
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

/// Write the unencrypted envelope header and return `SHA256(magic || len_be || json_bytes)`.
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
    let len_be = u32::try_from(json_bytes.len())
        .map_err(|_| CfmsError::Backup("Backup header exceeds u32 length".to_string()))?
        .to_be_bytes();

    writer.write_all(BACKUP_MAGIC)?;
    writer.write_all(&len_be)?;
    writer.write_all(&json_bytes)?;

    Ok(compute_envelope_digest(&len_be, &json_bytes))
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

/// Read the unencrypted outer header from an already-opened reader, returning both the parsed
/// report and `SHA256(magic || len_be || json_bytes)` used to bind chunk AEAD keys and AAD.
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
    let header_len = u32::from_be_bytes(len_buf) as usize;
    if header_len == 0 || header_len > MAX_HEADER_BYTES {
        return Err(CfmsError::Backup(format!(
            "Invalid backup header length ({header_len} bytes) in '{path_display}'"
        )));
    }

    let mut header_buf = vec![0u8; header_len];
    reader.read_exact(&mut header_buf).map_err(|e| {
        CfmsError::Backup(format!("Truncated backup header in '{path_display}': {e}"))
    })?;

    let mut report: BackupHeaderReport = serde_json::from_slice(&header_buf).map_err(|e| {
        CfmsError::Backup(format!("Malformed JSON header in backup '{path_display}': {e}"))
    })?;
    report.path = path_display.to_string();
    report.file_size = file_size;

    let digest = compute_envelope_digest(&len_buf, &header_buf);
    Ok((report, digest))
}

/// Validate header cryptographic parameters before starting chunked decryption.
pub fn validate_archive_crypto_header(
    header: &BackupHeaderReport,
) -> Result<(usize, [u8; 16], [u8; 7])> {
    if header.format_version != BACKUP_FORMAT_VERSION {
        return Err(CfmsError::Backup(format!(
            "Unsupported backup format version {} (expected {BACKUP_FORMAT_VERSION})",
            header.format_version
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

fn compute_envelope_digest(len_be: &[u8; 4], json_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BACKUP_MAGIC);
    hasher.update(len_be);
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
        let ct_len_be = u32::try_from(ct_len)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk overflow"))?
            .to_be_bytes();
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

        inner.write_all(&ct_len_be)?;
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

        let ct_len = u32::from_be_bytes([frame_hdr[0], frame_hdr[1], frame_hdr[2], frame_hdr[3]])
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
            vec!["audit".to_string()],
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
        let header_end = 12 + u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]) as usize;
        // First chunk is 5 + 64 + 16 = 85 bytes
        let truncated = wire[..header_end + 85].to_vec();
        let mut cur = Cursor::new(&truncated);
        let (h, d) = read_envelope_and_hash(&mut cur, "test", truncated.len() as u64).unwrap();
        let mut dec = ChunkedDecryptReader::new(cur, &key, &h, d).unwrap();
        assert!(dec.read_to_end(&mut tmp).is_err());

        // 4. Envelope header tampering (even preserving valid JSON length) fails AAD check
        let mut tampered_hdr = wire.clone();
        let pos = wire.windows(5).position(|w| w == b"audit").unwrap();
        tampered_hdr[pos] = b'A';
        let mut cur = Cursor::new(&tampered_hdr);
        let (h, d) = read_envelope_and_hash(&mut cur, "test", tampered_hdr.len() as u64).unwrap();
        let mut dec = ChunkedDecryptReader::new(cur, &key, &h, d).unwrap();
        assert!(dec.read_to_end(&mut tmp).is_err());
    }
}