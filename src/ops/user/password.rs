//! Password policy resolution, CSPRNG generation, validation, secure input,
//! and Argon2id hashing compatible with `cfms_on_websocket` (`argon2-cffi` defaults).

use std::collections::HashSet;
use std::io::{IsTerminal, Read};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use dialoguer::Password;
use rand::Rng as _;
use rand::seq::{IndexedRandom as _, SliceRandom as _};
use regex::Regex;
use zeroize::Zeroizing;
use crate::cli::user::UserResetPasswordArgs;
use crate::core::error::{CfmsError, Result};
use crate::core::paths::WorkspacePaths;
use crate::db::DbPool;
use crate::db::options::{OptionsSchemaRegistry, list_options};
use crate::ui::UiConsole;

/// `argon2-cffi` 25.1.0 `PasswordHasher()` default memory cost in KiB (64 MiB).
pub const ARGON2_MEMORY_KIB: u32 = 65_536;
/// `argon2-cffi` 25.1.0 `PasswordHasher()` default iterations.
pub const ARGON2_TIME_COST: u32 = 3;
/// `argon2-cffi` 25.1.0 `PasswordHasher()` default parallelism lanes.
pub const ARGON2_PARALLELISM: u32 = 4;
/// `argon2-cffi` 25.1.0 `PasswordHasher()` default output hash length in bytes.
pub const ARGON2_OUTPUT_LEN: usize = 32;

const DEFAULT_MIN_LENGTH: usize = 8;
const DEFAULT_MAX_LENGTH: usize = 32;
const DEFAULT_GENERATED_TARGET_LEN: usize = 16;
const DEFAULT_MIN_PASSED_COUNT: usize = 2;
const DEFAULT_RULES: &[&str] = &["[A-Z]", "[a-z]", "[0-9]", "[!@#$%^&*()]"];

const UPPER_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGIT_CHARS: &[u8] = b"0123456789";
const SYMBOL_CHARS: &[u8] = b"!@#$%^&*()";
const ALL_PASSWORD_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";

/// Effective `security.password` rules resolved from database options and CFMS defaults.
#[derive(Debug, Clone)]
pub struct PasswordPolicyConfig {
    pub passwd_min_length: usize,
    pub passwd_max_length: usize,
    pub passwd_rules: Vec<String>,
    pub passwd_min_passed_count: usize,
}

impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            passwd_min_length: DEFAULT_MIN_LENGTH,
            passwd_max_length: DEFAULT_MAX_LENGTH,
            passwd_rules: DEFAULT_RULES.iter().map(|s| (*s).to_string()).collect(),
            passwd_min_passed_count: DEFAULT_MIN_PASSED_COUNT,
        }
    }
}

impl PasswordPolicyConfig {
    /// Load `security.password` options from database, workspace `core_config_contract` (when present),
    /// and built-in CFMS server defaults.
    pub async fn load(pool: &DbPool, paths: &WorkspacePaths) -> Result<Self> {
        let registry = OptionsSchemaRegistry::from_workspace(paths, None)?;
        let records = list_options(pool, &registry, Some("security.password")).await?;

        let mut cfg = Self::default();
        for rec in records {
            match rec.option_key.as_str() {
                "passwd_min_length" => {
                    let val = rec.value.as_u64().ok_or_else(|| {
                        CfmsError::Config(
                            "Invalid security.password.passwd_min_length: expected positive integer"
                                .to_string(),
                        )
                    })?;
                    let min_len = usize::try_from(val).map_err(|_| {
                        CfmsError::Config(
                            "security.password.passwd_min_length out of range".to_string(),
                        )
                    })?;
                    if min_len == 0 {
                        return Err(CfmsError::Config(
                            "Invalid security.password.passwd_min_length: must be >= 1".to_string(),
                        ));
                    }
                    cfg.passwd_min_length = min_len;
                }
                "passwd_max_length" => {
                    let val = rec.value.as_u64().ok_or_else(|| {
                        CfmsError::Config(
                            "Invalid security.password.passwd_max_length: expected positive integer"
                                .to_string(),
                        )
                    })?;
                    let max_len = usize::try_from(val).map_err(|_| {
                        CfmsError::Config(
                            "security.password.passwd_max_length out of range".to_string(),
                        )
                    })?;
                    if max_len == 0 {
                        return Err(CfmsError::Config(
                            "Invalid security.password.passwd_max_length: must be >= 1".to_string(),
                        ));
                    }
                    cfg.passwd_max_length = max_len;
                }
                "passwd_rules" => {
                    let arr = rec.value.as_array().ok_or_else(|| {
                        CfmsError::Config(
                            "Invalid security.password.passwd_rules: expected array of regex strings"
                                .to_string(),
                        )
                    })?;
                    let mut rules = Vec::with_capacity(arr.len());
                    for item in arr {
                        let s = item.as_str().ok_or_else(|| {
                            CfmsError::Config(
                                "Invalid security.password.passwd_rules item: expected string"
                                    .to_string(),
                            )
                        })?;
                        rules.push(s.to_string());
                    }
                    cfg.passwd_rules = rules;
                }
                "passwd_min_passed_count" => {
                    let val = rec.value.as_u64().ok_or_else(|| {
                        CfmsError::Config(
                            "Invalid security.password.passwd_min_passed_count: expected non-negative integer"
                                .to_string(),
                        )
                    })?;
                    cfg.passwd_min_passed_count = usize::try_from(val).map_err(|_| {
                        CfmsError::Config(
                            "security.password.passwd_min_passed_count out of range".to_string(),
                        )
                    })?;
                }
                _ => {}
            }
        }

        cfg.ensure_consistent()?;
        Ok(cfg)
    }

    /// Verify policy bounds and compile all regex rules.
    pub fn ensure_consistent(&self) -> Result<Vec<(String, Regex)>> {
        if self.passwd_min_length == 0 {
            return Err(CfmsError::Config(
                "Invalid security.password policy: passwd_min_length must be >= 1".to_string(),
            ));
        }
        if self.passwd_min_length > self.passwd_max_length {
            return Err(CfmsError::Config(format!(
                "Invalid security.password policy: minimum length ({}) exceeds maximum ({})",
                self.passwd_min_length, self.passwd_max_length
            )));
        }

        let mut seen = HashSet::new();
        let mut compiled = Vec::with_capacity(self.passwd_rules.len());
        for pattern in &self.passwd_rules {
            if !seen.insert(pattern.as_str()) {
                continue;
            }
            let regex = Regex::new(pattern).map_err(|e| {
                CfmsError::Config(format!(
                    "Invalid regex in security.password.passwd_rules ({pattern:?}): {e}"
                ))
            })?;
            compiled.push((pattern.clone(), regex));
        }
        Ok(compiled)
    }

    /// Validate a candidate password strictly against length and rule policy.
    pub fn validate(&self, candidate: &str) -> Result<()> {
        if candidate.is_empty() {
            return Err(CfmsError::InvalidArgument(
                "Password must not be empty".to_string(),
            ));
        }

        let compiled = self.ensure_consistent()?;
        let char_len = candidate.chars().count();
        if char_len < self.passwd_min_length || char_len > self.passwd_max_length {
            return Err(CfmsError::InvalidArgument(format!(
                "Password length {char_len} does not meet policy requirement ({}..={})",
                self.passwd_min_length, self.passwd_max_length
            )));
        }

        if compiled.is_empty() || self.passwd_min_passed_count == 0 {
            return Ok(());
        }

        let required = self.passwd_min_passed_count.min(compiled.len());
        let mut passed = 0usize;
        let mut unpassed = Vec::new();
        for (pattern, re) in &compiled {
            if re.is_match(candidate) {
                passed += 1;
            } else {
                unpassed.push(pattern.as_str());
            }
        }

        if passed < required {
            return Err(CfmsError::InvalidArgument(format!(
                "Password does not meet security.password rules: {passed} passed, at least {required} required (unpassed: {})",
                unpassed.join(", ")
            )));
        }

        Ok(())
    }

    /// Generate a cryptographically random password satisfying length and active rules.
    pub fn generate_compliant(&self) -> Result<Zeroizing<String>> {
        let compiled = self.ensure_consistent()?;
        let target_len = DEFAULT_GENERATED_TARGET_LEN
            .clamp(self.passwd_min_length, self.passwd_max_length);

        let standard_buckets: [(&str, &[u8]); 4] = [
            ("[A-Z]", UPPER_CHARS),
            ("[a-z]", LOWER_CHARS),
            ("[0-9]", DIGIT_CHARS),
            ("[!@#$%^&*()]", SYMBOL_CHARS),
        ];

        // Collect guaranteed character pools for standard rules configured in policy
        // (or all 4 buckets when no standard rule matches, so generated passwords remain strong).
        let mut required_pools: Vec<&[u8]> = standard_buckets
            .iter()
            .filter_map(|(rule, pool)| {
                self.passwd_rules.iter().any(|r| r == rule).then_some(*pool)
            })
            .collect();
        if required_pools.is_empty() {
            required_pools = standard_buckets.iter().map(|(_, p)| *p).collect();
        }

        let max_standard_hits = required_pools.len().min(target_len);
        let mut rng = rand::rng();

        for _attempt in 0..512 {
            let mut buf = Zeroizing::new(Vec::with_capacity(target_len));
            for pool in required_pools.iter().take(max_standard_hits) {
                if let Some(&ch) = pool.choose(&mut rng) {
                    buf.push(ch);
                }
            }
            while buf.len() < target_len {
                if let Some(&ch) = ALL_PASSWORD_CHARS.choose(&mut rng) {
                    buf.push(ch);
                }
            }
            buf.shuffle(&mut rng);

            let candidate_str = String::from_utf8(buf.to_vec()).map_err(|e| {
                CfmsError::Config(format!("Internal UTF-8 error generating password: {e}"))
            })?;
            let candidate = Zeroizing::new(candidate_str);

            if self.validate(&candidate).is_err() {
                continue;
            }
            // If all standard buckets fit in `target_len`, require hitting every standard rule too.
            let std_hits_all = required_pools.iter().take(max_standard_hits).all(|pool| {
                candidate
                    .as_bytes()
                    .iter()
                    .any(|b| pool.contains(b))
            });
            let custom_sufficient = compiled.is_empty()
                || self.passwd_min_passed_count == 0
                || compiled
                    .iter()
                    .filter(|(_, re)| re.is_match(&candidate))
                    .count()
                    >= self.passwd_min_passed_count.min(compiled.len());

            if std_hits_all && custom_sufficient {
                return Ok(candidate);
            }
        }

        Err(CfmsError::Config(
            "Unable to automatically generate a password matching custom security.password.passwd_rules; pass --password-stdin or --prompt-password instead"
                .to_string(),
        ))
    }
}

/// Resolved password material ready to be hashed.
pub enum ResolvedPassword {
    /// Randomly generated during execution (exposed in `PasswordResetReport`).
    Generated(Zeroizing<String>),
    /// Caller-supplied via `--password`, `--password-stdin`, or `--prompt-password`.
    Explicit(Zeroizing<String>),
}

impl ResolvedPassword {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Generated(s) | Self::Explicit(s) => s,
        }
    }

    #[must_use]
    pub fn generated_plain(&self) -> Option<String> {
        match self {
            Self::Generated(s) => Some(s.to_string()),
            Self::Explicit(_) => None,
        }
    }
}

/// Resolve and validate explicit password input before DB write transactions (or return `None`
/// to indicate random generation should happen once user existence and policy are confirmed).
pub async fn read_explicit_password_input(
    args: &UserResetPasswordArgs,
    ui: &UiConsole,
) -> Result<Option<Zeroizing<String>>> {
    if let Some(raw) = &args.password {
        if raw.is_empty() {
            return Err(CfmsError::InvalidArgument(
                "`--password` cannot be empty; omit it to generate a secure random password"
                    .to_string(),
            ));
        }
        ui.print_warning(
            "Passing `--password` via command arguments exposes secrets in shell history and process listings; prefer `--password-stdin` or `--prompt-password`.",
        );
        return Ok(Some(Zeroizing::new(raw.clone())));
    }

    if args.password_stdin {
        let secret = tokio::task::spawn_blocking(|| -> Result<Zeroizing<String>> {
            let mut buf = Zeroizing::new(String::new());
            std::io::stdin().read_to_string(&mut buf)?;
            let stripped = buf
                .strip_suffix("\r\n")
                .or_else(|| buf.strip_suffix('\n'))
                .unwrap_or(&buf);
            if stripped.is_empty() {
                return Err(CfmsError::InvalidArgument(
                    "Password received on stdin is empty".to_string(),
                ));
            }
            Ok(Zeroizing::new(stripped.to_string()))
        })
        .await
        .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))??;
        return Ok(Some(secret));
    }

    if args.prompt_password {
        if !std::io::stdin().is_terminal() {
            return Err(CfmsError::InvalidArgument(
                "Cannot use `--prompt-password` without an interactive terminal; use `--password-stdin` or omit password flags to generate one"
                    .to_string(),
            ));
        }
        let username = args.username.clone();
        let secret = tokio::task::spawn_blocking(move || -> Result<Zeroizing<String>> {
            let entered = Password::new()
                .with_prompt(format!("New password for '{username}'"))
                .with_confirmation("Confirm new password", "Passwords did not match")
                .allow_empty_password(false)
                .interact()
                .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))?;
            Ok(Zeroizing::new(entered))
        })
        .await
        .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))??;
        return Ok(Some(secret));
    }

    Ok(None)
}

/// Generate a cryptographically random lowercase hex identifier/secret of `byte_len * 2` chars.
#[must_use]
pub fn generate_random_hex(byte_len: usize) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new(vec![0u8; byte_len]);
    rand::rng().fill_bytes(&mut bytes);
    Zeroizing::new(hex::encode(&*bytes))
}

/// Hash a plain password using `Argon2id` (`v=19, m=65536, t=3, p=4, out=32, salt=16`) matching
/// `cfms_on_websocket`'s `argon2-cffi 25.1.0` `PasswordHasher()` defaults (no HMAC pepper).
pub async fn hash_password_argon2id(password: Zeroizing<String>) -> Result<String> {
    tokio::task::spawn_blocking(move || -> Result<String> {
        let params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(|e| CfmsError::Config(format!("Invalid Argon2id parameters: {e}")))?;

        let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let phc = hasher
            .hash_password(password.as_bytes())
            .map_err(|e| CfmsError::Database(format!("Failed to hash password with Argon2id: {e}")))?;
        Ok(phc.to_string())
    })
    .await
    .map_err(|e| CfmsError::Io(std::io::Error::other(e.to_string())))?
}

#[cfg(test)]
mod tests {
    use argon2::password_hash::PasswordVerifier;
    use argon2::password_hash::phc::PasswordHash;
    use super::*;

    #[tokio::test]
    async fn argon2id_hash_matches_argon2_cffi_parameters_and_verifies() {
        let raw = Zeroizing::new("CorrectHorseBatteryStaple42!".to_string());
        let phc = hash_password_argon2id(raw.clone()).await.expect("hash");

        assert!(
            phc.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"),
            "unexpected PHC prefix: {phc}"
        );

        let parsed = PasswordHash::new(&phc).expect("parse PHC");
        assert_eq!(parsed.salt.as_ref().map(|s| s.len()), Some(16));
        Argon2::default()
            .verify_password(raw.as_bytes(), &parsed)
            .expect("verify with default Argon2 verifier");
        assert!(
            Argon2::default()
                .verify_password(b"wrong-password", &parsed)
                .is_err()
        );
    }

    #[test]
    fn password_policy_validation_and_generation() {
        let policy = PasswordPolicyConfig::default();

        assert!(policy.validate("").is_err());
        assert!(policy.validate("Ab1!").is_err());
        assert!(policy.validate("onlylowercasechars").is_err());
        assert!(policy.validate(&"A".repeat(33)).is_err());
        assert!(policy.validate("Pass1234").is_ok()); // passes [A-Z], [a-z], [0-9] (3 >= 2)

        for _ in 0..50 {
            let generated = policy.generate_compliant().expect("generate");
            assert_eq!(generated.chars().count(), 16);
            assert!(policy.validate(&generated).is_ok());
            assert!(generated.bytes().any(|b| SYMBOL_CHARS.contains(&b)));
            assert!(!generated.contains('/') && !generated.contains('?'));
        }
    }

    #[test]
    fn password_policy_custom_strict_rules_and_bounds() {
        let custom = PasswordPolicyConfig {
            passwd_min_length: 20,
            passwd_max_length: 24,
            passwd_rules: vec![
                "[A-Z]".to_string(),
                "[a-z]".to_string(),
                "[0-9]".to_string(),
                "[!@#$%^&*()]".to_string(),
                "[A-Z]".to_string(), // duplicate rule must not double-count
            ],
            passwd_min_passed_count: 4,
        };
        assert!(custom.validate("Aa1!missinglen").is_err());
        assert!(custom.validate("alllowercase1234567890!").is_err());

        for _ in 0..20 {
            let generated = custom.generate_compliant().expect("generate custom");
            assert!((20..=24).contains(&generated.chars().count()));
            assert!(custom.validate(&generated).is_ok());
        }
    }

    #[test]
    fn generate_random_hex_produces_expected_length() {
        let hex32 = generate_random_hex(32);
        assert_eq!(hex32.len(), 64);
        assert!(hex32.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }
}
