//! Pure Rust port of CFMS authentication policy evaluation, pruning, and
//! login/MFA/escalation availability invariants (`auth/policies.py` & `commands/auth_policies.py`).

use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Serialize};

pub const LOGIN_DISALLOWED_METHODS: &[&str] = &["totp"];

/// Purpose of an authentication policy row in `user_auth_policies`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthPurpose {
    Login,
    Mfa,
    Escalation,
}

impl AuthPurpose {
    pub const ALL: [Self; 3] = [Self::Login, Self::Mfa, Self::Escalation];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Mfa => "mfa",
            Self::Escalation => "escalation",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "login" => Some(Self::Login),
            "mfa" => Some(Self::Mfa),
            "escalation" => Some(Self::Escalation),
            _ => None,
        }
    }
}

/// One sequential step in an authentication chain (`user_auth_policies.chains`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStep {
    pub method: String,
    pub credential_ids: Vec<String>,
}

/// Loaded authentication policy row for one `(user_id, purpose)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRow {
    pub purpose: AuthPurpose,
    pub revision: i32,
    pub chains: Vec<Vec<AuthStep>>,
}

/// Snapshot of a user's registered authentication factor across credential tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCredential {
    pub method: String,
    pub credential_id: String,
    pub active: bool,
    /// Distinct hardware/key identity (SHA-256 hex fingerprint for `publickey`).
    pub key_identity: Option<String>,
}

/// Planned insert or CAS update against `user_auth_policies`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMutation {
    pub purpose: AuthPurpose,
    pub expected_revision: i32,
    pub new_revision: i32,
    pub new_chains: Vec<Vec<AuthStep>>,
}

/// Built-in provider metadata matching `auth_registry` + `oidc_sso`.
#[must_use]
pub fn method_supports_purpose(method: &str, purpose: AuthPurpose) -> bool {
    match method {
        "password" | "publickey" => true,
        "totp" => matches!(purpose, AuthPurpose::Mfa | AuthPurpose::Escalation),
        "oidc" => matches!(purpose, AuthPurpose::Login),
        _ => false,
    }
}

/// Determine whether a single policy chain can be completed using `credentials`.
#[must_use]
pub fn can_complete_auth_chain(chain: &[AuthStep], credentials: &[RegisteredCredential]) -> bool {
    if chain.is_empty() {
        return false;
    }

    let method = chain[0].method.as_str();
    if !chain.iter().all(|step| step.method == method) {
        return false;
    }

    if method != "publickey" {
        if chain.len() != 1 {
            return false;
        }
        return credentials.iter().any(|c| {
            c.active && c.method == method && chain[0].credential_ids.contains(&c.credential_id)
        });
    }

    // For `publickey`, each step must match an active credential whose physical key identity
    // is distinct from every other step in the chain (bipartite maximum matching).
    let active_pks: Vec<(usize, &str)> = credentials
        .iter()
        .enumerate()
        .filter(|(_, c)| c.active && c.method == "publickey")
        .map(|(idx, c)| {
            let ident = c.key_identity.as_deref().unwrap_or(&c.credential_id);
            (idx, ident)
        })
        .collect();

    // Build distinct key identity index -> step adjacency so identical underlying fingerprints share one node.
    let mut distinct_identities: Vec<&str> = Vec::new();
    for &(_, ident) in &active_pks {
        if !distinct_identities.contains(&ident) {
            distinct_identities.push(ident);
        }
    }

    let step_candidates: Vec<Vec<usize>> = chain
        .iter()
        .map(|step| {
            let mut matched_idents = Vec::new();
            for &(cred_idx, ident) in &active_pks {
                let cred_id = &credentials[cred_idx].credential_id;
                if step.credential_ids.contains(cred_id)
                    && let Some(ident_id) = distinct_identities.iter().position(|&x| x == ident)
                    && !matched_idents.contains(&ident_id)
                {
                    matched_idents.push(ident_id);
                }
            }
            matched_idents
        })
        .collect();

    if step_candidates.iter().any(Vec::is_empty) {
        return false;
    }

    // Kuhn's bipartite matching: match every step (left) to a unique key identity (right).
    let mut match_right: Vec<Option<usize>> = vec![None; distinct_identities.len()];
    for step_idx in 0..chain.len() {
        let mut visited = vec![false; distinct_identities.len()];
        if !kuhn_dfs(step_idx, &step_candidates, &mut visited, &mut match_right) {
            return false;
        }
    }
    true
}

fn kuhn_dfs(
    step_idx: usize,
    step_candidates: &[Vec<usize>],
    visited: &mut [bool],
    match_right: &mut [Option<usize>],
) -> bool {
    for &ident_idx in &step_candidates[step_idx] {
        if visited[ident_idx] {
            continue;
        }
        visited[ident_idx] = true;
        if match_right[ident_idx].is_none()
            || match_right[ident_idx]
                .is_some_and(|prev_step| kuhn_dfs(prev_step, step_candidates, visited, match_right))
        {
            match_right[ident_idx] = Some(step_idx);
            return true;
        }
    }
    false
}

/// Remove references to `method_to_remove` (optionally scoped to `target_credential_id`)
/// from all configured policies, returning only changed purposes.
///
/// Mirrors `remove_credential_from_auth_policies` in `cfms_on_websocket`:
/// - Any chain step whose `credential_ids` pool becomes empty drops the entire chain.
/// - Affected chains are re-validated via `can_complete_auth_chain` treating remaining
///   user credentials as active (`assumed_active`).
/// - Deduplicates retained chains preserving original order, keeping empty `chains: []` rows
///   so `revision += 1` invalidates in-flight `AuthenticationContext` sessions.
#[must_use]
pub fn prune_method_from_policies(
    policies: &BTreeMap<AuthPurpose, PolicyRow>,
    method_to_remove: &str,
    target_credential_id: Option<&str>,
    remaining_credentials: &[RegisteredCredential],
) -> Vec<PolicyMutation> {
    let matches_target = |method: &str, cid: &str| -> bool {
        method == method_to_remove
            && target_credential_id.is_none_or(|target| target == cid)
    };

    let assumed_active: Vec<RegisteredCredential> = remaining_credentials
        .iter()
        .filter(|c| !matches_target(&c.method, &c.credential_id))
        .map(|c| RegisteredCredential {
            active: true,
            ..c.clone()
        })
        .collect();

    let mut mutations = Vec::new();

    for purpose in AuthPurpose::ALL {
        let Some(policy) = policies.get(&purpose) else {
            continue;
        };

        let references_target = policy.chains.iter().any(|chain| {
            chain
                .iter()
                .any(|step| step.credential_ids.iter().any(|cid| matches_target(&step.method, cid)))
        });
        if !references_target {
            continue;
        }

        let mut retained: Vec<Vec<AuthStep>> = Vec::new();
        let mut seen: BTreeSet<Vec<(String, BTreeSet<String>)>> = BTreeSet::new();

        for chain in &policy.chains {
            let affected = chain.iter().any(|step| {
                step.credential_ids
                    .iter()
                    .any(|cid| matches_target(&step.method, cid))
            });

            let mut pruned_chain = Vec::with_capacity(chain.len());
            let mut dropped = false;
            for step in chain {
                let pool: Vec<String> = step
                    .credential_ids
                    .iter()
                    .filter(|cid| !matches_target(&step.method, cid))
                    .cloned()
                    .collect();
                if pool.is_empty() {
                    dropped = true;
                    break;
                }
                pruned_chain.push(AuthStep {
                    method: step.method.clone(),
                    credential_ids: pool,
                });
            }

            if dropped {
                continue;
            }
            if affected && !can_complete_auth_chain(&pruned_chain, &assumed_active) {
                continue;
            }

            let identity: Vec<(String, BTreeSet<String>)> = pruned_chain
                .iter()
                .map(|s| {
                    (
                        s.method.clone(),
                        s.credential_ids.iter().cloned().collect::<BTreeSet<_>>(),
                    )
                })
                .collect();

            if seen.insert(identity) {
                retained.push(pruned_chain);
            }
        }

        if retained != policy.chains {
            mutations.push(PolicyMutation {
                purpose,
                expected_revision: policy.revision,
                new_revision: policy.revision + 1,
                new_chains: retained,
            });
        }
    }

    mutations
}

/// Ensure the user's `login` policy includes a password chain referencing `password_cred_id`.
#[must_use]
pub fn ensure_password_in_login_policy(
    existing_login: Option<&PolicyRow>,
    password_cred_id: &str,
) -> Option<PolicyMutation> {
    let password_chain = vec![AuthStep {
        method: "password".to_string(),
        credential_ids: vec![password_cred_id.to_string()],
    }];

    match existing_login {
        None => Some(PolicyMutation {
            purpose: AuthPurpose::Login,
            expected_revision: 0,
            new_revision: 1,
            new_chains: vec![password_chain],
        }),
        Some(policy) => {
            let already_present = policy.chains.iter().any(|chain| {
                chain.len() == 1
                    && chain[0].method == "password"
                    && chain[0].credential_ids.iter().any(|cid| cid == password_cred_id)
            });
            if already_present {
                return None;
            }
            let mut next_chains = policy.chains.clone();
            next_chains.push(password_chain);
            Some(PolicyMutation {
                purpose: AuthPurpose::Login,
                expected_revision: policy.revision,
                new_revision: policy.revision + 1,
                new_chains: next_chains,
            })
        }
    }
}

/// Compute a view of policies after applying `mutations` in memory (before DB commit/validation).
#[must_use]
pub fn apply_mutations_preview(
    policies: &BTreeMap<AuthPurpose, PolicyRow>,
    mutations: &[PolicyMutation],
) -> BTreeMap<AuthPurpose, PolicyRow> {
    let mut updated = policies.clone();
    for m in mutations {
        updated.insert(
            m.purpose,
            PolicyRow {
                purpose: m.purpose,
                revision: m.new_revision,
                chains: m.new_chains.clone(),
            },
        );
    }
    updated
}

/// Require at least one completable login factor (compatible with MFA factor separation) and
/// preserve any configured escalation factor (`ensure_authentication_available` equivalent).
pub fn ensure_authentication_available(
    policies: &BTreeMap<AuthPurpose, PolicyRow>,
    credentials: &[RegisteredCredential],
) -> std::result::Result<(), &'static str> {
    let mut available: BTreeMap<AuthPurpose, BTreeSet<String>> = BTreeMap::new();

    for purpose in AuthPurpose::ALL {
        let mut methods = BTreeSet::new();
        if let Some(policy) = policies.get(&purpose) {
            for chain in &policy.chains {
                if chain.is_empty() {
                    continue;
                }
                let method = chain[0].method.as_str();
                if chain.iter().all(|s| s.method == method)
                    && method_supports_purpose(method, purpose)
                    && !(purpose == AuthPurpose::Login && LOGIN_DISALLOWED_METHODS.contains(&method))
                    && can_complete_auth_chain(chain, credentials)
                {
                    methods.insert(method.to_string());
                }
            }
        }
        available.insert(purpose, methods);
    }

    let mfa_nonempty = policies
        .get(&AuthPurpose::Mfa)
        .is_some_and(|p| !p.chains.is_empty());
    let login_methods = &available[&AuthPurpose::Login];
    let mfa_methods = &available[&AuthPurpose::Mfa];

    let login_reachable = login_methods.iter().any(|login_method| {
        !mfa_nonempty || mfa_methods.iter().any(|mfa_method| mfa_method != login_method)
    });
    if !login_reachable {
        return Err("login_unavailable");
    }

    let esc_nonempty = policies
        .get(&AuthPurpose::Escalation)
        .is_some_and(|p| !p.chains.is_empty());
    if esc_nonempty && available[&AuthPurpose::Escalation].is_empty() {
        return Err("escalation_unavailable");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(cid: &str, ident: &str) -> RegisteredCredential {
        RegisteredCredential {
            method: "publickey".to_string(),
            credential_id: cid.to_string(),
            active: true,
            key_identity: Some(ident.to_string()),
        }
    }

    fn pwd(cid: &str) -> RegisteredCredential {
        RegisteredCredential {
            method: "password".to_string(),
            credential_id: cid.to_string(),
            active: true,
            key_identity: None,
        }
    }

    fn totp(cid: &str, active: bool) -> RegisteredCredential {
        RegisteredCredential {
            method: "totp".to_string(),
            credential_id: cid.to_string(),
            active,
            key_identity: None,
        }
    }

    #[test]
    fn publickey_bipartite_matching_rejects_duplicate_key_material_and_accepts_distinct() {
        // Two credentials sharing identical fingerprint cannot satisfy a 2-step chain.
        let same_material = vec![pk("k1", "same-fp"), pk("k2", "same-fp")];
        let two_step = vec![
            AuthStep {
                method: "publickey".to_string(),
                credential_ids: vec!["k1".to_string(), "k2".to_string()],
            },
            AuthStep {
                method: "publickey".to_string(),
                credential_ids: vec!["k1".to_string(), "k2".to_string()],
            },
        ];
        assert!(!can_complete_auth_chain(&two_step, &same_material));

        // Distinct fingerprints satisfy overlapping pools via bipartite matching.
        let distinct = vec![pk("k1", "fp-a"), pk("k2", "fp-b")];
        assert!(can_complete_auth_chain(&two_step, &distinct));
    }

    #[test]
    fn prune_totp_keeps_empty_policy_row_with_incremented_revision_and_dedups() {
        let mut policies = BTreeMap::new();
        policies.insert(
            AuthPurpose::Login,
            PolicyRow {
                purpose: AuthPurpose::Login,
                revision: 1,
                chains: vec![vec![AuthStep {
                    method: "password".to_string(),
                    credential_ids: vec!["pwd1".to_string()],
                }]],
            },
        );
        policies.insert(
            AuthPurpose::Mfa,
            PolicyRow {
                purpose: AuthPurpose::Mfa,
                revision: 2,
                chains: vec![vec![
                    AuthStep {
                        method: "totp".to_string(),
                        credential_ids: vec!["totp1".to_string()],
                    },
                    AuthStep {
                        method: "totp".to_string(),
                        credential_ids: vec!["totp1".to_string()],
                    },
                ]],
            },
        );

        let creds = vec![pwd("pwd1")];
        let mutations = prune_method_from_policies(&policies, "totp", Some("totp1"), &creds);
        assert_eq!(mutations.len(), 1);
        assert_eq!(mutations[0].purpose, AuthPurpose::Mfa);
        assert_eq!(mutations[0].expected_revision, 2);
        assert_eq!(mutations[0].new_revision, 3);
        assert!(mutations[0].new_chains.is_empty());

        let preview = apply_mutations_preview(&policies, &mutations);
        assert_eq!(ensure_authentication_available(&preview, &creds), Ok(()));
    }

    #[test]
    fn ensure_auth_available_blocks_totp_removal_when_only_same_factor_mfa_remains() {
        // Login is publickey, MFA is [[totp], [publickey]]. Removing totp leaves MFA == {publickey},
        // which cannot provide a distinct second factor after publickey login!
        let mut policies = BTreeMap::new();
        policies.insert(
            AuthPurpose::Login,
            PolicyRow {
                purpose: AuthPurpose::Login,
                revision: 1,
                chains: vec![vec![AuthStep {
                    method: "publickey".to_string(),
                    credential_ids: vec!["pk1".to_string()],
                }]],
            },
        );
        policies.insert(
            AuthPurpose::Mfa,
            PolicyRow {
                purpose: AuthPurpose::Mfa,
                revision: 1,
                chains: vec![
                    vec![AuthStep {
                        method: "totp".to_string(),
                        credential_ids: vec!["totp1".to_string()],
                    }],
                    vec![AuthStep {
                        method: "publickey".to_string(),
                        credential_ids: vec!["pk1".to_string()],
                    }],
                ],
            },
        );

        let before = vec![pk("pk1", "fp1"), totp("totp1", true)];
        assert_eq!(ensure_authentication_available(&policies, &before), Ok(()));

        let remaining = vec![pk("pk1", "fp1")];
        let mutations = prune_method_from_policies(&policies, "totp", None, &remaining);
        let after = apply_mutations_preview(&policies, &mutations);
        assert_eq!(
            ensure_authentication_available(&after, &remaining),
            Err("login_unavailable")
        );
    }

    #[test]
    fn ensure_password_in_login_policy_adds_or_preserves() {
        let m_insert = ensure_password_in_login_policy(None, "p1").expect("should insert");
        assert_eq!(m_insert.expected_revision, 0);
        assert_eq!(m_insert.new_revision, 1);

        let existing = PolicyRow {
            purpose: AuthPurpose::Login,
            revision: 3,
            chains: vec![vec![AuthStep {
                method: "oidc".to_string(),
                credential_ids: vec!["oidc1".to_string()],
            }]],
        };
        let m_update =
            ensure_password_in_login_policy(Some(&existing), "p1").expect("should append");
        assert_eq!(m_update.expected_revision, 3);
        assert_eq!(m_update.new_revision, 4);
        assert_eq!(m_update.new_chains.len(), 2);

        let updated = PolicyRow {
            purpose: AuthPurpose::Login,
            revision: 4,
            chains: m_update.new_chains,
        };
        assert!(ensure_password_in_login_policy(Some(&updated), "p1").is_none());
    }
}
