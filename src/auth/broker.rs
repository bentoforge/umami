//! Token brokering: resolve a target API (audience), check eligibility, project permissions, apply
//! the claim mapping, and mint an access token. Shared by login, API-key exchange, and the user
//! downstream exchange. See `docs/AUDIENCES.md`.

use crate::auth::tokens::{AccessTokenClaims, TokenIssuer};
use crate::config::Config;
use crate::constants::{MESSAGING_CONFIGURED_MARKER, SYSTEM_TENANT_MARKER};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use warp::http::StatusCode;
use wasabi::{client_bail, status_bail};

/// Everything needed to mint a token for a principal (user, PAT, or M2M key) against a target API.
pub struct MintParams<'a> {
    /// Target API code in the config `apis` catalog.
    pub api_code: &'a str,
    /// `sub` (user id or key id).
    pub subject: &'a str,
    pub email: &'a str,
    pub tenant_id: &'a str,
    pub token_version: u32,
    /// The principal's **namespaced subject labels** — a user/PAT's `role:*` (already intersected
    /// for a restricted PAT) or an M2M key's `scope:*`.
    pub subjects: &'a [String],
    /// The tenant's granted features (namespaced `feature:*`).
    pub features: &'a [String],
    /// Whether the token's tenant is the configured system tenant (adds the `is:system-tenant`
    /// synthetic marker to the subject set).
    pub system_tenant: bool,
    pub user_custom_fields: &'a BTreeMap<String, Value>,
    pub tenant_custom_fields: &'a BTreeMap<String, Value>,
    /// Extra `kind` claim (e.g. `"api_key"`), if any.
    pub kind: Option<&'a str>,
    pub access_ttl_secs: i64,
}

/// Mints an access token for the target API: build the subject set → ordered permission
/// accumulate + eligibility → claim mapping. Returns `(access_token, exp)`. Unknown API → client
/// error; ineligibility → 403.
pub async fn mint_for_api(
    tokens: &TokenIssuer,
    config: &Config,
    params: MintParams<'_>,
) -> anyhow::Result<(String, i64)> {
    let api = match config.find_api(params.api_code) {
        Some(api) => api,
        None => client_bail!("Unknown API '{}'", params.api_code),
    };

    // Subject set S = principal's role:*/scope:* ∪ tenant feature:* ∪ synthetic is:*.
    let mut subject_set: Vec<String> = params.subjects.to_vec();
    subject_set.extend(params.features.iter().cloned());
    if params.system_tenant {
        subject_set.push(SYSTEM_TENANT_MARKER.to_owned());
    }
    // Global capability marker: messaging self-service is available when the deployment has a bot
    // and/or WhatsApp number configured.
    if config.messaging.is_configured() {
        subject_set.push(MESSAGING_CONFIGURED_MARKER.to_owned());
    }

    let permissions = match api.resolve(&subject_set) {
        Some(permissions) => permissions,
        None => status_bail!(
            StatusCode::FORBIDDEN,
            "Not eligible for API '{}'",
            params.api_code
        ),
    };

    let mut extra = api.build_claims(
        params.features,
        params.user_custom_fields,
        params.tenant_custom_fields,
    );
    if let Some(kind) = params.kind {
        let _ = extra.insert("kind".to_owned(), json!(kind));
    }

    tokens
        .issue_access_token(
            &AccessTokenClaims {
                subject: params.subject,
                email: params.email,
                tenant: Some(params.tenant_id),
                audience: Some(&api.audience),
                permissions: &permissions,
                token_version: params.token_version,
                extra: &extra,
            },
            params.access_ttl_secs,
        )
        .await
}
