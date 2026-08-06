//! Token brokering: resolve a target API (audience), check eligibility, project permissions, apply
//! the claim mapping, and mint an access token. Shared by login, API-key exchange, and the user
//! downstream exchange. See `docs/AUDIENCES.md`.

use crate::auth::tokens::{AccessTokenClaims, TokenIssuer};
use crate::config::Config;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use warp::http::StatusCode;
use wasabi::{client_bail, status_bail};

/// Everything needed to mint a token for a principal (user or API key) against a target API.
pub struct MintParams<'a> {
    /// Target API code in the config `apis` catalog.
    pub api_code: &'a str,
    /// `sub` (user id or key id).
    pub subject: &'a str,
    pub name: &'a str,
    pub email: &'a str,
    pub locale: &'a str,
    pub tenant_id: &'a str,
    pub token_version: u32,
    /// The principal's role codes (→ base permissions via config).
    pub roles: &'a [String],
    /// Optional down-scoping: when non-empty, the resolved base permissions are **intersected** with
    /// this set before eligibility/projection (used by personal access tokens; never an escalation).
    pub scopes: &'a [String],
    /// The tenant's effective features.
    pub features: &'a [String],
    pub user_custom_fields: &'a BTreeMap<String, Value>,
    pub tenant_custom_fields: &'a BTreeMap<String, Value>,
    /// Extra `kind` claim (e.g. `"api_key"`), if any.
    pub kind: Option<&'a str>,
    pub access_ttl_secs: i64,
}

/// Mints an access token for the target API: eligibility → permission projection → claim mapping.
/// Returns `(access_token, exp)`. Unknown API → client error; ineligibility → 403.
pub async fn mint_for_api(
    tokens: &TokenIssuer,
    config: &Config,
    params: MintParams<'_>,
) -> anyhow::Result<(String, i64)> {
    let api = match config.find_api(params.api_code) {
        Some(api) => api,
        None => client_bail!("Unknown API '{}'", params.api_code),
    };

    let mut base_permissions = config.permissions_for_roles(params.roles);
    // Down-scope (PATs): keep only permissions also present in `scopes`. Never adds permissions.
    if !params.scopes.is_empty() {
        base_permissions.retain(|permission| params.scopes.contains(permission));
    }
    if !api.is_eligible(&base_permissions, params.features) {
        status_bail!(
            StatusCode::FORBIDDEN,
            "Not eligible for API '{}'",
            params.api_code
        );
    }

    let permissions = api.project_permissions(&base_permissions, params.features);
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
                name: params.name,
                email: params.email,
                locale: params.locale,
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
