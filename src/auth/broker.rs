//! Token brokering: resolve a target API (audience), check eligibility, project permissions, apply
//! the claim mapping, and mint an access token. Shared by login, API-key exchange, and the user
//! downstream exchange. See `docs/AUDIENCES.md`.

use crate::auth::tokens::{AccessTokenClaims, TokenIssuer};
use crate::config::Config;
use crate::constants::{
    MESSAGING_CONFIGURED_MARKER, PASSKEY_MARKER, SYSTEM_TENANT_MARKER, TOTP_MARKER,
    TWO_FACTOR_MARKER,
};
use serde_json::json;
use std::collections::BTreeMap;
use warp::http::StatusCode;
use wasabi::{client_bail, status_bail};

/// Reads the auth-strength (`amr`) claim off a caller's access token → `(passkey, totp)`, so a
/// re-mint that has no session context (exchange / switch-tenant) can carry forward the second
/// factors the original login established.
pub fn auth_strength(caller: &wasabi::web::auth::user::User) -> (bool, bool) {
    let amr = caller.claim("amr").and_then(|value| value.as_array());
    let has = |method: &str| {
        amr.is_some_and(|entries| entries.iter().any(|entry| entry.as_str() == Some(method)))
    };
    (has("passkey"), has("totp"))
}

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
    /// Whether the session authenticated with a passkey (adds `is:passkey` + `is:2fa`).
    pub passkey: bool,
    /// Whether the session authenticated with a TOTP second factor (adds `is:totp` + `is:2fa`).
    pub totp: bool,
    /// The user principal, when the token acts as a user (`None` for an M2M service key). Source of
    /// the `$user.*` claim references and the composed display names.
    pub user: Option<&'a crate::users::User>,
    /// The token's tenant record, when available. Source of the `$tenant.name`/`slug`/`custom.*`
    /// claim references (`$tenant.id`/`features` come from `tenant_id`/`features` regardless).
    pub tenant: Option<&'a crate::tenants::Tenant>,
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
    // Authentication-strength markers reflecting how *this* session was authenticated, so permission
    // rules / API eligibility can require a second factor (e.g. `when: "is:2fa"`).
    if params.passkey {
        subject_set.push(PASSKEY_MARKER.to_owned());
    }
    if params.totp {
        subject_set.push(TOTP_MARKER.to_owned());
    }
    if params.passkey || params.totp {
        subject_set.push(TWO_FACTOR_MARKER.to_owned());
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

    // Assemble the claim context once, then let the config-driven mapping resolve `$…` references
    // against it (the single interpretation point lives in `config::resolve_claim_source`).
    let display_names = match params.user {
        Some(user) => user.display_names(&config.salutations),
        None => crate::users::DisplayNames::default(),
    };
    let empty_fields = BTreeMap::new();
    let ctx = crate::config::ClaimContext {
        user_id: params.subject,
        username: params.user.map_or("", |user| user.username.as_str()),
        email: params.email,
        display_names: &display_names,
        title: params.user.and_then(|user| user.title.as_deref()),
        salutation: params.user.map_or("", |user| user.salutation.code()),
        firstname: params.user.and_then(|user| user.firstname.as_deref()),
        lastname: params.user.and_then(|user| user.lastname.as_deref()),
        roles: params.user.map_or(&[][..], |user| user.roles.as_slice()),
        user_custom: params
            .user
            .map_or(&empty_fields, |user| &user.custom_fields),
        tenant_id: params.tenant_id,
        tenant_name: params.tenant.map_or("", |tenant| tenant.name.as_str()),
        tenant_slug: params.tenant.map_or("", |tenant| tenant.slug.as_str()),
        tenant_features: params.features,
        tenant_custom: params
            .tenant
            .map_or(&empty_fields, |tenant| &tenant.custom_fields),
    };
    let mut extra = api.build_claims(&ctx);
    if let Some(kind) = params.kind {
        let _ = extra.insert("kind".to_owned(), json!(kind));
    }
    // Record the second factors used (`amr`) so a downstream re-mint (exchange / switch-tenant) can
    // carry the auth-strength markers forward — see [`auth_strength`].
    let mut amr: Vec<&str> = Vec::new();
    if params.passkey {
        amr.push("passkey");
    }
    if params.totp {
        amr.push("totp");
    }
    if !amr.is_empty() {
        let _ = extra.insert("amr".to_owned(), json!(amr));
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
