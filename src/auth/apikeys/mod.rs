//! API keys: a long-lived credential exchanged for a short-lived access token.
//!
//! See `docs/API-KEYS.md`. A key is `umk_<keyId>_<secret>`; only `sha256(secret)` is stored. Two
//! **subject** kinds share this machinery (`user_id` on the key discriminates):
//! - **Service key** (`user_id = None`): a tenant machine principal. The exchange mints
//!   `sub = keyId` with the key's `scope:*` subjects (M2M granularity, independent of user roles).
//!   Origin-bound (Mode 1) for browser use, or a plain server-side secret. Managed at
//!   `/tenants/{id}/api-keys` (`write:members`).
//! - **Personal access token** (`user_id = Some`): acts as that user — the exchange mints
//!   `sub = userId` with the user's `role:*` subjects (optionally restricted to the key's `roles`),
//!   and respects the user's `tokenVersion` (deactivating the user kills the PAT). Self-managed at
//!   `/auth/me/api-keys`.
//!
//! Both exchange via `POST /auth/token` and carry `kind = "api_key"`; no session/cookie is created.

pub mod repository;

use crate::audit::repository::{AuditRepository, record_best_effort};
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::broker::{MintParams, mint_for_api};
use crate::auth::session::{generate_refresh_secret, hash_refresh_secret, verify_refresh_secret};
use crate::auth::tokens::TokenIssuer;
use crate::config::repository::ConfigRepository;
use crate::constants::{MAX_TEXT_BODY_SIZE, WRITE_MEMBERS_PERMISSION};
use crate::tenants::repository::TenantRepository;
use crate::users::UserStatus;
use crate::users::repository::UserRepository;
use anyhow::Context;
use chrono::{DateTime, Utc};
use repository::{ApiKey, ApiKeyRepository, ApiKeyStatus, NewApiKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::aws::dynamodb::generate_id;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::{with_user, with_user_with_any_permission};
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};
use wasabi::{client_bail, status_bail};

/// Prefix identifying an umami API key (helps secret scanners detect leaks).
const KEY_PREFIX: &str = "umk_";

/// Length of the embedded key id (a `generate_id()` value).
const KEY_ID_LEN: usize = 32;

/// Permission required to manage a tenant's API keys.
const REQUIRE_WRITE_MEMBERS: &[&str] = &[WRITE_MEMBERS_PERMISSION];

/// Splits a presented `umk_<keyId>_<secret>` into `(keyId, secret)`.
fn parse_api_key(presented: &str) -> Option<(&str, &str)> {
    let rest = presented.strip_prefix(KEY_PREFIX)?;
    if rest.len() <= KEY_ID_LEN + 1 {
        return None;
    }
    let (key_id, remainder) = rest.split_at(KEY_ID_LEN);
    let secret = remainder.strip_prefix('_')?;
    if key_id.is_empty() || secret.is_empty() {
        None
    } else {
        Some((key_id, secret))
    }
}

// ── Request/response types ───────────────────────────────────────────────────

/// Exchange request: the presented API key and, optionally, which target API to mint for. When the
/// key allows exactly one API, `api` may be omitted; otherwise it must name one of the key's APIs.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ExchangeRequest {
    api_key: String,
    api: Option<String>,
}

/// Exchange response: the short-lived access token.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ExchangeResponse {
    access_token: String,
    expires_in: i64,
}

/// Request body for creating a tenant **service** key (a machine principal).
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateApiKeyRequest {
    name: String,
    /// The `scope:*` subjects this M2M key carries (must be assignable given the tenant's features).
    scopes: Option<Vec<String>>,
    /// Target API codes this key may mint for; defaults to `["umami"]`.
    apis: Option<Vec<String>>,
    allowed_origins: Option<Vec<String>>,
    expires_at: Option<DateTime<Utc>>,
}

/// Request body for creating a **personal access token** (self-service).
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreatePatRequest {
    name: String,
    /// Optional restriction: limit the token to this subset of the user's own `role:*` (empty = all).
    roles: Option<Vec<String>>,
    /// Target API codes this PAT may mint for; defaults to `["umami"]`.
    apis: Option<Vec<String>>,
    expires_at: Option<DateTime<Utc>>,
}

/// Create response — the **only** time the full secret is returned.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateApiKeyResponse {
    key_id: String,
    api_key: String,
    name: String,
}

/// Public view of an API key (never includes the secret hash).
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ApiKeyView {
    key_id: String,
    tenant_id: String,
    /// Present for personal access tokens (the user the token acts as); `None` for service keys.
    user_id: Option<String>,
    name: String,
    roles: Vec<String>,
    scopes: Vec<String>,
    apis: Vec<String>,
    status: ApiKeyStatus,
    allowed_origins: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    created: DateTime<Utc>,
}

impl From<ApiKey> for ApiKeyView {
    fn from(key: ApiKey) -> Self {
        ApiKeyView {
            key_id: key.key_id,
            tenant_id: key.tenant_id,
            user_id: key.user_id,
            name: key.name,
            roles: key.roles,
            scopes: key.scopes,
            apis: key.apis,
            status: key.status,
            allowed_origins: key.allowed_origins,
            expires_at: key.expires_at,
            last_used_at: key.last_used_at,
            created: key.created,
        }
    }
}

/// List response.
#[derive(Serialize, Debug)]
struct ApiKeyListResponse {
    keys: Vec<ApiKeyView>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `POST /auth/token` — exchange an API key for a short-lived access token (unauthenticated; the
/// key is the credential).
#[allow(clippy::too_many_arguments)]
pub fn exchange_route(
    keys: Arc<dyn ApiKeyRepository>,
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    tokens: Arc<TokenIssuer>,
    audit: Arc<dyn AuditRepository>,
    system_tenant_id: Option<String>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "token")
        .and(warp::post())
        .and(with_body_as_json::<ExchangeRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(keys))
        .and(with_cloneable(users))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(tokens))
        .and(with_cloneable(audit))
        .and(with_cloneable(system_tenant_id))
        .and(warp::header::optional::<String>("origin"))
        .and_then(handle_exchange_route)
        .boxed()
}

/// `POST /tenants/{id}/api-keys` — create a key (requires `write:members`).
pub fn create_api_key_route(
    keys: Arc<dyn ApiKeyRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "api-keys")
        .and(warp::post())
        .and(with_body_as_json::<CreateApiKeyRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(keys))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_MEMBERS,
        ))
        .and_then(handle_create_api_key_route)
        .boxed()
}

/// `GET /tenants/{id}/api-keys` — list a tenant's keys (requires `write:members`).
pub fn list_api_keys_route(
    keys: Arc<dyn ApiKeyRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "api-keys")
        .and(warp::get())
        .and(with_cloneable(keys))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_MEMBERS,
        ))
        .and_then(handle_list_api_keys_route)
        .boxed()
}

/// `DELETE /tenants/{id}/api-keys/{keyId}` — revoke a key (requires `write:members`).
pub fn delete_api_key_route(
    keys: Arc<dyn ApiKeyRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "api-keys" / String)
        .and(warp::delete())
        .and(with_cloneable(keys))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_MEMBERS,
        ))
        .and_then(handle_delete_api_key_route)
        .boxed()
}

/// `POST /auth/me/api-keys` — create a personal access token for the authenticated user.
pub fn create_my_pat_route(
    keys: Arc<dyn ApiKeyRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "api-keys")
        .and(warp::post())
        .and(with_body_as_json::<CreatePatRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(keys))
        .and(with_user(authenticator))
        .and_then(handle_create_my_pat_route)
        .boxed()
}

/// `GET /auth/me/api-keys` — list the authenticated user's own personal access tokens.
pub fn list_my_pats_route(
    keys: Arc<dyn ApiKeyRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "api-keys")
        .and(warp::get())
        .and(with_cloneable(keys))
        .and(with_user(authenticator))
        .and_then(handle_list_my_pats_route)
        .boxed()
}

/// `DELETE /auth/me/api-keys/{keyId}` — revoke one of the authenticated user's own PATs.
pub fn delete_my_pat_route(
    keys: Arc<dyn ApiKeyRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "api-keys" / String)
        .and(warp::delete())
        .and(with_cloneable(keys))
        .and(with_user(authenticator))
        .and_then(handle_delete_my_pat_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "POST /auth/token", skip_all)]
#[allow(clippy::too_many_arguments)]
async fn handle_exchange_route(
    request: ExchangeRequest,
    keys: Arc<dyn ApiKeyRepository>,
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    tokens: Arc<TokenIssuer>,
    audit: Arc<dyn AuditRepository>,
    system_tenant_id: Option<String>,
    origin: Option<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(
        exchange(
            request,
            keys,
            users,
            tenants,
            config,
            tokens,
            audit,
            system_tenant_id,
            origin,
        )
        .await,
    )
}

#[tracing::instrument(level = "debug", name = "POST /auth/me/api-keys", skip_all)]
async fn handle_create_my_pat_route(
    request: CreatePatRequest,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_my_pat(request, keys, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /auth/me/api-keys", skip_all)]
async fn handle_list_my_pats_route(
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_my_pats(keys, caller).await)
}

#[tracing::instrument(level = "debug", name = "DELETE /auth/me/api-keys/{keyId}", skip_all)]
async fn handle_delete_my_pat_route(
    key_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(delete_my_pat(key_id, keys, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /tenants/{id}/api-keys", skip_all)]
async fn handle_create_api_key_route(
    tenant_id: String,
    request: CreateApiKeyRequest,
    keys: Arc<dyn ApiKeyRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_api_key(tenant_id, request, keys, tenants, config, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /tenants/{id}/api-keys", skip_all)]
async fn handle_list_api_keys_route(
    tenant_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_api_keys(tenant_id, keys, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "DELETE /tenants/{id}/api-keys/{keyId}",
    skip_all
)]
async fn handle_delete_api_key_route(
    tenant_id: String,
    key_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(delete_api_key(tenant_id, key_id, keys, caller).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

fn enforce_own(tenant_id: &str, caller: &AuthUser) -> anyhow::Result<()> {
    if caller.tenant_id()? != tenant_id {
        status_bail!(
            StatusCode::FORBIDDEN,
            "You may only manage your own tenant's keys"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn exchange(
    request: ExchangeRequest,
    keys: Arc<dyn ApiKeyRepository>,
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    tokens: Arc<TokenIssuer>,
    audit: Arc<dyn AuditRepository>,
    system_tenant_id: Option<String>,
    origin: Option<String>,
) -> anyhow::Result<ExchangeResponse> {
    // Uniform "invalid key" for every failure so we don't reveal which keys exist.
    let (key_id, secret) = match parse_api_key(&request.api_key) {
        Some(parsed) => parsed,
        None => status_bail!(StatusCode::UNAUTHORIZED, "Invalid API key"),
    };

    let key = match keys.get(key_id).await? {
        Some(key) if key.status == ApiKeyStatus::Active => key,
        _ => status_bail!(StatusCode::UNAUTHORIZED, "Invalid API key"),
    };

    if let Some(expires_at) = key.expires_at
        && Utc::now() >= expires_at
    {
        status_bail!(StatusCode::UNAUTHORIZED, "API key expired");
    }

    if !verify_refresh_secret(secret, &key.secret_hash) {
        status_bail!(StatusCode::UNAUTHORIZED, "Invalid API key");
    }

    // Mode 1: when origins are pinned, the browser-set Origin must be allow-listed.
    if !key.allowed_origins.is_empty() {
        let allowed = origin
            .as_deref()
            .is_some_and(|origin| key.allowed_origins.iter().any(|value| value == origin));
        if !allowed {
            status_bail!(StatusCode::FORBIDDEN, "Origin not allowed for this key");
        }
    }

    // Pick the target API: the request's `api` must be one the key allows; if the key has exactly
    // one API and none was requested, use it. Anything else is a client error.
    let api_code = match request.api.as_deref() {
        Some(requested) => {
            if !key.apis.iter().any(|code| code == requested) {
                status_bail!(
                    StatusCode::FORBIDDEN,
                    "This key may not mint tokens for API '{requested}'"
                );
            }
            requested.to_owned()
        }
        None => match key.apis.as_slice() {
            [only] => only.clone(),
            [] => client_bail!("This key has no target API configured"),
            _ => client_bail!("This key targets multiple APIs; specify 'api'"),
        },
    };

    let config = config.current().await?;
    let access_ttl_secs = config.security.access_ttl_secs as i64;
    let empty_fields = BTreeMap::new();

    let is_system = |tenant: &str| system_tenant_id.as_deref() == Some(tenant);

    // The token's subject set depends on the key kind: a PAT acts as its user (its `role:*`,
    // intersected with the key's optional restriction); a service key acts as itself (its `scope:*`).
    let (access_token, _exp) = match &key.user_id {
        Some(user_id) => {
            // Personal access token — load the user fresh so deactivation/lock stops new tokens.
            let user = match users.get_user(user_id).await? {
                Some(user) if user.status == UserStatus::Active => user,
                _ => status_bail!(StatusCode::UNAUTHORIZED, "Invalid API key"),
            };
            // Effective roles = user roles ∩ the key's restriction (empty restriction = all roles).
            let subjects: Vec<String> = if key.roles.is_empty() {
                user.roles.clone()
            } else {
                user.roles
                    .iter()
                    .filter(|role| key.roles.contains(role))
                    .cloned()
                    .collect()
            };
            let features = tenant_features(&tenants, &user.tenant_id).await?;
            let synthetic = user.email.clone().unwrap_or_default();
            mint_for_api(
                &tokens,
                &config,
                MintParams {
                    api_code: &api_code,
                    subject: &user.user_id,
                    name: &user.name,
                    email: &synthetic,
                    locale: &user.locale,
                    tenant_id: &user.tenant_id,
                    token_version: user.token_version,
                    subjects: &subjects,
                    features: &features,
                    system_tenant: is_system(&user.tenant_id),
                    user_custom_fields: &user.custom_fields,
                    tenant_custom_fields: &empty_fields,
                    kind: Some("api_key"),
                    access_ttl_secs,
                },
            )
            .await?
        }
        None => {
            // Service key — acts as itself; subjects are the key's `scope:*`.
            let features = tenant_features(&tenants, &key.tenant_id).await?;
            let synthetic_email = format!("{key_id}@api-key");
            mint_for_api(
                &tokens,
                &config,
                MintParams {
                    api_code: &api_code,
                    subject: &key.key_id,
                    name: &key.name,
                    email: &synthetic_email,
                    locale: "en-US",
                    tenant_id: &key.tenant_id,
                    token_version: 0,
                    subjects: &key.scopes,
                    features: &features,
                    system_tenant: is_system(&key.tenant_id),
                    user_custom_fields: &empty_fields,
                    tenant_custom_fields: &empty_fields,
                    kind: Some("api_key"),
                    access_ttl_secs,
                },
            )
            .await?
        }
    };

    // Best-effort usage marker; failure to record must not fail the exchange.
    if let Err(err) = keys.touch_last_used(key_id).await {
        tracing::warn!("failed to update api key lastUsedAt: {err:#}");
    }

    // A successful credential exchange is a "good" security event. `key.user_id` is the PAT's user
    // (None for a service key); the key and any PAT user share the tenant.
    record_best_effort(
        &audit,
        NewAuditEntry::new(
            AuditSeverity::Good,
            Some(key.tenant_id.clone()),
            key.user_id.clone(),
            format!("API key exchanged for API '{api_code}'"),
        ),
    )
    .await;

    Ok(ExchangeResponse {
        access_token,
        expires_in: access_ttl_secs,
    })
}

/// Resolves a tenant's authorization feature set for the broker (empty when the tenant is gone).
async fn tenant_features(
    tenants: &Arc<dyn TenantRepository>,
    tenant_id: &str,
) -> anyhow::Result<Vec<String>> {
    Ok(tenants
        .get_tenant(tenant_id)
        .await?
        .map(|tenant| tenant.features)
        .unwrap_or_default())
}

async fn create_api_key(
    tenant_id: String,
    request: CreateApiKeyRequest,
    keys: Arc<dyn ApiKeyRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<CreateApiKeyResponse> {
    enforce_own(&tenant_id, &caller)?;

    if request.name.trim().is_empty() {
        client_bail!("API key 'name' is required");
    }

    // Validate any requested scopes against what the tenant's features license.
    let scopes = request.scopes.unwrap_or_default();
    if !scopes.is_empty() {
        let features = tenant_features(&tenants, &tenant_id).await?;
        let config = config.current().await?;
        for scope in &scopes {
            if !config.can_assign_scope(scope, &features) {
                client_bail!("Scope '{scope}' is not assignable in this tenant");
            }
        }
    }

    let secret = generate_refresh_secret();
    let key_id = generate_id();
    let api_key = format!("{KEY_PREFIX}{key_id}_{secret}");
    // Default a key with no explicit target to the umami admin API.
    let apis = match request.apis {
        Some(apis) if !apis.is_empty() => apis,
        _ => vec!["umami".to_owned()],
    };

    keys.create(NewApiKey {
        key_id: key_id.clone(),
        tenant_id,
        secret_hash: hash_refresh_secret(&secret),
        name: request.name.clone(),
        user_id: None, // service key
        roles: Vec::new(),
        scopes,
        apis,
        allowed_origins: request.allowed_origins.unwrap_or_default(),
        expires_at: request.expires_at,
    })
    .await
    .context("Failed to create API key")?;

    Ok(CreateApiKeyResponse {
        key_id,
        api_key,
        name: request.name,
    })
}

async fn list_api_keys(
    tenant_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> anyhow::Result<ApiKeyListResponse> {
    enforce_own(&tenant_id, &caller)?;
    let list = keys.list_by_tenant(&tenant_id).await?;
    Ok(ApiKeyListResponse {
        // Only tenant service keys here; users' PATs are managed under /auth/me/api-keys.
        keys: list
            .into_iter()
            .filter(|key| key.user_id.is_none())
            .map(ApiKeyView::from)
            .collect(),
    })
}

async fn delete_api_key(
    tenant_id: String,
    key_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> anyhow::Result<serde_json::Value> {
    enforce_own(&tenant_id, &caller)?;

    // Scope to the caller's tenant, and to service keys only (PATs are self-managed).
    match keys.get(&key_id).await? {
        Some(key) if key.tenant_id == tenant_id && key.user_id.is_none() => {}
        _ => client_bail!("No such API key in this tenant"),
    }

    keys.delete(&key_id).await?;
    Ok(json!({ "status": "revoked" }))
}

// ── Personal access tokens (self-service) ──────────────────────────────────────

async fn create_my_pat(
    request: CreatePatRequest,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> anyhow::Result<CreateApiKeyResponse> {
    if request.name.trim().is_empty() {
        client_bail!("Token 'name' is required");
    }
    let user_id = caller.user_id()?.to_owned();
    let tenant_id = caller.tenant_id()?.to_owned();

    let secret = generate_refresh_secret();
    let key_id = generate_id();
    let api_key = format!("{KEY_PREFIX}{key_id}_{secret}");
    let apis = match request.apis {
        Some(apis) if !apis.is_empty() => apis,
        _ => vec!["umami".to_owned()],
    };

    keys.create(NewApiKey {
        key_id: key_id.clone(),
        tenant_id,
        secret_hash: hash_refresh_secret(&secret),
        name: request.name.clone(),
        user_id: Some(user_id),                   // personal access token
        roles: request.roles.unwrap_or_default(), // restriction ∩ the user's own roles at mint time
        scopes: Vec::new(),
        apis,
        allowed_origins: Vec::new(),
        expires_at: request.expires_at,
    })
    .await
    .context("Failed to create personal access token")?;

    Ok(CreateApiKeyResponse {
        key_id,
        api_key,
        name: request.name,
    })
}

async fn list_my_pats(
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> anyhow::Result<ApiKeyListResponse> {
    let user_id = caller.user_id()?;
    let tenant_id = caller.tenant_id()?;
    let list = keys.list_by_tenant(tenant_id).await?;
    Ok(ApiKeyListResponse {
        keys: list
            .into_iter()
            .filter(|key| key.user_id.as_deref() == Some(user_id))
            .map(ApiKeyView::from)
            .collect(),
    })
}

async fn delete_my_pat(
    key_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> anyhow::Result<serde_json::Value> {
    let user_id = caller.user_id()?;

    // A user may only delete their own PATs; anything else reads as "not found".
    match keys.get(&key_id).await? {
        Some(key) if key.user_id.as_deref() == Some(user_id) => {}
        _ => client_bail!("No such personal access token"),
    }

    keys.delete(&key_id).await?;
    Ok(json!({ "status": "revoked" }))
}
