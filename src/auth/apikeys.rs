//! Machine-to-machine API keys: a long-lived credential exchanged for a short-lived access token.
//!
//! See `docs/API-KEYS.md`. A key is `umk_<keyId>_<secret>`; only `sha256(secret)` is stored. The
//! exchange (`POST /auth/token`) issues an access token with `sub = keyId`, `kind = "api_key"`, and
//! the tenant + permissions resolved from the key's roles — no session/cookie. Optional
//! `allowedOrigins` gate the exchange against the browser-set `Origin` header (Mode 1).

pub mod repository;

use crate::auth::session::{generate_refresh_secret, hash_refresh_secret, verify_refresh_secret};
use crate::auth::tokens::{AccessTokenClaims, TokenIssuer};
use crate::config::repository::ConfigRepository;
use crate::constants::{MAX_TEXT_BODY_SIZE, WRITE_MEMBERS_PERMISSION};
use crate::tenants::effective_features;
use crate::tenants::repository::TenantRepository;
use anyhow::Context;
use chrono::{DateTime, Utc};
use repository::{ApiKey, ApiKeyRepository, ApiKeyStatus, NewApiKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::aws::dynamodb::generate_id;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
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

/// Exchange request: the presented API key.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ExchangeRequest {
    api_key: String,
}

/// Exchange response: the short-lived access token.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ExchangeResponse {
    access_token: String,
    expires_in: i64,
}

/// Request body for creating an API key.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateApiKeyRequest {
    name: String,
    roles: Option<Vec<String>>,
    allowed_origins: Option<Vec<String>>,
    expires_at: Option<DateTime<Utc>>,
}

/// Create response — the **only** time the full secret is returned.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateApiKeyResponse {
    key_id: String,
    api_key: String,
    name: String,
    roles: Vec<String>,
    allowed_origins: Vec<String>,
}

/// Public view of an API key (never includes the secret hash).
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ApiKeyView {
    key_id: String,
    tenant_id: String,
    name: String,
    roles: Vec<String>,
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
            name: key.name,
            roles: key.roles,
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
pub fn exchange_route(
    keys: Arc<dyn ApiKeyRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    tokens: Arc<TokenIssuer>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "token")
        .and(warp::post())
        .and(with_body_as_json::<ExchangeRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(keys))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(tokens))
        .and(warp::header::optional::<String>("origin"))
        .and_then(handle_exchange_route)
        .boxed()
}

/// `POST /tenants/{id}/api-keys` — create a key (requires `write:members`).
pub fn create_api_key_route(
    keys: Arc<dyn ApiKeyRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "api-keys")
        .and(warp::post())
        .and(with_body_as_json::<CreateApiKeyRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(keys))
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

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "POST /auth/token", skip_all)]
async fn handle_exchange_route(
    request: ExchangeRequest,
    keys: Arc<dyn ApiKeyRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    tokens: Arc<TokenIssuer>,
    origin: Option<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(exchange(request, keys, tenants, config, tokens, origin).await)
}

#[tracing::instrument(level = "debug", name = "POST /tenants/{id}/api-keys", skip_all)]
async fn handle_create_api_key_route(
    tenant_id: String,
    request: CreateApiKeyRequest,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_api_key(tenant_id, request, keys, caller).await)
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

async fn exchange(
    request: ExchangeRequest,
    keys: Arc<dyn ApiKeyRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    tokens: Arc<TokenIssuer>,
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

    let config = config.current().await?;
    let permissions = config.permissions_for_roles(&key.roles);
    let access_ttl_secs = config.security.access_ttl_secs as i64;

    // Config-driven extra claims: mark the token as machine-issued and, if requested, its tenant's
    // effective features.
    let mut extra: BTreeMap<String, Value> = BTreeMap::new();
    let _ = extra.insert("kind".to_owned(), json!("api_key"));
    if config.token_claims.iter().any(|claim| claim == "features")
        && let Some(tenant) = tenants.get_tenant(&key.tenant_id).await?
    {
        let features: Vec<String> = effective_features(&config, &tenant).into_iter().collect();
        let _ = extra.insert("features".to_owned(), json!(features));
    }

    let synthetic_email = format!("{key_id}@api-key");
    let (access_token, _exp) = tokens
        .issue_access_token(
            &AccessTokenClaims {
                subject: &key.key_id,
                name: &key.name,
                email: &synthetic_email,
                locale: "en-US",
                tenant: Some(&key.tenant_id),
                permissions: &permissions,
                token_version: 0,
                extra: &extra,
            },
            access_ttl_secs,
        )
        .await?;

    // Best-effort usage marker; failure to record must not fail the exchange.
    if let Err(err) = keys.touch_last_used(key_id).await {
        tracing::warn!("failed to update api key lastUsedAt: {err:#}");
    }

    Ok(ExchangeResponse {
        access_token,
        expires_in: access_ttl_secs,
    })
}

async fn create_api_key(
    tenant_id: String,
    request: CreateApiKeyRequest,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> anyhow::Result<CreateApiKeyResponse> {
    enforce_own(&tenant_id, &caller)?;

    if request.name.trim().is_empty() {
        client_bail!("API key 'name' is required");
    }

    let key_id = generate_id();
    let secret = generate_refresh_secret();
    let api_key = format!("{KEY_PREFIX}{key_id}_{secret}");
    let roles = request.roles.unwrap_or_default();
    let allowed_origins = request.allowed_origins.unwrap_or_default();

    keys.create(NewApiKey {
        key_id: key_id.clone(),
        tenant_id,
        secret_hash: hash_refresh_secret(&secret),
        name: request.name.clone(),
        roles: roles.clone(),
        allowed_origins: allowed_origins.clone(),
        expires_at: request.expires_at,
    })
    .await
    .context("Failed to create API key")?;

    Ok(CreateApiKeyResponse {
        key_id,
        api_key,
        name: request.name,
        roles,
        allowed_origins,
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
        keys: list.into_iter().map(ApiKeyView::from).collect(),
    })
}

async fn delete_api_key(
    tenant_id: String,
    key_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> anyhow::Result<serde_json::Value> {
    enforce_own(&tenant_id, &caller)?;

    // Scope to the caller's tenant — a foreign key reads as "not found".
    match keys.get(&key_id).await? {
        Some(key) if key.tenant_id == tenant_id => {}
        _ => client_bail!("No such API key in this tenant"),
    }

    keys.delete(&key_id).await?;
    Ok(json!({ "status": "revoked" }))
}
