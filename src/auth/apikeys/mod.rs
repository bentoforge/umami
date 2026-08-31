//! API keys: a long-lived credential exchanged for a short-lived access token.
//!
//! See `docs/API-KEYS.md`. A key is `umk_<keyId>_<secret>`; only `sha256(secret)` is stored. Two
//! **subject** kinds share this machinery (`user_id` on the key discriminates):
//! - **Service key** (`user_id = None`): a tenant machine principal. The exchange mints
//!   `sub = keyId` with the key's `scope:*` subjects (M2M granularity, independent of user roles).
//!   Origin-bound (Mode 1) for browser use, or a plain server-side secret. Managed at
//!   `/tenants/{id}/api-keys` (`manage:service-keys`).
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
use crate::auth::ratelimit::{
    Decision, POLICY_PER_IP_TOKEN, POLICY_TOKEN_EXCHANGE, Policy, RateLimiter, too_many_requests,
};
use crate::auth::session::{generate_refresh_secret, hash_refresh_secret, verify_refresh_secret};
use crate::auth::tokens::TokenIssuer;
use crate::bail_i18n;
use crate::config::VolumeRateLimit;
use crate::config::repository::ConfigRepository;
use crate::constants::{
    MANAGE_PERSONAL_TOKENS_PERMISSION, MANAGE_SERVICE_KEYS_PERMISSION, MANAGE_USERS_PERMISSION,
    MAX_TEXT_BODY_SIZE,
};
use crate::tenants::repository::TenantRepository;
use crate::users::repository::UserRepository;
use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use repository::{ApiKey, ApiKeyRepository, ApiKeyStatus, KeyRateLimit, NewApiKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::http::header::{CONTENT_TYPE, HeaderValue};
use warp::reply::Response;
use wasabi::aws::dynamodb::generate_id;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{
    client_ip, into_rejection, into_response, with_body_as_json, with_cloneable,
};
use wasabi::{client_bail, status_bail};

/// Prefix identifying an umami API key (helps secret scanners detect leaks).
const KEY_PREFIX: &str = "umk_";

/// Length of the embedded key id (a `generate_id()` value).
const KEY_ID_LEN: usize = 32;

/// Permission required to manage a tenant's service keys.
const REQUIRE_MANAGE_SERVICE_KEYS: &[&str] = &[MANAGE_SERVICE_KEYS_PERMISSION];

/// Permission required to read a tenant user's personal access tokens (admin, read-only view).
const REQUIRE_MANAGE_USERS: &[&str] = &[MANAGE_USERS_PERMISSION];

/// Permission required to manage one's own personal access tokens.
const REQUIRE_MANAGE_PAT: &[&str] = &[MANAGE_PERSONAL_TOKENS_PERMISSION];

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

/// Verifies a Mode-2 HMAC proof (constant-time). The HMAC key is the stored SHA-256 secret hash
/// itself — the client derives the same bytes from its secret, so no raw secret is ever sent and
/// none is kept at rest. The message binds the key id and the current hour bucket; the current hour
/// ±1 is accepted to tolerate clock skew and hour boundaries. Any malformed input returns `false`.
fn verify_key_hmac(secret_hash_b64: &str, key_id: &str, presented_mac: &str) -> bool {
    let (Ok(hmac_key), Ok(presented)) = (
        URL_SAFE_NO_PAD.decode(secret_hash_b64),
        URL_SAFE_NO_PAD.decode(presented_mac),
    ) else {
        return false;
    };
    let bucket = Utc::now().timestamp().div_euclid(3600);
    for slot in [bucket - 1, bucket, bucket + 1] {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&hmac_key) else {
            return false;
        };
        mac.update(format!("umami:apikey:{key_id}:{slot}").as_bytes());
        let expected = mac.finalize().into_bytes();
        if bool::from(presented.ct_eq(expected.as_slice())) {
            return true;
        }
    }
    false
}

// ── Request/response types ───────────────────────────────────────────────────

/// Exchange request. Two auth methods:
/// - **Mode 1** — present the raw key in `apiKey` (`umk_<keyId>_<secret>`).
/// - **Mode 2** — prove possession without sending the secret: `keyId` + `mac`, where `mac` is
///   `base64url(HMAC-SHA256(key = the stored secret hash, msg = "umami:apikey:<keyId>:<hourBucket>"))`
///   and `hourBucket = unixSeconds / 3600`. The server accepts the current hour ±1 (clock skew).
///
/// `api` (optional) picks the target audience (default `umami`), bounded by the key's scopes + the
/// API's eligibility.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ExchangeRequest {
    /// Mode 1: the full `umk_…` key.
    api_key: Option<String>,
    /// Mode 2: the key id (paired with `mac`).
    key_id: Option<String>,
    /// Mode 2: the HMAC proof (base64url).
    mac: Option<String>,
    api: Option<String>,
    /// Language for the minted token (BCP-47), landing in the `locale` claim.
    ///
    /// A machine has no language of its own, so a service key carries none. What it does have is
    /// an end user it is acting for: a bot relaying a failure into a chat, a backend rendering a
    /// page. Passing that user's language here puts it in the token, and every service down the
    /// line answers in it without a second channel. Absent = the deployment default.
    locale: Option<String>,
}

/// Exchange response: the short-lived access token.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ExchangeResponse {
    access_token: String,
    expires_in: i64,
}

/// Outcome of an exchange attempt: either a minted token, or a rate-limit block (translated by the
/// handler into `429 Too Many Requests` + `Retry-After`).
enum ExchangeOutcome {
    /// A token was issued.
    Ok(ExchangeResponse),
    /// The request was rate-limited; `retry_after` is the advertised delay in seconds.
    RateLimited {
        /// Seconds until the block lifts.
        retry_after: i64,
    },
}

/// Request body for creating a tenant **service** key (a machine principal).
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateApiKeyRequest {
    name: String,
    /// The `scope:*` subjects this M2M key carries (must be assignable given the tenant's features).
    scopes: Option<Vec<String>>,
    /// Whether the raw-secret (Mode 1) exchange is allowed; omitted/false ⇒ HMAC-only (Mode 2).
    allow_secret_login: Option<bool>,
    allowed_origins: Option<Vec<String>>,
    /// Optional per-key override of the global `tokenExchange` rate-limit policy.
    rate_limit: Option<KeyRateLimit>,
    expires_at: Option<DateTime<Utc>>,
}

/// Request body for creating a **personal access token** (self-service).
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreatePatRequest {
    name: String,
    /// Optional restriction: limit the token to this subset of the user's own `role:*` (empty = all).
    roles: Option<Vec<String>>,
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
    allow_secret_login: bool,
    status: ApiKeyStatus,
    allowed_origins: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limit: Option<KeyRateLimit>,
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
            allow_secret_login: key.allow_secret_login,
            status: key.status,
            allowed_origins: key.allowed_origins,
            rate_limit: key.rate_limit,
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
    rate_limiter: Arc<RateLimiter>,
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
        .and(with_cloneable(rate_limiter))
        .and(with_cloneable(system_tenant_id))
        .and(warp::header::optional::<String>("origin"))
        .and(client_ip())
        .and_then(handle_exchange_route)
        .boxed()
}

/// `POST /tenants/{id}/api-keys` — create a key (requires `manage:service-keys`).
pub fn create_api_key_route(
    keys: Arc<dyn ApiKeyRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "api-keys")
        .and(warp::post())
        .and(with_body_as_json::<CreateApiKeyRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(keys))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(system_tenant_id))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_SERVICE_KEYS,
        ))
        .and_then(handle_create_api_key_route)
        .boxed()
}

/// `GET /tenants/{id}/api-keys` — list a tenant's keys (requires `manage:service-keys`).
pub fn list_api_keys_route(
    keys: Arc<dyn ApiKeyRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "api-keys")
        .and(warp::get())
        .and(with_cloneable(keys))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_SERVICE_KEYS,
        ))
        .and_then(handle_list_api_keys_route)
        .boxed()
}

/// `GET /users/{id}/pats` — a tenant user's personal access tokens, read-only (requires
/// `manage:users`). PATs are user-centric; tenant service keys live under `/tenants/{id}/api-keys`.
pub fn list_user_pats_route(
    keys: Arc<dyn ApiKeyRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String / "pats")
        .and(warp::get())
        .and(with_cloneable(keys))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_list_user_pats_route)
        .boxed()
}

/// `DELETE /tenants/{id}/api-keys/{keyId}` — revoke a key (requires `manage:service-keys`).
pub fn delete_api_key_route(
    keys: Arc<dyn ApiKeyRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "api-keys" / String)
        .and(warp::delete())
        .and(with_cloneable(keys))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_SERVICE_KEYS,
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
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_PAT,
        ))
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
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_PAT,
        ))
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
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_PAT,
        ))
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
    rate_limiter: Arc<RateLimiter>,
    system_tenant_id: Option<String>,
    origin: Option<String>,
    ip: Option<String>,
) -> Result<Response, warp::Rejection> {
    match exchange(
        request,
        keys,
        users,
        tenants,
        config,
        tokens,
        audit,
        rate_limiter,
        system_tenant_id,
        origin,
        ip,
    )
    .await
    {
        // A blocked exchange returns 429 + Retry-After directly (the anyhow/ApiError path can't
        // carry a header), bypassing `into_response`.
        Ok(ExchangeOutcome::RateLimited { retry_after }) => Ok(too_many_requests(retry_after)),
        Ok(ExchangeOutcome::Ok(response)) => match serde_json::to_vec(&response) {
            Ok(bytes) => {
                let mut reply = Response::new(bytes.into());
                let _ = reply
                    .headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                Ok(reply)
            }
            Err(err) => Err(into_rejection(
                anyhow::Error::new(err).context("Failed to serialize exchange response"),
            )),
        },
        Err(err) => Err(into_rejection(err)),
    }
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
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(
        create_api_key(
            tenant_id,
            request,
            keys,
            tenants,
            config,
            system_tenant_id,
            caller,
        )
        .await,
    )
}

#[tracing::instrument(level = "debug", name = "GET /tenants/{id}/api-keys", skip_all)]
async fn handle_list_api_keys_route(
    tenant_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_api_keys(tenant_id, keys, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /users/{id}/pats", skip_all)]
async fn handle_list_user_pats_route(
    user_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_user_pats(user_id, keys, caller).await)
}

/// Lists a user's PATs by scanning the caller's tenant keys (which scopes the result to the caller's
/// tenant) and keeping the ones acting as that user. Read-only.
async fn list_user_pats(
    user_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    caller: AuthUser,
) -> anyhow::Result<ApiKeyListResponse> {
    let tenant_id = caller.tenant_id()?;
    let list = keys.list_by_tenant(tenant_id).await?;
    Ok(ApiKeyListResponse {
        keys: list
            .into_iter()
            .filter(|key| key.user_id.as_deref() == Some(user_id.as_str()))
            .map(ApiKeyView::from)
            .collect(),
    })
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
    rate_limiter: Arc<RateLimiter>,
    system_tenant_id: Option<String>,
    origin: Option<String>,
    ip: Option<String>,
) -> anyhow::Result<ExchangeOutcome> {
    let now = Utc::now();
    let config = config.current().await?;
    let limits = &config.security.rate_limits;
    // A key exchange has no token to read a preference from, and the caller states the end user's
    // language in the request body — but only on success. A rejected exchange therefore answers in
    // whatever the caller asked for, falling back to the deployment default.
    let exchange_locale = crate::i18n::resolve(&config, request.locale.as_deref(), None);

    // Per-IP volume cap (the blunt instrument): count *every* hit on this endpoint, blocking a
    // flooding IP regardless of whether its keys are valid. Skipped when the IP is unknown.
    if let Some(ip) = ip.as_deref() {
        let per_ip = Policy::new(
            limits.per_ip.max_per_window,
            limits.per_ip.window_secs,
            limits.per_ip.block_secs,
        );
        if let Decision::Block { retry_after } = rate_limiter
            .check(POLICY_PER_IP_TOKEN, &per_ip, ip, now)
            .await
        {
            return Ok(ExchangeOutcome::RateLimited { retry_after });
        }
    }

    // Resolve the key id from whichever auth method the caller used (Mode 1: parse it out of the
    // raw key; Mode 2: it's supplied directly). Uniform "invalid key" for every failure so we don't
    // reveal which keys exist.
    let key_id: String = if let Some(api_key) = request.api_key.as_deref() {
        match parse_api_key(api_key) {
            Some((key_id, _)) => key_id.to_owned(),
            None => bail_i18n!(StatusCode::UNAUTHORIZED, &exchange_locale, "apikey.invalid"),
        }
    } else if let Some(key_id) = request.key_id.as_deref() {
        key_id.to_owned()
    } else {
        client_bail!("Provide either 'apiKey' (Mode 1) or 'keyId' + 'mac' (Mode 2)");
    };

    let key = match keys.get(&key_id).await? {
        Some(key) if key.status == ApiKeyStatus::Active => key,
        _ => bail_i18n!(StatusCode::UNAUTHORIZED, &exchange_locale, "apikey.invalid"),
    };

    if let Some(expires_at) = key.expires_at
        && Utc::now() >= expires_at
    {
        bail_i18n!(StatusCode::UNAUTHORIZED, &exchange_locale, "apikey.expired");
    }

    // Verify possession by the method used: Mode 1 compares the presented secret against the stored
    // hash; Mode 2 checks the HMAC (no secret on the wire).
    if let Some(api_key) = request.api_key.as_deref() {
        let ok = parse_api_key(api_key)
            .is_some_and(|(_, secret)| verify_refresh_secret(secret, &key.secret_hash));
        if !ok {
            bail_i18n!(StatusCode::UNAUTHORIZED, &exchange_locale, "apikey.invalid");
        }
        // Mode 1 must be explicitly enabled on the key. Checked after verifying possession, so this
        // only ever tells the legitimate holder to switch to the signed (HMAC) exchange.
        if !key.allow_secret_login {
            status_bail!(
                StatusCode::FORBIDDEN,
                "This key does not allow the raw-secret exchange; use the signed (HMAC) form"
            );
        }
    } else if let Some(mac) = request.mac.as_deref() {
        if !verify_key_hmac(&key.secret_hash, &key.key_id, mac) {
            bail_i18n!(StatusCode::UNAUTHORIZED, &exchange_locale, "apikey.invalid");
        }
    } else {
        client_bail!("Provide either 'apiKey' (Mode 1) or 'keyId' + 'mac' (Mode 2)");
    }

    // Mode 1: when origins are pinned, the browser-set Origin must be allow-listed.
    if !key.allowed_origins.is_empty() {
        let allowed = origin
            .as_deref()
            .is_some_and(|origin| key.allowed_origins.iter().any(|value| value == origin));
        if !allowed {
            bail_i18n!(
                StatusCode::FORBIDDEN,
                &exchange_locale,
                "apikey.origin_denied"
            );
        }
    }

    // Per-key volume cap: catches one key hammering across many IPs (which per-IP alone can't see).
    // Applied only after possession is verified, so it counts *real* exchanges (the quota use-case),
    // and honors the key's optional override (raise, or disable for a controlled public-token flow).
    let key_policy = effective_token_policy(&limits.token_exchange, key.rate_limit.as_ref());
    if let Decision::Block { retry_after } = rate_limiter
        .check(POLICY_TOKEN_EXCHANGE, &key_policy, &key.key_id, now)
        .await
    {
        return Ok(ExchangeOutcome::RateLimited { retry_after });
    }

    // Pick the target API from the `api` param (default `umami`) — keys are not pinned to an
    // audience; the requested audience is still bounded by the key's scopes + the API's eligibility.
    let api_code = request.api.as_deref().unwrap_or("umami").to_owned();

    let access_ttl_secs = config.security.access_ttl_secs as i64;

    let is_system = |tenant: &str| system_tenant_id.as_deref() == Some(tenant);

    // The token's subject set depends on the key kind: a PAT acts as its user (its `role:*`,
    // intersected with the key's optional restriction); a service key acts as itself (its `scope:*`).
    let (access_token, _exp) = match &key.user_id {
        Some(user_id) => {
            // Personal access token — load the user fresh so deactivation/lock stops new tokens.
            let user = match users.get_user(user_id).await? {
                Some(user) if !user.locked => user,
                _ => bail_i18n!(StatusCode::UNAUTHORIZED, &exchange_locale, "apikey.invalid"),
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
                    email: &synthetic,
                    tenant_id: &user.tenant_id,
                    token_version: user.token_version,
                    subjects: &subjects,
                    features: &features,
                    // A key never switches tenants, so acting-in and membership coincide.
                    // A relaying service states the language of the person it acts for; a PAT
                    // otherwise inherits its owner's.
                    locale: &crate::i18n::resolve(
                        &config,
                        request.locale.as_deref().or(user.locale.as_deref()),
                        None,
                    ),
                    system_tenant: is_system(&user.tenant_id),
                    system_tenant_member: is_system(&user.tenant_id),
                    passkey: false,
                    totp: false,
                    user: Some(&user),
                    tenant: None,
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
                    email: &synthetic_email,
                    tenant_id: &key.tenant_id,
                    token_version: 0,
                    subjects: &key.scopes,
                    features: &features,
                    // A key never switches tenants, so acting-in and membership coincide.
                    // A pure machine key has no user to inherit from.
                    locale: &crate::i18n::resolve(&config, request.locale.as_deref(), None),
                    system_tenant: is_system(&key.tenant_id),
                    system_tenant_member: is_system(&key.tenant_id),
                    passkey: false,
                    totp: false,
                    user: None,
                    tenant: None,
                    kind: Some("api_key"),
                    access_ttl_secs,
                },
            )
            .await?
        }
    };

    // Best-effort usage markers; failure to record must not fail the exchange.
    if let Err(err) = keys.touch_last_used(&key_id).await {
        tracing::warn!("failed to update api key lastUsedAt: {err:#}");
    }
    if let Err(err) = tenants.touch_last_active(&key.tenant_id).await {
        tracing::warn!(
            "failed to update lastActive for tenant {}: {err:#}",
            key.tenant_id
        );
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

    Ok(ExchangeOutcome::Ok(ExchangeResponse {
        access_token,
        expires_in: access_ttl_secs,
    }))
}

/// Builds the effective per-key `tokenExchange` policy: the key's optional override raises/replaces
/// the global values (any unset field falls back to global), or disables the per-key cap entirely.
pub(crate) fn effective_token_policy(
    global: &VolumeRateLimit,
    override_: Option<&KeyRateLimit>,
) -> Policy {
    match override_ {
        Some(over) if over.disabled => Policy::new(0, global.window_secs, global.block_secs),
        Some(over) => Policy::new(
            over.max_per_window.unwrap_or(global.max_per_window),
            over.window_secs.unwrap_or(global.window_secs),
            over.block_secs.unwrap_or(global.block_secs),
        ),
        None => Policy::new(global.max_per_window, global.window_secs, global.block_secs),
    }
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
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> anyhow::Result<CreateApiKeyResponse> {
    enforce_own(&tenant_id, &caller)?;

    if request.name.trim().is_empty() {
        client_bail!("API key 'name' is required");
    }

    // Validate any requested scopes against what the tenant's features license — including the
    // synthetic markers (e.g. is:system-tenant) so system-only scopes validate in the system tenant.
    let scopes = request.scopes.unwrap_or_default();
    if !scopes.is_empty() {
        let features = tenant_features(&tenants, &tenant_id).await?;
        let config = config.current().await?;
        let is_system = system_tenant_id.as_deref() == Some(tenant_id.as_str());
        let set = config.eval_feature_set(&features, is_system);
        for scope in &scopes {
            if !config.can_assign_scope(scope, &set) {
                client_bail!("Scope '{scope}' is not assignable in this tenant");
            }
        }
    }

    let secret = generate_refresh_secret();
    let key_id = generate_id();
    let api_key = format!("{KEY_PREFIX}{key_id}_{secret}");

    keys.create(NewApiKey {
        key_id: key_id.clone(),
        tenant_id,
        secret_hash: hash_refresh_secret(&secret),
        name: request.name.clone(),
        user_id: None, // service key
        roles: Vec::new(),
        scopes,
        allow_secret_login: request.allow_secret_login.unwrap_or(false),
        allowed_origins: request.allowed_origins.unwrap_or_default(),
        rate_limit: request.rate_limit,
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

    keys.create(NewApiKey {
        key_id: key_id.clone(),
        tenant_id,
        secret_hash: hash_refresh_secret(&secret),
        name: request.name.clone(),
        user_id: Some(user_id),                   // personal access token
        roles: request.roles.unwrap_or_default(), // restriction ∩ the user's own roles at mint time
        scopes: Vec::new(),
        // PATs are used as a raw bearer token (CLI/scripts), so the raw-secret exchange is always
        // enabled — the `allowSecretLogin` toggle is a service-key concern only.
        allow_secret_login: true,
        allowed_origins: Vec::new(),
        // PATs use the global per-key exchange policy; no per-key override at self-service creation.
        rate_limit: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors what a Mode-2 client computes: HMAC over the hour bucket, keyed by SHA-256(secret).
    fn client_mac(secret: &str, key_id: &str, bucket: i64) -> String {
        let hmac_key = URL_SAFE_NO_PAD.decode(hash_refresh_secret(secret)).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&hmac_key).unwrap();
        mac.update(format!("umami:apikey:{key_id}:{bucket}").as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    #[test]
    fn hmac_accepts_the_current_bucket_and_rejects_tampering() {
        let secret = "s3cr3t-value";
        let stored = hash_refresh_secret(secret);
        let bucket = Utc::now().timestamp().div_euclid(3600);

        // Correct MAC for the current hour verifies.
        assert!(verify_key_hmac(
            &stored,
            "key-1",
            &client_mac(secret, "key-1", bucket)
        ));
        // A stale/far bucket (outside ±1) is rejected.
        assert!(!verify_key_hmac(
            &stored,
            "key-1",
            &client_mac(secret, "key-1", bucket - 5)
        ));
        // A MAC bound to a different key id is rejected (no cross-key replay).
        assert!(!verify_key_hmac(
            &stored,
            "key-1",
            &client_mac(secret, "key-2", bucket)
        ));
        // Wrong secret, and garbage input, are rejected.
        assert!(!verify_key_hmac(
            &stored,
            "key-1",
            &client_mac("wrong", "key-1", bucket)
        ));
        assert!(!verify_key_hmac(&stored, "key-1", "!!not-base64!!"));
    }
}
