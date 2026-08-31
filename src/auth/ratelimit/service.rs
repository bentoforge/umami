//! Read routes that make the rate limiter visible: a subject's live state, and the deployment-wide
//! overview of what recently tripped.
//!
//! Every route here is read-only, and so is the store access behind it — looking at a counter must
//! never move it (see [`RateLimiter::inspect_volume`]).
//!
//! # Two lookup shapes, two costs
//! - **A named subject** (`/auth/me`, `/users/{id}`, an API key) is a `GetItem` on the counter and
//!   the block for that subject: two small reads, no index.
//! - **The overview** cannot name its subjects in advance — which IPs tripped is the question — so
//!   it queries `BlocksByPolicyIndex` for one bounded page per policy. Only *blocks* are indexed,
//!   which is what keeps this cheap; see the repository's module docs.

use crate::auth::apikeys::effective_token_policy;
use crate::auth::apikeys::repository::ApiKeyRepository;
use crate::auth::ratelimit::repository::BlockRecord;
use crate::auth::ratelimit::{ALL_POLICIES, POLICY_LOGIN, POLICY_TOKEN_EXCHANGE, RateLimiter};
use crate::auth::ratelimit::{Policy, SubjectState};
use crate::config::repository::ConfigRepository;
use crate::constants::{
    MANAGE_PERSONAL_TOKENS_PERMISSION, MANAGE_SERVICE_KEYS_PERMISSION, MANAGE_USERS_PERMISSION,
    RATELIMIT_BLOCK_LIMIT, RATELIMIT_LOOKBACK_SECS, VIEW_RATELIMITS_PERMISSION,
};
use crate::users::repository::UserRepository;
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use serde::Serialize;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::client_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::{with_user, with_user_with_any_permission};
use wasabi::web::warp::{into_response, with_cloneable};

const REQUIRE_MANAGE_USERS: &[&str] = &[MANAGE_USERS_PERMISSION];
const REQUIRE_MANAGE_SERVICE_KEYS: &[&str] = &[MANAGE_SERVICE_KEYS_PERMISSION];
const REQUIRE_MANAGE_PAT: &[&str] = &[MANAGE_PERSONAL_TOKENS_PERMISSION];
const REQUIRE_VIEW_RATELIMITS: &[&str] = &[VIEW_RATELIMITS_PERMISSION];

/// A subject's live state under one policy.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SubjectStateView {
    /// The policy this state belongs to (`login`, `tokenExchange`, …).
    policy: String,
    /// Requests/failures counted in the current window.
    count: u64,
    /// The cap in force. `0` ⇒ the policy is switched off and nothing is counted.
    max: u32,
    /// The counting window, in seconds.
    window_secs: i64,
    /// How long a block lasts once the cap trips, in seconds.
    block_secs: i64,
    /// When the current window resets, if one is running.
    #[serde(skip_serializing_if = "Option::is_none")]
    window_ends_at: Option<String>,
    /// When an active block lifts; absent when the subject is not blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_until: Option<String>,
    /// Seconds until that block lifts (mirrors the `Retry-After` the subject would be served).
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<i64>,
}

impl SubjectStateView {
    fn build(state: SubjectState, now: DateTime<Utc>) -> Self {
        SubjectStateView {
            policy: state.policy,
            count: state.count,
            max: state.max,
            window_secs: state.window_secs,
            block_secs: state.block_secs,
            window_ends_at: state.window_ends_at.and_then(rfc3339),
            blocked_until: state.blocked_until.and_then(rfc3339),
            retry_after: state
                .blocked_until
                .map(|until| (until - now.timestamp()).max(0)),
        }
    }
}

/// The states that apply to one subject. A list rather than a single object: a user is only capped
/// on failed logins today, but the shape does not have to change when that stops being true.
#[derive(Serialize, Debug)]
struct SubjectStateResponse {
    states: Vec<SubjectStateView>,
}

/// One recently tripped block, for the overview.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BlockView {
    /// The policy that tripped.
    policy: String,
    /// The blocked subject — an IP for the `perIp:*` policies, a user id for `login`, a key id for
    /// `tokenExchange`.
    subject: String,
    /// When the block was set.
    blocked_at: String,
    /// When it lifts (in the past for an expired-but-recent block).
    blocked_until: String,
    /// Whether it is still in force.
    active: bool,
    /// Seconds until it lifts; absent once it has.
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<i64>,
}

/// The overview: recent blocks plus the window they were read over, so the client can label it
/// without restating the request.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BlockListResponse {
    blocks: Vec<BlockView>,
    /// Start of the window the blocks were read over.
    since: String,
    /// The policies queried.
    policies: Vec<String>,
}

/// Formats an epoch as RFC3339, dropping a value the clock cannot represent.
fn rfc3339(epoch: i64) -> Option<String> {
    Utc.timestamp_opt(epoch, 0)
        .single()
        .map(|when| when.to_rfc3339_opts(SecondsFormat::Secs, true))
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `GET /auth/me/rate-limit` — the caller's own login brute-force state.
pub fn my_rate_limit_route(
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "rate-limit")
        .and(warp::get())
        .and(with_cloneable(config))
        .and(with_cloneable(rate_limiter))
        .and(with_user(authenticator))
        .and_then(handle_my_rate_limit_route)
        .boxed()
}

/// `GET /users/{id}/rate-limit` — a tenant user's login brute-force state (requires
/// `manage:users`).
pub fn user_rate_limit_route(
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String / "rate-limit")
        .and(warp::get())
        .and(with_cloneable(users))
        .and(with_cloneable(config))
        .and(with_cloneable(rate_limiter))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_user_rate_limit_route)
        .boxed()
}

/// `GET /tenants/{id}/api-keys/{keyId}/rate-limit` — a service key's token-exchange state (requires
/// `manage:service-keys`).
pub fn api_key_rate_limit_route(
    keys: Arc<dyn ApiKeyRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "api-keys" / String / "rate-limit")
        .and(warp::get())
        .and(with_cloneable(keys))
        .and(with_cloneable(config))
        .and(with_cloneable(rate_limiter))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_SERVICE_KEYS,
        ))
        .and_then(handle_api_key_rate_limit_route)
        .boxed()
}

/// `GET /auth/me/api-keys/{keyId}/rate-limit` — one of the caller's own PATs (self-service).
pub fn my_pat_rate_limit_route(
    keys: Arc<dyn ApiKeyRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "api-keys" / String / "rate-limit")
        .and(warp::get())
        .and(with_cloneable(keys))
        .and(with_cloneable(config))
        .and(with_cloneable(rate_limiter))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_PAT,
        ))
        .and_then(handle_my_pat_rate_limit_route)
        .boxed()
}

/// `GET /users/{id}/pats/{keyId}/rate-limit` — a tenant user's personal access token, read-only
/// (requires `manage:users`), mirroring the read-only PAT list on the same screen.
pub fn user_pat_rate_limit_route(
    keys: Arc<dyn ApiKeyRepository>,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String / "pats" / String / "rate-limit")
        .and(warp::get())
        .and(with_cloneable(keys))
        .and(with_cloneable(users))
        .and(with_cloneable(config))
        .and(with_cloneable(rate_limiter))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_user_pat_rate_limit_route)
        .boxed()
}

/// `GET /rate-limits/blocks` — the deployment-wide overview of what recently tripped (requires
/// `view:ratelimits`).
///
/// Takes no parameters. The window and the cap are the server's to choose: they are what bounds
/// the index read, and a caller that could widen them could turn one screen into an expensive
/// query. The response states both, so the client labels the view from what it actually got.
pub fn rate_limit_blocks_route(
    rate_limiter: Arc<RateLimiter>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("rate-limits" / "blocks")
        .and(warp::get())
        .and(with_cloneable(rate_limiter))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_VIEW_RATELIMITS,
        ))
        .and_then(handle_rate_limit_blocks_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "GET /auth/me/rate-limit", skip_all)]
async fn handle_my_rate_limit_route(
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(my_rate_limit(config, rate_limiter, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /users/{id}/rate-limit", skip_all)]
async fn handle_user_rate_limit_route(
    user_id: String,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(user_rate_limit(user_id, users, config, rate_limiter, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "GET /tenants/{id}/api-keys/{keyId}/rate-limit",
    skip_all
)]
async fn handle_api_key_rate_limit_route(
    tenant_id: String,
    key_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(api_key_rate_limit(tenant_id, key_id, keys, config, rate_limiter, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "GET /auth/me/api-keys/{keyId}/rate-limit",
    skip_all
)]
async fn handle_my_pat_rate_limit_route(
    key_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(my_pat_rate_limit(key_id, keys, config, rate_limiter, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "GET /users/{id}/pats/{keyId}/rate-limit",
    skip_all
)]
async fn handle_user_pat_rate_limit_route(
    user_id: String,
    key_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(
        user_pat_rate_limit(user_id, key_id, keys, users, config, rate_limiter, caller).await,
    )
}

#[tracing::instrument(level = "debug", name = "GET /rate-limits/blocks", skip_all)]
async fn handle_rate_limit_blocks_route(
    rate_limiter: Arc<RateLimiter>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(rate_limit_blocks(rate_limiter).await)
}

// ── Business handlers ────────────────────────────────────────────────────────

/// The brute-force state of one account, keyed on the user id exactly as `/auth/login` keys it.
async fn login_state(
    user_id: &str,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
) -> anyhow::Result<SubjectStateResponse> {
    let config = config.current().await?;
    let limits = &config.security.rate_limits.login;
    let policy = Policy::new(limits.max_failures, limits.window_secs, limits.block_secs);
    let now = Utc::now();
    let state = rate_limiter
        .inspect_failures(POLICY_LOGIN, &policy, user_id, now)
        .await?;
    Ok(SubjectStateResponse {
        states: vec![SubjectStateView::build(state, now)],
    })
}

async fn my_rate_limit(
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    caller: AuthUser,
) -> anyhow::Result<SubjectStateResponse> {
    login_state(caller.user_id()?, config, rate_limiter).await
}

async fn user_rate_limit(
    user_id: String,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    caller: AuthUser,
) -> anyhow::Result<SubjectStateResponse> {
    let tenant_id = caller.tenant_id()?;
    // Scope strictly to the caller's tenant — a foreign user reads as "not found".
    match users.get_user(&user_id).await? {
        Some(user) if user.tenant_id == tenant_id => {}
        _ => client_bail!("No such user in this tenant"),
    }
    login_state(&user_id, config, rate_limiter).await
}

/// The token-exchange state of one key, under the policy that key actually runs on (its optional
/// override, or the global one).
async fn key_state(
    key_id: &str,
    key_rate_limit: Option<&crate::auth::apikeys::repository::KeyRateLimit>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
) -> anyhow::Result<SubjectStateResponse> {
    let config = config.current().await?;
    let policy =
        effective_token_policy(&config.security.rate_limits.token_exchange, key_rate_limit);
    let now = Utc::now();
    let state = rate_limiter
        .inspect_volume(POLICY_TOKEN_EXCHANGE, &policy, key_id, now)
        .await?;
    Ok(SubjectStateResponse {
        states: vec![SubjectStateView::build(state, now)],
    })
}

async fn api_key_rate_limit(
    tenant_id: String,
    key_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    caller: AuthUser,
) -> anyhow::Result<SubjectStateResponse> {
    if caller.tenant_id()? != tenant_id {
        client_bail!("No such API key in this tenant");
    }
    // Service keys only, scoped to the tenant — PATs are read through the self-service route.
    let key = match keys.get(&key_id).await? {
        Some(key) if key.tenant_id == tenant_id && key.user_id.is_none() => key,
        _ => client_bail!("No such API key in this tenant"),
    };
    key_state(&key.key_id, key.rate_limit.as_ref(), config, rate_limiter).await
}

async fn my_pat_rate_limit(
    key_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    caller: AuthUser,
) -> anyhow::Result<SubjectStateResponse> {
    let user_id = caller.user_id()?;
    // A user may only read their own PATs; anything else reads as "not found".
    let key = match keys.get(&key_id).await? {
        Some(key) if key.user_id.as_deref() == Some(user_id) => key,
        _ => client_bail!("No such personal access token"),
    };
    key_state(&key.key_id, key.rate_limit.as_ref(), config, rate_limiter).await
}

#[allow(clippy::too_many_arguments)]
async fn user_pat_rate_limit(
    user_id: String,
    key_id: String,
    keys: Arc<dyn ApiKeyRepository>,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    rate_limiter: Arc<RateLimiter>,
    caller: AuthUser,
) -> anyhow::Result<SubjectStateResponse> {
    let tenant_id = caller.tenant_id()?;
    // Scope strictly to the caller's tenant — a foreign user reads as "not found".
    match users.get_user(&user_id).await? {
        Some(user) if user.tenant_id == tenant_id => {}
        _ => client_bail!("No such user in this tenant"),
    }
    // …and the key must be that user's PAT, not just any key in the tenant.
    let key = match keys.get(&key_id).await? {
        Some(key) if key.user_id.as_deref() == Some(user_id.as_str()) => key,
        _ => client_bail!("No such personal access token"),
    };
    key_state(&key.key_id, key.rate_limit.as_ref(), config, rate_limiter).await
}

async fn rate_limit_blocks(rate_limiter: Arc<RateLimiter>) -> anyhow::Result<BlockListResponse> {
    let now = Utc::now();
    let since = now.timestamp() - RATELIMIT_LOOKBACK_SECS;
    let blocks = rate_limiter
        .recent_blocks(ALL_POLICIES, since, RATELIMIT_BLOCK_LIMIT)
        .await?;

    Ok(BlockListResponse {
        blocks: blocks
            .into_iter()
            .filter_map(|block| view(block, now))
            .collect(),
        since: rfc3339(since).unwrap_or_default(),
        policies: ALL_POLICIES.iter().map(|p| (*p).to_owned()).collect(),
    })
}

/// Renders one stored block, dropping a row whose epochs the clock cannot represent.
fn view(block: BlockRecord, now: DateTime<Utc>) -> Option<BlockView> {
    let remaining = block.blocked_until - now.timestamp();
    Some(BlockView {
        policy: block.policy,
        subject: block.subject,
        blocked_at: rfc3339(block.blocked_at)?,
        blocked_until: rfc3339(block.blocked_until)?,
        active: remaining > 0,
        retry_after: (remaining > 0).then_some(remaining),
    })
}
