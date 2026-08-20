//! `POST /auth/exchange` — downstream token exchange for a logged-in user.
//!
//! Authenticated by the caller's umami access token, this mints a token for a *product* API in the
//! config `apis` catalog (e.g. `dbx-core`) so a user/SPA can call that API directly. The requester's
//! set S = permissions ∪ features comes from the user's roles + their tenant's effective features;
//! the target API's eligibility, permission projection, and claim mapping apply. See
//! `docs/AUDIENCES.md`. RFC-8693-style; no session/cookie is created.

use crate::audit::repository::{AuditRepository, record_best_effort};
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::broker::{MintParams, mint_for_api};
use crate::auth::tokens::TokenIssuer;
use crate::config::repository::ConfigRepository;
use crate::constants::MAX_TEXT_BODY_SIZE;
use crate::tenants::repository::TenantRepository;
use crate::users::repository::UserRepository;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::status_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user;
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};

/// Exchange request: the target API code (from the config `apis` catalog).
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ExchangeRequest {
    api: String,
}

/// Exchange response: the short-lived downstream access token.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ExchangeResponse {
    access_token: String,
    expires_in: i64,
}

/// Dependencies for the user downstream exchange.
#[derive(Clone)]
pub struct ExchangeDeps {
    /// User store (roles + custom fields, resolved fresh).
    pub users: Arc<dyn UserRepository>,
    /// Tenant store (effective features + custom fields).
    pub tenants: Arc<dyn TenantRepository>,
    /// Config (the `apis` catalog).
    pub config: Arc<dyn ConfigRepository>,
    /// Token signer.
    pub tokens: Arc<TokenIssuer>,
    /// Security audit trail.
    pub audit: Arc<dyn AuditRepository>,
    /// The configured system tenant (adds `is:system-tenant` when the caller's tenant matches).
    pub system_tenant_id: Option<String>,
}

/// `POST /auth/exchange` — mint a downstream product-API token for the authenticated user.
pub fn exchange_route(
    deps: ExchangeDeps,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "exchange")
        .and(warp::post())
        .and(with_body_as_json::<ExchangeRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_user(authenticator))
        .and_then(handle_exchange_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /auth/exchange", skip_all)]
async fn handle_exchange_route(
    request: ExchangeRequest,
    deps: ExchangeDeps,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(exchange(request, deps, caller).await)
}

async fn exchange(
    request: ExchangeRequest,
    deps: ExchangeDeps,
    caller: AuthUser,
) -> anyhow::Result<ExchangeResponse> {
    let user = match deps.users.get_user(caller.user_id()?).await? {
        Some(user) if !user.locked => user,
        _ => status_bail!(StatusCode::UNAUTHORIZED, "Account not active"),
    };

    let config = deps.config.current().await?;
    let access_ttl_secs = config.security.access_ttl_secs as i64;

    // Carry the second factors from the caller's token so downstream tokens keep is:2fa etc.
    let (passkey, totp) = crate::auth::broker::auth_strength(&caller);

    let tenant = deps.tenants.get_tenant(&user.tenant_id).await?;
    let features: Vec<String> = tenant
        .as_ref()
        .map(|tenant| tenant.features.clone())
        .unwrap_or_default();
    let minted = mint_for_api(
        &deps.tokens,
        &config,
        MintParams {
            api_code: &request.api,
            subject: &user.user_id,
            email: user.email.as_deref().unwrap_or_default(),
            tenant_id: &user.tenant_id,
            token_version: user.token_version,
            subjects: &user.roles,
            features: &features,
            system_tenant: deps.system_tenant_id.as_deref() == Some(user.tenant_id.as_str()),
            passkey,
            totp,
            user: Some(&user),
            tenant: tenant.as_ref(),
            kind: None,
            access_ttl_secs,
        },
    )
    .await;

    // A routine "give me a fresher token for API X" is not worth an audit row (it would flood the
    // log) — we only bump the user's `lastSeen` on success. A *denial* (e.g. the user isn't
    // eligible for the API) is a "bad" event worth recording.
    if minted.is_err() {
        record_best_effort(
            &deps.audit,
            NewAuditEntry::new(
                AuditSeverity::Bad,
                Some(user.tenant_id.clone()),
                Some(user.user_id.clone()),
                format!("Denied downstream token for API '{}'", request.api),
            ),
        )
        .await;
    }

    let (access_token, _exp) = minted?;

    // Success: mark the user + tenant active (best-effort), no audit row.
    if let Err(err) = deps.users.touch_last_seen(&user.user_id).await {
        tracing::warn!("failed to update lastSeen for {}: {err:#}", user.user_id);
    }
    if let Err(err) = deps.tenants.touch_last_active(&user.tenant_id).await {
        tracing::warn!(
            "failed to update lastActive for tenant {}: {err:#}",
            user.tenant_id
        );
    }

    Ok(ExchangeResponse {
        access_token,
        expires_in: access_ttl_secs,
    })
}
