//! `POST /auth/exchange` — downstream token exchange for a logged-in user.
//!
//! Authenticated by the caller's umami access token, this mints a token for a *product* API in the
//! config `apis` catalog (e.g. `dbx-core`) so a user/SPA can call that API directly. The requester's
//! set S = permissions ∪ features comes from the user's roles + their tenant's effective features;
//! the target API's eligibility, permission projection, and claim mapping apply. See
//! `docs/AUDIENCES.md`. RFC-8693-style; no session/cookie is created.

use crate::auth::broker::{MintParams, mint_for_api};
use crate::auth::tokens::TokenIssuer;
use crate::config::repository::ConfigRepository;
use crate::constants::MAX_TEXT_BODY_SIZE;
use crate::tenants::effective_features;
use crate::tenants::repository::TenantRepository;
use crate::users::UserStatus;
use crate::users::repository::UserRepository;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
        Some(user) if user.status == UserStatus::Active => user,
        _ => status_bail!(StatusCode::UNAUTHORIZED, "Account not active"),
    };

    let config = deps.config.current().await?;
    let access_ttl_secs = config.security.access_ttl_secs as i64;

    let tenant = deps.tenants.get_tenant(&user.tenant_id).await?;
    let features: Vec<String> = tenant
        .as_ref()
        .map(|tenant| effective_features(&config, tenant).into_iter().collect())
        .unwrap_or_default();
    let empty_fields = BTreeMap::new();
    let tenant_custom_fields = tenant
        .as_ref()
        .map(|tenant| &tenant.custom_fields)
        .unwrap_or(&empty_fields);

    let (access_token, _exp) = mint_for_api(
        &deps.tokens,
        &config,
        MintParams {
            api_code: &request.api,
            subject: &user.user_id,
            name: &user.name,
            email: user.email.as_deref().unwrap_or_default(),
            locale: &user.locale,
            tenant_id: &user.tenant_id,
            token_version: user.token_version,
            roles: &user.roles,
            features: &features,
            user_custom_fields: &user.custom_fields,
            tenant_custom_fields,
            kind: None,
            access_ttl_secs,
        },
    )
    .await?;

    Ok(ExchangeResponse {
        access_token,
        expires_in: access_ttl_secs,
    })
}
