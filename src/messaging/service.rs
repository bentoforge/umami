//! Messaging-link routes: self-service (code + own links) and machine (link/resolve).
//!
//! - Self (`/auth/me/messaging-*`, any authenticated user): read/regenerate the link code, list +
//!   remove own external identities.
//! - Machine (`/messaging/*`): `POST /messaging/links` (`messaging:link`) claims a mapping from a
//!   code; `GET /messaging/resolve` (`messaging:resolve`) turns an identity into user info or a
//!   minted token. Both permissions are held only by system-tenant service keys (see the config
//!   `scope:messaging-*` mappings gated on `is:system-tenant`).

use crate::auth::broker::{MintParams, mint_for_api};
use crate::auth::tokens::TokenIssuer;
use crate::config::repository::ConfigRepository;
use crate::constants::{
    MAX_TEXT_BODY_SIZE, MESSAGING_LINK_PERMISSION, MESSAGING_RESOLVE_PERMISSION,
};
use crate::messaging::repository::MessagingRepository;
use crate::messaging::{MessagingLink, normalize_platform};
use crate::tenants::repository::TenantRepository;
use crate::users::UserStatus;
use crate::users::repository::UserRepository;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::{with_user, with_user_with_any_permission};
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};
use wasabi::{client_bail, status_bail};

const REQUIRE_LINK: &[&str] = &[MESSAGING_LINK_PERMISSION];
const REQUIRE_RESOLVE: &[&str] = &[MESSAGING_RESOLVE_PERMISSION];

/// Self-service link-code response.
#[derive(Serialize, Debug)]
struct CodeResponse {
    code: String,
}

/// Self-service link list.
#[derive(Serialize, Debug)]
struct LinksResponse {
    links: Vec<MessagingLink>,
}

/// Machine request to claim a mapping from a link code.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LinkRequest {
    code: String,
    platform: String,
    external_id: String,
}

/// Query for the resolve endpoint. `format=jwt` (with `api`) mints a token instead of JSON.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ResolveQuery {
    platform: String,
    external_id: String,
    format: Option<String>,
    api: Option<String>,
}

/// Resolved user info (default resolve output).
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ResolvedUser {
    user_id: String,
    tenant_id: String,
    name: String,
    email: Option<String>,
    locale: String,
    roles: Vec<String>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `GET /auth/me/messaging-code` — the caller's link code (created on first read).
pub fn my_code_route(
    messaging: Arc<dyn MessagingRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "messaging-code")
        .and(warp::get())
        .and(with_cloneable(messaging))
        .and(with_user(authenticator))
        .and_then(handle_my_code_route)
        .boxed()
}

/// `POST /auth/me/messaging-code/regenerate` — replace the caller's link code.
pub fn regenerate_code_route(
    messaging: Arc<dyn MessagingRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "messaging-code" / "regenerate")
        .and(warp::post())
        .and(with_cloneable(messaging))
        .and(with_user(authenticator))
        .and_then(handle_regenerate_code_route)
        .boxed()
}

/// `GET /auth/me/messaging-links` — the caller's external-identity mappings.
pub fn my_links_route(
    messaging: Arc<dyn MessagingRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "messaging-links")
        .and(warp::get())
        .and(with_cloneable(messaging))
        .and(with_user(authenticator))
        .and_then(handle_my_links_route)
        .boxed()
}

/// `DELETE /auth/me/messaging-links/{platform}/{externalId}` — remove one of the caller's mappings.
pub fn delete_my_link_route(
    messaging: Arc<dyn MessagingRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "messaging-links" / String / String)
        .and(warp::delete())
        .and(with_cloneable(messaging))
        .and(with_user(authenticator))
        .and_then(handle_delete_my_link_route)
        .boxed()
}

/// `POST /messaging/links` — machine: claim a mapping from a link code (`messaging:link`).
pub fn create_link_route(
    messaging: Arc<dyn MessagingRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("messaging" / "links")
        .and(warp::post())
        .and(with_body_as_json::<LinkRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(messaging))
        .and(with_user_with_any_permission(authenticator, REQUIRE_LINK))
        .and_then(handle_create_link_route)
        .boxed()
}

/// Dependencies for the resolve endpoint (JSON or minted token).
#[derive(Clone)]
pub struct ResolveDeps {
    /// Messaging mappings.
    pub messaging: Arc<dyn MessagingRepository>,
    /// User store (resolve the mapped user fresh).
    pub users: Arc<dyn UserRepository>,
    /// Tenant store (features for a minted token).
    pub tenants: Arc<dyn TenantRepository>,
    /// Config (`apis` catalog for the token variant).
    pub config: Arc<dyn ConfigRepository>,
    /// Token signer.
    pub tokens: Arc<TokenIssuer>,
}

/// `GET /messaging/resolve` — machine: identity → user info or token (`messaging:resolve`).
pub fn resolve_route(
    deps: ResolveDeps,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("messaging" / "resolve")
        .and(warp::get())
        .and(warp::query::<ResolveQuery>())
        .and(with_cloneable(deps))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_RESOLVE,
        ))
        .and_then(handle_resolve_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "GET /auth/me/messaging-code", skip_all)]
async fn handle_my_code_route(
    messaging: Arc<dyn MessagingRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(my_code(messaging, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "POST /auth/me/messaging-code/regenerate",
    skip_all
)]
async fn handle_regenerate_code_route(
    messaging: Arc<dyn MessagingRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(regenerate_code(messaging, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /auth/me/messaging-links", skip_all)]
async fn handle_my_links_route(
    messaging: Arc<dyn MessagingRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(my_links(messaging, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "DELETE /auth/me/messaging-links/{platform}/{externalId}",
    skip_all
)]
async fn handle_delete_my_link_route(
    platform: String,
    external_id: String,
    messaging: Arc<dyn MessagingRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(delete_my_link(platform, external_id, messaging, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /messaging/links", skip_all)]
async fn handle_create_link_route(
    request: LinkRequest,
    messaging: Arc<dyn MessagingRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_link(request, messaging).await)
}

#[tracing::instrument(level = "debug", name = "GET /messaging/resolve", skip_all)]
async fn handle_resolve_route(
    query: ResolveQuery,
    deps: ResolveDeps,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(resolve(query, deps).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

async fn my_code(
    messaging: Arc<dyn MessagingRepository>,
    caller: AuthUser,
) -> anyhow::Result<CodeResponse> {
    let code = messaging
        .ensure_code(caller.user_id()?, caller.tenant_id()?)
        .await?;
    Ok(CodeResponse { code })
}

async fn regenerate_code(
    messaging: Arc<dyn MessagingRepository>,
    caller: AuthUser,
) -> anyhow::Result<CodeResponse> {
    let code = messaging
        .regenerate_code(caller.user_id()?, caller.tenant_id()?)
        .await?;
    Ok(CodeResponse { code })
}

async fn my_links(
    messaging: Arc<dyn MessagingRepository>,
    caller: AuthUser,
) -> anyhow::Result<LinksResponse> {
    let links = messaging.list_links(caller.user_id()?).await?;
    Ok(LinksResponse { links })
}

async fn delete_my_link(
    platform: String,
    external_id: String,
    messaging: Arc<dyn MessagingRepository>,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    let platform = normalize_platform(&platform)?;
    messaging
        .delete_link(caller.user_id()?, &platform, &external_id)
        .await?;
    Ok(json!({ "status": "unlinked" }))
}

async fn create_link(
    request: LinkRequest,
    messaging: Arc<dyn MessagingRepository>,
) -> anyhow::Result<Value> {
    let platform = normalize_platform(&request.platform)?;
    let external_id = request.external_id.trim().to_owned();
    if external_id.is_empty() {
        client_bail!("'externalId' is required");
    }
    // Codes are uppercase; accept case-insensitively.
    let code = request.code.trim().to_uppercase();

    let subject = match messaging.subject_for_code(&code).await? {
        Some(subject) => subject,
        None => status_bail!(StatusCode::NOT_FOUND, "Invalid link code"),
    };
    messaging
        .create_link(&subject, &platform, &external_id)
        .await?;

    Ok(json!({ "userId": subject.user_id, "tenantId": subject.tenant_id }))
}

async fn resolve(query: ResolveQuery, deps: ResolveDeps) -> anyhow::Result<Value> {
    let platform = normalize_platform(&query.platform)?;
    let external_id = query.external_id.trim().to_owned();
    if external_id.is_empty() {
        client_bail!("'externalId' is required");
    }

    let subject = match deps
        .messaging
        .subject_for_external(&platform, &external_id)
        .await?
    {
        Some(subject) => subject,
        None => status_bail!(StatusCode::NOT_FOUND, "No user linked to that identity"),
    };

    let user = match deps.users.get_user(&subject.user_id).await? {
        Some(user) if user.status == UserStatus::Active => user,
        _ => status_bail!(StatusCode::NOT_FOUND, "Linked user is not active"),
    };

    // Token variant: mint a downstream token for the requested API.
    if query.format.as_deref() == Some("jwt") {
        let api = match query.api.as_deref() {
            Some(api) if !api.is_empty() => api,
            _ => client_bail!("'api' is required when format=jwt"),
        };
        let config = deps.config.current().await?;
        let access_ttl_secs = config.security.access_ttl_secs as i64;
        let tenant = deps.tenants.get_tenant(&user.tenant_id).await?;
        let features: Vec<String> = tenant
            .as_ref()
            .map(|tenant| tenant.features.clone())
            .unwrap_or_default();
        let empty = std::collections::BTreeMap::new();
        let tenant_custom_fields = tenant.as_ref().map(|t| &t.custom_fields).unwrap_or(&empty);
        let (access_token, _exp) = mint_for_api(
            &deps.tokens,
            &config,
            MintParams {
                api_code: api,
                subject: &user.user_id,
                name: &user.name,
                email: user.email.as_deref().unwrap_or_default(),
                locale: &user.locale,
                tenant_id: &user.tenant_id,
                token_version: user.token_version,
                subjects: &user.roles,
                features: &features,
                // A messaging-resolved token never carries system-admin rights.
                system_tenant: false,
                user_custom_fields: &user.custom_fields,
                tenant_custom_fields,
                kind: Some("messaging"),
                access_ttl_secs,
            },
        )
        .await?;
        return Ok(json!({ "accessToken": access_token, "expiresIn": access_ttl_secs }));
    }

    // Default: compact user info.
    Ok(serde_json::to_value(ResolvedUser {
        user_id: user.user_id,
        tenant_id: user.tenant_id,
        name: user.name,
        email: user.email,
        locale: user.locale,
        roles: user.roles,
    })?)
}
