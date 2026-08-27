//! Messaging-link routes: self-service (code + own links) and machine (link/resolve).
//!
//! - Self (`/auth/me/messaging-*`, any authenticated user): read/regenerate the link code, list +
//!   remove own external identities.
//! - Machine (`/messaging/*`): `POST /messaging/links` (`messaging:link`) claims a mapping from a
//!   code; `GET /messaging/resolve` (`messaging:resolve`) turns an identity into user info or a
//!   minted token. Both permissions are held only by system-tenant service keys (see the config
//!   `scope:messaging-*` mappings gated on `is:system-tenant`).

use crate::audit::repository::{AuditRepository, record_best_effort};
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::broker::{MintParams, mint_for_api};
use crate::auth::tokens::TokenIssuer;
use crate::config::MessagingConfig;
use crate::config::repository::ConfigRepository;
use crate::constants::{
    MANAGE_MESSAGING_PERMISSION, MANAGE_USERS_PERMISSION, MAX_TEXT_BODY_SIZE,
    MESSAGING_LINK_PERMISSION, MESSAGING_RESOLVE_PERMISSION,
};
use crate::messaging::repository::MessagingRepository;
use crate::messaging::{MessagingLink, normalize_platform};
use crate::tenants::repository::TenantRepository;
use crate::users::repository::UserRepository;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};
use wasabi::{client_bail, status_bail};

const REQUIRE_SELF: &[&str] = &[MANAGE_MESSAGING_PERMISSION];
const REQUIRE_LINK: &[&str] = &[MESSAGING_LINK_PERMISSION];
const REQUIRE_RESOLVE: &[&str] = &[MESSAGING_RESOLVE_PERMISSION];
const REQUIRE_MANAGE_USERS: &[&str] = &[MANAGE_USERS_PERMISSION];

/// Self-service link-code response, with ready-made deep links when the deployment is configured.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CodeResponse {
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    telegram_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    whatsapp_url: Option<String>,
}

impl CodeResponse {
    /// Builds the response, filling deep links from the configured bot/number.
    fn new(code: String, messaging: &MessagingConfig) -> Self {
        let telegram_url = messaging
            .telegram_bot
            .as_ref()
            .map(|bot| bot.trim().trim_start_matches('@'))
            .filter(|bot| !bot.is_empty())
            .map(|bot| format!("https://t.me/{bot}?start={code}"));
        let whatsapp_url = messaging
            .whatsapp_number
            .as_ref()
            .map(|num| num.chars().filter(char::is_ascii_digit).collect::<String>())
            .filter(|num| !num.is_empty())
            .map(|num| format!("https://wa.me/{num}?text={code}"));
        CodeResponse {
            code,
            telegram_url,
            whatsapp_url,
        }
    }
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
    email: Option<String>,
    roles: Vec<String>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `GET /auth/me/messaging-code` — the caller's link code (valid one, or freshly rotated).
pub fn my_code_route(
    messaging: Arc<dyn MessagingRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "messaging-code")
        .and(warp::get())
        .and(with_cloneable(messaging))
        .and(with_cloneable(config))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
        .and_then(handle_my_code_route)
        .boxed()
}

/// `POST /auth/me/messaging-code/regenerate` — replace the caller's link code.
pub fn regenerate_code_route(
    messaging: Arc<dyn MessagingRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "messaging-code" / "regenerate")
        .and(warp::post())
        .and(with_cloneable(messaging))
        .and(with_cloneable(config))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
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
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
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
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
        .and_then(handle_delete_my_link_route)
        .boxed()
}

/// `GET /users/{id}/messaging-links` — a tenant user's external-identity mappings, read-only
/// (admin view; requires `manage:users`, scoped to the caller's tenant).
pub fn user_links_route(
    messaging: Arc<dyn MessagingRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String / "messaging-links")
        .and(warp::get())
        .and(with_cloneable(messaging))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_user_links_route)
        .boxed()
}

/// `POST /messaging/links` — machine: claim a mapping from a link code (`messaging:link`).
pub fn create_link_route(
    messaging: Arc<dyn MessagingRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("messaging" / "links")
        .and(warp::post())
        .and(with_body_as_json::<LinkRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(messaging))
        .and(with_cloneable(config))
        .and(with_cloneable(audit))
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
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(my_code(messaging, config, audit, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "POST /auth/me/messaging-code/regenerate",
    skip_all
)]
async fn handle_regenerate_code_route(
    messaging: Arc<dyn MessagingRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(regenerate_code(messaging, config, audit, caller).await)
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
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_link(request, messaging, config, audit).await)
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
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<CodeResponse> {
    let user_id = caller.user_id()?;
    let tenant_id = caller.tenant_id()?;
    let config = config.current().await?;
    let ttl_secs = config.security.messaging_code_ttl_secs as i64;

    let (code, generated) = messaging.current_code(user_id, tenant_id, ttl_secs).await?;
    if generated {
        audit_code_generated(&audit, tenant_id, user_id).await;
    }
    Ok(CodeResponse::new(code, &config.messaging))
}

async fn regenerate_code(
    messaging: Arc<dyn MessagingRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<CodeResponse> {
    let user_id = caller.user_id()?;
    let tenant_id = caller.tenant_id()?;
    let code = messaging.regenerate_code(user_id, tenant_id).await?;
    audit_code_generated(&audit, tenant_id, user_id).await;
    Ok(CodeResponse::new(code, &config.current().await?.messaging))
}

/// Records a "link code generated" event (neutral — benign self-service).
async fn audit_code_generated(audit: &Arc<dyn AuditRepository>, tenant_id: &str, user_id: &str) {
    record_best_effort(
        audit,
        NewAuditEntry::new(
            AuditSeverity::Neutral,
            Some(tenant_id.to_owned()),
            Some(user_id.to_owned()),
            "Messaging link code generated".to_owned(),
        ),
    )
    .await;
}

async fn my_links(
    messaging: Arc<dyn MessagingRepository>,
    caller: AuthUser,
) -> anyhow::Result<LinksResponse> {
    let links = messaging.list_links(caller.user_id()?).await?;
    Ok(LinksResponse { links })
}

#[tracing::instrument(level = "debug", name = "GET /users/{id}/messaging-links", skip_all)]
async fn handle_user_links_route(
    user_id: String,
    messaging: Arc<dyn MessagingRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(user_links(user_id, messaging, caller).await)
}

/// Lists a tenant user's messaging links, read-only. Scoped to the caller's tenant by dropping any
/// link whose `tenant_id` differs — so a `manage:users` admin can never read another tenant's links.
async fn user_links(
    user_id: String,
    messaging: Arc<dyn MessagingRepository>,
    caller: AuthUser,
) -> anyhow::Result<LinksResponse> {
    let tenant_id = caller.tenant_id()?;
    let links = messaging
        .list_links(&user_id)
        .await?
        .into_iter()
        .filter(|link| link.tenant_id == tenant_id)
        .collect();
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
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
) -> anyhow::Result<Value> {
    let platform = normalize_platform(&request.platform)?;
    let external_id = request.external_id.trim().to_owned();
    if external_id.is_empty() {
        client_bail!("'externalId' is required");
    }
    // Codes are uppercase; accept case-insensitively.
    let code = request.code.trim().to_uppercase();
    let ttl_secs = config.current().await?.security.messaging_code_ttl_secs as i64;

    // Single-use: consuming deletes the code; only a still-valid one yields a subject.
    let subject = match messaging.consume_code(&code, ttl_secs).await? {
        Some(subject) => subject,
        None => {
            // No tenant/user context on a bad code — record the failed attempt globally.
            record_best_effort(
                &audit,
                NewAuditEntry::new(
                    AuditSeverity::Bad,
                    None,
                    None,
                    format!(
                        "Messaging link rejected (invalid/expired code) for platform '{platform}'"
                    ),
                ),
            )
            .await;
            status_bail!(StatusCode::NOT_FOUND, "Invalid or expired link code");
        }
    };

    messaging
        .create_link(&subject, &platform, &external_id)
        .await?;

    record_best_effort(
        &audit,
        NewAuditEntry::new(
            AuditSeverity::Good,
            Some(subject.tenant_id.clone()),
            Some(subject.user_id.clone()),
            format!("Messaging identity linked ({platform})"),
        ),
    )
    .await;

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
        Some(user) if !user.locked => user,
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
        let (access_token, _exp) = mint_for_api(
            &deps.tokens,
            &config,
            MintParams {
                api_code: api,
                subject: &user.user_id,
                email: user.email.as_deref().unwrap_or_default(),
                tenant_id: &user.tenant_id,
                token_version: user.token_version,
                subjects: &user.roles,
                features: &features,
                // A messaging-resolved token never carries system-admin rights.
                system_tenant: false,
                system_tenant_member: false,
                passkey: false,
                totp: false,
                user: Some(&user),
                tenant: tenant.as_ref(),
                kind: Some("messaging"),
                access_ttl_secs,
            },
        )
        .await?;

        // A messaging-resolved token mint is real activity — bump the user's and tenant's last-active markers
        // (best-effort; never fail the login on a bookkeeping write), same as password/refresh login.
        if let Err(err) = deps.users.touch_last_seen(&user.user_id).await {
            tracing::warn!("failed to update lastSeen for {}: {err:#}", user.user_id);
        }
        if let Err(err) = deps.tenants.touch_last_active(&user.tenant_id).await {
            tracing::warn!(
                "failed to update lastActive for tenant {}: {err:#}",
                user.tenant_id
            );
        }

        return Ok(json!({ "accessToken": access_token, "expiresIn": access_ttl_secs }));
    }

    // Default: compact user info.
    Ok(serde_json::to_value(ResolvedUser {
        user_id: user.user_id,
        tenant_id: user.tenant_id,
        email: user.email,
        roles: user.roles,
    })?)
}
