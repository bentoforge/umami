//! `POST /auth/switch-tenant` — a system admin re-scopes their **session** to another tenant.
//!
//! Guarded by `switch:tenant` (held only by system-tenant members). The re-issued token keeps the
//! acting user's identity + roles but sets `tenant` to the target and re-resolves permissions
//! against the target tenant's features. The synthetic `is:system-tenant` marker is **retained**
//! (so the admin keeps `manage:tenants`/`switch:tenant` and can switch again or back) — see
//! `mint_access_token`, which derives it from the user's home tenant.
//!
//! The switch is written to the session (`activeTenantId`), not just handed out as a one-off
//! token. Consequences, all deliberate:
//!
//! - every later `POST /auth/refresh` follows the switch, so a client needs no "acting as" state
//!   and no re-switch when the access token expires;
//! - the switch survives a page reload, because it lives in the cookie-backed session;
//! - switching back is a switch to the user's home tenant;
//! - because it is now durable, `refresh` re-checks on every call that the user may still switch
//!   (see `login.rs`); losing the permission falls back to the home tenant.
//!
//! `api` picks the target audience (default `umami`), exactly like `/auth/refresh?api=`. The
//! response token is a convenience so the caller need not immediately refresh.

use crate::audit::repository::record_best_effort;
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::AuthContext;
use crate::auth::broker::{MintParams, mint_for_api};
use crate::auth::cookies::parse_refresh_cookie;
use crate::constants::{MAX_TEXT_BODY_SIZE, SWITCH_TENANT_PERMISSION, UMAMI_API_CODE};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::status_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};

/// Permission required to switch tenants (cross-tenant admin).
const REQUIRE_SWITCH_TENANT: &[&str] = &[SWITCH_TENANT_PERMISSION];

/// Request: the tenant to switch into, and optionally which audience to mint for.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SwitchRequest {
    tenant_id: String,
    /// Target API from the config catalog. Defaults to the umami admin API.
    #[serde(default)]
    api: Option<String>,
}

/// Response: a fresh access token scoped to the target tenant.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SwitchResponse {
    access_token: String,
    expires_in: i64,
}

/// `POST /auth/switch-tenant` — re-issue the caller's token scoped to another tenant.
pub fn switch_tenant_route(
    context: AuthContext,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "switch-tenant")
        .and(warp::post())
        .and(with_body_as_json::<SwitchRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(context))
        // The bearer proves the *permission*; the cookie identifies the *session* to re-scope.
        // Both are required: a token alone cannot say which device is switching.
        .and(warp::header::optional::<String>("cookie"))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_SWITCH_TENANT,
        ))
        .and_then(handle_switch_tenant_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /auth/switch-tenant", skip_all)]
async fn handle_switch_tenant_route(
    request: SwitchRequest,
    context: AuthContext,
    cookie_header: Option<String>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(switch_tenant(request, context, cookie_header, caller).await)
}

async fn switch_tenant(
    request: SwitchRequest,
    context: AuthContext,
    cookie_header: Option<String>,
    caller: AuthUser,
) -> anyhow::Result<SwitchResponse> {
    // The acting admin, loaded fresh (deactivation/lock stops switching).
    let user = match context.users.get_user(caller.user_id()?).await? {
        Some(user) if !user.locked => user,
        _ => status_bail!(StatusCode::UNAUTHORIZED, "Account not active"),
    };

    let target = match context.tenants.get_tenant(&request.tenant_id).await? {
        Some(tenant) => tenant,
        None => status_bail!(StatusCode::NOT_FOUND, "No such tenant"),
    };

    // Re-scope the session before minting, so the state the client will refresh against and the
    // token it gets back agree. A switch without a session would only last one token lifetime.
    let (session_id, _secret) = match parse_refresh_cookie(cookie_header.as_deref()) {
        Some(parsed) => parsed,
        None => status_bail!(
            StatusCode::BAD_REQUEST,
            "Switching a tenant needs the refresh cookie — it identifies the session to re-scope"
        ),
    };
    let session = match context.sessions.get_session(&session_id).await? {
        // Belongs to somebody else? Then the bearer and the cookie come from different logins;
        // re-scoping a foreign session would be a hand-over of someone else's device.
        Some(session) if session.user_id == user.user_id => session,
        _ => status_bail!(StatusCode::UNAUTHORIZED, "No active session"),
    };
    if session.is_expired(chrono::Utc::now()) {
        status_bail!(StatusCode::UNAUTHORIZED, "Session expired");
    }
    context
        .sessions
        .set_active_tenant(&session.session_id, &target.tenant_id)
        .await?;

    let config = context.config.current().await?;
    let access_ttl_secs = config.security.access_ttl_secs as i64;

    // Carry the caller's second factors forward so the impersonation token keeps is:2fa etc.
    let (passkey, totp) = crate::auth::broker::auth_strength(&caller);

    // Default to the admin console, like `/auth/refresh?api=`. An audience the switched subject
    // is not eligible for is rejected by `mint_for_api` with a 403 — the session is already
    // re-scoped at that point, which is correct: the switch happened, only this particular
    // audience is off limits.
    let api_code = request.api.as_deref().unwrap_or(UMAMI_API_CODE);

    let (access_token, _exp) = mint_for_api(
        &context.tokens,
        &config,
        MintParams {
            api_code,
            subject: &user.user_id,
            email: user.email.as_deref().unwrap_or_default(),
            tenant_id: &target.tenant_id,
            token_version: user.token_version,
            subjects: &user.roles,
            features: &target.features,
            // Only a system-tenant member may switch, so the member marker always holds here —
            // that is what keeps `switch:tenant` alive and lets them switch again or back. The
            // acting marker follows the *target*: switching into a customer tenant means no
            // longer acting inside the system tenant. `mint_access_token` on the refresh path
            // derives both the same way.
            // Session tokens carry the user's own language; nothing overrides it here.
            // Switching keeps the user's language; the header played its part at sign-in.
            locale: &crate::i18n::resolve(&config, user.locale.as_deref(), None),
            system_tenant: context.system_tenant_id.as_deref() == Some(target.tenant_id.as_str()),
            system_tenant_member: true,
            passkey,
            totp,
            user: Some(&user),
            tenant: Some(&target),
            kind: None,
            access_ttl_secs,
        },
    )
    .await?;

    record_best_effort(
        &context.audit,
        NewAuditEntry::new(
            AuditSeverity::Neutral,
            Some(target.tenant_id.clone()),
            Some(user.user_id.clone()),
            format!(
                "System admin '{}' switched session '{}' into tenant '{}'",
                user.user_id, session.session_id, target.tenant_id
            ),
        ),
    )
    .await;

    Ok(SwitchResponse {
        access_token,
        expires_in: access_ttl_secs,
    })
}
