//! `POST /auth/switch-tenant` — a system admin re-scopes their access token to another tenant.
//!
//! Guarded by `switch:tenant` (held only by system-tenant members). The re-issued `umami` token
//! keeps the acting user's identity + roles but sets `tenant` to the target and re-resolves
//! permissions against the target tenant's features. The synthetic `is:system-tenant` marker is
//! **retained** (so the admin keeps `manage:tenants`/`switch:tenant` + owner-level rights in the target and can switch
//! again/back). Access-token only — no session/cookie is created, so a later refresh returns the
//! admin to their home tenant.

use crate::audit::repository::record_best_effort;
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::AuthContext;
use crate::auth::broker::{MintParams, mint_for_api};
use crate::constants::{MAX_TEXT_BODY_SIZE, SWITCH_TENANT_PERMISSION};
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

/// The API a switched console token is minted for.
const UMAMI_API_CODE: &str = "umami";

/// Permission required to switch tenants (cross-tenant admin).
const REQUIRE_SWITCH_TENANT: &[&str] = &[SWITCH_TENANT_PERMISSION];

/// Request: the tenant to switch into.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SwitchRequest {
    tenant_id: String,
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
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(switch_tenant(request, context, caller).await)
}

async fn switch_tenant(
    request: SwitchRequest,
    context: AuthContext,
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

    let config = context.config.current().await?;
    let access_ttl_secs = config.security.access_ttl_secs as i64;

    let (access_token, _exp) = mint_for_api(
        &context.tokens,
        &config,
        MintParams {
            api_code: UMAMI_API_CODE,
            subject: &user.user_id,
            email: user.email.as_deref().unwrap_or_default(),
            tenant_id: &target.tenant_id,
            token_version: user.token_version,
            subjects: &user.roles,
            features: &target.features,
            // Retain system-admin: keep is:system-tenant so manage:tenants + switch:tenant + the switch ability persist.
            system_tenant: true,
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
                "System admin '{}' switched into tenant '{}'",
                user.user_id, target.tenant_id
            ),
        ),
    )
    .await;

    Ok(SwitchResponse {
        access_token,
        expires_in: access_ttl_secs,
    })
}
