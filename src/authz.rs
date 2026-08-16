//! Authorization management: what may be *assigned* (roles/scopes) and *granted* (features).
//!
//! The permission model (see `docs/PERMISSIONS.md`) has three assignable subject kinds, each gated
//! by the tenant's authorization feature set (`tenant.features`):
//! - **roles** (`role:*`) assigned to users — assignable when their `assignableIf` holds;
//! - **scopes** (`scope:*`) carried by M2M service keys — same gating;
//! - **features** (`feature:*`) granted to a tenant — a cross-tenant/system-admin action.
//!
//! These read-only "what's assignable here" endpoints feed the management UI's pickers; the
//! grant/revoke endpoints mutate `tenant.features`. Synthetic markers (`is:*`) are computed at mint
//! time and are never grantable or revocable.

use crate::config::repository::ConfigRepository;
use crate::config::{eval_expression, is_synthetic};
use crate::constants::{
    MANAGE_SERVICE_KEYS_PERMISSION, MANAGE_TENANTS_PERMISSION, MANAGE_USERS_PERMISSION,
};
use crate::tenants::repository::TenantRepository;
use crate::users::repository::UserRepository;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{into_response, with_cloneable};
use wasabi::{client_bail, status_bail};

/// Permission required to read a user's assignable roles.
const REQUIRE_MANAGE_USERS: &[&str] = &[MANAGE_USERS_PERMISSION];

/// Permission required to read a tenant's assignable service-key scopes.
const REQUIRE_MANAGE_SERVICE_KEYS: &[&str] = &[MANAGE_SERVICE_KEYS_PERMISSION];

/// Permission required to grant/revoke a tenant's authorization features (cross-tenant admin).
const REQUIRE_MANAGE_TENANTS: &[&str] = &[MANAGE_TENANTS_PERMISSION];

/// The set of assignable/grantable codes for a UI picker.
#[derive(Serialize, Debug)]
struct CodesResponse {
    codes: Vec<String>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `GET /users/{id}/assignable-roles` — roles that may be assigned to a user in the caller's tenant.
pub fn assignable_roles_route(
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String / "assignable-roles")
        .and(warp::get())
        .and(with_cloneable(users))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_assignable_roles_route)
        .boxed()
}

/// `GET /tenants/{id}/assignable-scopes` — scopes assignable to a service key in the caller's tenant.
pub fn assignable_scopes_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "assignable-scopes")
        .and(warp::get())
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(system_tenant_id))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_SERVICE_KEYS,
        ))
        .and_then(handle_assignable_scopes_route)
        .boxed()
}

/// `GET /tenants/{id}/assignable-features` — features grantable to a tenant right now (system admin).
pub fn assignable_features_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "assignable-features")
        .and(warp::get())
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_TENANTS,
        ))
        .and_then(handle_assignable_features_route)
        .boxed()
}

/// `POST /tenants/{id}/features/{code}` — grant an authorization feature to a tenant (system admin).
pub fn grant_feature_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "features" / String)
        .and(warp::post())
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_TENANTS,
        ))
        .and_then(handle_grant_feature_route)
        .boxed()
}

/// `DELETE /tenants/{id}/features/{code}` — revoke an authorization feature (system admin).
pub fn revoke_feature_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "features" / String)
        .and(warp::delete())
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_TENANTS,
        ))
        .and_then(handle_revoke_feature_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "GET /users/{id}/assignable-roles", skip_all)]
async fn handle_assignable_roles_route(
    user_id: String,
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(assignable_roles(user_id, users, tenants, config, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "GET /tenants/{id}/assignable-scopes",
    skip_all
)]
async fn handle_assignable_scopes_route(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(assignable_scopes(tenant_id, tenants, config, system_tenant_id, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "GET /tenants/{id}/assignable-features",
    skip_all
)]
async fn handle_assignable_features_route(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(assignable_features(tenant_id, tenants, config).await)
}

#[tracing::instrument(level = "debug", name = "POST /tenants/{id}/features/{code}", skip_all)]
async fn handle_grant_feature_route(
    tenant_id: String,
    code: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(grant_feature(tenant_id, code, tenants, config).await)
}

#[tracing::instrument(
    level = "debug",
    name = "DELETE /tenants/{id}/features/{code}",
    skip_all
)]
async fn handle_revoke_feature_route(
    tenant_id: String,
    code: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(revoke_feature(tenant_id, code, tenants, config).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

/// Ensures the caller may only act within their own tenant.
fn enforce_own(tenant_id: &str, caller: &AuthUser) -> anyhow::Result<()> {
    if caller.tenant_id()? != tenant_id {
        status_bail!(StatusCode::FORBIDDEN, "You may only manage your own tenant");
    }
    Ok(())
}

async fn assignable_roles(
    user_id: String,
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<CodesResponse> {
    let tenant_id = caller.tenant_id()?;
    // Scope strictly to the caller's tenant — a foreign user reads as "not found".
    let user = match users.get_user(&user_id).await? {
        Some(user) if user.tenant_id == tenant_id => user,
        _ => client_bail!("No such user in this tenant"),
    };
    let features = tenant_features(&tenants, &user.tenant_id).await?;
    let codes = config.current().await?.assignable_roles(&features);
    Ok(CodesResponse { codes })
}

async fn assignable_scopes(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> anyhow::Result<CodesResponse> {
    enforce_own(&tenant_id, &caller)?;
    let features = tenant_features(&tenants, &tenant_id).await?;
    let config = config.current().await?;
    // Include synthetic markers (e.g. is:system-tenant) so scopes gated on them show up correctly.
    let is_system = system_tenant_id.as_deref() == Some(tenant_id.as_str());
    let set = config.eval_feature_set(&features, is_system);
    let codes = config.assignable_scopes(&set);
    Ok(CodesResponse { codes })
}

async fn assignable_features(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
) -> anyhow::Result<CodesResponse> {
    let features = tenant_features(&tenants, &tenant_id).await?;
    let codes = config.current().await?.assignable_features(&features);
    Ok(CodesResponse { codes })
}

async fn grant_feature(
    tenant_id: String,
    code: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
) -> anyhow::Result<Value> {
    let config = config.current().await?;
    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };

    if tenant.features.iter().any(|f| f == &code) {
        return Ok(json!({ "status": "granted" }));
    }
    if !config.can_grant_feature(&code, &tenant.features) {
        client_bail!("Feature '{code}' is not grantable for this tenant");
    }

    tenant.features.push(code);
    let _ = tenants.put_tenant(tenant).await?;
    Ok(json!({ "status": "granted" }))
}

async fn revoke_feature(
    tenant_id: String,
    code: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
) -> anyhow::Result<Value> {
    // Synthetic markers are computed at mint time — never stored, so never revocable.
    if is_synthetic(&code) {
        client_bail!("Synthetic feature '{code}' cannot be revoked");
    }

    let config = config.current().await?;
    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };
    if !tenant.features.iter().any(|f| f == &code) {
        return Ok(json!({ "status": "revoked" }));
    }

    // The feature set that would remain after removal.
    let remaining: Vec<String> = tenant
        .features
        .iter()
        .filter(|f| *f != &code)
        .cloned()
        .collect();
    let remaining_set: BTreeSet<&str> = remaining.iter().map(String::as_str).collect();

    // Reject if any still-granted feature's `assignableIf` would stop holding — i.e. it depends on
    // the one being revoked. The operator must revoke the dependent feature first.
    for other in &remaining {
        if let Some(expr) = config.feature_assignable_if(other)
            && !eval_expression(expr, &remaining_set)
        {
            client_bail!("Feature '{other}' depends on '{code}'; revoke it first");
        }
    }

    tenant.features = remaining;
    let _ = tenants.put_tenant(tenant).await?;
    Ok(json!({ "status": "revoked" }))
}

/// Resolves a tenant's authorization feature set (empty when the tenant is gone).
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
