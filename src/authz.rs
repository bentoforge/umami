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

use crate::bail_i18n;
use crate::config::repository::ConfigRepository;
use crate::config::{eval_expression, is_synthetic};
use crate::constants::{
    MANAGE_SERVICE_KEYS_PERMISSION, MANAGE_TENANTS_PERMISSION, MANAGE_USERS_PERMISSION,
};
use crate::tenants::repository::TenantRepository;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::client_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{DecodedSegment, into_response, with_cloneable};

/// Permission required to read a tenant's assignable user roles.
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

/// `GET /tenants/{id}/assignable-roles` — roles that may be assigned to a user in that tenant.
///
/// Keyed by tenant, not by user: the answer depends only on the tenant's feature set, and a
/// create form has no user to ask about yet.
pub fn assignable_roles_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "assignable-roles")
        .and(warp::get())
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(system_tenant_id))
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
    system_tenant_id: Option<String>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "assignable-features")
        .and(warp::get())
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(system_tenant_id))
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
    system_tenant_id: Option<String>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "features" / DecodedSegment)
        .and(warp::post())
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(system_tenant_id))
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
    warp::path!("tenants" / String / "features" / DecodedSegment)
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

#[tracing::instrument(level = "debug", name = "GET /tenants/{id}/assignable-roles", skip_all)]
async fn handle_assignable_roles_route(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(assignable_roles(tenant_id, tenants, config, system_tenant_id, caller).await)
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
    system_tenant_id: Option<String>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(assignable_features(tenant_id, tenants, config, system_tenant_id).await)
}

#[tracing::instrument(level = "debug", name = "POST /tenants/{id}/features/{code}", skip_all)]
async fn handle_grant_feature_route(
    tenant_id: String,
    code: DecodedSegment,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(grant_feature(tenant_id, code.0, tenants, config, system_tenant_id, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "DELETE /tenants/{id}/features/{code}",
    skip_all
)]
async fn handle_revoke_feature_route(
    tenant_id: String,
    code: DecodedSegment,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(revoke_feature(tenant_id, code.0, tenants, config, caller).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

/// Ensures the caller may only act within their own tenant.
fn enforce_own(tenant_id: &str, caller: &AuthUser) -> anyhow::Result<()> {
    if caller.tenant_id()? != tenant_id {
        bail_i18n!(StatusCode::FORBIDDEN, caller.locale(), "tenant.foreign");
    }
    Ok(())
}

async fn assignable_roles(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> anyhow::Result<CodesResponse> {
    enforce_own(&tenant_id, &caller)?;
    let features = tenant_features(&tenants, &tenant_id).await?;
    let config = config.current().await?;
    // Synthetic markers included, or every `is:system-tenant`-gated role would read as
    // unassignable inside the system tenant itself.
    let is_system = system_tenant_id.as_deref() == Some(tenant_id.as_str());
    let set = config.eval_feature_set(&features, is_system);
    let codes = config.assignable_roles(&set);
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
    system_tenant_id: Option<String>,
) -> anyhow::Result<CodesResponse> {
    let features = tenant_features(&tenants, &tenant_id).await?;
    let config = config.current().await?;
    let is_system = system_tenant_id.as_deref() == Some(tenant_id.as_str());
    let set = config.eval_feature_set(&features, is_system);
    let codes = config.assignable_features(&set);
    Ok(CodesResponse { codes })
}

async fn grant_feature(
    tenant_id: String,
    code: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    let config = config.current().await?;
    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };

    if tenant.features.iter().any(|f| f == &code) {
        return Ok(json!({ "status": "granted" }));
    }
    let is_system = system_tenant_id.as_deref() == Some(tenant_id.as_str());
    let effective = config.eval_feature_set(&tenant.features, is_system);
    if !config.can_grant_feature(&code, &effective) {
        client_bail!("Feature '{code}' is not grantable for this tenant");
    }

    tenant.features.push(code);
    tenant.last_changed_by = Some(caller.user_id()?.to_owned());
    let _ = tenants.put_tenant(tenant).await?;
    Ok(json!({ "status": "granted" }))
}

async fn revoke_feature(
    tenant_id: String,
    code: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
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
    tenant.last_changed_by = Some(caller.user_id()?.to_owned());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::repository::StaticConfigRepository;
    use crate::config::{Config, RoleDef};
    use crate::tenants::repository::MockTenantRepository;
    use wasabi::web::auth::user::User as WasabiUser;
    use wasabi::web::auth::{CLAIM_SUB, CLAIM_TENANT};

    /// A system admin who has switched into `tenant-2`: the token names the target tenant, while
    /// the admin's own user row stays in the system tenant.
    fn a_switched_admin() -> AuthUser {
        WasabiUser::builder()
            .with_string(CLAIM_SUB, "admin-1")
            .with_string(CLAIM_TENANT, "tenant-2")
            .build()
    }

    /// A config whose single role is assignable everywhere, so an empty answer can only mean the
    /// tenant was resolved wrongly.
    async fn a_config_with_an_ungated_role() -> Arc<dyn ConfigRepository> {
        let repository = StaticConfigRepository::with_default();
        let config = Config {
            roles: vec![RoleDef {
                code: "role:member".to_owned(),
                name: "Member".into(),
                description: None,
                assignable_if: None,
            }],
            ..Config::default()
        };
        let _ = repository.save(config, 1).await.unwrap();
        Arc::new(repository)
    }

    fn tenants_without_features() -> Arc<dyn TenantRepository> {
        let mut tenants = MockTenantRepository::new();
        let _ = tenants
            .expect_get_tenant()
            .returning(|_| Box::pin(async { Ok(None) }));
        Arc::new(tenants)
    }

    /// The answer follows the tenant in the path, not a user row. This is what a create form needs:
    /// it has no user to ask about, and after a tenant switch the admin's own row names the wrong
    /// tenant.
    #[tokio::test]
    async fn assignable_roles_follow_the_acting_tenant() {
        let response = assignable_roles(
            "tenant-2".to_owned(),
            tenants_without_features(),
            a_config_with_an_ungated_role().await,
            Some("system".to_owned()),
            a_switched_admin(),
        )
        .await
        .unwrap();

        assert_eq!(response.codes, vec!["role:member".to_owned()]);
    }

    /// The home case, which the switched one must not have cost: an admin sitting in the system
    /// tenant reads its roles, and the synthetic marker does not narrow the ungated ones away.
    #[tokio::test]
    async fn assignable_roles_in_the_system_tenant() {
        let caller = WasabiUser::builder()
            .with_string(CLAIM_SUB, "admin-1")
            .with_string(CLAIM_TENANT, "system")
            .build();

        let response = assignable_roles(
            "system".to_owned(),
            tenants_without_features(),
            a_config_with_an_ungated_role().await,
            Some("system".to_owned()),
            caller,
        )
        .await
        .unwrap();

        assert_eq!(response.codes, vec!["role:member".to_owned()]);
    }

    /// Reading another tenant's roles needs a switch into it first — the token decides, not the path.
    #[tokio::test]
    async fn a_foreign_tenant_is_refused() {
        let error = assignable_roles(
            "tenant-3".to_owned(),
            tenants_without_features(),
            a_config_with_an_ungated_role().await,
            Some("system".to_owned()),
            a_switched_admin(),
        )
        .await
        .expect_err("a foreign tenant must not be readable");

        let status = error
            .downcast_ref::<wasabi::web::error::ApiError>()
            .map(|api_error| api_error.status);
        assert_eq!(status, Some(StatusCode::FORBIDDEN));
    }
}
