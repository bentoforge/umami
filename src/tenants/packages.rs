//! Package assignment + entitlement resolution routes (admin, own tenant).
//!
//! `POST /tenants/{id}/packages` assigns a package (accounting record), `DELETE
//! /tenants/{id}/packages/{assignmentId}` removes one, and `GET /tenants/{id}/entitlements`
//! resolves the tenant's effective limits and monthly total. All writes go through the tenant's
//! optimistic lock (see `repository::put_tenant`).

use crate::config::repository::ConfigRepository;
use crate::constants::{ADMIN_TENANT_PERMISSION, MAX_TEXT_BODY_SIZE};
use crate::tenants::repository::TenantRepository;
use crate::tenants::{
    FeatureToggle, PackageAssignment, effective_features, effective_limits, monthly_total,
};
use chrono::{NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::aws::dynamodb::generate_id;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};
use wasabi::{client_bail, status_bail};

/// Permission required to manage a tenant's packages/entitlements.
const REQUIRE_ADMIN_TENANT: &[&str] = &[ADMIN_TENANT_PERMISSION];

/// Request body for assigning a package.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AssignPackageRequest {
    code: String,
    monthly_price: Option<Decimal>,
    price_fixed_until: Option<NaiveDate>,
    accounted_until: Option<NaiveDate>,
}

/// Request body for setting a tenant feature toggle.
#[derive(Deserialize, Debug)]
struct SetFeatureRequest {
    value: FeatureToggle,
}

/// Resolved entitlements for a tenant.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct EntitlementsResponse {
    limits: BTreeMap<String, Decimal>,
    features: BTreeSet<String>,
    monthly_total: Decimal,
    packages: Vec<PackageAssignment>,
}

/// `POST /tenants/{id}/packages` — assign a package to the tenant.
pub fn assign_package_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "packages")
        .and(warp::post())
        .and(with_body_as_json::<AssignPackageRequest>(
            MAX_TEXT_BODY_SIZE,
        ))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_assign_package_route)
        .boxed()
}

/// `DELETE /tenants/{id}/packages/{assignmentId}` — remove a package assignment.
pub fn remove_package_route(
    tenants: Arc<dyn TenantRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "packages" / String)
        .and(warp::delete())
        .and(with_cloneable(tenants))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_remove_package_route)
        .boxed()
}

/// `PUT /tenants/{id}/features/{code}` — set a feature toggle (standard/on/off).
pub fn set_feature_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "features" / String)
        .and(warp::put())
        .and(with_body_as_json::<SetFeatureRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_set_feature_route)
        .boxed()
}

/// `GET /tenants/{id}/entitlements` — resolved limits + monthly total.
pub fn entitlements_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "entitlements")
        .and(warp::get())
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_entitlements_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /tenants/{id}/packages", skip_all)]
async fn handle_assign_package_route(
    tenant_id: String,
    request: AssignPackageRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(assign_package(tenant_id, request, tenants, config, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "DELETE /tenants/{id}/packages/{aid}",
    skip_all
)]
async fn handle_remove_package_route(
    tenant_id: String,
    assignment_id: String,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(remove_package(tenant_id, assignment_id, tenants, caller).await)
}

#[tracing::instrument(level = "debug", name = "PUT /tenants/{id}/features/{code}", skip_all)]
async fn handle_set_feature_route(
    tenant_id: String,
    feature_code: String,
    request: SetFeatureRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(set_feature(tenant_id, feature_code, request, tenants, config, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /tenants/{id}/entitlements", skip_all)]
async fn handle_entitlements_route(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(entitlements(tenant_id, tenants, config, caller).await)
}

/// Ensures the caller acts on their own tenant.
fn enforce_own(tenant_id: &str, caller: &AuthUser) -> anyhow::Result<()> {
    if caller.tenant_id()? != tenant_id {
        status_bail!(
            StatusCode::FORBIDDEN,
            "You may only administer your own tenant"
        );
    }
    Ok(())
}

async fn assign_package(
    tenant_id: String,
    request: AssignPackageRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<crate::tenants::Tenant> {
    enforce_own(&tenant_id, &caller)?;

    let config = config.current().await?;
    if !config
        .packages
        .iter()
        .any(|package| package.code == request.code)
    {
        client_bail!("Unknown package code '{}'", request.code);
    }

    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };

    tenant.packages.push(PackageAssignment {
        id: generate_id(),
        code: request.code,
        assigned_at: Utc::now().date_naive(),
        accounted_until: request.accounted_until,
        monthly_price: request.monthly_price,
        price_fixed_until: request.price_fixed_until,
        active: true,
    });

    tenants.put_tenant(tenant).await
}

async fn remove_package(
    tenant_id: String,
    assignment_id: String,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> anyhow::Result<crate::tenants::Tenant> {
    enforce_own(&tenant_id, &caller)?;

    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };

    let before = tenant.packages.len();
    tenant
        .packages
        .retain(|assignment| assignment.id != assignment_id);
    if tenant.packages.len() == before {
        client_bail!("No such package assignment");
    }

    tenants.put_tenant(tenant).await
}

async fn set_feature(
    tenant_id: String,
    feature_code: String,
    request: SetFeatureRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<crate::tenants::Tenant> {
    enforce_own(&tenant_id, &caller)?;

    let config = config.current().await?;
    if !config
        .features
        .iter()
        .any(|feature| feature.code == feature_code)
    {
        client_bail!("Unknown feature code '{feature_code}'");
    }

    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };

    // `Standard` is the default (inherit), so store it as the absence of an override.
    match request.value {
        FeatureToggle::Standard => {
            let _ = tenant.feature_overrides.remove(&feature_code);
        }
        toggle => {
            let _ = tenant.feature_overrides.insert(feature_code, toggle);
        }
    }

    tenants.put_tenant(tenant).await
}

async fn entitlements(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<EntitlementsResponse> {
    enforce_own(&tenant_id, &caller)?;

    let config = config.current().await?;
    let tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };

    let at = Utc::now().date_naive();
    Ok(EntitlementsResponse {
        limits: effective_limits(&config, &tenant),
        features: effective_features(&config, &tenant),
        monthly_total: monthly_total(&config, &tenant, at),
        packages: tenant.packages,
    })
}
