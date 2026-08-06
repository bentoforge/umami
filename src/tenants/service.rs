//! Tenant routes: cross-tenant admin (list/create/delete) and per-tenant get/patch.
//!
//! `GET /tenants` (list all), `POST /tenants` (create tenant + first owner) and
//! `DELETE /tenants/{id}` (only when the tenant has no users) are **cross-tenant** operations,
//! restricted in Schritt 1 to members of the configured **system tenant**
//! (`UMAMI_SYSTEM_TENANT_ID`) via [`enforce_system_tenant`] — superseded by the `is:system-tenant`
//! feature → permission projection in Schritt 2. `GET`/`PATCH /tenants/{id}` require `admin:tenant`
//! and operate only on the caller's own tenant.

use crate::config::Config;
use crate::config::repository::ConfigRepository;
use crate::constants::{ADMIN_TENANT_PERMISSION, DEFAULT_LOCALE, MAX_TEXT_BODY_SIZE, ROLE_OWNER};
use crate::tenants::repository::TenantRepository;
use crate::tenants::{Tenant, TenantStatus, slugify};
use crate::users::repository::{NewUser, UserRepository};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};
use wasabi::{client_bail, status_bail};

/// Permission required to read/administer a tenant.
const REQUIRE_ADMIN_TENANT: &[&str] = &[ADMIN_TENANT_PERMISSION];

/// The configured system tenant, or `None` when `UMAMI_SYSTEM_TENANT_ID` is unset. Passed to the
/// cross-tenant routes; `None` locks them down entirely.
pub type SystemTenantId = Option<String>;

/// The first (owner) user created alongside a new tenant.
#[derive(Deserialize, Debug)]
struct OwnerSpec {
    /// Login username (required, unique). Falls back to `email` when omitted.
    username: Option<String>,
    /// Optional contact email (not unique).
    email: Option<String>,
    password: String,
    name: String,
    locale: Option<String>,
}

/// Request body for self-serve tenant creation.
#[derive(Deserialize, Debug)]
struct CreateTenantRequest {
    name: String,
    owner: OwnerSpec,
}

/// Response echoing the new tenant and its owner user id.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateTenantResponse {
    tenant_id: String,
    owner_user_id: String,
}

/// `GET /tenants` response.
#[derive(Serialize, Debug)]
struct TenantListResponse {
    tenants: Vec<Tenant>,
}

/// Request body for patching a tenant's name/plan/custom fields.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PatchTenantRequest {
    name: Option<String>,
    plan: Option<String>,
    custom_fields: Option<BTreeMap<String, Value>>,
}

/// Request body for a tenant status transition (micro-CRM).
#[derive(Deserialize, Debug)]
struct PatchStatusRequest {
    status: TenantStatus,
}

/// Request body for licensing changes.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PatchLicenseRequest {
    plan: Option<String>,
    billed_until: Option<NaiveDate>,
    seats_limit: Option<u32>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `POST /tenants` — system-admin: create a tenant and its first owner. Restricted to the system
/// tenant (see [`enforce_system_tenant`]).
pub fn create_tenant_route(
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
    system_tenant_id: SystemTenantId,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants")
        .and(warp::post())
        .and(with_body_as_json::<CreateTenantRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_cloneable(users))
        .and(with_cloneable(config))
        .and(with_cloneable(system_tenant_id))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_create_tenant_route)
        .boxed()
}

/// `GET /tenants` — list every tenant (system-admin only; sorted newest-updated first).
pub fn list_tenants_route(
    tenants: Arc<dyn TenantRepository>,
    authenticator: Arc<Authenticator>,
    system_tenant_id: SystemTenantId,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants")
        .and(warp::get())
        .and(with_cloneable(tenants))
        .and(with_cloneable(system_tenant_id))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_list_tenants_route)
        .boxed()
}

/// `DELETE /tenants/{id}` — delete a tenant, but only when it has no users (system-admin only).
pub fn delete_tenant_route(
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    authenticator: Arc<Authenticator>,
    system_tenant_id: SystemTenantId,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String)
        .and(warp::delete())
        .and(with_cloneable(tenants))
        .and(with_cloneable(users))
        .and(with_cloneable(system_tenant_id))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_delete_tenant_route)
        .boxed()
}

/// `GET /tenants/{id}` — read the caller's own tenant (requires `admin:tenant`).
pub fn get_tenant_route(
    tenants: Arc<dyn TenantRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String)
        .and(warp::get())
        .and(with_cloneable(tenants))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_get_tenant_route)
        .boxed()
}

/// `PATCH /tenants/{id}` — update the caller's own tenant's name/plan (requires `admin:tenant`).
pub fn patch_tenant_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String)
        .and(warp::patch())
        .and(with_body_as_json::<PatchTenantRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_patch_tenant_route)
        .boxed()
}

/// `PATCH /tenants/{id}/status` — set the tenant's CRM status (requires `admin:tenant`).
pub fn patch_status_route(
    tenants: Arc<dyn TenantRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "status")
        .and(warp::patch())
        .and(with_body_as_json::<PatchStatusRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_patch_status_route)
        .boxed()
}

/// `PATCH /tenants/{id}/license` — set plan/billing/seats (requires `admin:tenant`).
pub fn patch_license_route(
    tenants: Arc<dyn TenantRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "license")
        .and(warp::patch())
        .and(with_body_as_json::<PatchLicenseRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_patch_license_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "POST /tenants", skip_all)]
async fn handle_create_tenant_route(
    request: CreateTenantRequest,
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: SystemTenantId,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_tenant(request, tenants, users, config, system_tenant_id, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /tenants", skip_all)]
async fn handle_list_tenants_route(
    tenants: Arc<dyn TenantRepository>,
    system_tenant_id: SystemTenantId,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_tenants(tenants, system_tenant_id, caller).await)
}

#[tracing::instrument(level = "debug", name = "DELETE /tenants/{id}", skip_all)]
async fn handle_delete_tenant_route(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    system_tenant_id: SystemTenantId,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(delete_tenant(tenant_id, tenants, users, system_tenant_id, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /tenants/{id}", skip_all)]
async fn handle_get_tenant_route(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(get_tenant(tenant_id, tenants, caller).await)
}

#[tracing::instrument(level = "debug", name = "PATCH /tenants/{id}", skip_all)]
async fn handle_patch_tenant_route(
    tenant_id: String,
    request: PatchTenantRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(patch_tenant(tenant_id, request, tenants, config, caller).await)
}

#[tracing::instrument(level = "debug", name = "PATCH /tenants/{id}/status", skip_all)]
async fn handle_patch_status_route(
    tenant_id: String,
    request: PatchStatusRequest,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(patch_status(tenant_id, request, tenants, caller).await)
}

#[tracing::instrument(level = "debug", name = "PATCH /tenants/{id}/license", skip_all)]
async fn handle_patch_license_route(
    tenant_id: String,
    request: PatchLicenseRequest,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(patch_license(tenant_id, request, tenants, caller).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

async fn create_tenant(
    request: CreateTenantRequest,
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: SystemTenantId,
    caller: AuthUser,
) -> anyhow::Result<CreateTenantResponse> {
    enforce_system_tenant(&caller, &system_tenant_id)?;

    if request.name.trim().is_empty() {
        client_bail!("Tenant 'name' is required");
    }
    // Owner login identifier: explicit username, else the email; at least one is required.
    let owner_email = request
        .owner
        .email
        .map(|email| email.trim().to_owned())
        .filter(|email| !email.is_empty());
    let owner_username = request
        .owner
        .username
        .map(|username| username.trim().to_owned())
        .filter(|username| !username.is_empty())
        .or_else(|| owner_email.clone());
    let owner_username = match owner_username {
        Some(username) => username,
        None => client_bail!("Owner 'username' (or 'email' to use as the username) is required"),
    };
    config
        .current()
        .await?
        .validate_password(&request.owner.password)?;

    let tenant = tenants
        .create_tenant(request.name.trim(), &slugify(&request.name))
        .await?;

    let password_hash = crate::auth::password::hash(&request.owner.password)?;
    let owner = users
        .create_user(NewUser {
            tenant_id: tenant.tenant_id.clone(),
            roles: vec![ROLE_OWNER.to_owned()],
            username: owner_username,
            email: owner_email,
            name: request.owner.name,
            locale: request
                .owner
                .locale
                .unwrap_or_else(|| DEFAULT_LOCALE.to_owned()),
            password_hash: Some(password_hash),
            custom_fields: BTreeMap::new(),
        })
        .await?;

    Ok(CreateTenantResponse {
        tenant_id: tenant.tenant_id,
        owner_user_id: owner.user_id,
    })
}

async fn list_tenants(
    tenants: Arc<dyn TenantRepository>,
    system_tenant_id: SystemTenantId,
    caller: AuthUser,
) -> anyhow::Result<TenantListResponse> {
    enforce_system_tenant(&caller, &system_tenant_id)?;
    Ok(TenantListResponse {
        tenants: tenants.list_all().await?,
    })
}

async fn delete_tenant(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    system_tenant_id: SystemTenantId,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    enforce_system_tenant(&caller, &system_tenant_id)?;

    // Refuse to delete the system tenant itself — that would lock out cross-tenant administration.
    if system_tenant_id.as_deref() == Some(tenant_id.as_str()) {
        status_bail!(StatusCode::CONFLICT, "The system tenant cannot be deleted");
    }

    if tenants.get_tenant(&tenant_id).await?.is_none() {
        client_bail!("No such tenant");
    }

    // Only empty tenants may be deleted — otherwise their users would be orphaned.
    if !users.list_by_tenant(&tenant_id).await?.is_empty() {
        status_bail!(
            StatusCode::CONFLICT,
            "Tenant still has users — remove them before deleting the tenant"
        );
    }

    tenants.delete_tenant(&tenant_id).await?;
    Ok(json!({ "status": "deleted" }))
}

async fn get_tenant(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> anyhow::Result<Tenant> {
    enforce_own_tenant(&tenant_id, &caller)?;

    match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => Ok(tenant),
        None => client_bail!("No such tenant"),
    }
}

async fn patch_tenant(
    tenant_id: String,
    request: PatchTenantRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<Tenant> {
    enforce_own_tenant(&tenant_id, &caller)?;

    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };

    if let Some(name) = request.name {
        tenant.name = name;
    }
    if let Some(plan) = request.plan {
        tenant.plan = plan;
    }
    if let Some(custom_fields) = request.custom_fields {
        Config::validate_custom_fields(
            &config.current().await?.custom_tenant_fields,
            &custom_fields,
        )?;
        tenant.custom_fields = custom_fields;
    }

    tenants.put_tenant(tenant).await
}

async fn patch_status(
    tenant_id: String,
    request: PatchStatusRequest,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> anyhow::Result<Tenant> {
    enforce_own_tenant(&tenant_id, &caller)?;

    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };
    tenant.status = request.status;
    tenants.put_tenant(tenant).await
}

async fn patch_license(
    tenant_id: String,
    request: PatchLicenseRequest,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> anyhow::Result<Tenant> {
    enforce_own_tenant(&tenant_id, &caller)?;

    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };
    if let Some(plan) = request.plan {
        tenant.plan = plan;
    }
    if request.billed_until.is_some() {
        tenant.billed_until = request.billed_until;
    }
    if request.seats_limit.is_some() {
        tenant.seats_limit = request.seats_limit;
    }
    tenants.put_tenant(tenant).await
}

/// Ensures the caller is acting on their own tenant (a foreign tenant reads as forbidden).
fn enforce_own_tenant(tenant_id: &str, caller: &AuthUser) -> anyhow::Result<()> {
    if caller.tenant_id()? != tenant_id {
        status_bail!(
            StatusCode::FORBIDDEN,
            "You may only administer your own tenant"
        );
    }
    Ok(())
}

/// Interim cross-tenant admin guard (Schritt 1): the caller must belong to the configured system
/// tenant. `None` (`UMAMI_SYSTEM_TENANT_ID` unset) locks these routes down entirely. Superseded by
/// the `is:system-tenant` feature → permission projection in Schritt 2.
fn enforce_system_tenant(caller: &AuthUser, system_tenant_id: &SystemTenantId) -> anyhow::Result<()> {
    let system = match system_tenant_id.as_deref() {
        Some(id) if !id.is_empty() => id,
        _ => status_bail!(
            StatusCode::FORBIDDEN,
            "System-tenant administration is disabled (UMAMI_SYSTEM_TENANT_ID not set)"
        ),
    };
    if caller.tenant_id()? != system {
        status_bail!(
            StatusCode::FORBIDDEN,
            "System-tenant administration requires membership in the system tenant"
        );
    }
    Ok(())
}
