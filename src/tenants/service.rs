//! Tenant routes: cross-tenant admin (list/create/delete) and per-tenant get/patch.
//!
//! `GET /tenants` (list all), `POST /tenants` (create tenant + first owner) and
//! `DELETE /tenants/{id}` (only when the tenant has no users) are **cross-tenant** operations
//! guarded by the `manage:tenants` permission, projected from `is:system-tenant` (see docs/CONFIG.md). `GET`/`PATCH /tenants/{id}` require `admin:tenant` and operate only on
//! the caller's own tenant.

use crate::config::Config;
use crate::config::repository::ConfigRepository;
use crate::constants::{
    ADMIN_TENANT_PERMISSION, DEFAULT_LOCALE, MANAGE_TENANTS_PERMISSION, MAX_LIST_RESULTS,
    MAX_TEXT_BODY_SIZE, ROLE_OWNER,
};
use crate::search::{query_matches, value_search_text};
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

/// Permission required for cross-tenant administration (list/create/delete tenants). Held only by
/// system-tenant members via the `is:system-tenant` → `manage:tenants` projection.
const REQUIRE_MANAGE_TENANTS: &[&str] = &[MANAGE_TENANTS_PERMISSION];

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
#[serde(rename_all = "camelCase")]
struct CreateTenantRequest {
    name: String,
    owner: OwnerSpec,
    /// Optional custom-field values for the new tenant (validated against `customTenantFields`).
    custom_fields: Option<BTreeMap<String, Value>>,
}

/// Response echoing the new tenant and its owner user id.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateTenantResponse {
    tenant_id: String,
    owner_user_id: String,
}

/// Optional search for the list endpoint (`?q=`).
#[derive(Deserialize, Debug)]
struct ListQuery {
    q: Option<String>,
}

/// `GET /tenants` response. `truncated` is true when more than [`MAX_LIST_RESULTS`] matched and the
/// list was capped (refine the search).
#[derive(Serialize, Debug)]
struct TenantListResponse {
    tenants: Vec<Tenant>,
    truncated: bool,
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

/// `POST /tenants` — system-admin: create a tenant and its first owner (requires `manage:tenants`).
pub fn create_tenant_route(
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants")
        .and(warp::post())
        .and(with_body_as_json::<CreateTenantRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_cloneable(users))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_TENANTS,
        ))
        .and_then(handle_create_tenant_route)
        .boxed()
}

/// `GET /tenants[?q=…]` — list every tenant (requires `manage:tenants`; sorted newest-updated first,
/// capped, optional case-insensitive multi-term search over name/slug/custom fields).
pub fn list_tenants_route(
    tenants: Arc<dyn TenantRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants")
        .and(warp::get())
        .and(warp::query::<ListQuery>())
        .and(with_cloneable(tenants))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_TENANTS,
        ))
        .and_then(handle_list_tenants_route)
        .boxed()
}

/// `DELETE /tenants/{id}` — delete a tenant, but only when it has no users (requires `manage:tenants`).
pub fn delete_tenant_route(
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String)
        .and(warp::delete())
        .and(with_cloneable(tenants))
        .and(with_cloneable(users))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_TENANTS,
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
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_tenant(request, tenants, users, config).await)
}

#[tracing::instrument(level = "debug", name = "GET /tenants", skip_all)]
async fn handle_list_tenants_route(
    query: ListQuery,
    tenants: Arc<dyn TenantRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_tenants(query, tenants).await)
}

#[tracing::instrument(level = "debug", name = "DELETE /tenants/{id}", skip_all)]
async fn handle_delete_tenant_route(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(delete_tenant(tenant_id, tenants, users).await)
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
) -> anyhow::Result<CreateTenantResponse> {
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
    let config = config.current().await?;
    config.validate_password(&request.owner.password)?;
    let custom_fields = request.custom_fields.unwrap_or_default();
    Config::validate_custom_fields(&config.custom_tenant_fields, &custom_fields)?;

    let tenant = tenants
        .create_tenant(request.name.trim(), &slugify(&request.name))
        .await?;

    // Persist any custom-field values (create_tenant starts them empty).
    if !custom_fields.is_empty() {
        let mut with_fields = tenant.clone();
        with_fields.custom_fields = custom_fields;
        let _ = tenants.put_tenant(with_fields).await?;
    }

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
    query: ListQuery,
    tenants: Arc<dyn TenantRepository>,
) -> anyhow::Result<TenantListResponse> {
    let search = query.q.unwrap_or_default();
    let mut matched: Vec<Tenant> = tenants
        .list_all()
        .await?
        .into_iter()
        .filter(|tenant| query_matches(&tenant_haystack(tenant), &search))
        .collect();

    let truncated = matched.len() > MAX_LIST_RESULTS;
    matched.truncate(MAX_LIST_RESULTS);
    Ok(TenantListResponse {
        tenants: matched,
        truncated,
    })
}

/// Concatenates a tenant's searchable text: name, slug, and every custom-field value (which is
/// where a customer number / address would live).
fn tenant_haystack(tenant: &Tenant) -> String {
    let mut haystack = format!("{} {}", tenant.name, tenant.slug);
    for value in tenant.custom_fields.values() {
        haystack.push(' ');
        haystack.push_str(&value_search_text(value));
    }
    haystack
}

async fn delete_tenant(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
) -> anyhow::Result<Value> {
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
