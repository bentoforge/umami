//! Tenant routes: self-serve creation (tenant + first owner) and admin get/patch.
//!
//! `POST /tenants` is the self-serve signup (gated by `UMAMI_ALLOW_SIGNUP`): it creates the tenant
//! **and its first `owner` user**, which is the bootstrap that replaces the earlier open-signup
//! hack. `GET`/`PATCH` require `admin:tenant` and operate only on the caller's own tenant.

use crate::config::Config;
use crate::config::repository::ConfigRepository;
use crate::constants::{ADMIN_TENANT_PERMISSION, DEFAULT_LOCALE, MAX_TEXT_BODY_SIZE, ROLE_OWNER};
use crate::tenants::repository::TenantRepository;
use crate::tenants::{Tenant, slugify};
use crate::users::repository::{NewUser, UserRepository};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::env;
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

/// The first (owner) user created alongside a new tenant.
#[derive(Deserialize, Debug)]
struct OwnerSpec {
    email: String,
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

/// Request body for patching a tenant's name/plan/custom fields.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PatchTenantRequest {
    name: Option<String>,
    plan: Option<String>,
    custom_fields: Option<BTreeMap<String, Value>>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `POST /tenants` — self-serve: create a tenant and its first owner (gated by `UMAMI_ALLOW_SIGNUP`).
pub fn create_tenant_route(
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants")
        .and(warp::post())
        .and(with_body_as_json::<CreateTenantRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_cloneable(users))
        .and(with_cloneable(config))
        .and_then(handle_create_tenant_route)
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

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "POST /tenants", skip_all)]
async fn handle_create_tenant_route(
    request: CreateTenantRequest,
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_tenant(request, tenants, users, config).await)
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

// ── Business logic ──────────────────────────────────────────────────────────────

async fn create_tenant(
    request: CreateTenantRequest,
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
) -> anyhow::Result<CreateTenantResponse> {
    if env::var("UMAMI_ALLOW_SIGNUP").as_deref() != Ok("true") {
        status_bail!(
            StatusCode::FORBIDDEN,
            "Self-serve signup is disabled (set UMAMI_ALLOW_SIGNUP=true to enable)"
        );
    }

    if request.name.trim().is_empty() {
        client_bail!("Tenant 'name' is required");
    }
    if request.owner.email.trim().is_empty() {
        client_bail!("Owner 'email' is required");
    }
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
            email: request.owner.email,
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
