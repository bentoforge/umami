//! Tenant routes: cross-tenant admin (list/create/delete) and per-tenant get/patch.
//!
//! `GET /tenants` (list all), `POST /tenants` (create tenant, optionally with a first owner) and
//! `DELETE /tenants/{id}` (refused for the system tenant, the caller's current tenant, or a tenant
//! that still has users/API keys) are **cross-tenant** operations guarded by the `manage:tenants`
//! permission, projected from `is:system-tenant` (see docs/CONFIG.md). `GET`/`PATCH /tenants/{id}`
//! need it too — a tenant does not administer itself.

use crate::auth::apikeys::repository::ApiKeyRepository;
use crate::bail_i18n;
use crate::config::Config;
use crate::config::repository::ConfigRepository;
use crate::constants::{
    MANAGE_TENANTS_PERMISSION, MAX_LIST_RESULTS, MAX_TEXT_BODY_SIZE, ROLE_OWNER,
    SWITCH_TENANT_PERMISSION,
};
use crate::tenants::repository::TenantRepository;
use crate::tenants::{Tenant, slugify};
use crate::users::repository::{NewUser, UserRepository};
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

/// Permission required for every tenant route, cross-tenant *and* per-tenant.
///
/// Reading and editing a tenant record is system-admin territory: a tenant must not be able to
/// rename itself or rewrite its own custom fields. Its predecessor also accepted `admin:tenant`,
/// which conflated "read the audit log" with "administer yourself"; the log is now the separate,
/// narrower `view:audit`. What a member legitimately needs about their own tenant arrives with
/// `GET /auth/me`, which carries the tenant alongside the user.
const REQUIRE_MANAGE_TENANTS: &[&str] = &[MANAGE_TENANTS_PERMISSION];

/// Listing is also part of *switching*, which is a different entitlement.
///
/// `manage:tenants` is naturally gated on `is:system-tenant`, and that marker follows the tenant a
/// token is minted **for** — so an admin who switches into a customer tenant loses it, and with it
/// the list they would pick the next tenant from. They may still switch (that rule keys off
/// `is:system-tenant-member`, the home tenant), leaving them able to move but unable to see where:
/// switching a second time meant going home first.
///
/// Read-only, and no real widening: whoever holds `switch:tenant` can already reach any tenant by
/// id. Every mutating route below keeps requiring `manage:tenants`.
const REQUIRE_LIST_TENANTS: &[&str] = &[MANAGE_TENANTS_PERMISSION, SWITCH_TENANT_PERMISSION];

/// The first (owner) user created alongside a new tenant.
#[derive(Deserialize, Debug)]
struct OwnerSpec {
    /// Login username — required and globally unique.
    username: Option<String>,

    password: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    salutation: Option<crate::users::Salutation>,
    #[serde(default)]
    firstname: Option<String>,
    #[serde(default)]
    lastname: Option<String>,
}

/// Request body for self-serve tenant creation.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateTenantRequest {
    name: String,
    /// Optional first owner. When omitted the tenant is created empty — add users afterwards
    /// (e.g. impersonate the tenant on the Tenants screen, then create its users).
    #[serde(default)]
    owner: Option<OwnerSpec>,
    /// Optional custom-field values for the new tenant (validated against `customTenantFields`).
    custom_fields: Option<BTreeMap<String, Value>>,
}

/// Response echoing the new tenant and (when an owner was created) its owner user id.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateTenantResponse {
    tenant_id: String,
    owner_user_id: Option<String>,
}

/// Optional search + page cap for the list endpoint (`?q=&limit=`).
#[derive(Deserialize, Debug)]
struct ListQuery {
    q: Option<String>,
    limit: Option<usize>,
}

/// `GET /tenants` response. `truncated` is true when more than [`MAX_LIST_RESULTS`] matched and the
/// list was capped (refine the search).
#[derive(Serialize, Debug)]
struct TenantListResponse {
    tenants: Vec<Tenant>,
    truncated: bool,
}

/// Request body for patching a tenant's name/custom fields.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PatchTenantRequest {
    name: Option<String>,
    custom_fields: Option<BTreeMap<String, Value>>,
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
            REQUIRE_LIST_TENANTS,
        ))
        .and_then(handle_list_tenants_route)
        .boxed()
}

/// `DELETE /tenants/{id}` — delete a tenant (requires `manage:tenants`). Refused for the system
/// tenant, the tenant the caller is currently in, and any tenant that still has users or API keys.
pub fn delete_tenant_route(
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    api_keys: Arc<dyn ApiKeyRepository>,
    system_tenant_id: Option<String>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String)
        .and(warp::delete())
        .and(with_cloneable(tenants))
        .and(with_cloneable(users))
        .and(with_cloneable(api_keys))
        .and(with_cloneable(system_tenant_id))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_TENANTS,
        ))
        .and_then(handle_delete_tenant_route)
        .boxed()
}

/// `GET /tenants/{id}` — read a tenant (requires `manage:tenants`).
pub fn get_tenant_route(
    tenants: Arc<dyn TenantRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String)
        .and(warp::get())
        .and(with_cloneable(tenants))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_TENANTS,
        ))
        .and_then(handle_get_tenant_route)
        .boxed()
}

/// `PATCH /tenants/{id}` — update a tenant's name + custom fields (requires `manage:tenants`).
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
            REQUIRE_MANAGE_TENANTS,
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
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_tenant(request, tenants, users, config, caller).await)
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
    api_keys: Arc<dyn ApiKeyRepository>,
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(
        delete_tenant(
            tenant_id,
            tenants,
            users,
            api_keys,
            system_tenant_id,
            caller,
        )
        .await,
    )
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
    caller: AuthUser,
) -> anyhow::Result<CreateTenantResponse> {
    if request.name.trim().is_empty() {
        client_bail!("Tenant 'name' is required");
    }
    let created_by = caller.user_id()?.to_owned();
    let config = config.current().await?;
    let custom_fields = request.custom_fields.unwrap_or_default();
    Config::validate_custom_fields(&config.custom_tenant_fields, &custom_fields)?;

    // Resolve the owner up-front (fail before creating the tenant) when one was requested.
    let owner = match request.owner {
        Some(owner) => {
            // The owner's login identifier. An address is a contact, not an identity, so there is
            // nothing to fall back to.
            let username = owner
                .username
                .map(|username| username.trim().to_owned())
                .filter(|username| !username.is_empty());
            let username = match username {
                Some(username) => username,
                None => client_bail!("Owner 'username' is required"),
            };
            config.validate_password(&owner.password)?;
            let password_hash = crate::auth::password::hash(&owner.password)?;
            Some(NewUser {
                tenant_id: String::new(), // filled in once the tenant exists
                roles: vec![ROLE_OWNER.to_owned()],
                username,
                title: owner.title,
                salutation: owner.salutation.unwrap_or_default(),
                firstname: owner.firstname,
                lastname: owner.lastname,
                password_hash: Some(password_hash),
                custom_fields: BTreeMap::new(),
                created_by: Some(created_by.clone()),
                password_generated: false,
            })
        }
        None => None,
    };

    let tenant = tenants
        .create_tenant(
            request.name.trim(),
            &slugify(&request.name),
            Some(&created_by),
        )
        .await?;

    // Persist any custom-field values (create_tenant starts them empty).
    if !custom_fields.is_empty() {
        let mut with_fields = tenant.clone();
        with_fields.custom_fields = custom_fields;
        with_fields.last_changed_by = Some(created_by.clone());
        let _ = tenants.put_tenant(with_fields).await?;
    }

    let owner_user_id = match owner {
        Some(mut new_user) => {
            new_user.tenant_id = tenant.tenant_id.clone();
            Some(users.create_user(new_user).await?.user_id)
        }
        None => None,
    };

    Ok(CreateTenantResponse {
        tenant_id: tenant.tenant_id,
        owner_user_id,
    })
}

async fn list_tenants(
    query: ListQuery,
    tenants: Arc<dyn TenantRepository>,
) -> anyhow::Result<TenantListResponse> {
    let search = query.q.unwrap_or_default();
    // Caller may request a smaller page (e.g. the switch-tenant dropdown wants 5); never above the
    // hard cap. The repository stops streaming once it has this many matches.
    let limit = query
        .limit
        .unwrap_or(MAX_LIST_RESULTS)
        .clamp(1, MAX_LIST_RESULTS);
    let (matched, truncated) = tenants.find_tenants(&search, limit).await?;
    Ok(TenantListResponse {
        tenants: matched,
        truncated,
    })
}

async fn delete_tenant(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    users: Arc<dyn UserRepository>,
    api_keys: Arc<dyn ApiKeyRepository>,
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    // The system tenant is the root of cross-tenant administration — never deletable.
    if system_tenant_id.as_deref() == Some(tenant_id.as_str()) {
        bail_i18n!(
            StatusCode::FORBIDDEN,
            caller.locale(),
            "tenant.system_undeletable"
        );
    }
    // Don't delete the tenant the caller is currently acting in (would strand their own session).
    if caller.tenant_id()? == tenant_id {
        status_bail!(
            StatusCode::FORBIDDEN,
            "You cannot delete the tenant you are currently in"
        );
    }

    if tenants.get_tenant(&tenant_id).await?.is_none() {
        client_bail!("No such tenant");
    }

    // Only empty tenants may be deleted — otherwise their users would be orphaned. A cap of 1 stops
    // the stream at the first user.
    if !users.find_users(&tenant_id, "", 1).await?.0.is_empty() {
        status_bail!(
            StatusCode::CONFLICT,
            "Tenant still has users — remove them before deleting the tenant"
        );
    }

    // Likewise its API keys (service keys / PATs) would be orphaned.
    if !api_keys.list_by_tenant(&tenant_id).await?.is_empty() {
        status_bail!(
            StatusCode::CONFLICT,
            "Tenant still has API keys — remove them before deleting the tenant"
        );
    }

    tenants.delete_tenant(&tenant_id).await?;
    Ok(json!({ "status": "deleted" }))
}

async fn get_tenant(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    _caller: AuthUser,
) -> anyhow::Result<Tenant> {
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
    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };

    if let Some(name) = request.name {
        tenant.name = name;
    }
    if let Some(custom_fields) = request.custom_fields {
        Config::validate_custom_fields(
            &config.current().await?.custom_tenant_fields,
            &custom_fields,
        )?;
        tenant.custom_fields = custom_fields;
    }
    tenant.last_changed_by = Some(caller.user_id()?.to_owned());

    tenants.put_tenant(tenant).await
}
