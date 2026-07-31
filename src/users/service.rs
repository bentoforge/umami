//! User administration routes (within the caller's tenant).
//!
//! All routes require `write:members` and operate strictly on the caller's own tenant (resolved
//! from the caller's token), so an admin can never see or touch another tenant's users. The first
//! user of a tenant is created by `POST /tenants` (see `tenants::service`), not here.

use crate::constants::{DEFAULT_LOCALE, MAX_TEXT_BODY_SIZE, ROLE_MEMBER, WRITE_MEMBERS_PERMISSION};
use crate::users::repository::{NewUser, UserRepository};
use crate::users::{User, UserStatus};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::client_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};

/// Permission required to administer a tenant's users.
const REQUIRE_WRITE_MEMBERS: &[&str] = &[WRITE_MEMBERS_PERMISSION];

/// Request body for creating a user.
#[derive(Deserialize, Debug)]
struct CreateUserRequest {
    email: String,
    password: String,
    name: String,
    locale: Option<String>,
    roles: Option<Vec<String>>,
}

/// Request body for patching a user's roles and/or status.
#[derive(Deserialize, Debug)]
struct PatchUserRequest {
    roles: Option<Vec<String>>,
    status: Option<UserStatus>,
}

/// Public view of a user — **never** includes the password hash.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct UserView {
    user_id: String,
    tenant_id: String,
    roles: Vec<String>,
    email: String,
    name: String,
    locale: String,
    status: UserStatus,
}

impl From<User> for UserView {
    fn from(user: User) -> Self {
        UserView {
            user_id: user.user_id,
            tenant_id: user.tenant_id,
            roles: user.roles,
            email: user.email,
            name: user.name,
            locale: user.locale,
            status: user.status,
        }
    }
}

/// List response.
#[derive(Serialize, Debug)]
struct UserListResponse {
    users: Vec<UserView>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `POST /users` — create a user in the caller's tenant (requires `write:members`).
pub fn create_user_route(
    users: Arc<dyn UserRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users")
        .and(warp::post())
        .and(with_body_as_json::<CreateUserRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(users))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_MEMBERS,
        ))
        .and_then(handle_create_user_route)
        .boxed()
}

/// `GET /users` — list the caller's tenant's users (requires `write:members`).
pub fn list_users_route(
    users: Arc<dyn UserRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users")
        .and(warp::get())
        .and(with_cloneable(users))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_MEMBERS,
        ))
        .and_then(handle_list_users_route)
        .boxed()
}

/// `PATCH /users/{id}` — update a user's role/status within the caller's tenant.
pub fn patch_user_route(
    users: Arc<dyn UserRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String)
        .and(warp::patch())
        .and(with_body_as_json::<PatchUserRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(users))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_MEMBERS,
        ))
        .and_then(handle_patch_user_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "POST /users", skip_all)]
async fn handle_create_user_route(
    request: CreateUserRequest,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_user(request, users, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /users", skip_all)]
async fn handle_list_users_route(
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_users(users, caller).await)
}

#[tracing::instrument(level = "debug", name = "PATCH /users/{id}", skip_all)]
async fn handle_patch_user_route(
    user_id: String,
    request: PatchUserRequest,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(patch_user(user_id, request, users, caller).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

async fn create_user(
    request: CreateUserRequest,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> anyhow::Result<UserView> {
    let tenant_id = caller.tenant_id()?.to_owned();

    if request.email.trim().is_empty() || request.password.is_empty() {
        client_bail!("Both 'email' and 'password' are required");
    }

    let password_hash = crate::auth::password::hash(&request.password)?;
    let roles = request
        .roles
        .filter(|roles| !roles.is_empty())
        .unwrap_or_else(|| vec![ROLE_MEMBER.to_owned()]);
    let user = users
        .create_user(NewUser {
            tenant_id,
            roles,
            email: request.email,
            name: request.name,
            locale: request.locale.unwrap_or_else(|| DEFAULT_LOCALE.to_owned()),
            password_hash: Some(password_hash),
        })
        .await?;

    Ok(user.into())
}

async fn list_users(
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> anyhow::Result<UserListResponse> {
    let tenant_id = caller.tenant_id()?;
    let list = users.list_by_tenant(tenant_id).await?;
    Ok(UserListResponse {
        users: list.into_iter().map(UserView::from).collect(),
    })
}

async fn patch_user(
    user_id: String,
    request: PatchUserRequest,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> anyhow::Result<UserView> {
    let tenant_id = caller.tenant_id()?;

    let mut user = match users.get_user(&user_id).await? {
        // Scope strictly to the caller's tenant — a foreign user reads as "not found".
        Some(user) if user.tenant_id == tenant_id => user,
        _ => client_bail!("No such user in this tenant"),
    };

    if let Some(roles) = request.roles {
        user.roles = roles;
    }
    if let Some(status) = request.status {
        user.status = status;
    }

    let updated = users.put_user(user).await?;
    Ok(updated.into())
}
