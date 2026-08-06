//! User administration routes (within the caller's tenant).
//!
//! All routes require `write:members` and operate strictly on the caller's own tenant (resolved
//! from the caller's token), so an admin can never see or touch another tenant's users. The first
//! user of a tenant is created by `POST /tenants` (see `tenants::service`), not here.

use crate::config::Config;
use crate::config::repository::ConfigRepository;
use crate::constants::{
    DEFAULT_LOCALE, MAX_LIST_RESULTS, MAX_TEXT_BODY_SIZE, ROLE_MEMBER, WRITE_MEMBERS_PERMISSION,
};
use crate::search::{query_matches, value_search_text};
use crate::users::repository::{NewUser, UserRepository};
use crate::users::{User, UserStatus};
use chrono::{DateTime, Utc};
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

/// Permission required to administer a tenant's users.
const REQUIRE_WRITE_MEMBERS: &[&str] = &[WRITE_MEMBERS_PERMISSION];

/// Request body for creating a user.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateUserRequest {
    /// Login username (required, unique). If omitted, the `email` is used as the username.
    username: Option<String>,
    /// Optional contact email (not unique, may be absent).
    email: Option<String>,
    password: String,
    name: String,
    locale: Option<String>,
    roles: Option<Vec<String>>,
    custom_fields: Option<BTreeMap<String, Value>>,
}

/// Request body for patching a user's roles, status and/or custom fields.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PatchUserRequest {
    roles: Option<Vec<String>>,
    status: Option<UserStatus>,
    custom_fields: Option<BTreeMap<String, Value>>,
}

/// Public view of a user — **never** includes the password hash.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct UserView {
    user_id: String,
    tenant_id: String,
    roles: Vec<String>,
    username: String,
    email: Option<String>,
    name: String,
    locale: String,
    status: UserStatus,
    custom_fields: BTreeMap<String, Value>,
    created: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

impl From<User> for UserView {
    fn from(user: User) -> Self {
        UserView {
            user_id: user.user_id,
            tenant_id: user.tenant_id,
            roles: user.roles,
            username: user.username,
            email: user.email,
            name: user.name,
            locale: user.locale,
            status: user.status,
            custom_fields: user.custom_fields,
            created: user.created,
            last_seen: user.last_seen,
        }
    }
}

/// Optional search for the list endpoint (`?q=`).
#[derive(Deserialize, Debug)]
struct ListQuery {
    q: Option<String>,
}

/// List response. `truncated` is true when more than [`MAX_LIST_RESULTS`] matched and the list was
/// capped (refine the search).
#[derive(Serialize, Debug)]
struct UserListResponse {
    users: Vec<UserView>,
    truncated: bool,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `POST /users` — create a user in the caller's tenant (requires `write:members`).
pub fn create_user_route(
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users")
        .and(warp::post())
        .and(with_body_as_json::<CreateUserRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(users))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_MEMBERS,
        ))
        .and_then(handle_create_user_route)
        .boxed()
}

/// `GET /users[?q=…]` — list the caller's tenant's users (requires `write:members`). Sorted by
/// recent activity, capped, with optional case-insensitive multi-term search over
/// username/email/name/custom fields.
pub fn list_users_route(
    users: Arc<dyn UserRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users")
        .and(warp::get())
        .and(warp::query::<ListQuery>())
        .and(with_cloneable(users))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_MEMBERS,
        ))
        .and_then(handle_list_users_route)
        .boxed()
}

/// `PATCH /users/{id}` — update a user's roles/status/custom fields within the caller's tenant.
pub fn patch_user_route(
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String)
        .and(warp::patch())
        .and(with_body_as_json::<PatchUserRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(users))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_MEMBERS,
        ))
        .and_then(handle_patch_user_route)
        .boxed()
}

/// `DELETE /users/{id}` — hard-delete a user within the caller's tenant (requires `write:members`).
pub fn delete_user_route(
    users: Arc<dyn UserRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String)
        .and(warp::delete())
        .and(with_cloneable(users))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_MEMBERS,
        ))
        .and_then(handle_delete_user_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "POST /users", skip_all)]
async fn handle_create_user_route(
    request: CreateUserRequest,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_user(request, users, config, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /users", skip_all)]
async fn handle_list_users_route(
    query: ListQuery,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_users(query, users, caller).await)
}

#[tracing::instrument(level = "debug", name = "PATCH /users/{id}", skip_all)]
async fn handle_patch_user_route(
    user_id: String,
    request: PatchUserRequest,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(patch_user(user_id, request, users, config, caller).await)
}

#[tracing::instrument(level = "debug", name = "DELETE /users/{id}", skip_all)]
async fn handle_delete_user_route(
    user_id: String,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(delete_user(user_id, users, caller).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

async fn create_user(
    request: CreateUserRequest,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<UserView> {
    let tenant_id = caller.tenant_id()?.to_owned();

    // Username is the login identifier; fall back to the email when the caller omits it. At least
    // one of the two must be present.
    let email = request
        .email
        .map(|email| email.trim().to_owned())
        .filter(|email| !email.is_empty());
    let username = request
        .username
        .map(|username| username.trim().to_owned())
        .filter(|username| !username.is_empty())
        .or_else(|| email.clone());
    let username = match username {
        Some(username) => username,
        None => client_bail!("A 'username' (or 'email' to use as the username) is required"),
    };

    let config = config.current().await?;
    config.validate_password(&request.password)?;
    let custom_fields = request.custom_fields.unwrap_or_default();
    Config::validate_custom_fields(&config.custom_user_fields, &custom_fields)?;

    let password_hash = crate::auth::password::hash(&request.password)?;
    let roles = request
        .roles
        .filter(|roles| !roles.is_empty())
        .unwrap_or_else(|| vec![ROLE_MEMBER.to_owned()]);
    let user = users
        .create_user(NewUser {
            tenant_id,
            roles,
            username,
            email,
            name: request.name,
            locale: request.locale.unwrap_or_else(|| DEFAULT_LOCALE.to_owned()),
            password_hash: Some(password_hash),
            custom_fields,
        })
        .await?;

    Ok(user.into())
}

async fn list_users(
    query: ListQuery,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> anyhow::Result<UserListResponse> {
    let tenant_id = caller.tenant_id()?;
    let search = query.q.unwrap_or_default();

    let mut matched: Vec<UserView> = users
        .list_by_tenant(tenant_id)
        .await?
        .into_iter()
        .filter(|user| query_matches(&user_haystack(user), &search))
        .map(UserView::from)
        .collect();

    let truncated = matched.len() > MAX_LIST_RESULTS;
    matched.truncate(MAX_LIST_RESULTS);
    Ok(UserListResponse {
        users: matched,
        truncated,
    })
}

/// Concatenates a user's searchable text: username, email, display name, and every custom-field
/// value (which is where first/last name would live).
fn user_haystack(user: &User) -> String {
    let mut haystack = format!(
        "{} {} {}",
        user.username,
        user.email.as_deref().unwrap_or(""),
        user.name
    );
    for value in user.custom_fields.values() {
        haystack.push(' ');
        haystack.push_str(&value_search_text(value));
    }
    haystack
}

async fn patch_user(
    user_id: String,
    request: PatchUserRequest,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
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
    if let Some(custom_fields) = request.custom_fields {
        Config::validate_custom_fields(
            &config.current().await?.custom_user_fields,
            &custom_fields,
        )?;
        user.custom_fields = custom_fields;
    }

    let updated = users.put_user(user).await?;
    Ok(updated.into())
}

async fn delete_user(
    user_id: String,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    let tenant_id = caller.tenant_id()?;

    let user = match users.get_user(&user_id).await? {
        // Scope strictly to the caller's tenant — a foreign user reads as "not found".
        Some(user) if user.tenant_id == tenant_id => user,
        _ => client_bail!("No such user in this tenant"),
    };

    // An admin must not delete their own account (would strand their session and risk locking the
    // tenant out of member administration).
    if user.user_id == caller.user_id()? {
        status_bail!(StatusCode::FORBIDDEN, "You cannot delete your own account");
    }

    users.delete_user(&user.user_id, &user.username).await?;
    Ok(json!({ "status": "deleted" }))
}
