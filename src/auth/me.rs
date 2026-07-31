//! `GET /auth/me` (current profile) and `POST /auth/logout-all` (global revocation).
//!
//! Both are authenticated by a valid access token; a user may always inspect themselves and revoke
//! all of their own sessions. `logout-all` bumps `tokenVersion`, invalidating every session at its
//! next refresh.

use crate::tenants::Tenant;
use crate::tenants::repository::TenantRepository;
use crate::users::repository::UserRepository;
use crate::users::{User, UserStatus};
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::status_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user;
use wasabi::web::warp::{into_response, with_cloneable};

/// Current user, without the password hash.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MeUser {
    user_id: String,
    tenant_id: String,
    roles: Vec<String>,
    email: String,
    name: String,
    locale: String,
    status: UserStatus,
}

impl From<User> for MeUser {
    fn from(user: User) -> Self {
        MeUser {
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

/// `GET /auth/me` response: the fresh user record plus their tenant.
#[derive(Serialize, Debug)]
struct MeResponse {
    user: MeUser,
    tenant: Option<Tenant>,
}

/// `GET /auth/me` — profile (user + tenant) resolved fresh from the store.
pub fn me_route(
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me")
        .and(warp::get())
        .and(with_cloneable(users))
        .and(with_cloneable(tenants))
        .and(with_user(authenticator))
        .and_then(handle_me_route)
        .boxed()
}

/// `POST /auth/logout-all` — bump `tokenVersion`, revoking all of the caller's sessions.
pub fn logout_all_route(
    users: Arc<dyn UserRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "logout-all")
        .and(warp::post())
        .and(with_cloneable(users))
        .and(with_user(authenticator))
        .and_then(handle_logout_all_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /auth/me", skip_all)]
async fn handle_me_route(
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(me(users, tenants, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /auth/logout-all", skip_all)]
async fn handle_logout_all_route(
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(logout_all(users, caller).await)
}

async fn me(
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> anyhow::Result<MeResponse> {
    let user_id = caller.user_id()?;

    let user = match users.get_user(user_id).await? {
        Some(user) => user,
        None => status_bail!(StatusCode::UNAUTHORIZED, "User no longer exists"),
    };

    let tenant = tenants.get_tenant(&user.tenant_id).await?;

    Ok(MeResponse {
        user: user.into(),
        tenant,
    })
}

async fn logout_all(
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> anyhow::Result<serde_json::Value> {
    users.bump_token_version(caller.user_id()?).await?;
    Ok(json!({ "status": "ok" }))
}
