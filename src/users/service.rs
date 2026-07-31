//! User creation route.
//!
//! Phase 2 exposes a **dev-bootstrap** `POST /users` so there is an account to log in as. It is
//! disabled unless `UMAMI_ALLOW_OPEN_SIGNUP=true`. Phase 3 replaces the env gate with proper
//! `admin:tenant`/`write:members` permission enforcement.

use crate::auth::password;
use crate::constants::MAX_TEXT_BODY_SIZE;
use crate::users::repository::UserRepository;
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};
use wasabi::{client_bail, status_bail};

/// Default locale for users created without an explicit one.
const DEFAULT_LOCALE: &str = "en-US";

/// Request body for creating a user.
#[derive(Deserialize, Debug)]
struct CreateUserRequest {
    email: String,
    password: String,
    name: String,
    locale: Option<String>,
}

/// Response echoing the new user's id.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateUserResponse {
    user_id: String,
}

/// `POST /users` — create a user (dev-bootstrap; see module docs).
pub fn create_user_route(users: Arc<dyn UserRepository>) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users")
        .and(warp::post())
        .and(with_body_as_json::<CreateUserRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(users))
        .and_then(handle_create_user_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /users", skip_all)]
async fn handle_create_user_route(
    request: CreateUserRequest,
    users: Arc<dyn UserRepository>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_user(request, users).await)
}

async fn create_user(
    request: CreateUserRequest,
    users: Arc<dyn UserRepository>,
) -> anyhow::Result<CreateUserResponse> {
    if env::var("UMAMI_ALLOW_OPEN_SIGNUP").as_deref() != Ok("true") {
        status_bail!(
            StatusCode::FORBIDDEN,
            "Open signup is disabled (set UMAMI_ALLOW_OPEN_SIGNUP=true for dev bootstrap)"
        );
    }

    if request.email.trim().is_empty() || request.password.is_empty() {
        client_bail!("Both 'email' and 'password' are required");
    }

    let password_hash = password::hash(&request.password)?;
    let locale = request.locale.unwrap_or_else(|| DEFAULT_LOCALE.to_owned());

    let user = users
        .create_user(&request.email, &request.name, &locale, Some(password_hash))
        .await?;

    Ok(CreateUserResponse {
        user_id: user.user_id,
    })
}
