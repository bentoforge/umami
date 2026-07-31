//! Password login, silent refresh (with rotation + reuse detection), and logout.
//!
//! On success `POST /auth/login` sets the `HttpOnly` refresh cookie and returns a short-lived
//! access token. `POST /auth/refresh` rotates the cookie and issues a fresh access token;
//! `POST /auth/logout` deletes the session and clears the cookie.

use crate::auth::AuthContext;
use crate::auth::cookies::{build_refresh_cookie, clear_refresh_cookie, parse_refresh_cookie};
use crate::auth::password;
use crate::auth::session::{
    NewSession, generate_refresh_secret, hash_refresh_secret, verify_refresh_secret,
};
use crate::auth::tokens::AccessTokenClaims;
use crate::constants::MAX_TEXT_BODY_SIZE;
use crate::users::UserStatus;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::http::header::SET_COOKIE;
use wasabi::status_bail;
use wasabi::web::warp::{into_rejection, with_body_as_json, with_cloneable};

/// Login request body. A user belongs to exactly one tenant, so no tenant selection is needed.
#[derive(Deserialize, Debug)]
struct LoginRequest {
    email: String,
    password: String,
}

/// Login/refresh success body. The access token is returned in the body (kept in memory by the
/// client); the refresh token travels only in the `HttpOnly` cookie.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    access_token: String,
    /// Tenants the user can act in (empty until memberships land in Phase 3).
    tenants: Vec<String>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `POST /auth/login` — password login; sets the refresh cookie, returns an access token.
pub fn login_route(context: AuthContext) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "login")
        .and(warp::post())
        .and(with_body_as_json::<LoginRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(Arc::new(context)))
        .and(warp::header::optional::<String>("user-agent"))
        .and(warp::filters::addr::remote())
        .and_then(handle_login_route)
        .boxed()
}

/// `POST /auth/refresh` — rotate the refresh cookie and issue a fresh access token.
pub fn refresh_route(context: AuthContext) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "refresh")
        .and(warp::post())
        .and(with_cloneable(Arc::new(context)))
        .and(warp::header::optional::<String>("cookie"))
        .and_then(handle_refresh_route)
        .boxed()
}

/// `POST /auth/logout` — delete the current session and clear the refresh cookie.
pub fn logout_route(context: AuthContext) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "logout")
        .and(warp::post())
        .and(with_cloneable(Arc::new(context)))
        .and(warp::header::optional::<String>("cookie"))
        .and_then(handle_logout_route)
        .boxed()
}

// ── Route handlers (map anyhow → HTTP, attach cookies) ───────────────────────────

#[tracing::instrument(level = "debug", name = "POST /auth/login", skip_all)]
async fn handle_login_route(
    request: LoginRequest,
    context: Arc<AuthContext>,
    user_agent: Option<String>,
    remote: Option<SocketAddr>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ip = remote.map(|addr| addr.ip().to_string());
    match login(&context, request, user_agent, ip).await {
        Ok((body, set_cookie)) => Ok(reply_with_cookie(StatusCode::OK, body, set_cookie)),
        Err(err) => Err(into_rejection(err)),
    }
}

#[tracing::instrument(level = "debug", name = "POST /auth/refresh", skip_all)]
async fn handle_refresh_route(
    context: Arc<AuthContext>,
    cookie_header: Option<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    match refresh(&context, cookie_header.as_deref()).await {
        Ok((body, set_cookie)) => Ok(reply_with_cookie(StatusCode::OK, body, set_cookie)),
        Err(err) => Err(into_rejection(err)),
    }
}

#[tracing::instrument(level = "debug", name = "POST /auth/logout", skip_all)]
async fn handle_logout_route(
    context: Arc<AuthContext>,
    cookie_header: Option<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    match logout(&context, cookie_header.as_deref()).await {
        Ok(set_cookie) => {
            let body = serde_json::json!({ "status": "ok" });
            Ok(reply_with_cookie(StatusCode::OK, body, set_cookie))
        }
        Err(err) => Err(into_rejection(err)),
    }
}

/// Builds a JSON reply with the given status and a `Set-Cookie` header.
fn reply_with_cookie<S: Serialize>(
    status: StatusCode,
    body: S,
    set_cookie: String,
) -> impl warp::Reply {
    let reply = warp::reply::json(&body);
    let reply = warp::reply::with_header(reply, SET_COOKIE, set_cookie);
    warp::reply::with_status(reply, status)
}

// ── Business logic ──────────────────────────────────────────────────────────────

async fn login(
    context: &AuthContext,
    request: LoginRequest,
    user_agent: Option<String>,
    ip: Option<String>,
) -> anyhow::Result<(TokenResponse, String)> {
    // Uniform "invalid credentials" for unknown email / wrong password / inactive account, so we
    // don't reveal which users exist.
    let user = match context.users.find_by_email(&request.email).await? {
        Some(user) if user.status == UserStatus::Active => user,
        _ => status_bail!(StatusCode::UNAUTHORIZED, "Invalid email or password"),
    };

    let password_hash = match user.password_hash.as_deref() {
        Some(hash) => hash,
        None => status_bail!(StatusCode::UNAUTHORIZED, "Invalid email or password"),
    };

    if !password::verify(&request.password, password_hash)? {
        status_bail!(StatusCode::UNAUTHORIZED, "Invalid email or password");
    }

    let secret = generate_refresh_secret();
    let refresh_hash = hash_refresh_secret(&secret);

    let session = context
        .sessions
        .create_session(NewSession {
            user_id: user.user_id.clone(),
            active_tenant_id: Some(user.tenant_id.clone()),
            refresh_hash,
            token_version_at_issue: user.token_version,
            ttl_secs: context.refresh_ttl_secs,
            user_agent,
            ip,
        })
        .await?;

    // Effective permissions are resolved from the user's roles via the config catalog.
    let config = context.config.current().await?;
    let permissions = config.permissions_for_roles(&user.roles);

    let (access_token, _exp) = context
        .tokens
        .issue_access_token(&AccessTokenClaims {
            subject: &user.user_id,
            name: &user.name,
            email: &user.email,
            locale: &user.locale,
            tenant: Some(&user.tenant_id),
            permissions: &permissions,
            token_version: user.token_version,
        })
        .await?;

    let set_cookie = build_refresh_cookie(
        &session.session_id,
        &secret,
        context.cookie_domain.as_deref(),
        context.refresh_ttl_secs,
    );

    Ok((
        TokenResponse {
            access_token,
            tenants: Vec::new(),
        },
        set_cookie,
    ))
}

async fn refresh(
    context: &AuthContext,
    cookie_header: Option<&str>,
) -> anyhow::Result<(TokenResponse, String)> {
    let (session_id, secret) = match parse_refresh_cookie(cookie_header) {
        Some(parsed) => parsed,
        None => status_bail!(StatusCode::UNAUTHORIZED, "No refresh cookie present"),
    };

    let session = match context.sessions.get_session(&session_id).await? {
        Some(session) => session,
        None => status_bail!(StatusCode::UNAUTHORIZED, "No active session"),
    };

    // Reuse/theft detection: a present session with a non-matching secret means a stale or stolen
    // token was replayed — revoke the session and reject.
    if !verify_refresh_secret(&secret, &session.refresh_hash) {
        context.sessions.delete_session(&session_id).await?;
        status_bail!(StatusCode::UNAUTHORIZED, "Refresh token rejected");
    }

    if session.is_expired(Utc::now()) {
        context.sessions.delete_session(&session_id).await?;
        status_bail!(StatusCode::UNAUTHORIZED, "Session expired");
    }

    let user = match context.users.get_user(&session.user_id).await? {
        Some(user) if user.status == UserStatus::Active => user,
        _ => {
            context.sessions.delete_session(&session_id).await?;
            status_bail!(StatusCode::UNAUTHORIZED, "Account not active");
        }
    };

    // Global revocation lever: a bumped tokenVersion invalidates every prior session.
    if session.token_version_at_issue != user.token_version {
        context.sessions.delete_session(&session_id).await?;
        status_bail!(StatusCode::UNAUTHORIZED, "Session revoked");
    }

    let new_secret = generate_refresh_secret();
    let new_hash = hash_refresh_secret(&new_secret);
    context
        .sessions
        .rotate_session(&session_id, new_hash, context.refresh_ttl_secs)
        .await?;

    let config = context.config.current().await?;
    let permissions = config.permissions_for_roles(&user.roles);

    let (access_token, _exp) = context
        .tokens
        .issue_access_token(&AccessTokenClaims {
            subject: &user.user_id,
            name: &user.name,
            email: &user.email,
            locale: &user.locale,
            tenant: session.active_tenant_id.as_deref(),
            permissions: &permissions,
            token_version: user.token_version,
        })
        .await?;

    let set_cookie = build_refresh_cookie(
        &session_id,
        &new_secret,
        context.cookie_domain.as_deref(),
        context.refresh_ttl_secs,
    );

    Ok((
        TokenResponse {
            access_token,
            tenants: Vec::new(),
        },
        set_cookie,
    ))
}

async fn logout(context: &AuthContext, cookie_header: Option<&str>) -> anyhow::Result<String> {
    if let Some((session_id, _secret)) = parse_refresh_cookie(cookie_header) {
        context.sessions.delete_session(&session_id).await?;
    }

    Ok(clear_refresh_cookie(context.cookie_domain.as_deref()))
}
