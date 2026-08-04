//! Password login, silent refresh (with rotation + reuse detection), and logout.
//!
//! On success `POST /auth/login` sets the `HttpOnly` refresh cookie and returns a short-lived
//! access token. `POST /auth/refresh` rotates the cookie and issues a fresh access token;
//! `POST /auth/logout` deletes the session and clears the cookie.

use crate::auth::AuthContext;
use crate::auth::broker::{MintParams, mint_for_api};
use crate::auth::cookies::{build_refresh_cookie, clear_refresh_cookie, parse_refresh_cookie};
use crate::auth::password;
use crate::auth::session::{
    NewSession, generate_refresh_secret, hash_refresh_secret, verify_refresh_secret,
};
use crate::config::Config;
use crate::constants::MAX_TEXT_BODY_SIZE;
use crate::tenants::effective_features;
use crate::users::{User, UserStatus};
use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::http::header::{CONTENT_TYPE, HeaderValue, SET_COOKIE};
use warp::reply::Response;
use wasabi::status_bail;
use wasabi::web::warp::{into_rejection, with_body_as_json, with_cloneable};

/// Login request body. A user belongs to exactly one tenant, so no tenant selection is needed.
/// `totp_code` completes the second factor when the account has MFA enabled.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LoginRequest {
    email: String,
    password: String,
    totp_code: Option<String>,
    /// Optional target API (from the config `apis` catalog) to mint the access token for directly,
    /// skipping a follow-up `/auth/exchange`. Defaults to the `umami` admin API. The session
    /// remembers this so `refresh` keeps minting for the same API.
    api: Option<String>,
}

/// Refresh success body — the access token is returned in the body (kept in memory by the client);
/// the refresh token travels only in the `HttpOnly` cookie.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    access_token: String,
    tenants: Vec<String>,
}

/// Login response: either an MFA challenge (`mfaRequired: true`, no token/cookie) or success
/// (an access token + refresh cookie).
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    mfa_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
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
        Ok((body, set_cookie)) => {
            match json_with_optional_cookie(StatusCode::OK, &body, set_cookie) {
                Ok(reply) => Ok(reply),
                Err(err) => Err(into_rejection(err)),
            }
        }
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

/// Builds a JSON response, attaching a `Set-Cookie` header only when one is provided (the login
/// MFA-challenge path sets no cookie).
fn json_with_optional_cookie<S: Serialize>(
    status: StatusCode,
    body: &S,
    set_cookie: Option<String>,
) -> anyhow::Result<Response> {
    let bytes = serde_json::to_vec(body).context("Failed to serialize response")?;
    let mut response = Response::new(bytes.into());
    *response.status_mut() = status;
    let _ = response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(cookie) = set_cookie {
        let value = HeaderValue::from_str(&cookie).context("Invalid Set-Cookie header value")?;
        let _ = response.headers_mut().insert(SET_COOKIE, value);
    }
    Ok(response)
}

// ── Business logic ──────────────────────────────────────────────────────────────

/// Mints an access token for the given target API, resolving the user's roles/features through the
/// config `apis` catalog (eligibility, permission projection, claim mapping). Shared by password
/// login, WebAuthn login, and refresh — every session-issued access token is minted here.
async fn mint_access_token(
    context: &AuthContext,
    config: &Config,
    user: &User,
    tenant_id: &str,
    api_code: &str,
) -> anyhow::Result<String> {
    let access_ttl_secs = config.security.access_ttl_secs as i64;

    let tenant = context.tenants.get_tenant(tenant_id).await?;
    let features: Vec<String> = tenant
        .as_ref()
        .map(|tenant| effective_features(config, tenant).into_iter().collect())
        .unwrap_or_default();
    let empty_fields = BTreeMap::new();
    let tenant_custom_fields = tenant
        .as_ref()
        .map(|tenant| &tenant.custom_fields)
        .unwrap_or(&empty_fields);

    let (access_token, _exp) = mint_for_api(
        &context.tokens,
        config,
        MintParams {
            api_code,
            subject: &user.user_id,
            name: &user.name,
            email: &user.email,
            locale: &user.locale,
            tenant_id,
            token_version: user.token_version,
            roles: &user.roles,
            features: &features,
            user_custom_fields: &user.custom_fields,
            tenant_custom_fields,
            kind: None,
            access_ttl_secs,
        },
    )
    .await?;

    Ok(access_token)
}

async fn login(
    context: &AuthContext,
    request: LoginRequest,
    user_agent: Option<String>,
    ip: Option<String>,
) -> anyhow::Result<(LoginResponse, Option<String>)> {
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

    // Second factor: if TOTP MFA is enabled, a valid code is required. Without one, return a
    // challenge (no session/token) so the client can prompt and retry with the code.
    if let Some(encrypted_secret) = user.totp_secret.as_deref() {
        let code = match request.totp_code.as_deref() {
            Some(code) if !code.is_empty() => code,
            _ => {
                return Ok((
                    LoginResponse {
                        mfa_required: true,
                        access_token: None,
                        tenants: Vec::new(),
                    },
                    None,
                ));
            }
        };
        if !crate::auth::totp::verify_encrypted_totp(
            &context.mfa,
            encrypted_secret,
            &user.email,
            code,
        )? {
            status_bail!(StatusCode::UNAUTHORIZED, "Invalid TOTP code");
        }
    }

    // Default to the umami admin API when the caller didn't request a specific target.
    let api_code = request.api.as_deref().unwrap_or("umami");
    let (access_token, set_cookie) =
        issue_session(context, &user, api_code, user_agent, ip).await?;

    Ok((
        LoginResponse {
            mfa_required: false,
            access_token: Some(access_token),
            tenants: Vec::new(),
        },
        Some(set_cookie),
    ))
}

/// Creates a session and issues an access token + refresh cookie for an already-authenticated user.
/// `api_code` selects the target API the access token (and every later refresh) is minted for; the
/// session records it. Shared by password login and the WebAuthn passkey login. Returns
/// `(access_token, set_cookie)`.
pub(crate) async fn issue_session(
    context: &AuthContext,
    user: &User,
    api_code: &str,
    user_agent: Option<String>,
    ip: Option<String>,
) -> anyhow::Result<(String, String)> {
    let config = context.config.current().await?;
    let refresh_ttl_secs = config.security.refresh_ttl_secs as i64;

    // Mint first: if the user isn't eligible for the requested API, fail before creating a session.
    let access_token = mint_access_token(context, &config, user, &user.tenant_id, api_code).await?;

    let secret = generate_refresh_secret();
    let refresh_hash = hash_refresh_secret(&secret);

    let session = context
        .sessions
        .create_session(NewSession {
            user_id: user.user_id.clone(),
            active_tenant_id: Some(user.tenant_id.clone()),
            api_code: api_code.to_owned(),
            refresh_hash,
            token_version_at_issue: user.token_version,
            ttl_secs: refresh_ttl_secs,
            user_agent,
            ip,
        })
        .await?;

    let set_cookie = build_refresh_cookie(
        &session.session_id,
        &secret,
        context.cookie_domain.as_deref(),
        refresh_ttl_secs,
    );

    Ok((access_token, set_cookie))
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

    let config = context.config.current().await?;
    let refresh_ttl_secs = config.security.refresh_ttl_secs as i64;

    let new_secret = generate_refresh_secret();
    let new_hash = hash_refresh_secret(&new_secret);
    context
        .sessions
        .rotate_session(&session_id, new_hash, refresh_ttl_secs)
        .await?;

    // The session's active tenant is the user's home tenant (single-tenant v1); fall back to it.
    let tenant_id = session
        .active_tenant_id
        .as_deref()
        .unwrap_or(&user.tenant_id);
    // Re-mint for the API this session was opened against, so the audience stays stable.
    let access_token =
        mint_access_token(context, &config, &user, tenant_id, &session.api_code).await?;

    let set_cookie = build_refresh_cookie(
        &session_id,
        &new_secret,
        context.cookie_domain.as_deref(),
        refresh_ttl_secs,
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
