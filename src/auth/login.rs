//! Password login, silent refresh (with rotation + reuse detection), and logout.
//!
//! On success `POST /auth/login` sets the `HttpOnly` refresh cookie and returns a short-lived
//! access token. `POST /auth/refresh` rotates the cookie and issues a fresh access token;
//! `POST /auth/logout` deletes the session and clears the cookie.

use crate::audit::repository::record_best_effort;
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::AuthContext;
use crate::auth::broker::{MintParams, mint_for_api};
use crate::auth::cookies::{build_refresh_cookie, clear_refresh_cookie, parse_refresh_cookie};
use crate::auth::password;
use crate::auth::ratelimit::{
    Decision, POLICY_LOGIN, POLICY_PER_IP_LOGIN, Policy, too_many_requests,
};
use crate::auth::session::repository::NewSession;
use crate::auth::session::{generate_refresh_secret, hash_refresh_secret, verify_refresh_secret};
use crate::bail_i18n;
use crate::config::Config;
use crate::constants::{
    MAX_TEXT_BODY_SIZE, PASSKEY_MARKER, SWITCH_TENANT_PERMISSION, SYSTEM_TENANT_MARKER,
    SYSTEM_TENANT_MEMBER_MARKER, TOTP_MARKER, TWO_FACTOR_MARKER, UMAMI_API_CODE,
};
use crate::users::User;
use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::http::header::{CONTENT_TYPE, HeaderValue, SET_COOKIE};
use warp::reply::Response;
use wasabi::web::locale::accept_language as accept_language_filter;
use wasabi::web::warp::{client_ip, into_rejection, with_body_as_json, with_cloneable};

/// Login request body. A user belongs to exactly one tenant, so no tenant selection is needed.
/// `totp_code` completes the second factor when the account has MFA enabled.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LoginRequest {
    username: String,
    password: String,
    totp_code: Option<String>,
    /// Optional target API (from the config `apis` catalog) for the first access token, so a product
    /// SPA gets a usable token straight from login. Defaults to the `umami` admin API. The session
    /// itself is audience-agnostic — later `/auth/refresh` calls pick their own `api`.
    api: Option<String>,
}

/// Query for `POST /auth/refresh` — the target API to mint the fresh access token for.
#[derive(Deserialize, Debug)]
struct RefreshQuery {
    /// Target API code from the config `apis` catalog. Defaults to `umami` (the admin API).
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

/// Outcome of a login attempt: a normal response (success or MFA challenge), or a rate-limit block
/// translated by the handler into `429 Too Many Requests` + `Retry-After`.
enum LoginOutcome {
    /// A normal login response with its optional `Set-Cookie`.
    Response {
        /// The JSON body (success token or MFA challenge).
        body: LoginResponse,
        /// The refresh cookie on the success path; `None` for an MFA challenge.
        set_cookie: Option<String>,
    },
    /// The attempt was rate-limited; `retry_after` is the advertised delay in seconds.
    RateLimited {
        /// Seconds until the block lifts.
        retry_after: i64,
    },
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `POST /auth/login` — password login; sets the refresh cookie, returns an access token.
pub fn login_route(context: AuthContext) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "login")
        .and(warp::post())
        .and(with_body_as_json::<LoginRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(Arc::new(context)))
        .and(warp::header::optional::<String>("user-agent"))
        .and(accept_language_filter())
        .and(client_ip())
        .and_then(handle_login_route)
        .boxed()
}

/// `POST /auth/refresh` — trade the refresh cookie for a fresh access token (and rotate the cookie).
/// Optional `?api=` picks the target API from the config catalog (default `umami`); the session is
/// audience-agnostic, so the same cookie can mint tokens for any API the user is eligible for.
pub fn refresh_route(context: AuthContext) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "refresh")
        .and(warp::post())
        .and(with_cloneable(Arc::new(context)))
        .and(warp::header::optional::<String>("cookie"))
        .and(warp::query::<RefreshQuery>())
        .and(accept_language_filter())
        .and(client_ip())
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
    accept_language: Option<String>,
    ip: Option<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    match login(
        &context,
        request,
        user_agent,
        accept_language.as_deref(),
        ip,
    )
    .await
    {
        Ok(LoginOutcome::Response { body, set_cookie }) => {
            match json_with_optional_cookie(StatusCode::OK, &body, set_cookie) {
                Ok(reply) => Ok(reply),
                Err(err) => Err(into_rejection(err)),
            }
        }
        // A blocked attempt returns 429 + Retry-After directly (the ApiError path can't carry a
        // header), bypassing `json_with_optional_cookie`.
        Ok(LoginOutcome::RateLimited { retry_after }) => Ok(too_many_requests(retry_after)),
        Err(err) => Err(into_rejection(err)),
    }
}

#[tracing::instrument(level = "debug", name = "POST /auth/refresh", skip_all)]
async fn handle_refresh_route(
    context: Arc<AuthContext>,
    cookie_header: Option<String>,
    query: RefreshQuery,
    accept_language: Option<String>,
    ip: Option<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    match refresh(
        &context,
        cookie_header.as_deref(),
        query.api.as_deref(),
        accept_language.as_deref(),
        ip,
    )
    .await
    {
        Ok((body, set_cookie)) => {
            json_with_optional_cookie(StatusCode::OK, &body, set_cookie).map_err(into_rejection)
        }
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

/// Whether `user` may still hold a session scoped to a foreign tenant.
///
/// Deliberately config-driven rather than a bare `system_tenant_id == user.tenant_id` comparison:
/// which subjects get `switch:tenant` is a decision of the `umami` API's permission mapping, and
/// hardcoding "only system-tenant members" here would silently diverge from it the first time
/// somebody maps the permission differently.
fn may_switch_tenant(
    context: &AuthContext,
    config: &Config,
    user: &User,
    strength: AuthStrength,
) -> bool {
    let Some(api) = config.find_api(UMAMI_API_CODE) else {
        return false;
    };
    let subjects = switch_subjects(
        &user.roles,
        context.system_tenant_id.as_deref() == Some(user.tenant_id.as_str()),
        strength,
    );
    api.resolve(&subjects)
        .is_some_and(|permissions| permissions.iter().any(|p| p == SWITCH_TENANT_PERMISSION))
}

/// The subject set a tenant-switch entitlement is decided on.
///
/// Pulled out of [`may_switch_tenant`] so the part that got this wrong can be tested without an
/// `AuthContext`: it has to produce **the same subjects the broker puts on a token**, or the
/// re-check answers a different question than the config rule asks.
///
/// That is exactly how it broke. The natural way to gate tenant switching is
/// `role:switch-tenant + is:system-tenant-member + is:2fa`, and `is:2fa` was missing here — so the
/// rule could never match, every refresh concluded the user may not switch, and the session fell
/// back to its home tenant. The switch survived precisely as long as the access token it was made
/// with: reload the page or open a second tab and it was gone.
fn switch_subjects(
    roles: &[String],
    system_tenant_member: bool,
    strength: AuthStrength,
) -> Vec<String> {
    let mut subjects: Vec<String> = roles.to_vec();
    // Evaluated against the user's **home** tenant, which is where the entitlement lives — and
    // at home both markers hold: the user is a member of that tenant *and* acting in it. Pushing
    // only one would silently answer a different question than the config rule asks.
    if system_tenant_member {
        subjects.push(SYSTEM_TENANT_MARKER.to_owned());
        subjects.push(SYSTEM_TENANT_MEMBER_MARKER.to_owned());
    }
    if strength.passkey {
        subjects.push(PASSKEY_MARKER.to_owned());
    }
    if strength.totp {
        subjects.push(TOTP_MARKER.to_owned());
    }
    if strength.passkey || strength.totp {
        subjects.push(TWO_FACTOR_MARKER.to_owned());
    }
    subjects
}

#[cfg(test)]
mod switch_entitlement_tests {
    use super::*;
    use crate::config::{ApiDef, PermissionRule};

    /// The rule as a deployment actually writes it — second factor required.
    fn api() -> ApiDef {
        ApiDef {
            code: UMAMI_API_CODE.to_owned(),
            audience: UMAMI_API_CODE.to_owned(),
            eligibility: None,
            permissions: vec![PermissionRule {
                when: "role:switch-tenant + is:system-tenant-member + is:2fa".to_owned(),
                grant: vec![SWITCH_TENANT_PERMISSION.to_owned()],
            }],
            claims: Default::default(),
        }
    }

    fn may(strength: AuthStrength) -> bool {
        let subjects = switch_subjects(&["role:switch-tenant".to_owned()], true, strength);
        api()
            .resolve(&subjects)
            .is_some_and(|p| p.iter().any(|p| p == SWITCH_TENANT_PERMISSION))
    }

    #[test]
    fn a_second_factor_keeps_the_switch_across_a_refresh() {
        assert!(may(AuthStrength {
            passkey: false,
            totp: true
        }));
        assert!(may(AuthStrength {
            passkey: true,
            totp: false
        }));
    }

    #[test]
    fn without_a_second_factor_the_session_falls_back() {
        assert!(!may(AuthStrength {
            passkey: false,
            totp: false
        }));
    }

    #[test]
    fn the_entitlement_lives_in_the_home_tenant() {
        let subjects = switch_subjects(
            &["role:switch-tenant".to_owned()],
            false,
            AuthStrength {
                passkey: false,
                totp: true,
            },
        );
        assert!(
            api().resolve(&subjects).is_some_and(|p| p.is_empty()),
            "a user whose home tenant is not the system tenant may not switch",
        );
    }
}

/// Mints an access token for the given target API, resolving the user's roles/features through the
/// config `apis` catalog (eligibility, permission projection, claim mapping). Shared by password
/// login, WebAuthn login, and refresh — every session-issued access token is minted here.
async fn mint_access_token(
    context: &AuthContext,
    config: &Config,
    user: &User,
    tenant_id: &str,
    api_code: &str,
    accept_language: Option<&str>,
    strength: AuthStrength,
) -> anyhow::Result<String> {
    let access_ttl_secs = config.security.access_ttl_secs as i64;

    let tenant = context.tenants.get_tenant(tenant_id).await?;
    let features: Vec<String> = tenant
        .as_ref()
        .map(|tenant| tenant.features.clone())
        .unwrap_or_default();
    let (access_token, _exp) = mint_for_api(
        &context.tokens,
        config,
        MintParams {
            api_code,
            subject: &user.user_id,
            email: user.email.as_deref().unwrap_or_default(),
            tenant_id,
            token_version: user.token_version,
            subjects: &user.roles,
            features: &features,
            // The two markers deliberately disagree after a tenant switch. `is:system-tenant`
            // follows the tenant being minted for — a support user working inside a customer
            // tenant is *not* acting in the system tenant, and rules like "manage users
            // everywhere except in the system tenant itself" depend on that being false.
            // `is:system-tenant-member` follows the user's **home** tenant, so the same token
            // keeps `switch:tenant`; without it the switched admin could not switch back.
            // Always filled, so no service downstream has to re-derive it: the user's stated
            // preference if they have one, otherwise what this request's `Accept-Language` says,
            // otherwise the deployment default.
            locale: &crate::i18n::resolve(config, user.locale.as_deref(), accept_language),
            system_tenant: context.system_tenant_id.as_deref() == Some(tenant_id),
            system_tenant_member: context.system_tenant_id.as_deref()
                == Some(user.tenant_id.as_str()),
            passkey: strength.passkey,
            totp: strength.totp,
            user: Some(user),
            tenant: tenant.as_ref(),
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
    accept_language: Option<&str>,
    ip: Option<String>,
) -> anyhow::Result<LoginOutcome> {
    // Clone for the audit records: `ip` itself is moved into `issue_session` on the success path.
    let audit_ip = ip.clone();

    // Rate limiting. The per-IP volume cap (all attempts) is checked first — it is the DoS guard for
    // the user lookup below, so we can afford to resolve the account before applying the per-account
    // brute-force cap. The per-account cap is keyed on the stable **user id** (not the username), and
    // therefore only applies to a real account; floods against unknown usernames are absorbed by the
    // per-IP cap. Everything is fail-open (a rate-limit-store outage never blocks login).
    let now = Utc::now();
    let config = context.config.current().await?;
    // No token yet, so no stated preference to honour — but the request still says something.
    // `Accept-Language` is exactly right *here*, before we know who is knocking; once we do, their
    // profile takes over.
    let locale = crate::i18n::resolve(&config, None, accept_language);
    let limits = &config.security.rate_limits;
    let per_ip = Policy::new(
        limits.per_ip.max_per_window,
        limits.per_ip.window_secs,
        limits.per_ip.block_secs,
    );
    let login_policy = Policy::new(
        limits.login.max_failures,
        limits.login.window_secs,
        limits.login.block_secs,
    );

    if let Some(ip) = audit_ip.as_deref()
        && let Decision::Block { retry_after } = context
            .rate_limiter
            .check(POLICY_PER_IP_LOGIN, &per_ip, ip, now)
            .await
    {
        return Ok(LoginOutcome::RateLimited { retry_after });
    }

    // Uniform "invalid credentials" for unknown username / wrong password / inactive account, so we
    // don't reveal which users exist.
    let user = match context.users.find_by_username(&request.username).await? {
        Some(user) if !user.locked => user,
        _ => {
            record_best_effort(
                &context.audit,
                NewAuditEntry::new(
                    AuditSeverity::Bad,
                    None,
                    None,
                    format!(
                        "Login failed for '{}': unknown or inactive account",
                        request.username
                    ),
                )
                .with_ip(audit_ip.clone()),
            )
            .await;
            // No per-account counter here — there is no account to key on; the per-IP cap covers
            // floods against unknown/inactive usernames.
            bail_i18n!(
                StatusCode::UNAUTHORIZED,
                &locale,
                "auth.invalid_credentials"
            );
        }
    };

    // Per-account brute-force block, keyed on the resolved user id and checked before the (expensive)
    // password verification.
    if let Decision::Block { retry_after } = context
        .rate_limiter
        .is_blocked(POLICY_LOGIN, &login_policy, &user.user_id, now)
        .await
    {
        return Ok(LoginOutcome::RateLimited { retry_after });
    }

    let bad = |message: String| {
        NewAuditEntry::new(
            AuditSeverity::Bad,
            Some(user.tenant_id.clone()),
            Some(user.user_id.clone()),
            message,
        )
        .with_ip(audit_ip.clone())
    };

    let password_hash = match user.password_hash.as_deref() {
        Some(hash) => hash,
        None => {
            record_best_effort(
                &context.audit,
                bad("Login failed: account has no password".into()),
            )
            .await;
            let _ = context
                .rate_limiter
                .record_failure(POLICY_LOGIN, &login_policy, &user.user_id, now)
                .await;
            bail_i18n!(
                StatusCode::UNAUTHORIZED,
                &locale,
                "auth.invalid_credentials"
            );
        }
    };

    if !password::verify(&request.password, password_hash)? {
        record_best_effort(&context.audit, bad("Login failed: wrong password".into())).await;
        let _ = context
            .rate_limiter
            .record_failure(POLICY_LOGIN, &login_policy, &user.user_id, now)
            .await;
        bail_i18n!(
            StatusCode::UNAUTHORIZED,
            &locale,
            "auth.invalid_credentials"
        );
    }

    // Second factor: if TOTP MFA is enabled, a valid code is required. Without one, return a
    // challenge (no session/token) so the client can prompt and retry with the code.
    if let Some(encrypted_secret) = user.totp_secret.as_deref() {
        let code = match request.totp_code.as_deref() {
            Some(code) if !code.is_empty() => code,
            _ => {
                // Correct password, second factor still pending — neither a failure nor a success,
                // so the brute-force counter is left untouched.
                return Ok(LoginOutcome::Response {
                    body: LoginResponse {
                        mfa_required: true,
                        access_token: None,
                        tenants: Vec::new(),
                    },
                    set_cookie: None,
                });
            }
        };
        if !crate::auth::totp::verify_encrypted_totp(
            &context.mfa,
            encrypted_secret,
            &user.username,
            code,
        )? {
            record_best_effort(
                &context.audit,
                bad("Login failed: invalid TOTP code".into()),
            )
            .await;
            let _ = context
                .rate_limiter
                .record_failure(POLICY_LOGIN, &login_policy, &user.user_id, now)
                .await;
            bail_i18n!(StatusCode::UNAUTHORIZED, &locale, "auth.mfa_invalid");
        }
    }

    // If the account has TOTP, we only reach here after verifying it above — so a present secret
    // means this login was TOTP-secured. (Password login never involves a passkey.)
    let mfa_totp = user.totp_secret.is_some();

    // Credentials (and any second factor) verified — clear the account's failure counter/block.
    context
        .rate_limiter
        .record_success(POLICY_LOGIN, &login_policy, &user.user_id)
        .await;

    // Default to the umami admin API when the caller didn't request a specific target.
    let api_code = request.api.as_deref().unwrap_or("umami");
    let (access_token, set_cookie) = issue_session(
        context,
        &user,
        api_code,
        AuthStrength {
            passkey: false,
            totp: mfa_totp,
        },
        accept_language,
        user_agent,
        ip,
    )
    .await?;

    record_best_effort(
        &context.audit,
        NewAuditEntry::new(
            AuditSeverity::Good,
            Some(user.tenant_id.clone()),
            Some(user.user_id.clone()),
            "Password login".to_owned(),
        )
        .with_ip(audit_ip.clone()),
    )
    .await;

    Ok(LoginOutcome::Response {
        body: LoginResponse {
            mfa_required: false,
            access_token: Some(access_token),
            tenants: Vec::new(),
        },
        set_cookie: Some(set_cookie),
    })
}

/// Creates a session and issues an access token + refresh cookie for an already-authenticated user.
/// `api_code` selects the target API for the *initial* access token only — the session is
/// audience-agnostic, so later `/auth/refresh` calls pick their own `api`. Shared by password login
/// and the WebAuthn passkey login. Returns `(access_token, set_cookie)`.
/// How strongly this session authenticated — the two markers travel together everywhere and mean
/// nothing apart, so they are one value rather than two adjacent booleans nobody can tell apart at
/// a call site.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthStrength {
    pub passkey: bool,
    pub totp: bool,
}

pub(crate) async fn issue_session(
    context: &AuthContext,
    user: &User,
    api_code: &str,
    strength: AuthStrength,
    accept_language: Option<&str>,
    user_agent: Option<String>,
    ip: Option<String>,
) -> anyhow::Result<(String, String)> {
    let config = context.config.current().await?;
    let refresh_ttl_secs = config.security.refresh_ttl_secs as i64;

    // Mint first: if the user isn't eligible for the requested API, fail before creating a session.
    let access_token = mint_access_token(
        context,
        &config,
        user,
        &user.tenant_id,
        api_code,
        accept_language,
        strength,
    )
    .await?;

    let secret = generate_refresh_secret();
    let refresh_hash = hash_refresh_secret(&secret);

    let session = context
        .sessions
        .create_session(NewSession {
            user_id: user.user_id.clone(),
            active_tenant_id: Some(user.tenant_id.clone()),
            refresh_hash,
            token_version_at_issue: user.token_version,
            mfa_passkey: strength.passkey,
            mfa_totp: strength.totp,
            ttl_secs: refresh_ttl_secs,
            user_agent,
            ip,
        })
        .await?;

    // Best-effort activity marker for the per-tenant user listing (never fail login on this).
    if let Err(err) = context.users.touch_last_seen(&user.user_id).await {
        tracing::warn!("failed to update lastSeen for {}: {err:#}", user.user_id);
    }

    let set_cookie = build_refresh_cookie(
        &session.session_id,
        &secret,
        context.cookie_domain.as_deref(),
        refresh_ttl_secs,
        context.cookie_policy,
    );

    Ok((access_token, set_cookie))
}

async fn refresh(
    context: &AuthContext,
    cookie_header: Option<&str>,
    api: Option<&str>,
    accept_language: Option<&str>,
    ip: Option<String>,
) -> anyhow::Result<(TokenResponse, Option<String>)> {
    // No token yet on this path — the cookie is what we are about to validate. Header first,
    // deployment default behind it; the user's own preference re-enters once we know who they are.
    let refresh_locale = {
        let config = context.config.current().await?;
        crate::i18n::resolve(&config, None, accept_language)
    };
    let (session_id, secret) = match parse_refresh_cookie(cookie_header) {
        Some(parsed) => parsed,
        None => bail_i18n!(
            StatusCode::UNAUTHORIZED,
            &refresh_locale,
            "auth.refresh_missing"
        ),
    };

    let session = match context.sessions.get_session(&session_id).await? {
        Some(session) => session,
        None => bail_i18n!(
            StatusCode::UNAUTHORIZED,
            &refresh_locale,
            "auth.session_none"
        ),
    };

    let matches_current = verify_refresh_secret(&secret, &session.refresh_hash);
    // Grace: the immediately-previous secret is briefly honored after a rotation, so a racing or
    // retried refresh (concurrent tabs, a network retry) isn't mistaken for token theft.
    let matches_grace = !matches_current
        && session
            .prev_refresh_hash
            .as_deref()
            .is_some_and(|hash| verify_refresh_secret(&secret, hash))
        && session
            .prev_refresh_expires_at
            .is_some_and(|until| Utc::now() < until);

    // Reuse/theft detection: neither the current nor a still-valid previous secret matched — a stale
    // or stolen token was replayed. Revoke the session and reject.
    if !matches_current && !matches_grace {
        context.sessions.delete_session(&session_id).await?;
        record_best_effort(
            &context.audit,
            NewAuditEntry::new(
                AuditSeverity::Bad,
                session.active_tenant_id.clone(),
                Some(session.user_id.clone()),
                "Refresh token reuse detected — session revoked".to_owned(),
            )
            .with_ip(ip),
        )
        .await;
        bail_i18n!(
            StatusCode::UNAUTHORIZED,
            &refresh_locale,
            "auth.refresh_rejected"
        );
    }

    if session.is_expired(Utc::now()) {
        context.sessions.delete_session(&session_id).await?;
        bail_i18n!(
            StatusCode::UNAUTHORIZED,
            &refresh_locale,
            "auth.session_expired"
        );
    }

    let user = match context.users.get_user(&session.user_id).await? {
        Some(user) if !user.locked => user,
        _ => {
            context.sessions.delete_session(&session_id).await?;
            bail_i18n!(
                StatusCode::UNAUTHORIZED,
                &refresh_locale,
                "auth.account_inactive"
            );
        }
    };

    // Global revocation lever: a bumped tokenVersion invalidates every prior session.
    if session.token_version_at_issue != user.token_version {
        context.sessions.delete_session(&session_id).await?;
        bail_i18n!(
            StatusCode::UNAUTHORIZED,
            &refresh_locale,
            "auth.session_revoked"
        );
    }

    let config = context.config.current().await?;
    let refresh_ttl_secs = config.security.refresh_ttl_secs as i64;

    // Only the *current* secret rotates the session and issues a fresh cookie. A grace-window hit is
    // a duplicate of an already-succeeded refresh, so we mint a token but leave the cookie alone
    // (the winning request already set the current one).
    let set_cookie = if matches_current {
        let new_secret = generate_refresh_secret();
        let new_hash = hash_refresh_secret(&new_secret);
        context
            .sessions
            .rotate_session(&session_id, new_hash, refresh_ttl_secs)
            .await?;
        Some(build_refresh_cookie(
            &session_id,
            &new_secret,
            context.cookie_domain.as_deref(),
            refresh_ttl_secs,
            context.cookie_policy,
        ))
    } else {
        None
    };

    // The session's active tenant. Normally the user's home tenant; a system admin may have
    // re-scoped it via `POST /auth/switch-tenant`.
    //
    // Because that switch is durable, entitlement has to be re-checked here rather than relying on
    // a short token lifetime to expire it: an admin removed from the system tenant (or whose role
    // lost `switch:tenant`) must stop minting tokens for the foreign tenant on their very next
    // refresh. No extra I/O for this — `config` and `user` are already loaded, and the check is a
    // permission projection over data in hand.
    let tenant_id = match session.active_tenant_id.as_deref() {
        Some(active) if active != user.tenant_id => {
            if may_switch_tenant(
                context,
                &config,
                &user,
                AuthStrength {
                    passkey: session.mfa_passkey,
                    totp: session.mfa_totp,
                },
            ) {
                active
            } else {
                record_best_effort(
                    &context.audit,
                    NewAuditEntry::new(
                        AuditSeverity::Bad,
                        Some(user.tenant_id.clone()),
                        Some(user.user_id.clone()),
                        format!(
                            "Session '{session_id}' was scoped to tenant '{active}' but \
                             '{}' may no longer switch tenants — falling back to the home tenant",
                            user.user_id
                        ),
                    ),
                )
                .await;
                &user.tenant_id
            }
        }
        _ => &user.tenant_id,
    };
    // Mint for the API the caller asked for (default `umami`) — the session is audience-agnostic, so
    // the same cookie can be traded for a token for any API the user is eligible for. Carry the
    // session's original auth-strength markers (is:passkey/is:totp/is:2fa) across the rotation.
    let api_code = api.unwrap_or("umami");
    let access_token = mint_access_token(
        context,
        &config,
        &user,
        tenant_id,
        api_code,
        // Also on refresh, not just at sign-in: without it a user who never set a preference
        // would be greeted in their browser's language and then switched to the deployment
        // default ten minutes later, when the access token rotates.
        accept_language,
        AuthStrength {
            passkey: session.mfa_passkey,
            totp: session.mfa_totp,
        },
    )
    .await?;

    // Best-effort activity marker (a refresh counts as "seen"); never fail refresh on this.
    if let Err(err) = context.users.touch_last_seen(&user.user_id).await {
        tracing::warn!("failed to update lastSeen for {}: {err:#}", user.user_id);
    }
    if let Err(err) = context.tenants.touch_last_active(tenant_id).await {
        tracing::warn!("failed to update lastActive for tenant {tenant_id}: {err:#}");
    }

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

    Ok(clear_refresh_cookie(
        context.cookie_domain.as_deref(),
        context.cookie_policy,
    ))
}
