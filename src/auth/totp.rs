//! TOTP (authenticator-app) MFA: enrolment and management.
//!
//! `POST /auth/mfa/totp/setup` generates a secret and stores it **pending** (AES-GCM encrypted);
//! `POST /auth/mfa/totp/verify` confirms it with a valid code and activates MFA; `POST
//! /auth/mfa/totp/disable` turns it off (requires a current code). The login MFA challenge lives in
//! `auth/login.rs`.

use crate::auth::secretbox::SecretBox;
use crate::constants::MAX_TEXT_BODY_SIZE;
use crate::users::User;
use crate::users::repository::UserRepository;
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user;
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};
use wasabi::{client_bail, status_bail};

/// Issuer label shown in authenticator apps.
const TOTP_ISSUER: &str = "umami";

/// A code submitted to verify/disable TOTP.
#[derive(Deserialize, Debug)]
struct CodeRequest {
    code: String,
}

/// Setup response: the base32 secret and the `otpauth://` URL for QR rendering.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SetupResponse {
    secret: String,
    otpauth_url: String,
}

/// Whether MFA is currently enabled after the operation.
#[derive(Serialize, Debug)]
struct MfaStatusResponse {
    enabled: bool,
}

/// Verifies a submitted code against an encrypted TOTP secret. Used by the login MFA branch.
pub fn verify_encrypted_totp(
    secret_box: &SecretBox,
    encrypted_secret: &str,
    account: &str,
    code: &str,
) -> anyhow::Result<bool> {
    let raw = secret_box.decrypt(encrypted_secret)?;
    let totp = make_totp(raw, account)?;
    totp.check_current(code)
        .map_err(|err| anyhow!("Failed to check TOTP code: {err}"))
}

/// Builds a [`TOTP`] from raw secret bytes for the given account (6 digits, 30s, ±1 step skew).
fn make_totp(secret_bytes: Vec<u8>, account: &str) -> anyhow::Result<TOTP> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(TOTP_ISSUER.to_owned()),
        account.to_owned(),
    )
    .map_err(|err| anyhow!("Failed to build TOTP: {err}"))
}

/// `POST /auth/mfa/totp/setup` — generate + store a pending TOTP secret.
pub fn totp_setup_route(
    users: Arc<dyn UserRepository>,
    secret_box: Arc<SecretBox>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "mfa" / "totp" / "setup")
        .and(warp::post())
        .and(with_cloneable(users))
        .and(with_cloneable(secret_box))
        .and(with_user(authenticator))
        .and_then(handle_totp_setup_route)
        .boxed()
}

/// `POST /auth/mfa/totp/verify` — confirm the pending secret and enable MFA.
pub fn totp_verify_route(
    users: Arc<dyn UserRepository>,
    secret_box: Arc<SecretBox>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "mfa" / "totp" / "verify")
        .and(warp::post())
        .and(with_body_as_json::<CodeRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(users))
        .and(with_cloneable(secret_box))
        .and(with_user(authenticator))
        .and_then(handle_totp_verify_route)
        .boxed()
}

/// `POST /auth/mfa/totp/disable` — disable MFA (requires a current code).
pub fn totp_disable_route(
    users: Arc<dyn UserRepository>,
    secret_box: Arc<SecretBox>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "mfa" / "totp" / "disable")
        .and(warp::post())
        .and(with_body_as_json::<CodeRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(users))
        .and(with_cloneable(secret_box))
        .and(with_user(authenticator))
        .and_then(handle_totp_disable_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /auth/mfa/totp/setup", skip_all)]
async fn handle_totp_setup_route(
    users: Arc<dyn UserRepository>,
    secret_box: Arc<SecretBox>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(totp_setup(users, secret_box, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /auth/mfa/totp/verify", skip_all)]
async fn handle_totp_verify_route(
    request: CodeRequest,
    users: Arc<dyn UserRepository>,
    secret_box: Arc<SecretBox>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(totp_verify(request, users, secret_box, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /auth/mfa/totp/disable", skip_all)]
async fn handle_totp_disable_route(
    request: CodeRequest,
    users: Arc<dyn UserRepository>,
    secret_box: Arc<SecretBox>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(totp_disable(request, users, secret_box, caller).await)
}

/// Loads the caller's umami user record.
async fn load_caller(users: &Arc<dyn UserRepository>, caller: &AuthUser) -> anyhow::Result<User> {
    match users.get_user(caller.user_id()?).await? {
        Some(user) => Ok(user),
        None => status_bail!(StatusCode::UNAUTHORIZED, "User no longer exists"),
    }
}

async fn totp_setup(
    users: Arc<dyn UserRepository>,
    secret_box: Arc<SecretBox>,
    caller: AuthUser,
) -> anyhow::Result<SetupResponse> {
    let mut user = load_caller(&users, &caller).await?;

    let secret = Secret::generate_secret();
    let raw = secret
        .to_bytes()
        .map_err(|err| anyhow!("Failed to generate TOTP secret: {err}"))?;
    let base32 = secret.to_encoded().to_string();
    let otpauth_url = make_totp(raw.clone(), &user.email)?.get_url();

    user.totp_pending = Some(secret_box.encrypt(&raw)?);
    let _ = users.put_user(user).await?;

    Ok(SetupResponse {
        secret: base32,
        otpauth_url,
    })
}

async fn totp_verify(
    request: CodeRequest,
    users: Arc<dyn UserRepository>,
    secret_box: Arc<SecretBox>,
    caller: AuthUser,
) -> anyhow::Result<MfaStatusResponse> {
    let mut user = load_caller(&users, &caller).await?;

    let pending = match user.totp_pending.as_deref() {
        Some(pending) => pending,
        None => client_bail!("No TOTP setup in progress"),
    };

    let raw = secret_box.decrypt(pending)?;
    let totp = make_totp(raw, &user.email)?;
    if !totp
        .check_current(&request.code)
        .map_err(|err| anyhow!("Failed to check TOTP code: {err}"))?
    {
        status_bail!(StatusCode::UNAUTHORIZED, "Invalid TOTP code");
    }

    user.totp_secret = user.totp_pending.take();
    let _ = users.put_user(user).await?;

    Ok(MfaStatusResponse { enabled: true })
}

async fn totp_disable(
    request: CodeRequest,
    users: Arc<dyn UserRepository>,
    secret_box: Arc<SecretBox>,
    caller: AuthUser,
) -> anyhow::Result<MfaStatusResponse> {
    let mut user = load_caller(&users, &caller).await?;

    let active = match user.totp_secret.as_deref() {
        Some(active) => active,
        None => client_bail!("TOTP MFA is not enabled"),
    };

    let raw = secret_box.decrypt(active)?;
    let totp = make_totp(raw, &user.email)?;
    if !totp
        .check_current(&request.code)
        .map_err(|err| anyhow!("Failed to check TOTP code: {err}"))?
    {
        status_bail!(StatusCode::UNAUTHORIZED, "Invalid TOTP code");
    }

    user.totp_secret = None;
    user.totp_pending = None;
    let _ = users.put_user(user).await?;

    Ok(MfaStatusResponse { enabled: false })
}
