//! WebAuthn / FIDO2 passkeys (platform passkeys + hardware keys like YubiKey).
//!
//! Wraps `webauthn-rs` register/authenticate ceremonies. The short-lived ceremony state is
//! persisted between `start` and `finish` (see [`repository`]); the resulting passkeys are stored
//! per user. Registration is authenticated (enrolment); login is a passwordless passkey flow.

pub mod repository;

use crate::auth::AuthContext;
use crate::auth::login::issue_session;
use crate::auth::webauthn::repository::WebauthnRepository;
use crate::constants::MAX_TEXT_BODY_SIZE;
use crate::users::repository::UserRepository;
use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::http::header::SET_COOKIE;
use wasabi::aws::dynamodb::generate_id;
use wasabi::status_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user;
use wasabi::web::warp::{into_rejection, into_response, with_body_as_json, with_cloneable};
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder,
};

/// Ceremony state lifetime (seconds) — a passkey ceremony must complete within this window.
const CEREMONY_TTL_SECS: i64 = 300;

/// Thin wrapper over a configured [`Webauthn`] relying party. Ceremony state and credential
/// persistence live in the route layer + [`repository`]; this type owns the crypto ceremonies only.
pub struct WebauthnService {
    webauthn: Webauthn,
}

impl WebauthnService {
    /// Builds the service from `UMAMI_WEBAUTHN_RP_ID` (e.g. `localhost` / `umami.example.com`) and
    /// `UMAMI_WEBAUTHN_ORIGIN` (e.g. `http://localhost:8093`).
    pub fn from_env() -> anyhow::Result<Self> {
        let rp_id = env::var("UMAMI_WEBAUTHN_RP_ID")
            .context("Please provide UMAMI_WEBAUTHN_RP_ID (the effective WebAuthn RP id)")?;
        let origin = env::var("UMAMI_WEBAUTHN_ORIGIN")
            .context("Please provide UMAMI_WEBAUTHN_ORIGIN (the site origin, scheme+host+port)")?;
        Self::new(&rp_id, &origin)
    }

    /// Builds the service for a given relying-party id and origin.
    pub fn new(rp_id: &str, origin: &str) -> anyhow::Result<Self> {
        let origin = Url::parse(origin).context("Invalid UMAMI_WEBAUTHN_ORIGIN")?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .context("Invalid WebAuthn RP configuration")?
            .rp_name("umami")
            .build()
            .context("Failed to build WebAuthn relying party")?;
        Ok(Self { webauthn })
    }

    /// Derives the stable 16-byte WebAuthn user handle from a user id.
    fn user_handle(user_id: &str) -> Uuid {
        // SHA-256 always yields 32 bytes, so the first 16 are always present.
        let bytes = Sha256::digest(user_id.as_bytes())
            .first_chunk::<16>()
            .copied()
            .unwrap_or_default();
        Uuid::from_bytes(bytes)
    }

    /// Begins passkey registration; the returned state must be persisted until `finish`.
    pub fn start_registration(
        &self,
        user_id: &str,
        user_name: &str,
        display_name: &str,
        exclude: Vec<CredentialID>,
    ) -> anyhow::Result<(CreationChallengeResponse, PasskeyRegistration)> {
        let exclude = if exclude.is_empty() {
            None
        } else {
            Some(exclude)
        };
        self.webauthn
            .start_passkey_registration(
                Self::user_handle(user_id),
                user_name,
                display_name,
                exclude,
            )
            .map_err(|err| anyhow!("Failed to start passkey registration: {err}"))
    }

    /// Completes passkey registration, yielding the passkey to store.
    pub fn finish_registration(
        &self,
        credential: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> anyhow::Result<Passkey> {
        self.webauthn
            .finish_passkey_registration(credential, state)
            .map_err(|err| anyhow!("Failed to finish passkey registration: {err}"))
    }

    /// Begins passkey authentication over the user's registered passkeys.
    pub fn start_authentication(
        &self,
        passkeys: &[Passkey],
    ) -> anyhow::Result<(RequestChallengeResponse, PasskeyAuthentication)> {
        self.webauthn
            .start_passkey_authentication(passkeys)
            .map_err(|err| anyhow!("Failed to start passkey authentication: {err}"))
    }

    /// Completes passkey authentication.
    pub fn finish_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> anyhow::Result<AuthenticationResult> {
        self.webauthn
            .finish_passkey_authentication(credential, state)
            .map_err(|err| anyhow!("Failed to finish passkey authentication: {err}"))
    }
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// Base64url string form of a passkey's credential id (the `webauthn-credentials` sort key).
fn credential_id_string(passkey: &Passkey) -> String {
    URL_SAFE_NO_PAD.encode(passkey.cred_id())
}

/// `POST /auth/webauthn/register/start` — begin enrolling a passkey for the caller.
pub fn webauthn_register_start_route(
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
    users: Arc<dyn UserRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "webauthn" / "register" / "start")
        .and(warp::post())
        .and(with_cloneable(service))
        .and(with_cloneable(webauthn))
        .and(with_cloneable(users))
        .and(with_user(authenticator))
        .and_then(handle_register_start)
        .boxed()
}

/// `POST /auth/webauthn/register/finish` — complete passkey enrolment.
pub fn webauthn_register_finish_route(
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "webauthn" / "register" / "finish")
        .and(warp::post())
        .and(with_body_as_json::<RegisterFinishRequest>(
            MAX_TEXT_BODY_SIZE,
        ))
        .and(with_cloneable(service))
        .and(with_cloneable(webauthn))
        .and(with_user(authenticator))
        .and_then(handle_register_finish)
        .boxed()
}

/// `POST /auth/webauthn/login/start` — begin a passwordless passkey login.
pub fn webauthn_login_start_route(
    context: AuthContext,
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "webauthn" / "login" / "start")
        .and(warp::post())
        .and(with_body_as_json::<LoginStartRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(Arc::new(context)))
        .and(with_cloneable(service))
        .and(with_cloneable(webauthn))
        .and_then(handle_login_start)
        .boxed()
}

/// `POST /auth/webauthn/login/finish` — complete passkey login; issues a token + refresh cookie.
pub fn webauthn_login_finish_route(
    context: AuthContext,
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "webauthn" / "login" / "finish")
        .and(warp::post())
        .and(with_body_as_json::<LoginFinishRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(Arc::new(context)))
        .and(with_cloneable(service))
        .and(with_cloneable(webauthn))
        .and(warp::header::optional::<String>("user-agent"))
        .and(warp::filters::addr::remote())
        .and_then(handle_login_finish)
        .boxed()
}

// ── Request/response types ───────────────────────────────────────────────────

/// Register-start response: the ceremony id to echo back, and the creation options for the browser.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RegisterStartResponse {
    ceremony_id: String,
    options: CreationChallengeResponse,
}

/// Register-finish request: the ceremony id + the authenticator's attestation.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RegisterFinishRequest {
    ceremony_id: String,
    credential: RegisterPublicKeyCredential,
}

/// Register-finish response.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RegisterFinishResponse {
    credential_id: String,
}

/// Login-start request.
#[derive(Deserialize, Debug)]
struct LoginStartRequest {
    username: String,
}

/// Login-start response: the ceremony id + the request options for the browser.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LoginStartResponse {
    ceremony_id: String,
    options: RequestChallengeResponse,
}

/// Login-finish request.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LoginFinishRequest {
    ceremony_id: String,
    credential: PublicKeyCredential,
    /// Optional target API (config `apis` catalog) to mint the access token for directly; the
    /// session remembers it so refresh keeps the audience. Defaults to `umami`.
    api: Option<String>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "POST /auth/webauthn/register/start", skip_all)]
async fn handle_register_start(
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(register_start(service, webauthn, users, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "POST /auth/webauthn/register/finish",
    skip_all
)]
async fn handle_register_finish(
    request: RegisterFinishRequest,
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(register_finish(request, service, webauthn, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /auth/webauthn/login/start", skip_all)]
async fn handle_login_start(
    request: LoginStartRequest,
    context: Arc<AuthContext>,
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(login_start(request, &context, service, webauthn).await)
}

#[tracing::instrument(level = "debug", name = "POST /auth/webauthn/login/finish", skip_all)]
async fn handle_login_finish(
    request: LoginFinishRequest,
    context: Arc<AuthContext>,
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
    user_agent: Option<String>,
    remote: Option<SocketAddr>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let ip = remote.map(|addr| addr.ip().to_string());
    match login_finish(request, &context, service, webauthn, user_agent, ip).await {
        Ok((access_token, set_cookie)) => {
            let body = json!({ "accessToken": access_token, "tenants": [] });
            let reply = warp::reply::json(&body);
            let reply = warp::reply::with_header(reply, SET_COOKIE, set_cookie);
            Ok(warp::reply::with_status(reply, StatusCode::OK))
        }
        Err(err) => Err(into_rejection(err)),
    }
}

// ── Business logic ──────────────────────────────────────────────────────────────

/// Deserializes a list of stored passkey JSONs.
fn parse_passkeys(raw: Vec<String>) -> anyhow::Result<Vec<Passkey>> {
    raw.iter()
        .map(|json| serde_json::from_str(json).context("Corrupt stored passkey"))
        .collect()
}

async fn register_start(
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> anyhow::Result<RegisterStartResponse> {
    let user_id = caller.user_id()?;
    let user = match users.get_user(user_id).await? {
        Some(user) => user,
        None => status_bail!(StatusCode::UNAUTHORIZED, "User no longer exists"),
    };

    let exclude: Vec<CredentialID> = parse_passkeys(webauthn.list_passkeys(&user.user_id).await?)?
        .iter()
        .map(|passkey| passkey.cred_id().clone())
        .collect();

    let (options, state) =
        service.start_registration(&user.user_id, &user.username, &user.username, exclude)?;

    let ceremony_id = generate_id();
    webauthn
        .store_ceremony(
            &ceremony_id,
            &user.user_id,
            serde_json::to_string(&state).context("Failed to serialize ceremony state")?,
            CEREMONY_TTL_SECS,
        )
        .await?;

    Ok(RegisterStartResponse {
        ceremony_id,
        options,
    })
}

async fn register_finish(
    request: RegisterFinishRequest,
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
    caller: AuthUser,
) -> anyhow::Result<RegisterFinishResponse> {
    let ceremony = match webauthn.take_ceremony(&request.ceremony_id).await? {
        Some(ceremony) => ceremony,
        None => status_bail!(StatusCode::BAD_REQUEST, "Unknown or expired ceremony"),
    };
    if ceremony.user_id != caller.user_id()? {
        status_bail!(StatusCode::FORBIDDEN, "Ceremony does not belong to you");
    }

    let state: PasskeyRegistration =
        serde_json::from_str(&ceremony.state).context("Corrupt ceremony state")?;
    let passkey = service.finish_registration(&request.credential, &state)?;
    let credential_id = credential_id_string(&passkey);

    webauthn
        .put_credential(
            &ceremony.user_id,
            &credential_id,
            serde_json::to_string(&passkey).context("Failed to serialize passkey")?,
        )
        .await?;

    Ok(RegisterFinishResponse { credential_id })
}

async fn login_start(
    request: LoginStartRequest,
    context: &AuthContext,
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
) -> anyhow::Result<LoginStartResponse> {
    let user = match context.users.find_by_username(&request.username).await? {
        Some(user) if !user.locked => user,
        _ => status_bail!(StatusCode::UNAUTHORIZED, "No passkey login available"),
    };

    let passkeys = parse_passkeys(webauthn.list_passkeys(&user.user_id).await?)?;
    if passkeys.is_empty() {
        status_bail!(StatusCode::UNAUTHORIZED, "No passkey login available");
    }

    let (options, state) = service.start_authentication(&passkeys)?;

    let ceremony_id = generate_id();
    webauthn
        .store_ceremony(
            &ceremony_id,
            &user.user_id,
            serde_json::to_string(&state).context("Failed to serialize ceremony state")?,
            CEREMONY_TTL_SECS,
        )
        .await?;

    Ok(LoginStartResponse {
        ceremony_id,
        options,
    })
}

async fn login_finish(
    request: LoginFinishRequest,
    context: &AuthContext,
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
    user_agent: Option<String>,
    ip: Option<String>,
) -> anyhow::Result<(String, String)> {
    let ceremony = match webauthn.take_ceremony(&request.ceremony_id).await? {
        Some(ceremony) => ceremony,
        None => status_bail!(StatusCode::UNAUTHORIZED, "Unknown or expired ceremony"),
    };

    let state: PasskeyAuthentication =
        serde_json::from_str(&ceremony.state).context("Corrupt ceremony state")?;
    let result = service.finish_authentication(&request.credential, &state)?;

    // Persist the updated signature counter (replay/clone detection).
    for mut passkey in parse_passkeys(webauthn.list_passkeys(&ceremony.user_id).await?)? {
        if passkey.cred_id() == result.cred_id() {
            if passkey.update_credential(&result).is_some() {
                webauthn
                    .put_credential(
                        &ceremony.user_id,
                        &credential_id_string(&passkey),
                        serde_json::to_string(&passkey).context("Failed to serialize passkey")?,
                    )
                    .await?;
            }
            break;
        }
    }

    let user = match context.users.get_user(&ceremony.user_id).await? {
        Some(user) if !user.locked => user,
        _ => status_bail!(StatusCode::UNAUTHORIZED, "Account not active"),
    };

    // Mint for the requested API (default: umami admin API); the session records it for refresh.
    let api_code = request.api.as_deref().unwrap_or("umami");
    issue_session(context, &user, api_code, user_agent, ip).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    const ORIGIN: &str = "http://localhost:8093";

    // Round-trips the ceremony state through JSON exactly as the DynamoDB-backed storage does, so
    // the test also proves the persisted-state path.
    fn roundtrip<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) -> T {
        serde_json::from_str(&serde_json::to_string(value).unwrap()).unwrap()
    }

    #[test]
    fn register_then_authenticate_with_soft_passkey() {
        let service = WebauthnService::new("localhost", ORIGIN).unwrap();
        // falsify_uv = true: the soft token asserts user-verification, which our policy requires.
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let origin = Url::parse(ORIGIN).unwrap();

        // ── registration ──
        let (ccr, reg_state) = service
            .start_registration("user-1", "user@example.test", "User One", vec![])
            .unwrap();
        let reg_state = roundtrip(&reg_state); // as if reloaded from the ceremony table
        let reg_credential = authenticator.do_registration(origin.clone(), ccr).unwrap();
        let passkey = service
            .finish_registration(&reg_credential, &reg_state)
            .unwrap();
        let passkey = roundtrip(&passkey); // as if reloaded from the credentials table

        // ── authentication ──
        let (rcr, auth_state) = service
            .start_authentication(std::slice::from_ref(&passkey))
            .unwrap();
        let auth_state = roundtrip(&auth_state);
        let auth_credential = authenticator.do_authentication(origin, rcr).unwrap();
        let result = service
            .finish_authentication(&auth_credential, &auth_state)
            .unwrap();

        assert_eq!(result.cred_id(), passkey.cred_id());
        assert!(result.user_verified());
    }
}
