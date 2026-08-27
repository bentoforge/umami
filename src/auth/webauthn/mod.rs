//! WebAuthn / FIDO2 passkeys (platform passkeys + hardware keys like YubiKey).
//!
//! Wraps `webauthn-rs` register/authenticate ceremonies. The short-lived ceremony state is
//! persisted between `start` and `finish` (see [`repository`]); the resulting passkeys are stored
//! per user. Registration is authenticated (enrolment); login is a passwordless passkey flow.

pub mod repository;

use crate::audit::repository::{AuditRepository, record_best_effort};
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::AuthContext;
use crate::auth::login::{AuthStrength, issue_session};
use crate::auth::ratelimit::{Decision, Policy, too_many_requests};
use crate::auth::webauthn::repository::WebauthnRepository;
use crate::constants::{MANAGE_PASSWORDS_PERMISSION, MAX_TEXT_BODY_SIZE};
use crate::users::repository::UserRepository;
use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use std::sync::Arc;
use warp::Filter;
use warp::Reply;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::http::header::SET_COOKIE;
use warp::reply::Response;
use wasabi::aws::dynamodb::generate_id;
use wasabi::status_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;

/// Passkey registration is a security-settings change, so it requires `manage:passwords` (the
/// passwordless *login* routes below stay unauthenticated).
const REQUIRE_PASSWORDS: &[&str] = &[MANAGE_PASSWORDS_PERMISSION];
use wasabi::web::warp::{
    client_ip, into_rejection, into_response, with_body_as_json, with_cloneable,
};
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, CredentialID, DiscoverableAuthentication,
    DiscoverableKey, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder,
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
    ///
    /// One-way on purpose, which is why a discoverable login cannot recover the user id from the
    /// handle the authenticator returns and resolves it through the credential id instead. The
    /// handle is still worth comparing afterwards: it must agree with the resolved user.
    pub fn user_handle(user_id: &str) -> Uuid {
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

    /// Begins a discoverable ("conditional UI") authentication: no allow-list, so the
    /// authenticator offers whatever resident credential it holds for this relying party.
    pub fn start_discoverable_authentication(
        &self,
    ) -> anyhow::Result<(RequestChallengeResponse, DiscoverableAuthentication)> {
        self.webauthn
            .start_discoverable_authentication()
            .map_err(|err| anyhow!("Failed to start discoverable authentication: {err}"))
    }

    /// Reads the user handle and credential id out of a discoverable assertion. This is
    /// **unverified** input — it only says which credential the authenticator claims to have
    /// used, so it may do no more than select which keys the signature is then checked against.
    pub fn identify_discoverable(
        &self,
        credential: &PublicKeyCredential,
    ) -> anyhow::Result<(Uuid, Vec<u8>)> {
        self.webauthn
            .identify_discoverable_authentication(credential)
            .map(|(handle, credential_id)| (handle, credential_id.to_vec()))
            .map_err(|err| anyhow!("Failed to identify discoverable credential: {err}"))
    }

    /// Completes a discoverable authentication against the resolved user's keys.
    pub fn finish_discoverable_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        keys: &[DiscoverableKey],
    ) -> anyhow::Result<AuthenticationResult> {
        self.webauthn
            .finish_discoverable_authentication(credential, state, keys)
            .map_err(|err| anyhow!("Failed to finish discoverable authentication: {err}"))
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
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_PASSWORDS,
        ))
        .and_then(handle_register_start)
        .boxed()
}

/// `POST /auth/webauthn/register/finish` — complete passkey enrolment.
pub fn webauthn_register_finish_route(
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "webauthn" / "register" / "finish")
        .and(warp::post())
        .and(with_body_as_json::<RegisterFinishRequest>(
            MAX_TEXT_BODY_SIZE,
        ))
        .and(with_cloneable(service))
        .and(with_cloneable(webauthn))
        .and(with_cloneable(users))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_PASSWORDS,
        ))
        .and(client_ip())
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
        .and(client_ip())
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
    /// Omitted for a discoverable login: the authenticator picks the credential, and with it
    /// the user. Required for the classic flow, where the allow-list is that user's passkeys.
    #[serde(default)]
    username: Option<String>,
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
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
    ip: Option<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(register_finish(request, service, webauthn, users, audit, caller, ip).await)
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
    ip: Option<String>,
) -> Result<Response, warp::Rejection> {
    // Per-IP volume cap on login attempts (shared "perIp:login" budget with password login).
    // Passkeys are public-key challenges, so there is no per-account brute-force counter here.
    if let Some(ip) = ip.as_deref() {
        let config = context.config.current().await.map_err(into_rejection)?;
        let limits = &config.security.rate_limits;
        let per_ip = Policy::new(
            limits.per_ip.max_per_window,
            limits.per_ip.window_secs,
            limits.per_ip.block_secs,
        );
        if let Decision::Block { retry_after } = context
            .rate_limiter
            .check("perIp:login", &per_ip, ip, Utc::now())
            .await
        {
            return Ok(too_many_requests(retry_after));
        }
    }

    match login_finish(request, &context, service, webauthn, user_agent, ip).await {
        Ok((access_token, set_cookie)) => {
            let body = json!({ "accessToken": access_token, "tenants": [] });
            let reply = warp::reply::json(&body);
            let reply = warp::reply::with_header(reply, SET_COOKIE, set_cookie);
            Ok(warp::reply::with_status(reply, StatusCode::OK).into_response())
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
            Some(user.user_id.as_str()),
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
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
    ip: Option<String>,
) -> anyhow::Result<RegisterFinishResponse> {
    let ceremony = match webauthn.take_ceremony(&request.ceremony_id).await? {
        Some(ceremony) => ceremony,
        None => status_bail!(StatusCode::BAD_REQUEST, "Unknown or expired ceremony"),
    };
    // Registration is authenticated, so its ceremony always carries the enroling user. A
    // discoverable (user-less) ceremony must never be redeemable as a registration.
    let ceremony_user = match ceremony.user_id.as_deref() {
        Some(user_id) => user_id,
        None => status_bail!(StatusCode::BAD_REQUEST, "Not a registration ceremony"),
    };
    if ceremony_user != caller.user_id()? {
        status_bail!(StatusCode::FORBIDDEN, "Ceremony does not belong to you");
    }

    let state: PasskeyRegistration =
        serde_json::from_str(&ceremony.state).context("Corrupt ceremony state")?;
    let passkey = service.finish_registration(&request.credential, &state)?;
    let credential_id = credential_id_string(&passkey);

    webauthn
        .put_credential(
            ceremony_user,
            &credential_id,
            serde_json::to_string(&passkey).context("Failed to serialize passkey")?,
        )
        .await?;

    // Best-effort denormalized flag for the admin user list; a failure here just hides the badge.
    if let Err(err) = users.set_has_passkey(ceremony_user).await {
        tracing::warn!("failed to set hasPasskey for {ceremony_user}: {err:#}");
    }

    // A new second factor enrolled is a security-relevant change → audit it (with the client IP).
    let tenant_id = caller.tenant_id().ok().map(str::to_owned);
    record_best_effort(
        &audit,
        NewAuditEntry::new(
            AuditSeverity::Good,
            tenant_id,
            Some(ceremony_user.to_owned()),
            "Passkey registered".to_owned(),
        )
        .with_ip(ip),
    )
    .await;

    Ok(RegisterFinishResponse { credential_id })
}

async fn login_start(
    request: LoginStartRequest,
    context: &AuthContext,
    service: Arc<WebauthnService>,
    webauthn: Arc<dyn WebauthnRepository>,
) -> anyhow::Result<LoginStartResponse> {
    // No username: discoverable flow. The challenge carries no allow-list, so the response
    // leaks nothing about who exists — which is also why it is safe to answer unconditionally.
    let Some(username) = request
        .username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        let (options, state) = service.start_discoverable_authentication()?;
        let ceremony_id = generate_id();
        webauthn
            .store_ceremony(
                &ceremony_id,
                None,
                serde_json::to_string(&state).context("Failed to serialize ceremony state")?,
                CEREMONY_TTL_SECS,
            )
            .await?;
        return Ok(LoginStartResponse {
            ceremony_id,
            options,
        });
    };

    let user = match context.users.find_by_username(username).await? {
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
            Some(user.user_id.as_str()),
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

    // Which flavour of ceremony this is decides how the user is found: the classic flow knows
    // them up front, the discoverable one learns them from the credential the authenticator used.
    let (user_id, result) = match ceremony.user_id {
        Some(user_id) => {
            let state: PasskeyAuthentication =
                serde_json::from_str(&ceremony.state).context("Corrupt ceremony state")?;
            let result = service.finish_authentication(&request.credential, &state)?;
            (user_id, result)
        }
        None => {
            let state: DiscoverableAuthentication =
                serde_json::from_str(&ceremony.state).context("Corrupt ceremony state")?;
            let (handle, credential_id) = service.identify_discoverable(&request.credential)?;
            let credential_id = URL_SAFE_NO_PAD.encode(credential_id);
            // Both failures below answer with the same opaque message on purpose — the client
            // must not learn which credentials exist. The log is where they are told apart.
            let user_id = match webauthn.find_user_by_credential(&credential_id).await? {
                Some(user_id) => user_id,
                None => {
                    tracing::warn!(
                        credential_id,
                        "Discoverable login: no user owns this credential (index not yet \
                         populated, or the credential was removed)"
                    );
                    status_bail!(StatusCode::UNAUTHORIZED, "No passkey login available")
                }
            };
            // The credential id and the user handle are two independent statements about who
            // this is; if they disagree, something is wrong and no signature check would notice.
            if WebauthnService::user_handle(&user_id) != handle {
                tracing::warn!(
                    credential_id,
                    user_id,
                    "Discoverable login: user handle does not match the user the credential \
                     resolves to"
                );
                status_bail!(StatusCode::UNAUTHORIZED, "No passkey login available");
            }
            let keys: Vec<DiscoverableKey> =
                parse_passkeys(webauthn.list_passkeys(&user_id).await?)?
                    .iter()
                    .map(DiscoverableKey::from)
                    .collect();
            let result =
                service.finish_discoverable_authentication(&request.credential, state, &keys)?;
            (user_id, result)
        }
    };

    // Persist the updated signature counter (replay/clone detection).
    for mut passkey in parse_passkeys(webauthn.list_passkeys(&user_id).await?)? {
        if passkey.cred_id() == result.cred_id() {
            if passkey.update_credential(&result).is_some() {
                webauthn
                    .put_credential(
                        &user_id,
                        &credential_id_string(&passkey),
                        serde_json::to_string(&passkey).context("Failed to serialize passkey")?,
                    )
                    .await?;
            }
            break;
        }
    }

    let user = match context.users.get_user(&user_id).await? {
        Some(user) if !user.locked => user,
        _ => status_bail!(StatusCode::UNAUTHORIZED, "Account not active"),
    };

    // Mint for the requested API (default: umami admin API); the session records it for refresh.
    // A passkey login is a strong factor → is:passkey + is:2fa.
    let api_code = request.api.as_deref().unwrap_or("umami");
    let audit_ip = ip.clone();
    // A passkey login is a strong factor → is:passkey + is:2fa. No `Accept-Language` here: the
    // ceremony is driven by a client that already knows who it is talking to, and the user's own
    // preference (or the deployment default) is the honest answer.
    let issued = issue_session(
        context,
        &user,
        api_code,
        AuthStrength {
            passkey: true,
            totp: false,
        },
        None,
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
            "Passkey login".to_owned(),
        )
        .with_ip(audit_ip),
    )
    .await;

    Ok(issued)
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

    /// What can be checked of the discoverable ceremony without a discoverable authenticator:
    /// the challenge must name no credential at all, and its state must survive the trip through
    /// the ceremony table.
    ///
    /// The full round trip is **not** covered, and cannot be with the current test harness:
    /// both soft authenticators in `webauthn-authenticator-rs` 0.5.5 hardcode
    /// `user_handle: None` in the assertion, and without that handle
    /// `identify_discoverable_authentication` has nothing to resolve. Exercising the rest needs a
    /// real authenticator.
    #[test]
    fn discoverable_challenge_names_no_credential() {
        let service = WebauthnService::new("localhost", ORIGIN).unwrap();

        let (rcr, auth_state) = service.start_discoverable_authentication().unwrap();

        assert!(
            rcr.public_key.allow_credentials.is_empty(),
            "a discoverable challenge must not name any credential — naming one would both \
             defeat the purpose and leak which credentials exist"
        );
        // Same JSON hop the DynamoDB-backed ceremony table performs.
        let reloaded = roundtrip(&auth_state);
        assert_eq!(
            serde_json::to_string(&reloaded).unwrap(),
            serde_json::to_string(&auth_state).unwrap()
        );
    }

    /// A handle derived from a different user must not match — this is the check that makes the
    /// credential-id lookup and the handle two independent statements rather than one.
    #[test]
    fn user_handles_are_distinct_per_user() {
        assert_ne!(
            WebauthnService::user_handle("user-1"),
            WebauthnService::user_handle("user-2")
        );
        assert_eq!(
            WebauthnService::user_handle("user-1"),
            WebauthnService::user_handle("user-1"),
            "the handle has to be stable, it is what the authenticator stored"
        );
    }
}
