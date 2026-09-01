//! Self-service email-contact routes (`/auth/me/contacts…`) plus the admin read view.
//!
//! Every mutation is audited — added, removed, and (once the mail path lands) verified. Reachability
//! is a security-relevant property: whoever controls the address a reset link goes to controls the
//! account, so the trail of who changed it when has to exist from the start rather than being added
//! after the first incident.
//!
//! The surface is gated on `manage:contacts`, which the default config grants in the baseline
//! self-service rule: keeping your own addresses current is profile data, not a deployment
//! capability. Verification and password recovery are what depend on infrastructure.

use crate::audit::repository::{AuditRepository, record_best_effort};
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::challenge::{ChallengeRepository, Purpose, confirm_address};
use crate::auth::ratelimit::{Decision, POLICY_MAIL_SEND, RateLimiter, too_many_requests};
use crate::config::repository::ConfigRepository;
use crate::constants::{MANAGE_CONTACTS_PERMISSION, MANAGE_USERS_PERMISSION, MAX_TEXT_BODY_SIZE};
use crate::contacts::preference::preference_for;
use crate::contacts::repository::{ContactRepository, NewContact};
use crate::contacts::{Contact, normalize_email};
use crate::notify::{Notifier, OutboundMail};
use crate::users::repository::UserRepository;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::{Filter, Reply};
use wasabi::status_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{
    into_rejection, into_response, into_response_with_status, with_body_as_json, with_cloneable,
};

const REQUIRE_SELF: &[&str] = &[MANAGE_CONTACTS_PERMISSION];
const REQUIRE_MANAGE_USERS: &[&str] = &[MANAGE_USERS_PERMISSION];

/// The caller's addresses plus which one they prefer.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ContactsResponse {
    contacts: Vec<Contact>,
    /// The address mail actually goes to — the user's choice while it holds, else the fallback.
    /// See [`crate::contacts::preference`].
    preferred: Option<String>,
    /// The choice the user actually made, when they made one.
    ///
    /// Reported next to `preferred` so a screen can tell "I picked this" from "this is simply the
    /// one you have left". Without the distinction, offering to un-pick a derived preference is an
    /// action that visibly does nothing: clearing an empty value changes no answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    chosen: Option<String>,
    /// Whether this deployment can actually send a verification mail.
    ///
    /// Reported so the screen that offers "verify" knows whether the button leads anywhere. Without
    /// it a deployment with no mail queue would show an action that accepts the click and does
    /// nothing — the failure mode with no error to see.
    verification_available: bool,
}

/// Request to add an address.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AddContactRequest {
    address: String,
    #[serde(default)]
    label: Option<String>,
}

/// Request naming one of the caller's own addresses.
///
/// In the **body**, not the path. An address is personal data, and a path lands in every access log,
/// proxy log and tracing span along the way — places with no retention policy and no erasure story.
/// umami goes out of its way not to hand addresses to the apps it serves (`/notifications/audience`
/// returns none); putting them in the URL would leak them to the infrastructure instead.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AddressRequest {
    address: String,
}

/// Request finishing a verification: the secret from the mailed link.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest {
    token: String,
}

/// Everything the verification-start route needs.
#[derive(Clone)]
pub struct VerifyDeps {
    /// Contact store.
    pub contacts: Arc<dyn ContactRepository>,
    /// Pending-challenge store.
    pub challenges: Arc<dyn ChallengeRepository>,
    /// User store (the name the mail addresses the reader by).
    pub users: Arc<dyn UserRepository>,
    /// Config (challenge TTL + the send policy).
    pub config: Arc<dyn ConfigRepository>,
    /// The outbound seam.
    pub notifier: Arc<dyn Notifier>,
    /// Per-user cap on mail umami sends on somebody's behalf.
    pub rate_limiter: Arc<RateLimiter>,
    /// umami's public base URL, for the link in the mail.
    pub public_base_url: String,
}

/// Request to set (or clear) the caller's preferred address.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PreferredRequest {
    /// The address to prefer; `null` clears the preference.
    address: Option<String>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `GET /auth/me/contacts` — the caller's addresses.
pub fn my_contacts_route(
    contacts: Arc<dyn ContactRepository>,
    users: Arc<dyn UserRepository>,
    notifier: Arc<dyn Notifier>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "contacts")
        .and(warp::get())
        .and(with_cloneable(contacts))
        .and(with_cloneable(users))
        .and(with_cloneable(notifier))
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
        .and_then(handle_my_contacts_route)
        .boxed()
}

/// `POST /auth/me/contacts` — add an address (unverified).
pub fn add_my_contact_route(
    contacts: Arc<dyn ContactRepository>,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "contacts")
        .and(warp::post())
        .and(with_body_as_json::<AddContactRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(contacts))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
        .and_then(handle_add_my_contact_route)
        .boxed()
}

/// `DELETE /auth/me/contacts/{address}` — remove one of the caller's addresses.
pub fn delete_my_contact_route(
    contacts: Arc<dyn ContactRepository>,
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "contacts")
        .and(warp::delete())
        .and(with_body_as_json::<AddressRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(contacts))
        .and(with_cloneable(users))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
        .and_then(handle_delete_my_contact_route)
        .boxed()
}

/// `PUT /auth/me/preferred-contact` — set or clear the caller's preferred address.
pub fn preferred_contact_route(
    contacts: Arc<dyn ContactRepository>,
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "preferred-contact")
        .and(warp::put())
        .and(with_body_as_json::<PreferredRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(contacts))
        .and(with_cloneable(users))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
        .and_then(handle_preferred_contact_route)
        .boxed()
}

/// `POST /auth/me/contacts/{address}/verify` — mail a challenge to one of the caller's addresses.
pub fn start_verification_route(
    deps: VerifyDeps,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "contacts" / "verify")
        .and(warp::post())
        .and(with_body_as_json::<AddressRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
        .and_then(handle_start_verification_route)
        .boxed()
}

/// `POST /auth/contacts/verify` — finish a verification with the secret from the mail.
///
/// **Unauthenticated on purpose.** The link is clicked in a mail client, which is regularly a
/// different browser or device than the one that started the flow; the secret *is* the proof, and
/// demanding a session on top would lock out exactly the people reading mail on their phone.
pub fn finish_verification_route(
    contacts: Arc<dyn ContactRepository>,
    challenges: Arc<dyn ChallengeRepository>,
    audit: Arc<dyn AuditRepository>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "contacts" / "verify")
        .and(warp::post())
        .and(with_body_as_json::<VerifyRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(contacts))
        .and(with_cloneable(challenges))
        .and(with_cloneable(audit))
        .and_then(handle_finish_verification_route)
        .boxed()
}

/// `GET /users/{id}/contacts` — a tenant user's addresses, read-only (requires `manage:users`).
pub fn user_contacts_route(
    contacts: Arc<dyn ContactRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String / "contacts")
        .and(warp::get())
        .and(with_cloneable(contacts))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_user_contacts_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "GET /auth/me/contacts", skip_all)]
async fn handle_my_contacts_route(
    contacts: Arc<dyn ContactRepository>,
    users: Arc<dyn UserRepository>,
    notifier: Arc<dyn Notifier>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(my_contacts(contacts, users, notifier, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /auth/me/contacts", skip_all)]
async fn handle_add_my_contact_route(
    request: AddContactRequest,
    contacts: Arc<dyn ContactRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response_with_status(add_my_contact(request, contacts, audit, caller).await)
}

#[tracing::instrument(level = "debug", name = "DELETE /auth/me/contacts/{address}", skip_all)]
async fn handle_delete_my_contact_route(
    request: AddressRequest,
    contacts: Arc<dyn ContactRepository>,
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(delete_my_contact(request, contacts, users, audit, caller).await)
}

#[tracing::instrument(level = "debug", name = "PUT /auth/me/preferred-contact", skip_all)]
async fn handle_preferred_contact_route(
    request: PreferredRequest,
    contacts: Arc<dyn ContactRepository>,
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(preferred_contact(request, contacts, users, audit, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "POST /auth/me/contacts/{address}/verify",
    skip_all
)]
async fn handle_start_verification_route(
    request: AddressRequest,
    deps: VerifyDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    match start_verification(request, deps, audit, caller).await {
        // A blocked send returns 429 + Retry-After directly: the ApiError path cannot carry the
        // header, so it bypasses `into_response` the same way a blocked login does.
        Ok(StartOutcome::RateLimited { retry_after }) => Ok(too_many_requests(retry_after)),
        Ok(StartOutcome::Sent { already_verified }) => {
            let status = if already_verified {
                "already-verified"
            } else {
                "sent"
            };
            Ok(warp::reply::json(&json!({ "status": status })).into_response())
        }
        Err(err) => Err(into_rejection(err)),
    }
}

#[tracing::instrument(level = "debug", name = "POST /auth/contacts/verify", skip_all)]
async fn handle_finish_verification_route(
    request: VerifyRequest,
    contacts: Arc<dyn ContactRepository>,
    challenges: Arc<dyn ChallengeRepository>,
    audit: Arc<dyn AuditRepository>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(finish_verification(request, contacts, challenges, audit).await)
}

#[tracing::instrument(level = "debug", name = "GET /users/{id}/contacts", skip_all)]
async fn handle_user_contacts_route(
    user_id: String,
    contacts: Arc<dyn ContactRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(user_contacts(user_id, contacts, caller).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

async fn my_contacts(
    contacts: Arc<dyn ContactRepository>,
    users: Arc<dyn UserRepository>,
    notifier: Arc<dyn Notifier>,
    caller: AuthUser,
) -> anyhow::Result<ContactsResponse> {
    let user_id = caller.user_id()?;
    let list = contacts.list_contacts(user_id).await?;
    let stored = users
        .get_user(user_id)
        .await?
        .and_then(|user| user.preferred_contact);
    Ok(ContactsResponse {
        // The resolved address, not the stored choice: the screen has to mark the row that actually
        // receives mail, or the badge means something different here than it does to a sender.
        preferred: preference_for(stored.as_deref(), &list),
        chosen: stored,
        contacts: list,
        verification_available: notifier.is_configured(),
    })
}

/// What starting a verification did.
enum StartOutcome {
    /// A challenge was mailed, or the address was already verified and none was spent.
    Sent {
        /// `true` when nothing was sent because the address is already proven.
        already_verified: bool,
    },
    /// The user's send budget is exhausted; `retry_after` is the advertised delay in seconds.
    RateLimited {
        /// Seconds until the block lifts.
        retry_after: i64,
    },
}

/// Mails a fresh challenge to one of the caller's own addresses.
async fn start_verification(
    request: AddressRequest,
    deps: VerifyDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<StartOutcome> {
    let user_id = caller.user_id()?;
    let tenant_id = caller.tenant_id()?;
    let address = normalize_email(&request.address)?;

    // Only the caller's own addresses, and only ones they still hold. Half the key is their user id,
    // so a foreign address is simply not in their partition.
    let contact = match deps.contacts.get_contact(user_id, &address).await? {
        Some(contact) => contact,
        None => status_bail!(StatusCode::NOT_FOUND, "You have no such address on file"),
    };
    // Idempotent, and deliberately free: re-verifying a proven address would spend a mail to learn
    // something already known.
    if contact.verified {
        return Ok(StartOutcome::Sent {
            already_verified: true,
        });
    }

    // Refuse up front rather than accepting a request that goes nowhere.
    if !deps.notifier.is_configured() {
        // Audited even though nothing was sent. A user clicking "confirm" and getting an error is
        // precisely the symptom of a deployment with no mail queue, and the operator who has to
        // notice that is not the person seeing the error.
        audit_contact(
            &audit,
            AuditSeverity::Bad,
            tenant_id,
            user_id,
            format!("Verification mail for {address} not sent — this deployment cannot send mail"),
        )
        .await;
        status_bail!(
            StatusCode::SERVICE_UNAVAILABLE,
            "This deployment cannot send mail, so an address cannot be verified"
        );
    }

    let config = deps.config.current().await?;
    let policy = crate::auth::ratelimit::Policy::new(
        config.security.rate_limits.mail_send.max_per_window,
        config.security.rate_limits.mail_send.window_secs,
        config.security.rate_limits.mail_send.block_secs,
    );
    // Keyed on the user, not the IP: the address being mailed sits on *their* list, so they are the
    // party to hold accountable for how often a stranger hears from us.
    if let Decision::Block { retry_after } = deps
        .rate_limiter
        .check(POLICY_MAIL_SEND, &policy, user_id, Utc::now())
        .await
    {
        audit_contact(
            &audit,
            AuditSeverity::Bad,
            tenant_id,
            user_id,
            format!("Verification mail for {address} not sent — rate limit reached"),
        )
        .await;
        return Ok(StartOutcome::RateLimited { retry_after });
    }

    let secret = deps
        .challenges
        .issue(
            Purpose::ConfirmAddress,
            user_id,
            tenant_id,
            &address,
            config.security.contact_challenge_ttl_secs as i64,
        )
        .await?;

    // The reader's own language, already resolved into the token's `locale` claim at mint time.
    // Already resolved into the token at mint time, so the mail speaks the language the user chose
    // rather than whatever the request happened to advertise.
    let locale = match caller.locale() {
        locale if !locale.trim().is_empty() => locale.to_owned(),
        _ => config.default_locale.clone(),
    };
    let greeting = deps
        .users
        .get_user(user_id)
        .await?
        .map(|user| user.display_names(&config.default_locale).addressable_name)
        .unwrap_or_default();
    let link = format!(
        "{}app/verify-contact?token={}",
        deps.public_base_url, secret
    );

    let mail = OutboundMail::new(
        "contact-verification",
        address.clone(),
        crate::i18n::message(&locale, "contact.verify.subject"),
        crate::i18n::message(&locale, "contact.verify.body")
            .replace("%{name}", &greeting)
            .replace("%{link}", &link),
        locale,
        user_id.to_owned(),
        tenant_id.to_owned(),
    );
    let message_id = mail.message_id.clone();
    deps.notifier.send(mail).await?;

    audit_contact(
        &audit,
        AuditSeverity::Neutral,
        tenant_id,
        user_id,
        format!("Verification mail queued for {address} (message {message_id})"),
    )
    .await;

    Ok(StartOutcome::Sent {
        already_verified: false,
    })
}

/// Consumes a challenge secret and marks the address it proves verified.
async fn finish_verification(
    request: VerifyRequest,
    contacts: Arc<dyn ContactRepository>,
    challenges: Arc<dyn ChallengeRepository>,
    audit: Arc<dyn AuditRepository>,
) -> anyhow::Result<Value> {
    let proven = match challenges
        .consume(Purpose::ConfirmAddress, request.token.trim())
        .await?
    {
        Some(proven) => proven,
        // One message for unknown, already-used and expired alike: distinguishing them would tell a
        // holder of a stale link which of the three it is, and none of that helps a legitimate user.
        None => status_bail!(
            StatusCode::NOT_FOUND,
            "This confirmation link is invalid or has expired"
        ),
    };

    // A challenge can outlive its address — the user may have removed it between receiving the mail
    // and clicking the link. That is not an error, just nothing left to verify.
    if !confirm_address(&contacts, &proven).await? {
        status_bail!(
            StatusCode::NOT_FOUND,
            "That address is no longer on the account"
        );
    }

    audit_contact(
        &audit,
        AuditSeverity::Good,
        &proven.tenant_id,
        &proven.user_id,
        format!("Email contact verified ({})", proven.address),
    )
    .await;

    Ok(json!({ "status": "verified", "address": proven.address }))
}

async fn add_my_contact(
    request: AddContactRequest,
    contacts: Arc<dyn ContactRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<(StatusCode, Contact)> {
    let user_id = caller.user_id()?;
    let tenant_id = caller.tenant_id()?;
    let address = normalize_email(&request.address)?;

    let contact = contacts
        .add_contact(NewContact {
            user_id: user_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            address: address.clone(),
            label: request.label,
        })
        .await?;

    audit_contact(
        &audit,
        AuditSeverity::Neutral,
        tenant_id,
        user_id,
        format!("Email contact added ({address}), pending verification"),
    )
    .await;

    Ok((StatusCode::CREATED, contact))
}

async fn delete_my_contact(
    request: AddressRequest,
    contacts: Arc<dyn ContactRepository>,
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    let user_id = caller.user_id()?;
    let tenant_id = caller.tenant_id()?;
    let address = normalize_email(&request.address)?;

    contacts.delete_contact(user_id, &address).await?;

    audit_contact(
        &audit,
        AuditSeverity::Neutral,
        tenant_id,
        user_id,
        format!("Email contact removed ({address})"),
    )
    .await;

    // Drop a stored choice that named this address. Resolution would ignore it anyway, but a
    // re-added address of the same name would otherwise silently inherit a preference the user set
    // in another life. Which address is reached instead follows from the list — nothing to write.
    if let Some(mut user) = users.get_user(user_id).await?
        && user.preferred_contact.as_deref() == Some(address.as_str())
    {
        user.preferred_contact = None;
        let _ = users.put_user(user).await?;
    }

    Ok(json!({ "status": "removed" }))
}

/// Sets or clears the caller's preferred address.
///
/// The address must be **verified**. A preference for an unverified one would be a setting that
/// changes nothing — only a proven address is ever sent to — while reading like the account's mail
/// now goes there. Refusing it says plainly that the confirmation is the missing step.
async fn preferred_contact(
    request: PreferredRequest,
    contacts: Arc<dyn ContactRepository>,
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    let user_id = caller.user_id()?;
    let tenant_id = caller.tenant_id()?;

    let address = match request.address {
        Some(raw) if !raw.trim().is_empty() => Some(normalize_email(&raw)?),
        _ => None,
    };
    if let Some(address) = address.as_deref() {
        match contacts.get_contact(user_id, address).await? {
            None => status_bail!(StatusCode::NOT_FOUND, "You have no such address on file"),
            Some(contact) if !contact.verified => status_bail!(
                StatusCode::CONFLICT,
                "Confirm this address before making it the preferred one"
            ),
            Some(_) => {}
        }
    }

    let mut user = match users.get_user(user_id).await? {
        Some(user) => user,
        None => status_bail!(StatusCode::NOT_FOUND, "No such user"),
    };
    user.preferred_contact = address.clone();
    let _ = users.put_user(user).await?;

    audit_contact(
        &audit,
        AuditSeverity::Neutral,
        tenant_id,
        user_id,
        match address.as_deref() {
            Some(address) => format!("Preferred email contact set ({address})"),
            None => "Preferred email contact cleared".to_owned(),
        },
    )
    .await;

    Ok(json!({ "preferred": address }))
}

/// Records a contact change. Best-effort: a failed audit write must not fail the change, but every
/// change does get an entry, because the address a reset link goes to is a security-relevant fact.
async fn audit_contact(
    audit: &Arc<dyn AuditRepository>,
    severity: AuditSeverity,
    tenant_id: &str,
    user_id: &str,
    message: String,
) {
    record_best_effort(
        audit,
        NewAuditEntry::new(
            severity,
            Some(tenant_id.to_owned()),
            Some(user_id.to_owned()),
            message,
        ),
    )
    .await;
}

/// Lists a tenant user's addresses, read-only. Scoped to the caller's tenant by dropping any row
/// whose `tenant_id` differs — so a `manage:users` admin can never read another tenant's addresses.
async fn user_contacts(
    user_id: String,
    contacts: Arc<dyn ContactRepository>,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    let tenant_id = caller.tenant_id()?;
    let list: Vec<Contact> = contacts
        .list_contacts(&user_id)
        .await?
        .into_iter()
        .filter(|contact| contact.tenant_id == tenant_id)
        .collect();
    Ok(json!({ "contacts": list }))
}
