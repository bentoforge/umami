//! External-recipient routes: the tenant admin's side under `/tenants/{id}/recipients…`, and the
//! recipient's own side behind a mailed token under `/recipients/…`.
//!
//! The admin side is gated on `manage:recipients` and scoped to the caller's own tenant. The
//! recipient's side is **unauthenticated on purpose**: the links arrive by mail, in a client that
//! has no umami session and never will, and the token in the body is the proof — a single-use
//! challenge for the confirmation, the recipient's own long-lived secret for everything after.
//!
//! Every mutation is audited in the tenant's log, exactly as a contact's is. "I never asked for
//! these" has to be answerable for a mailbox as it is for a user.

use crate::audit::repository::{AuditRepository, record_best_effort};
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::challenge::{ChallengeRepository, Purpose};
use crate::auth::ratelimit::{Decision, POLICY_MAIL_SEND, Policy, RateLimiter, too_many_requests};
use crate::auth::secretbox::SecretBox;
use crate::config::Config;
use crate::config::repository::ConfigRepository;
use crate::constants::{MANAGE_RECIPIENTS_PERMISSION, MAX_TEXT_BODY_SIZE};
use crate::contacts::normalize_email;
use crate::notify::service::{eligible_for_recipients, tenant_subjects};
use crate::notify::types::{CHOICE_OFF, normalize_cadence};
use crate::notify::{
    Notifier, OutboundMail, Recipient as MailRecipient, TEMPLATE_RECIPIENT_CONFIRMATION, render,
};
use crate::recipients::repository::RecipientRepository;
use crate::recipients::{
    ExternalRecipient, RecipientView, compose_token, generate_secret, normalize_display_name,
    split_token,
};
use crate::tenants::Tenant;
use crate::tenants::repository::TenantRepository;
use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::{Filter, Reply};
use wasabi::aws::dynamodb::generate_id;
use wasabi::status_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{
    into_rejection, into_response, into_response_with_status, with_body_as_json, with_cloneable,
};

const REQUIRE_MANAGE: &[&str] = &[MANAGE_RECIPIENTS_PERMISSION];

/// Everything the recipient routes need.
#[derive(Clone)]
pub struct RecipientDeps {
    /// The recipients themselves.
    pub recipients: Arc<dyn RecipientRepository>,
    /// Tenant store (the name the confirmation mail says is asking, and the features eligibility
    /// is judged on).
    pub tenants: Arc<dyn TenantRepository>,
    /// Pending-challenge store, for the confirmation link.
    pub challenges: Arc<dyn ChallengeRepository>,
    /// Config (the type catalogue, TTLs, the send policy).
    pub config: Arc<dyn ConfigRepository>,
    /// The outbound seam.
    pub notifier: Arc<dyn Notifier>,
    /// Per-admin cap on confirmation mails umami sends on their behalf.
    pub rate_limiter: Arc<RateLimiter>,
    /// Encrypts the management secret at rest.
    pub secrets: Arc<SecretBox>,
    /// umami's public base URL, for the links in the mails.
    pub public_base_url: String,
    /// System tenant id, for the `is:system-tenant*` markers in eligibility.
    pub system_tenant_id: Option<String>,
}

/// Request creating a recipient.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateRequest {
    address: String,
    display_name: String,
    locale: String,
    /// Choice per type code — `on`, `off` or a cadence. At least one has to be something other
    /// than `off`: the confirmation mail has to be able to say what the mailbox is agreeing to.
    #[serde(default)]
    choices: BTreeMap<String, String>,
}

/// Request changing a recipient: every field optional, the address never among them.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PatchRequest {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    locale: Option<String>,
    #[serde(default)]
    choices: Option<BTreeMap<String, String>>,
}

/// A request from a mailed link: the token is the proof.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TokenRequest {
    token: String,
}

/// The recipient changing its own choices.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ManageRequest {
    token: String,
    choices: BTreeMap<String, String>,
}

/// One type a recipient may subscribe to, resolved into a language.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct RecipientTypeView {
    code: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    cadences: Vec<CadenceView>,
    /// Every value the type accepts, `off` first.
    allowed: Vec<String>,
}

/// One cadence as a picker sees it.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct CadenceView {
    code: String,
    name: String,
}

/// The admin's list: the recipients, the types they may subscribe to, and whether a confirmation
/// mail can go out at all.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ListResponse {
    recipients: Vec<RecipientView>,
    types: Vec<RecipientTypeView>,
    verification_available: bool,
}

/// A freshly created recipient, plus whether its confirmation mail went out.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreatedRecipient {
    #[serde(flatten)]
    recipient: RecipientView,
    /// `false` when the deployment cannot send mail or the admin is over the hourly cap. The row
    /// exists either way; the screen offers "send again".
    verification_sent: bool,
}

/// What the recipient sees behind its management link: who is writing, and its own choices.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ManageView {
    tenant_name: String,
    display_name: String,
    locale: String,
    confirmed: bool,
    choices: BTreeMap<String, String>,
    types: Vec<RecipientTypeView>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `GET /tenants/{id}/recipients` — the tenant's recipients and the types open to them.
pub fn list_recipients_route(
    deps: RecipientDeps,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "recipients")
        .and(warp::get())
        .and(with_cloneable(deps))
        .and(with_user_with_any_permission(authenticator, REQUIRE_MANAGE))
        .and_then(handle_list_recipients_route)
        .boxed()
}

/// `POST /tenants/{id}/recipients` — register an address, unconfirmed, and mail its confirmation.
pub fn create_recipient_route(
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "recipients")
        .and(warp::post())
        .and(with_body_as_json::<CreateRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_MANAGE))
        .and_then(handle_create_recipient_route)
        .boxed()
}

/// `PATCH /tenants/{id}/recipients/{recipientId}` — display name, language, choices.
pub fn patch_recipient_route(
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "recipients" / String)
        .and(warp::patch())
        .and(with_body_as_json::<PatchRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_MANAGE))
        .and_then(handle_patch_recipient_route)
        .boxed()
}

/// `DELETE /tenants/{id}/recipients/{recipientId}` — remove a recipient.
pub fn delete_recipient_route(
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "recipients" / String)
        .and(warp::delete())
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_MANAGE))
        .and_then(handle_delete_recipient_route)
        .boxed()
}

/// `POST /tenants/{id}/recipients/{recipientId}/verify` — send the confirmation again.
pub fn resend_confirmation_route(
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "recipients" / String / "verify")
        .and(warp::post())
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_MANAGE))
        .and_then(handle_resend_confirmation_route)
        .boxed()
}

/// `POST /recipients/confirm` — finish a confirmation with the secret from the mail.
///
/// **Unauthenticated on purpose.** The link is opened in a mail client by somebody who has no
/// umami account and never will; the secret is the proof.
pub fn confirm_recipient_route(
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("recipients" / "confirm")
        .and(warp::post())
        .and(with_body_as_json::<TokenRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and_then(handle_confirm_recipient_route)
        .boxed()
}

/// `POST /recipients/manage` — what the recipient sees behind its link. Unauthenticated; the
/// token in the body is the proof. A `POST` rather than a `GET` so the token never sits in a
/// URL that every proxy logs.
pub fn manage_view_route(deps: RecipientDeps) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("recipients" / "manage")
        .and(warp::post())
        .and(with_body_as_json::<TokenRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and_then(handle_manage_view_route)
        .boxed()
}

/// `PUT /recipients/manage` — the recipient changes its own choices.
pub fn manage_choices_route(
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("recipients" / "manage")
        .and(warp::put())
        .and(with_body_as_json::<ManageRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and_then(handle_manage_choices_route)
        .boxed()
}

/// `DELETE /recipients/manage` — the recipient removes itself: unsubscribed from everything.
pub fn unsubscribe_route(
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("recipients" / "manage")
        .and(warp::delete())
        .and(with_body_as_json::<TokenRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and_then(handle_unsubscribe_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "GET /tenants/{id}/recipients", skip_all)]
async fn handle_list_recipients_route(
    tenant_id: String,
    deps: RecipientDeps,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_recipients(tenant_id, deps, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /tenants/{id}/recipients", skip_all)]
async fn handle_create_recipient_route(
    tenant_id: String,
    request: CreateRequest,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response_with_status(create_recipient(tenant_id, request, deps, audit, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "PATCH /tenants/{id}/recipients/{recipientId}",
    skip_all
)]
async fn handle_patch_recipient_route(
    tenant_id: String,
    recipient_id: String,
    request: PatchRequest,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(patch_recipient(tenant_id, recipient_id, request, deps, audit, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "DELETE /tenants/{id}/recipients/{recipientId}",
    skip_all
)]
async fn handle_delete_recipient_route(
    tenant_id: String,
    recipient_id: String,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(delete_recipient(tenant_id, recipient_id, deps, audit, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "POST /tenants/{id}/recipients/{recipientId}/verify",
    skip_all
)]
async fn handle_resend_confirmation_route(
    tenant_id: String,
    recipient_id: String,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    match resend_confirmation(tenant_id, recipient_id, deps, audit, caller).await {
        // A blocked send answers 429 + Retry-After directly, as the contact route does: the
        // ApiError path cannot carry the header.
        Ok(SendOutcome::RateLimited { retry_after }) => Ok(too_many_requests(retry_after)),
        Ok(SendOutcome::Sent) => {
            Ok(warp::reply::json(&json!({ "status": "sent" })).into_response())
        }
        Ok(SendOutcome::AlreadyConfirmed) => {
            Ok(warp::reply::json(&json!({ "status": "already-confirmed" })).into_response())
        }
        Err(err) => Err(into_rejection(err)),
    }
}

#[tracing::instrument(level = "debug", name = "POST /recipients/confirm", skip_all)]
async fn handle_confirm_recipient_route(
    request: TokenRequest,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(confirm_recipient(request, deps, audit).await)
}

#[tracing::instrument(level = "debug", name = "POST /recipients/manage", skip_all)]
async fn handle_manage_view_route(
    request: TokenRequest,
    deps: RecipientDeps,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(manage_view(request, deps).await)
}

#[tracing::instrument(level = "debug", name = "PUT /recipients/manage", skip_all)]
async fn handle_manage_choices_route(
    request: ManageRequest,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(manage_choices(request, deps, audit).await)
}

#[tracing::instrument(level = "debug", name = "DELETE /recipients/manage", skip_all)]
async fn handle_unsubscribe_route(
    request: TokenRequest,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(unsubscribe(request, deps, audit).await)
}

// ── Business logic: the admin's side ─────────────────────────────────────────

/// The link a recipient's mails carry, behind which it manages its own choices.
pub fn manage_url(public_base_url: &str, recipient_id: &str, secret: &str) -> String {
    format!(
        "{public_base_url}app/recipient?token={}",
        compose_token(recipient_id, secret)
    )
}

/// The link the confirmation mail carries.
fn confirm_url(public_base_url: &str, secret: &str) -> String {
    format!("{public_base_url}app/confirm-recipient?token={secret}")
}

/// Refuses a path naming another tenant. `403`, not `404`: the caller proved who they are and is
/// simply not allowed here.
fn require_own_tenant(caller: &AuthUser, tenant_id: &str) -> anyhow::Result<()> {
    if caller.tenant_id()? != tenant_id {
        status_bail!(
            StatusCode::FORBIDDEN,
            "You may only manage your own tenant's recipients"
        );
    }
    Ok(())
}

/// The tenant, or a `404`.
async fn tenant(deps: &RecipientDeps, tenant_id: &str) -> anyhow::Result<Tenant> {
    match deps.tenants.get_tenant(tenant_id).await? {
        Some(tenant) => Ok(tenant),
        None => status_bail!(StatusCode::NOT_FOUND, "No such tenant"),
    }
}

/// One of the tenant's recipients, or a `404`. A recipient of another tenant reads as missing —
/// the id is opaque, and whether it exists elsewhere is nobody's business.
async fn own_recipient(
    deps: &RecipientDeps,
    tenant_id: &str,
    recipient_id: &str,
) -> anyhow::Result<ExternalRecipient> {
    match deps.recipients.get_recipient(recipient_id).await? {
        Some(recipient) if recipient.tenant_id == tenant_id => Ok(recipient),
        _ => status_bail!(StatusCode::NOT_FOUND, "No such recipient in this tenant"),
    }
}

/// The types a tenant's recipients may subscribe to, with their labels in `locale`.
fn recipient_types(
    config: &Config,
    subjects: &BTreeSet<String>,
    locale: &str,
) -> Vec<RecipientTypeView> {
    config
        .notification_types
        .iter()
        .filter(|type_def| eligible_for_recipients(type_def, subjects))
        .map(|type_def| RecipientTypeView {
            code: type_def.code.clone(),
            name: type_def
                .name
                .resolve(locale, &config.default_locale)
                .to_owned(),
            description: type_def
                .description
                .as_ref()
                .map(|text| text.resolve(locale, &config.default_locale).to_owned()),
            cadences: type_def
                .cadences
                .iter()
                .map(|cadence| CadenceView {
                    code: cadence.code.clone(),
                    name: cadence
                        .name
                        .resolve(locale, &config.default_locale)
                        .to_owned(),
                })
                .collect(),
            allowed: type_def
                .allowed_choices()
                .into_iter()
                .map(str::to_owned)
                .collect(),
        })
        .collect()
}

/// Checks a set of choices against the catalogue: every type has to be open to recipients and
/// eligible for the tenant, every value one the type accepts. Returns the choices normalized.
///
/// A value the type does not accept is refused rather than stored, exactly as for a user: a stored
/// choice nothing ever fires at would leave the mailbox waiting forever.
fn check_choices(
    config: &Config,
    subjects: &BTreeSet<String>,
    choices: &BTreeMap<String, String>,
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut checked = BTreeMap::new();
    for (code, value) in choices {
        let code = code.trim();
        let Some(type_def) = config.find_notification_type(code) else {
            status_bail!(
                StatusCode::BAD_REQUEST,
                "Unknown notification type '{code}'"
            );
        };
        if !eligible_for_recipients(type_def, subjects) {
            status_bail!(
                StatusCode::BAD_REQUEST,
                "Notification type '{code}' is not open to external recipients of this tenant"
            );
        }
        let value = normalize_cadence(value);
        if !type_def.accepts(&value) {
            status_bail!(
                StatusCode::BAD_REQUEST,
                "'{code}' does not accept '{value}' — pick one of: {}",
                type_def.allowed_choices().join(", ")
            );
        }
        let _ = checked.insert(code.to_owned(), value);
    }
    Ok(checked)
}

/// Whether any choice is something other than `off`.
fn subscribes_to_anything(choices: &BTreeMap<String, String>) -> bool {
    choices.values().any(|value| value != CHOICE_OFF)
}

/// Normalizes a language tag and checks the deployment can actually write in it. The confirmation
/// mail is rendered in this language, and an unknown tag would silently fall back to English.
fn check_locale(config: &Config, raw: &str) -> anyhow::Result<String> {
    let tag = raw.trim().to_ascii_lowercase();
    let primary = tag.split(['-', '_']).next().unwrap_or_default();
    let supported = crate::i18n::supported(config);
    if tag.is_empty() || !supported.iter().any(|known| known == primary) {
        status_bail!(
            StatusCode::BAD_REQUEST,
            "Locale '{}' is not one this deployment writes mail in — pick one of: {}",
            raw.trim(),
            supported.join(", ")
        );
    }
    Ok(tag)
}

/// The tenant's offline subject set, for eligibility.
fn subjects_of(deps: &RecipientDeps, tenant: &Tenant) -> BTreeSet<String> {
    tenant_subjects(
        &tenant.tenant_id,
        &tenant.features,
        deps.system_tenant_id.as_deref(),
    )
}

async fn list_recipients(
    tenant_id: String,
    deps: RecipientDeps,
    caller: AuthUser,
) -> anyhow::Result<ListResponse> {
    require_own_tenant(&caller, &tenant_id)?;
    let config = deps.config.current().await?;
    let tenant = tenant(&deps, &tenant_id).await?;
    let subjects = subjects_of(&deps, &tenant);
    let recipients = deps
        .recipients
        .list_recipients(&tenant_id)
        .await?
        .iter()
        .map(RecipientView::from)
        .collect();
    Ok(ListResponse {
        recipients,
        types: recipient_types(&config, &subjects, caller.locale()),
        verification_available: deps.notifier.is_configured(),
    })
}

async fn create_recipient(
    tenant_id: String,
    request: CreateRequest,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<(StatusCode, CreatedRecipient)> {
    require_own_tenant(&caller, &tenant_id)?;
    let admin_id = caller.user_id()?;
    let config = deps.config.current().await?;
    let tenant = tenant(&deps, &tenant_id).await?;
    let subjects = subjects_of(&deps, &tenant);

    let address = normalize_email(&request.address)?;
    let display_name = normalize_display_name(&request.display_name)?;
    let locale = check_locale(&config, &request.locale)?;
    let choices = check_choices(&config, &subjects, &request.choices)?;
    // The confirmation mail says what the mailbox is agreeing to; with nothing chosen there would
    // be nothing to say, and a recipient that hears nothing is a row somebody will wonder about.
    if !subscribes_to_anything(&choices) {
        status_bail!(
            StatusCode::BAD_REQUEST,
            "Choose at least one notification type for the recipient"
        );
    }

    let secret = generate_secret();
    let now = Utc::now();
    let recipient = ExternalRecipient {
        recipient_id: generate_id(),
        tenant_id: tenant_id.clone(),
        address: address.clone(),
        display_name,
        locale,
        choices,
        confirmed: false,
        confirmed_at: None,
        manage_secret: deps
            .secrets
            .encrypt(secret.as_bytes())
            .context("Failed to encrypt the management secret")?,
        created: now,
        last_updated: now,
    };
    deps.recipients.add_recipient(recipient.clone()).await?;

    audit_recipient(
        &audit,
        AuditSeverity::Neutral,
        &tenant_id,
        Some(admin_id),
        format!(
            "External recipient {} added ({address}), pending confirmation; choices: {}",
            recipient.recipient_id,
            describe_choices(&recipient.choices)
        ),
    )
    .await;

    // Best-effort, like a contact's: the row exists either way, and turning a missing mail path
    // into an error would invite a retry that answers `409`.
    let verification_sent =
        match send_confirmation(&deps, &audit, &config, &tenant, &recipient, admin_id).await {
            Ok(SendOutcome::Sent) => true,
            Ok(_) => false,
            Err(err) => {
                tracing::warn!("added a recipient but could not mail its confirmation: {err:#}");
                false
            }
        };

    Ok((
        StatusCode::CREATED,
        CreatedRecipient {
            recipient: RecipientView::from(&recipient),
            verification_sent,
        },
    ))
}

async fn patch_recipient(
    tenant_id: String,
    recipient_id: String,
    request: PatchRequest,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<RecipientView> {
    require_own_tenant(&caller, &tenant_id)?;
    let config = deps.config.current().await?;
    let tenant = tenant(&deps, &tenant_id).await?;
    let mut recipient = own_recipient(&deps, &tenant_id, &recipient_id).await?;

    let mut changes: Vec<String> = Vec::new();
    if let Some(display_name) = request.display_name {
        recipient.display_name = normalize_display_name(&display_name)?;
        changes.push(format!("display name '{}'", recipient.display_name));
    }
    if let Some(locale) = request.locale {
        recipient.locale = check_locale(&config, &locale)?;
        changes.push(format!("locale '{}'", recipient.locale));
    }
    if let Some(choices) = request.choices {
        recipient.choices = check_choices(&config, &subjects_of(&deps, &tenant), &choices)?;
        changes.push(format!("choices: {}", describe_choices(&recipient.choices)));
    }
    if changes.is_empty() {
        return Ok(RecipientView::from(&recipient));
    }
    recipient.last_updated = Utc::now();
    deps.recipients.put_recipient(recipient.clone()).await?;

    audit_recipient(
        &audit,
        AuditSeverity::Neutral,
        &tenant_id,
        Some(caller.user_id()?),
        format!(
            "External recipient {recipient_id} ({}) changed — {}",
            recipient.address,
            changes.join("; ")
        ),
    )
    .await;

    Ok(RecipientView::from(&recipient))
}

async fn delete_recipient(
    tenant_id: String,
    recipient_id: String,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    require_own_tenant(&caller, &tenant_id)?;
    let recipient = own_recipient(&deps, &tenant_id, &recipient_id).await?;
    deps.recipients.delete_recipient(&recipient_id).await?;

    audit_recipient(
        &audit,
        AuditSeverity::Neutral,
        &tenant_id,
        Some(caller.user_id()?),
        format!(
            "External recipient {recipient_id} removed ({})",
            recipient.address
        ),
    )
    .await;

    Ok(json!({ "status": "removed" }))
}

/// What sending a confirmation did.
enum SendOutcome {
    /// A challenge was mailed.
    Sent,
    /// The recipient is already confirmed; nothing was spent.
    AlreadyConfirmed,
    /// The admin's send budget is exhausted; `retry_after` is the advertised delay in seconds.
    RateLimited {
        /// Seconds until the block lifts.
        retry_after: i64,
    },
}

async fn resend_confirmation(
    tenant_id: String,
    recipient_id: String,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<SendOutcome> {
    require_own_tenant(&caller, &tenant_id)?;
    let config = deps.config.current().await?;
    let tenant = tenant(&deps, &tenant_id).await?;
    let recipient = own_recipient(&deps, &tenant_id, &recipient_id).await?;
    send_confirmation(
        &deps,
        &audit,
        &config,
        &tenant,
        &recipient,
        caller.user_id()?,
    )
    .await
}

/// Mails the confirmation challenge to a recipient, on an admin's behalf.
///
/// Refuses up front when the deployment cannot mail, and counts against the **admin's** send
/// budget: the address being mailed is one they typed in, so they are the party to hold
/// accountable for how often a stranger hears from us.
async fn send_confirmation(
    deps: &RecipientDeps,
    audit: &Arc<dyn AuditRepository>,
    config: &Config,
    tenant: &Tenant,
    recipient: &ExternalRecipient,
    admin_id: &str,
) -> anyhow::Result<SendOutcome> {
    if recipient.confirmed {
        return Ok(SendOutcome::AlreadyConfirmed);
    }
    let address = &recipient.address;
    let tenant_id = &tenant.tenant_id;

    if !deps.notifier.is_configured() {
        audit_recipient(
            audit,
            AuditSeverity::Bad,
            tenant_id,
            Some(admin_id),
            format!(
                "Confirmation mail for recipient {} ({address}) not sent — this deployment cannot \
                 send mail",
                recipient.recipient_id
            ),
        )
        .await;
        status_bail!(
            StatusCode::SERVICE_UNAVAILABLE,
            "This deployment cannot send mail, so a recipient cannot be confirmed"
        );
    }

    let policy = Policy::new(
        config.security.rate_limits.mail_send.max_per_window,
        config.security.rate_limits.mail_send.window_secs,
        config.security.rate_limits.mail_send.block_secs,
    );
    if let Decision::Block { retry_after } = deps
        .rate_limiter
        .check(POLICY_MAIL_SEND, &policy, admin_id, Utc::now())
        .await
    {
        audit_recipient(
            audit,
            AuditSeverity::Bad,
            tenant_id,
            Some(admin_id),
            format!(
                "Confirmation mail for recipient {} ({address}) not sent — rate limit reached",
                recipient.recipient_id
            ),
        )
        .await;
        return Ok(SendOutcome::RateLimited { retry_after });
    }

    let secret = deps
        .challenges
        .issue(
            Purpose::ConfirmRecipient,
            &recipient.recipient_id,
            tenant_id,
            address,
            config.security.contact_challenge_ttl_secs as i64,
        )
        .await?;

    // What the mailbox is agreeing to, in its own language: the types it was signed up for.
    let subjects = subjects_of(deps, tenant);
    let types = recipient_types(config, &subjects, &recipient.locale)
        .into_iter()
        .filter(|view| {
            recipient
                .choices
                .get(&view.code)
                .is_some_and(|value| value != CHOICE_OFF)
        })
        .map(|view| view.name)
        .collect::<Vec<_>>()
        .join(", ");
    let link_context = json!({
        "link": confirm_url(&deps.public_base_url, &secret),
        "tenantName": tenant.name,
        "types": types,
    });
    let parts = MailRecipient::named(&recipient.display_name);
    let vars = render::MailContext {
        recipient: Some(&parts),
        context: Some(&link_context),
        global_context: &config.mail.global_context,
        notification: None,
    };
    let mail = OutboundMail::for_recipient(
        address.clone(),
        render::message(&recipient.locale, "recipient.confirm.subject", &vars)?,
        render::message(&recipient.locale, "recipient.confirm.body", &vars)?,
        recipient.locale.clone(),
        recipient.recipient_id.clone(),
        tenant_id.clone(),
    )
    .with_template(Some(TEMPLATE_RECIPIENT_CONFIRMATION.to_owned()))
    .with_recipient(parts)
    .with_context(Some(link_context))
    .with_deployment(&config.mail, &deps.public_base_url)?;
    let message_id = mail.message_id.clone();
    deps.notifier.send(mail).await?;

    audit_recipient(
        audit,
        AuditSeverity::Neutral,
        tenant_id,
        Some(admin_id),
        format!(
            "Confirmation mail queued for recipient {} ({address}) (message {message_id})",
            recipient.recipient_id
        ),
    )
    .await;

    Ok(SendOutcome::Sent)
}

// ── Business logic: the recipient's side ─────────────────────────────────────

/// Consumes a confirmation secret and marks the recipient it proves confirmed.
async fn confirm_recipient(
    request: TokenRequest,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
) -> anyhow::Result<Value> {
    let proven = match deps
        .challenges
        .consume(Purpose::ConfirmRecipient, request.token.trim())
        .await?
    {
        Some(proven) => proven,
        // One message for unknown, used and expired alike, as for a contact.
        None => status_bail!(
            StatusCode::NOT_FOUND,
            "This confirmation link is invalid or has expired"
        ),
    };

    // The recipient may have been removed between the mail going out and the click. Not an
    // error, just nothing left to confirm — and the address has to still be the one mailed.
    let recipient = deps
        .recipients
        .get_recipient(&proven.subject_id)
        .await?
        .filter(|recipient| recipient.address == proven.address);
    let Some(recipient) = recipient else {
        status_bail!(
            StatusCode::NOT_FOUND,
            "This recipient is no longer registered"
        );
    };
    deps.recipients
        .mark_confirmed(&recipient.recipient_id)
        .await?;

    audit_recipient(
        &audit,
        AuditSeverity::Good,
        &recipient.tenant_id,
        None,
        format!(
            "External recipient {} confirmed ({})",
            recipient.recipient_id, recipient.address
        ),
    )
    .await;

    let tenant_name = deps
        .tenants
        .get_tenant(&recipient.tenant_id)
        .await?
        .map(|tenant| tenant.name)
        .unwrap_or_default();
    Ok(json!({ "status": "confirmed", "tenantName": tenant_name }))
}

/// Resolves a management token to the recipient it belongs to, or a `404`.
///
/// The id half is a keyed read; the secret half is compared in constant time against the stored
/// one. One answer for a malformed token, an unknown id and a wrong secret alike — none of the
/// three helps a legitimate holder.
async fn recipient_for_token(
    deps: &RecipientDeps,
    token: &str,
) -> anyhow::Result<ExternalRecipient> {
    let (recipient_id, presented) = match split_token(token) {
        Ok(halves) => halves,
        Err(_) => status_bail!(StatusCode::NOT_FOUND, "This link is invalid"),
    };
    let Some(recipient) = deps.recipients.get_recipient(recipient_id).await? else {
        status_bail!(StatusCode::NOT_FOUND, "This link is invalid");
    };
    let stored = deps
        .secrets
        .decrypt(&recipient.manage_secret)
        .context("Failed to decrypt a recipient's management secret")?;
    if !bool::from(stored.as_slice().ct_eq(presented.as_bytes())) {
        status_bail!(StatusCode::NOT_FOUND, "This link is invalid");
    }
    Ok(recipient)
}

/// What a recipient sees behind its link, in its own language.
async fn view_for(
    deps: &RecipientDeps,
    recipient: &ExternalRecipient,
) -> anyhow::Result<ManageView> {
    let config = deps.config.current().await?;
    let tenant = tenant(deps, &recipient.tenant_id).await?;
    let subjects = subjects_of(deps, &tenant);
    Ok(ManageView {
        tenant_name: tenant.name,
        display_name: recipient.display_name.clone(),
        locale: recipient.locale.clone(),
        confirmed: recipient.confirmed,
        choices: recipient.choices.clone(),
        types: recipient_types(&config, &subjects, &recipient.locale),
    })
}

async fn manage_view(request: TokenRequest, deps: RecipientDeps) -> anyhow::Result<ManageView> {
    let recipient = recipient_for_token(&deps, &request.token).await?;
    view_for(&deps, &recipient).await
}

/// The recipient changes its own choices. The same validation as the admin's; the only thing a
/// recipient cannot do that an admin can is subscribe an address that has not confirmed, and
/// that is not a choice but a state.
async fn manage_choices(
    request: ManageRequest,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
) -> anyhow::Result<ManageView> {
    let mut recipient = recipient_for_token(&deps, &request.token).await?;
    let config = deps.config.current().await?;
    let tenant = tenant(&deps, &recipient.tenant_id).await?;
    recipient.choices = check_choices(&config, &subjects_of(&deps, &tenant), &request.choices)?;
    recipient.last_updated = Utc::now();
    deps.recipients.put_recipient(recipient.clone()).await?;

    audit_recipient(
        &audit,
        AuditSeverity::Neutral,
        &recipient.tenant_id,
        None,
        format!(
            "External recipient {} ({}) changed its own choices: {}",
            recipient.recipient_id,
            recipient.address,
            describe_choices(&recipient.choices)
        ),
    )
    .await;

    view_for(&deps, &recipient).await
}

/// The recipient removes itself. Deleting rather than switching everything off: a row that
/// receives nothing is a row somebody will re-enable, and the mailbox asked to be left alone.
async fn unsubscribe(
    request: TokenRequest,
    deps: RecipientDeps,
    audit: Arc<dyn AuditRepository>,
) -> anyhow::Result<Value> {
    let recipient = recipient_for_token(&deps, &request.token).await?;
    deps.recipients
        .delete_recipient(&recipient.recipient_id)
        .await?;

    audit_recipient(
        &audit,
        AuditSeverity::Neutral,
        &recipient.tenant_id,
        None,
        format!(
            "External recipient {} ({}) unsubscribed and removed itself",
            recipient.recipient_id, recipient.address
        ),
    )
    .await;

    Ok(json!({ "status": "removed" }))
}

/// The choices as one audit-friendly line: `form-submission=on, new-content=weekly`.
fn describe_choices(choices: &BTreeMap<String, String>) -> String {
    if choices.is_empty() {
        return "none".to_owned();
    }
    choices
        .iter()
        .map(|(code, value)| format!("{code}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Records a recipient change in the tenant's log. Best-effort: a failed audit write must not
/// fail the change, but every change does get an entry.
async fn audit_recipient(
    audit: &Arc<dyn AuditRepository>,
    severity: AuditSeverity,
    tenant_id: &str,
    user_id: Option<&str>,
    message: String,
) {
    record_best_effort(
        audit,
        NewAuditEntry::new(
            severity,
            Some(tenant_id.to_owned()),
            user_id.map(str::to_owned),
            message,
        ),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::repository::MockAuditRepository;
    use crate::auth::challenge::{MockChallengeRepository, Proven};
    use crate::auth::ratelimit::repository::MockRateLimitRepository;
    use crate::config::repository::memory::StaticConfigRepository;
    use crate::notify::types::{CadenceDef, NotificationTypeDef};
    use crate::recipients::repository::MockRecipientRepository;
    use crate::tenants::repository::MockTenantRepository;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use wasabi::web::auth::user::User as WasabiUser;
    use wasabi::web::auth::{CLAIM_LOCALE, CLAIM_SUB, CLAIM_TENANT};

    /// A notifier that keeps what it was handed.
    struct RecordingNotifier {
        configured: bool,
        sent: Mutex<Vec<OutboundMail>>,
    }

    #[async_trait]
    impl Notifier for RecordingNotifier {
        async fn send(&self, mail: OutboundMail) -> anyhow::Result<()> {
            if let Ok(mut sent) = self.sent.lock() {
                sent.push(mail);
            }
            Ok(())
        }
        fn is_configured(&self) -> bool {
            self.configured
        }
    }

    fn permissive_limiter() -> Arc<RateLimiter> {
        let mut repo = MockRateLimitRepository::new();
        let _ = repo
            .expect_increment()
            .returning(|_, _| Box::pin(async { Ok(1) }));
        let _ = repo
            .expect_get_block()
            .returning(|_| Box::pin(async { Ok(None) }));
        Arc::new(RateLimiter::new(Arc::new(repo), 16))
    }

    /// A catalogue with one type open to recipients (gated on a feature), one with a rhythm that
    /// is open, and one closed to them.
    fn config() -> Config {
        let mut config = Config::default();
        config.notification_types = vec![
            NotificationTypeDef {
                code: "form-submission".to_owned(),
                name: crate::config::text::LocalizedText::from("Form submissions"),
                description: None,
                cadences: Vec::new(),
                default: Some("on".to_owned()),
                eligible_if: Some("feature:forms".to_owned()),
                recipients: true,
            },
            NotificationTypeDef {
                code: "new-content".to_owned(),
                name: "New content".into(),
                description: None,
                cadences: vec![CadenceDef {
                    code: "weekly".to_owned(),
                    name: "Weekly".into(),
                }],
                default: None,
                eligible_if: None,
                recipients: true,
            },
            NotificationTypeDef {
                code: "build-failed".to_owned(),
                name: "Build failed".into(),
                description: None,
                cadences: Vec::new(),
                default: Some("on".to_owned()),
                eligible_if: None,
                recipients: false,
            },
        ];
        config
    }

    fn a_tenant(features: &[&str]) -> Tenant {
        let now = Utc::now();
        Tenant {
            tenant_id: "tenant-1".to_owned(),
            version: 1,
            features: features.iter().map(|f| (*f).to_owned()).collect(),
            custom_fields: Default::default(),
            limits: Default::default(),
            name: "Example Ltd".to_owned(),
            slug: "example-ltd".to_owned(),
            created: now,
            last_updated: now,
            last_active: None,
            last_active_or_created: now,
            created_by: None,
            last_changed_by: None,
        }
    }

    fn an_admin() -> AuthUser {
        WasabiUser::builder()
            .with_string(CLAIM_SUB, "admin-1")
            .with_string(CLAIM_TENANT, "tenant-1")
            .with_string(CLAIM_LOCALE, "en")
            .build()
    }

    fn a_recipient(secrets: &SecretBox, secret: &str, confirmed: bool) -> ExternalRecipient {
        let now = Utc::now();
        ExternalRecipient {
            recipient_id: "recipient-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            address: "info@example.com".to_owned(),
            display_name: "Front desk".to_owned(),
            locale: "de".to_owned(),
            choices: BTreeMap::from([("form-submission".to_owned(), "on".to_owned())]),
            confirmed,
            confirmed_at: None,
            manage_secret: secrets.encrypt(secret.as_bytes()).unwrap(),
            created: now,
            last_updated: now,
        }
    }

    type Harness = (
        RecipientDeps,
        Arc<RecordingNotifier>,
        Arc<dyn AuditRepository>,
        Arc<Mutex<Vec<String>>>,
    );

    fn build_deps(
        recipients: MockRecipientRepository,
        challenges: MockChallengeRepository,
        features: &[&str],
        configured: bool,
    ) -> Harness {
        let notifier = Arc::new(RecordingNotifier {
            configured,
            sent: Mutex::new(Vec::new()),
        });
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = log.clone();
        let mut audit = MockAuditRepository::new();
        let _ = audit.expect_record().returning(move |entry| {
            let sink = sink.clone();
            Box::pin(async move {
                if let Ok(mut lines) = sink.lock() {
                    lines.push(entry.message);
                }
                Ok(())
            })
        });
        let tenant = a_tenant(features);
        let mut tenants = MockTenantRepository::new();
        let _ = tenants.expect_get_tenant().returning(move |id| {
            let tenant = (id == "tenant-1").then(|| tenant.clone());
            Box::pin(async move { Ok(tenant) })
        });
        let deps = RecipientDeps {
            recipients: Arc::new(recipients),
            tenants: Arc::new(tenants),
            challenges: Arc::new(challenges),
            config: Arc::new(StaticConfigRepository::with_config(config())),
            notifier: notifier.clone(),
            rate_limiter: permissive_limiter(),
            secrets: Arc::new(SecretBox::with_test_key()),
            public_base_url: "https://umami.example.com/".to_owned(),
            system_tenant_id: None,
        };
        (deps, notifier, Arc::new(audit), log)
    }

    fn issuing_challenges() -> MockChallengeRepository {
        let mut challenges = MockChallengeRepository::new();
        let _ = challenges
            .expect_issue()
            .returning(|_, _, _, _, _| Box::pin(async { Ok("challenge-secret".to_owned()) }));
        challenges
    }

    fn create(choices: &[(&str, &str)]) -> CreateRequest {
        CreateRequest {
            address: " Info@Example.com ".to_owned(),
            display_name: " Front desk ".to_owned(),
            locale: "DE".to_owned(),
            choices: choices
                .iter()
                .map(|(code, value)| ((*code).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    /// The whole creation path: normalized, stored unconfirmed with an encrypted secret, and the
    /// confirmation mail names the tenant, the chosen type and the link.
    #[tokio::test]
    async fn creating_a_recipient_stores_it_and_mails_the_confirmation() {
        let stored = Arc::new(Mutex::new(None));
        let mut recipients = MockRecipientRepository::new();
        let sink = stored.clone();
        let _ = recipients
            .expect_add_recipient()
            .returning(move |recipient| {
                *sink.lock().unwrap() = Some(recipient);
                Box::pin(async { Ok(()) })
            });
        let (deps, notifier, audit, log) =
            build_deps(recipients, issuing_challenges(), &["feature:forms"], true);

        let (status, created) = create_recipient(
            "tenant-1".to_owned(),
            create(&[("form-submission", "ON")]),
            deps.clone(),
            audit,
            an_admin(),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert!(created.verification_sent);
        assert_eq!(created.recipient.address, "info@example.com");
        assert_eq!(created.recipient.display_name, "Front desk");
        assert_eq!(created.recipient.locale, "de");
        assert_eq!(
            created.recipient.choices.get("form-submission").unwrap(),
            "on"
        );
        assert!(!created.recipient.confirmed);

        let row = stored.lock().unwrap().clone().unwrap();
        assert_ne!(row.manage_secret, "", "the secret is stored");
        assert!(
            deps.secrets.decrypt(&row.manage_secret).is_ok(),
            "…encrypted with the deployment's box"
        );

        let sent = notifier.sent.lock().unwrap();
        let mail = sent.first().unwrap();
        assert_eq!(mail.to, "info@example.com");
        assert_eq!(
            mail.recipient_id.as_deref(),
            Some(row.recipient_id.as_str())
        );
        assert!(mail.user_id.is_none());
        assert!(mail.body.contains("Example Ltd"), "{}", mail.body);
        assert!(mail.body.contains("Form submissions"), "{}", mail.body);
        assert!(
            mail.body
                .contains("app/confirm-recipient?token=challenge-secret"),
            "{}",
            mail.body
        );
        assert_eq!(
            mail.template.as_deref(),
            Some(TEMPLATE_RECIPIENT_CONFIRMATION)
        );
        let lines = log.lock().unwrap().clone();
        assert!(lines.iter().any(|line| line.contains("added")), "{lines:?}");
        assert!(
            lines.iter().any(|line| line.contains("queued")),
            "{lines:?}"
        );
    }

    /// A choice has to be for a type the catalogue opened to recipients, that the tenant is
    /// eligible for, with a value the type accepts — and there has to be at least one.
    #[tokio::test]
    async fn choices_are_checked_against_the_catalogue() {
        type Case = (
            &'static [(&'static str, &'static str)],
            &'static [&'static str],
            &'static str,
        );
        let cases: [Case; 5] = [
            (
                &[("build-failed", "on")],
                &["feature:forms"],
                "closed to recipients",
            ),
            (
                &[("form-submission", "on")],
                &[],
                "tenant lacks the feature",
            ),
            (
                &[("new-content", "daily")],
                &[],
                "cadence the type never fires at",
            ),
            (&[("unknown", "on")], &[], "unknown type"),
            (&[("new-content", "off")], &[], "nothing chosen"),
        ];
        for (choices, features, why) in cases {
            let (deps, notifier, audit, _) = build_deps(
                MockRecipientRepository::new(),
                MockChallengeRepository::new(),
                features,
                true,
            );
            let result = create_recipient(
                "tenant-1".to_owned(),
                create(choices),
                deps,
                audit,
                an_admin(),
            )
            .await;
            assert!(result.is_err(), "{why}");
            assert!(notifier.sent.lock().unwrap().is_empty(), "{why}");
        }
    }

    /// `403` for another tenant's path: the caller proved who they are and is simply not allowed.
    #[tokio::test]
    async fn another_tenants_recipients_are_forbidden() {
        let (deps, _, _, _) = build_deps(
            MockRecipientRepository::new(),
            MockChallengeRepository::new(),
            &[],
            true,
        );
        let err = list_recipients("tenant-2".to_owned(), deps, an_admin())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("own tenant"));
    }

    /// Confirming consumes the challenge and marks the row; the address has to still match.
    #[tokio::test]
    async fn confirming_marks_the_recipient() {
        let secrets = SecretBox::with_test_key();
        let recipient = a_recipient(&secrets, "s", false);
        let mut recipients = MockRecipientRepository::new();
        let _ = recipients.expect_get_recipient().returning(move |_| {
            let recipient = recipient.clone();
            Box::pin(async move { Ok(Some(recipient)) })
        });
        let _ = recipients
            .expect_mark_confirmed()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));
        let mut challenges = MockChallengeRepository::new();
        let _ = challenges.expect_consume().returning(|purpose, token| {
            let proven =
                (purpose == Purpose::ConfirmRecipient && token == "good").then(|| Proven {
                    subject_id: "recipient-1".to_owned(),
                    tenant_id: "tenant-1".to_owned(),
                    address: "info@example.com".to_owned(),
                });
            Box::pin(async move { Ok(proven) })
        });
        let (deps, _, audit, log) = build_deps(recipients, challenges, &[], true);

        assert!(
            confirm_recipient(
                TokenRequest {
                    token: "stale".to_owned()
                },
                deps.clone(),
                audit.clone(),
            )
            .await
            .is_err()
        );
        let answer = confirm_recipient(
            TokenRequest {
                token: "good".to_owned(),
            },
            deps,
            audit,
        )
        .await
        .unwrap();
        assert_eq!(answer["status"], "confirmed");
        assert_eq!(answer["tenantName"], "Example Ltd");
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .any(|line| line.contains("confirmed"))
        );
    }

    /// The management token: right secret opens the view, wrong secret and malformed token are
    /// one and the same `404`.
    #[tokio::test]
    async fn the_management_token_is_checked_against_the_stored_secret() {
        let secrets = SecretBox::with_test_key();
        let recipient = a_recipient(&secrets, "right-secret", true);
        let mut recipients = MockRecipientRepository::new();
        let _ = recipients.expect_get_recipient().returning(move |id| {
            let recipient = (id == "recipient-1").then(|| recipient.clone());
            Box::pin(async move { Ok(recipient) })
        });
        let (deps, _, _, _) = build_deps(
            recipients,
            MockChallengeRepository::new(),
            &["feature:forms"],
            true,
        );

        let view = manage_view(
            TokenRequest {
                token: compose_token("recipient-1", "right-secret"),
            },
            deps.clone(),
        )
        .await
        .unwrap();
        assert_eq!(view.tenant_name, "Example Ltd");
        assert_eq!(view.choices.get("form-submission").unwrap(), "on");
        assert_eq!(
            view.types
                .iter()
                .map(|t| t.code.as_str())
                .collect::<Vec<_>>(),
            ["form-submission", "new-content"],
            "only the types open to recipients, in the catalogue's order"
        );

        for bad in [
            compose_token("recipient-1", "wrong-secret"),
            compose_token("recipient-9", "right-secret"),
            "garbage".to_owned(),
        ] {
            let err = manage_view(TokenRequest { token: bad.clone() }, deps.clone())
                .await
                .unwrap_err();
            assert!(format!("{err:#}").contains("invalid"), "{bad}");
        }
    }

    /// The recipient's own change is validated like the admin's and audited without a user.
    #[tokio::test]
    async fn a_recipient_changes_its_own_choices_and_can_leave() {
        let secrets = SecretBox::with_test_key();
        let recipient = a_recipient(&secrets, "s", true);
        let mut recipients = MockRecipientRepository::new();
        let _ = recipients.expect_get_recipient().returning(move |_| {
            let recipient = recipient.clone();
            Box::pin(async move { Ok(Some(recipient)) })
        });
        let written = Arc::new(Mutex::new(None));
        let sink = written.clone();
        let _ = recipients
            .expect_put_recipient()
            .returning(move |recipient| {
                *sink.lock().unwrap() = Some(recipient);
                Box::pin(async { Ok(()) })
            });
        let _ = recipients
            .expect_delete_recipient()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));
        let (deps, _, audit, log) = build_deps(
            recipients,
            MockChallengeRepository::new(),
            &["feature:forms"],
            true,
        );
        let token = compose_token("recipient-1", "s");

        let view = manage_choices(
            ManageRequest {
                token: token.clone(),
                choices: BTreeMap::from([
                    ("form-submission".to_owned(), "off".to_owned()),
                    ("new-content".to_owned(), "Weekly".to_owned()),
                ]),
            },
            deps.clone(),
            audit.clone(),
        )
        .await
        .unwrap();
        assert_eq!(view.choices.get("new-content").unwrap(), "weekly");
        assert_eq!(
            written
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .choices
                .get("form-submission")
                .unwrap(),
            "off"
        );

        assert!(
            manage_choices(
                ManageRequest {
                    token: token.clone(),
                    choices: BTreeMap::from([("build-failed".to_owned(), "on".to_owned())]),
                },
                deps.clone(),
                audit.clone(),
            )
            .await
            .is_err(),
            "a type closed to recipients stays closed, whoever asks"
        );

        let answer = unsubscribe(TokenRequest { token }, deps, audit)
            .await
            .unwrap();
        assert_eq!(answer["status"], "removed");
        let lines = log.lock().unwrap().clone();
        assert!(
            lines.iter().any(|line| line.contains("its own choices")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("unsubscribed")),
            "{lines:?}"
        );
    }

    /// Without a mail path the add still succeeds, says so, and the operator sees why.
    #[tokio::test]
    async fn without_a_mail_path_the_row_is_kept_and_the_mail_is_reported_unsent() {
        let mut recipients = MockRecipientRepository::new();
        let _ = recipients
            .expect_add_recipient()
            .returning(|_| Box::pin(async { Ok(()) }));
        let (deps, notifier, audit, log) = build_deps(
            recipients,
            MockChallengeRepository::new(),
            &["feature:forms"],
            false,
        );
        let (_, created) = create_recipient(
            "tenant-1".to_owned(),
            create(&[("form-submission", "on")]),
            deps,
            audit,
            an_admin(),
        )
        .await
        .unwrap();
        assert!(!created.verification_sent);
        assert!(notifier.sent.lock().unwrap().is_empty());
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .any(|line| line.contains("cannot send mail"))
        );
    }
}
