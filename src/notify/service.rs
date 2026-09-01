//! Notification routes: what a user subscribes to, who a firing reaches, and handing the finished
//! messages over.
//!
//! ## The division of labour
//!
//! The app owns **when** and **what**; umami owns **who** and **where**.
//!
//! - `GET /notifications/audience` answers who hears about one firing — the type's eligibility, each
//!   user's own choice, and whether they are reachable at all. It returns **no addresses**: a
//!   recipient is a `userId`, a name to address them by and their language, which is everything
//!   needed to *write* a message and nothing needed to *harvest* a mailing list.
//! - `POST /notifications/send` takes those `userId`s back with finished text. umami resolves the
//!   address itself, so no address ever leaves the service. The app gets to reach people without
//!   getting to know them.
//!
//! That second endpoint exists as a convenience rather than a necessity: without it every app would
//! carry its own queue credentials and its own retry story for something umami already does once.
//!
//! ## What is not here
//!
//! No accumulation, no digesting, no scheduling. A firing carries the cadences it represents and
//! umami intersects — see [`super::types`] for why that is the whole model.

use crate::audit::repository::{AuditRepository, record_best_effort};
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::config::Config;
use crate::config::repository::ConfigRepository;
use crate::constants::{
    MANAGE_CONTACTS_PERMISSION, MAX_TEXT_BODY_SIZE, NOTIFICATIONS_AUDIENCE_PERMISSION,
    NOTIFICATIONS_REPORT_PERMISSION, NOTIFICATIONS_SEND_PERMISSION,
};
use crate::contacts::normalize_email;
use crate::contacts::preference::preference_for;
use crate::contacts::repository::ContactRepository;
use crate::notify::types::{
    CHOICE_OFF, CadenceDef, Delivery, NotificationTypeDef, normalize_cadence, resolve_delivery,
};
use crate::notify::{Notifier, OutboundMail};
use crate::tenants::repository::TenantRepository;
use crate::users::User;
use crate::users::repository::UserRepository;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::status_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};

/// Cap on one send batch. High enough for a tenant-wide firing, low enough that one request cannot
/// turn into unbounded work — the app already holds the audience, so it can page.
const MAX_BATCH: usize = 500;

const REQUIRE_SELF: &[&str] = &[MANAGE_CONTACTS_PERMISSION];
const REQUIRE_AUDIENCE: &[&str] = &[NOTIFICATIONS_AUDIENCE_PERMISSION];
const REQUIRE_SEND: &[&str] = &[NOTIFICATIONS_SEND_PERMISSION];
const REQUIRE_REPORT: &[&str] = &[NOTIFICATIONS_REPORT_PERMISSION];

/// Dependencies shared by the two machine endpoints.
#[derive(Clone)]
pub struct NotifyDeps {
    /// User store (roles, names, language, preferences).
    pub users: Arc<dyn UserRepository>,
    /// Tenant store (the tenant's features, for eligibility).
    pub tenants: Arc<dyn TenantRepository>,
    /// Contact store (resolving a recipient to a confirmed address).
    pub contacts: Arc<dyn ContactRepository>,
    /// Config (the type catalogue).
    pub config: Arc<dyn ConfigRepository>,
    /// The outbound seam.
    pub notifier: Arc<dyn Notifier>,
    /// System tenant id, for the `is:system-tenant*` markers.
    pub system_tenant_id: Option<String>,
}

/// One notification type as the profile screen sees it.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TypeView {
    code: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// The cadences this type is actually fired at — code plus label, the only choices worth
    /// offering. The label travels with the code because the vocabulary is the deployment's, so
    /// nothing in a client's message catalogue could know what to call it.
    cadences: Vec<CadenceDef>,
    /// What applies when the user has never chosen: `"on"`, a cadence code, or `null` for off.
    default: Option<String>,
    /// Every value this type accepts, always including `"off"` — what a picker should offer.
    allowed: Vec<String>,
    /// The user's own choice, absent when they never touched it (the default then applies).
    #[serde(skip_serializing_if = "Option::is_none")]
    choice: Option<String>,
    /// What currently applies, choice and default folded together. `"off"` = nothing arrives.
    effective: String,
}

/// The caller's subscribable types.
#[derive(Serialize, Debug)]
struct MyTypesResponse {
    types: Vec<TypeView>,
}

/// Request setting the caller's choice for one type: `"off"`, `"on"`, or a cadence code.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ChoiceRequest {
    choice: String,
}

/// Query resolving an audience.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AudienceRequest {
    tenant_id: String,
    #[serde(rename = "type")]
    type_code: String,
    /// The cadences **this firing** represents. A Friday run is typically `["daily","weekly"]`.
    cadences: Vec<String>,
}

/// One resolved recipient. Deliberately carries no address.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Recipient {
    user_id: String,
    /// How to address them, composed for their own language.
    addressable_name: String,
    /// Their resolved language (BCP-47), so the app can render in it.
    locale: String,
    /// Which of the firing's cadences matched, or `null` for a type with no rhythm. Ignorable when
    /// the wording does not differ.
    #[serde(skip_serializing_if = "Option::is_none")]
    cadence: Option<String>,
}

/// Request handing finished messages over for delivery.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SendRequest {
    #[serde(rename = "type")]
    type_code: String,
    messages: Vec<SendMessage>,
}

/// One finished message for one recipient.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SendMessage {
    user_id: String,
    subject: String,
    body: String,
}

/// What the mail worker reports back about a message it could not deliver.
///
/// **Hard failures only.** A full mailbox or a greylisting is the worker's problem to retry; only a
/// permanent failure — the address does not exist — or a complaint says anything about whether the
/// address is still the user's.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct DeliveryReport {
    /// The user the message was for, as umami handed it over.
    user_id: String,
    /// The address it went to.
    address: String,
    /// `bounced` or `complained`.
    event: String,
    /// The `messageId` from the payload, for the audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
}

/// Per-recipient outcome. Partial success is the normal case, so the response says so per entry.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SendResult {
    user_id: String,
    /// `queued`, `no-address` (nobody confirmed one) or `failed`.
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `GET /auth/me/notifications` — the caller's subscribable types and choices.
pub fn my_notifications_route(
    deps: NotifyDeps,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "notifications")
        .and(warp::get())
        .and(with_cloneable(deps))
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
        .and_then(handle_my_notifications_route)
        .boxed()
}

/// `PUT /auth/me/notifications/{code}` — set the caller's choice (`null` = never).
pub fn set_choice_route(
    deps: NotifyDeps,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "notifications" / String)
        .and(warp::put())
        .and(with_body_as_json::<ChoiceRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
        .and_then(handle_set_choice_route)
        .boxed()
}

/// `DELETE /auth/me/notifications/{code}` — clear the choice back to *unset*.
///
/// A separate verb because unset and never are different states: clearing means "follow whatever the
/// deployment decides", which is not the same as "never".
pub fn clear_choice_route(
    deps: NotifyDeps,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "notifications" / String)
        .and(warp::delete())
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_SELF))
        .and_then(handle_clear_choice_route)
        .boxed()
}

/// `POST /notifications/audience` — who hears about one firing (`notifications:audience`).
pub fn audience_route(
    deps: NotifyDeps,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("notifications" / "audience")
        .and(warp::post())
        .and(with_body_as_json::<AudienceRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_AUDIENCE,
        ))
        .and_then(handle_audience_route)
        .boxed()
}

/// `POST /notifications/undeliverable` — the mail worker reports a hard failure
/// (`notifications:report`).
pub fn report_undeliverable_route(
    contacts: Arc<dyn ContactRepository>,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("notifications" / "undeliverable")
        .and(warp::post())
        .and(with_body_as_json::<DeliveryReport>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(contacts))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_REPORT))
        .and_then(handle_report_undeliverable_route)
        .boxed()
}

/// `POST /notifications/send` — hand finished messages over (`notifications:send`).
pub fn send_route(
    deps: NotifyDeps,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("notifications" / "send")
        .and(warp::post())
        .and(with_body_as_json::<SendRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(authenticator, REQUIRE_SEND))
        .and_then(handle_send_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "GET /auth/me/notifications", skip_all)]
async fn handle_my_notifications_route(
    deps: NotifyDeps,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(my_notifications(deps, caller).await)
}

#[tracing::instrument(level = "debug", name = "PUT /auth/me/notifications/{code}", skip_all)]
async fn handle_set_choice_route(
    code: String,
    request: ChoiceRequest,
    deps: NotifyDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(set_choice(code, Some(request), deps, audit, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "DELETE /auth/me/notifications/{code}",
    skip_all
)]
async fn handle_clear_choice_route(
    code: String,
    deps: NotifyDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(set_choice(code, None, deps, audit, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /notifications/audience", skip_all)]
async fn handle_audience_route(
    request: AudienceRequest,
    deps: NotifyDeps,
    audit: Arc<dyn AuditRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(audience(request, deps, audit).await)
}

#[tracing::instrument(level = "debug", name = "POST /notifications/undeliverable", skip_all)]
async fn handle_report_undeliverable_route(
    report: DeliveryReport,
    contacts: Arc<dyn ContactRepository>,
    audit: Arc<dyn AuditRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(report_undeliverable(report, contacts, audit).await)
}

#[tracing::instrument(level = "debug", name = "POST /notifications/send", skip_all)]
async fn handle_send_route(
    request: SendRequest,
    deps: NotifyDeps,
    audit: Arc<dyn AuditRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(send(request, deps, audit).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

/// The **offline** subject set for a user: what an eligibility expression may gate on when there is
/// no session. Session markers (`is:2fa`, `is:passkey`, `is:totp`) are absent by construction — see
/// [`NotificationTypeDef::eligible_if`].
fn offline_subjects(
    user: &User,
    tenant_features: &[String],
    system_tenant_id: Option<&str>,
) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = user.roles.iter().cloned().collect();
    set.extend(tenant_features.iter().cloned());
    if system_tenant_id.is_some_and(|id| id == user.tenant_id) {
        let _ = set.insert(crate::constants::SYSTEM_TENANT_MARKER.to_owned());
        let _ = set.insert(crate::constants::SYSTEM_TENANT_MEMBER_MARKER.to_owned());
    }
    set
}

/// Whether `user` is eligible for `type_def` at all, before their own choice is considered.
fn eligible(
    type_def: &NotificationTypeDef,
    user: &User,
    tenant_features: &[String],
    system_tenant_id: Option<&str>,
) -> bool {
    match type_def.eligible_if.as_deref() {
        None => true,
        Some(expression) => {
            let subjects = offline_subjects(user, tenant_features, system_tenant_id);
            let view: BTreeSet<&str> = subjects.iter().map(String::as_str).collect();
            crate::config::eval_expression(expression, &view)
        }
    }
}

/// The user's stored choice for a type, in the three-state form
/// [`resolve_delivery`](crate::notify::types::resolve_delivery) expects.
fn stored_choice<'a>(user: &'a User, code: &str) -> Option<&'a str> {
    user.notification_choices.get(code).map(String::as_str)
}

async fn my_notifications(deps: NotifyDeps, caller: AuthUser) -> anyhow::Result<MyTypesResponse> {
    let user_id = caller.user_id()?;
    let config = deps.config.current().await?;
    let user = match deps.users.get_user(user_id).await? {
        Some(user) => user,
        None => status_bail!(StatusCode::NOT_FOUND, "No such user"),
    };
    let features = tenant_features(&deps, &user.tenant_id).await?;

    let types = config
        .notification_types
        .iter()
        .filter(|type_def| eligible(type_def, &user, &features, deps.system_tenant_id.as_deref()))
        .map(|type_def| {
            let choice = stored_choice(&user, &type_def.code);
            // What actually applies right now, folded the same way a firing folds it. `Immediate` is
            // the stand-in rhythm for "would arrive at all" when the type has no others.
            let effective = choice.or(type_def.default.as_deref()).unwrap_or(CHOICE_OFF);
            TypeView {
                code: type_def.code.clone(),
                name: type_def.name.clone(),
                description: type_def.description.clone(),
                cadences: type_def.cadences.clone(),
                default: type_def.default.clone(),
                allowed: type_def
                    .allowed_choices()
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                choice: choice.map(str::to_owned),
                effective: effective.to_owned(),
            }
        })
        .collect();
    Ok(MyTypesResponse { types })
}

/// Sets (`Some`) or clears (`None`) the caller's choice for one type.
async fn set_choice(
    code: String,
    request: Option<ChoiceRequest>,
    deps: NotifyDeps,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    let user_id = caller.user_id()?;
    let config = deps.config.current().await?;
    let Some(type_def) = config.find_notification_type(&code) else {
        status_bail!(StatusCode::NOT_FOUND, "Unknown notification type '{code}'");
    };
    // A value the type does not accept would leave the user waiting forever, so it is refused rather
    // than stored. `off` is always among them: switching something off never depends on the type
    // having a rhythm.
    let chosen: Option<String> = match request {
        None => None,
        Some(ChoiceRequest { choice }) => {
            let value = normalize_cadence(&choice);
            if !type_def.accepts(&value) {
                status_bail!(
                    StatusCode::BAD_REQUEST,
                    "'{code}' does not accept '{value}' — pick one of: {}",
                    type_def.allowed_choices().join(", ")
                );
            }
            Some(value)
        }
    };

    let mut user = match deps.users.get_user(user_id).await? {
        Some(user) => user,
        None => status_bail!(StatusCode::NOT_FOUND, "No such user"),
    };
    match chosen {
        // Clearing *removes the key*: an absent entry means "follow the deployment", which is not
        // the same as storing today's default and freezing it.
        None => {
            let _ = user.notification_choices.remove(&code);
        }
        Some(ref value) => {
            let _ = user
                .notification_choices
                .insert(code.clone(), value.clone());
        }
    }
    let _ = deps.users.put_user(user).await?;

    // Consent is worth a trail: "I never asked for these" is a claim umami has to be able to answer,
    // and the answer is only as good as the record of who changed what when.
    record_best_effort(
        &audit,
        NewAuditEntry::new(
            AuditSeverity::Neutral,
            caller.tenant_id().ok().map(str::to_owned),
            Some(user_id.to_owned()),
            match chosen.as_deref() {
                Some(value) => format!("Notification '{code}' set to '{value}'"),
                None => format!("Notification '{code}' reset to the deployment default"),
            },
        ),
    )
    .await;

    Ok(json!({ "code": code, "choice": chosen }))
}

/// The tenant's granted features, or none when the tenant is gone.
async fn tenant_features(deps: &NotifyDeps, tenant_id: &str) -> anyhow::Result<Vec<String>> {
    Ok(deps
        .tenants
        .get_tenant(tenant_id)
        .await?
        .map(|tenant| tenant.features)
        .unwrap_or_default())
}

/// Resolves who hears about one firing.
async fn audience(
    request: AudienceRequest,
    deps: NotifyDeps,
    audit: Arc<dyn AuditRepository>,
) -> anyhow::Result<Value> {
    let config = deps.config.current().await?;
    let type_def = notification_type(&config, &request.type_code)?;

    let firing = parse_firing(&request.cadences, type_def)?;
    let features = tenant_features(&deps, &request.tenant_id).await?;
    // Every user of the tenant; the cap is the admin list cap, and the query is a firing rather
    // than a search, so there is nothing to narrow by.
    let (users, truncated) = deps
        .users
        .find_users(&request.tenant_id, "", crate::constants::MAX_LIST_RESULTS)
        .await?;

    let mut recipients: Vec<Recipient> = Vec::new();
    for user in users {
        if user.locked || !eligible(type_def, &user, &features, deps.system_tenant_id.as_deref()) {
            continue;
        }
        // Owned right away, so the borrow the resolver takes on `user` ends before the recipient
        // is built out of it.
        let cadence =
            match resolve_delivery(type_def, stored_choice(&user, &type_def.code), &firing) {
                Delivery::Deliver(cadence) => cadence.map(str::to_owned),
                Delivery::Skip => continue,
            };
        // Reachability is part of the answer: naming somebody the app cannot be told to message
        // would only produce a `no-address` on the way back.
        if !has_confirmed_address(&deps, &user.user_id).await? {
            continue;
        }
        let locale = crate::i18n::resolve(&config, user.locale.as_deref(), None);
        recipients.push(Recipient {
            addressable_name: user.display_names(&config.default_locale).addressable_name,
            user_id: user.user_id,
            locale,
            cadence,
        });
    }

    // Audited because the endpoint answers with personal data, and because a count of zero is the
    // only visible symptom of an app that forgot to name a cadence its own job fires at.
    record_best_effort(
        &audit,
        NewAuditEntry::new(
            AuditSeverity::Neutral,
            Some(request.tenant_id.clone()),
            None,
            format!(
                "Audience resolved for '{}' [{}]: {} recipient(s)",
                type_def.code,
                request.cadences.join(","),
                recipients.len()
            ),
        ),
    )
    .await;

    Ok(json!({ "recipients": recipients, "truncated": truncated }))
}

/// Whether the user has at least one confirmed address.
async fn has_confirmed_address(deps: &NotifyDeps, user_id: &str) -> anyhow::Result<bool> {
    Ok(deps
        .contacts
        .list_contacts(user_id)
        .await?
        .iter()
        .any(|contact| contact.verified))
}

/// The address a notification for `user` goes to.
///
/// The one rule, shared with the profile screen — see [`crate::contacts::preference`]. A sender and
/// the screen disagreeing about where mail goes is a bug nobody would see until a password reset
/// landed in the wrong mailbox, so neither gets its own copy of the answer.
async fn delivery_address(deps: &NotifyDeps, user: &User) -> anyhow::Result<Option<String>> {
    let held = deps.contacts.list_contacts(&user.user_id).await?;
    Ok(preference_for(user.preferred_contact.as_deref(), &held))
}

/// Queues one finished message per recipient.
async fn send(
    request: SendRequest,
    deps: NotifyDeps,
    audit: Arc<dyn AuditRepository>,
) -> anyhow::Result<Value> {
    let config = deps.config.current().await?;
    let type_def = notification_type(&config, &request.type_code)?;
    if request.messages.is_empty() {
        status_bail!(StatusCode::BAD_REQUEST, "'messages' must not be empty");
    }
    if request.messages.len() > MAX_BATCH {
        status_bail!(
            StatusCode::BAD_REQUEST,
            "At most {MAX_BATCH} messages per request — the caller already holds the audience, so \
             it can page"
        );
    }
    if !deps.notifier.is_configured() {
        status_bail!(
            StatusCode::SERVICE_UNAVAILABLE,
            "This deployment cannot send mail"
        );
    }

    let mut results: Vec<SendResult> = Vec::with_capacity(request.messages.len());
    for message in request.messages {
        let user = match deps.users.get_user(&message.user_id).await? {
            Some(user) if !user.locked => user,
            _ => {
                results.push(SendResult {
                    user_id: message.user_id,
                    status: "no-address",
                    message_id: None,
                });
                continue;
            }
        };
        let Some(address) = delivery_address(&deps, &user).await? else {
            results.push(SendResult {
                user_id: message.user_id,
                status: "no-address",
                message_id: None,
            });
            continue;
        };

        let locale = crate::i18n::resolve(&config, user.locale.as_deref(), None);
        let mail = OutboundMail::new(
            "notification",
            address,
            message.subject,
            message.body,
            locale,
            user.user_id.clone(),
            user.tenant_id.clone(),
        );
        let message_id = mail.message_id.clone();
        // One failure must not abandon the rest of the batch — partial success is the normal case,
        // and the caller is told per entry which is which.
        match deps.notifier.send(mail).await {
            Ok(()) => results.push(SendResult {
                user_id: user.user_id,
                status: "queued",
                message_id: Some(message_id),
            }),
            Err(err) => {
                tracing::warn!("failed to queue a notification: {err:#}");
                results.push(SendResult {
                    user_id: user.user_id,
                    status: "failed",
                    message_id: None,
                });
            }
        }
    }

    let queued = results
        .iter()
        .filter(|result| result.status == "queued")
        .count();
    record_best_effort(
        &audit,
        NewAuditEntry::new(
            AuditSeverity::Neutral,
            None,
            None,
            format!(
                "Notification '{}' queued for {queued} of {} recipient(s)",
                type_def.code,
                results.len()
            ),
        ),
    )
    .await;

    Ok(json!({ "results": results }))
}

/// Withdraws an address's confirmation after a hard delivery failure.
///
/// This is the one thing umami cannot learn on its own: it hands a message over and never sees what
/// happened to it. Without this endpoint a confirmed address that has since stopped existing stays
/// confirmed forever, and every later notification — including a password reset — goes on being sent
/// into nothing.
async fn report_undeliverable(
    report: DeliveryReport,
    contacts: Arc<dyn ContactRepository>,
    audit: Arc<dyn AuditRepository>,
) -> anyhow::Result<Value> {
    let event = report.event.trim().to_lowercase();
    let (severity, what) = match event.as_str() {
        "bounced" => (AuditSeverity::Bad, "bounced"),
        // A complaint is not a delivery failure but a stronger statement — the person said they do
        // not want mail here. Withdrawing the confirmation is the least umami can do about it.
        "complained" => (AuditSeverity::Bad, "was reported as spam"),
        other => status_bail!(
            StatusCode::BAD_REQUEST,
            "Unknown delivery event '{other}' (expected 'bounced' or 'complained')"
        ),
    };
    let address = normalize_email(&report.address)?;

    let tenant_id = contacts
        .get_contact(&report.user_id, &address)
        .await?
        .map(|contact| contact.tenant_id);
    contacts.mark_unverified(&report.user_id, &address).await?;

    record_best_effort(
        &audit,
        NewAuditEntry::new(
            severity,
            tenant_id,
            Some(report.user_id.clone()),
            match report.message_id.as_deref() {
                Some(id) => {
                    format!("Mail to {address} {what}; confirmation withdrawn (message {id})")
                }
                None => format!("Mail to {address} {what}; confirmation withdrawn"),
            },
        ),
    )
    .await;

    Ok(json!({ "status": "withdrawn" }))
}

/// Looks a type up, or fails with a client error naming it.
fn notification_type<'a>(
    config: &'a Config,
    code: &str,
) -> anyhow::Result<&'a NotificationTypeDef> {
    match config.find_notification_type(code) {
        Some(type_def) => Ok(type_def),
        None => status_bail!(
            StatusCode::BAD_REQUEST,
            "Unknown notification type '{code}'"
        ),
    }
}

/// Parses the cadences a firing claims to represent, refusing any the type is never fired at.
///
/// The refusal is the point: an app whose job schedule drifted from the config would otherwise
/// silently resolve an empty audience, and "nobody was subscribed" looks exactly like "it worked".
fn parse_firing(raw: &[String], type_def: &NotificationTypeDef) -> anyhow::Result<Vec<String>> {
    if raw.is_empty() {
        status_bail!(
            StatusCode::BAD_REQUEST,
            "'cadences' must name at least one cadence this firing represents"
        );
    }
    let mut firing = Vec::with_capacity(raw.len());
    for entry in raw {
        let cadence = normalize_cadence(entry);
        if !type_def.fires_at(&cadence) {
            status_bail!(
                StatusCode::BAD_REQUEST,
                "'{}' does not declare the cadence '{cadence}' — declared: {}",
                type_def.code,
                type_def
                    .cadences
                    .iter()
                    .map(|c| c.code.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        firing.push(cadence);
    }
    Ok(firing)
}
