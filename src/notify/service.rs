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
    CHOICE_OFF, Delivery, NotificationTypeDef, normalize_cadence, resolve_delivery,
};
// Aliased: `Recipient` in this module is the audience response's, which carries no name parts and
// deliberately no address.
use crate::notify::{
    NotificationMeta, Notifier, OutboundMail, Recipient as MailRecipient, TEMPLATE_NAMESPACE,
    TEMPLATE_UMAMI_PREFIX, template_namespace,
};
use crate::tenants::repository::TenantRepository;
use crate::users::User;
use crate::users::repository::UserRepository;
use anyhow::Context;
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
use wasabi::web::locale::accept_language as accept_language_filter;
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};

/// Cap on one send batch. High enough for a tenant-wide firing, low enough that one request cannot
/// turn into unbounded work — the app already holds the audience, so it can page.
const MAX_BATCH: usize = 500;

/// Cap on one message's `context`, serialized.
///
/// Generous for what the field is for — the handful of values a layout renders — and small enough
/// that a batch of 500 cannot be used to push a payload through umami into a queue. It is also a
/// reminder of what `context` is: data for a template, not a place to move an object.
const MAX_CONTEXT_BYTES: usize = 4096;

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
    /// umami's own public base URL — every mail carries it in `globalContext`.
    pub public_base_url: String,
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
    cadences: Vec<CadenceView>,
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

/// One cadence as the picker sees it: the code to send back, and the words to show.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CadenceView {
    code: String,
    name: String,
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
    /// The notification type this send follows. **Omitted** for a transactional message — one
    /// person, one reason, and the catalogue was never consulted (see [`crate::notify::types`]).
    ///
    /// Optional rather than required so that case has a way to say so. The cost is that a typo in
    /// the field name reads as "transactional" instead of failing; what stops that from turning
    /// into an empty mail is [`check_messages`], which every send passes either way.
    #[serde(default, rename = "type")]
    type_code: Option<String>,
    messages: Vec<SendMessage>,
}

/// One message for one recipient — finished text, something for the worker to render, or both.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SendMessage {
    user_id: String,
    /// Subject line. Goes together with `body`, and may be omitted only when `template` is given.
    #[serde(default)]
    subject: Option<String>,
    /// Plain-text body. Goes together with `subject`.
    #[serde(default)]
    body: Option<String>,
    /// The app's own name for a layout the worker should render instead.
    ///
    /// umami neither knows nor validates these names — it forwards them. Sending a template
    /// **and** finished text is the robust combination: a worker that does not know the name still
    /// has something to deliver.
    #[serde(default)]
    template: Option<String>,
    /// Opaque data for that layout, forwarded untouched.
    ///
    /// Keep personal data out of it beyond what the mail itself says. It travels into the queue and
    /// through the worker's logs — places with no retention policy and no erasure story, which is
    /// the same reason no address ever appears in a umami URL.
    #[serde(default)]
    context: Option<Value>,
    /// Which cadence this recipient matched, straight from the audience.
    ///
    /// The caller passes it back rather than umami re-deriving it: `send` deliberately never
    /// re-reads a preference. It is checked against the type all the same, because a cadence the
    /// type is never fired at means the caller and the catalogue disagree.
    #[serde(default)]
    cadence: Option<String>,
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
        .and(accept_language_filter())
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
    accept_language: Option<String>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(my_notifications(deps, accept_language, caller).await)
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

async fn my_notifications(
    deps: NotifyDeps,
    accept_language: Option<String>,
    caller: AuthUser,
) -> anyhow::Result<MyTypesResponse> {
    let user_id = caller.user_id()?;
    let config = deps.config.current().await?;
    let user = match deps.users.get_user(user_id).await? {
        Some(user) => user,
        None => status_bail!(StatusCode::NOT_FOUND, "No such user"),
    };
    let features = tenant_features(&deps, &user.tenant_id).await?;
    // Resolved here rather than shipped as maps — the client has no business re-deriving which
    // language this user reads in. Profile preference first, then the request's `Accept-Language`,
    // then the default: umami's own tokens carry no `locale` claim by default, so the header is the
    // fallback that actually lands right for a user who never set a profile language.
    let resolved =
        crate::i18n::resolve(&config, user.locale.as_deref(), accept_language.as_deref());
    let locale = resolved.as_str();

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
    let type_def = match request.type_code.as_deref() {
        Some(code) => Some(notification_type(&config, code)?),
        None => None,
    };
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
    check_messages(&request.messages, type_def)?;

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
        let recipient = MailRecipient::of(&user, &locale);
        let mut mail = OutboundMail::new(
            address,
            message.subject.unwrap_or_default(),
            message.body.unwrap_or_default(),
            locale,
            user.user_id.clone(),
            user.tenant_id.clone(),
        )
        .with_recipient(recipient)
        .with_template(message.template)
        .with_context(message.context);
        if let Some(type_def) = type_def {
            mail = mail.with_notification(notification_meta(type_def, message.cadence.as_deref()));
        }
        // Last, because it assembles the body out of everything above.
        let mail = mail.with_deployment(&config.mail, &deps.public_base_url)?;
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
            match type_def {
                Some(type_def) => format!(
                    "Notification '{}' queued for {queued} of {} recipient(s)",
                    type_def.code,
                    results.len()
                ),
                None => format!(
                    "Transactional message queued for {queued} of {} recipient(s)",
                    results.len()
                ),
            },
        ),
    )
    .await;

    Ok(json!({ "results": results }))
}

/// Refuses a batch that would put an unrenderable mail in front of somebody.
///
/// Up front, before the first message goes out, because the alternative is worse than a strict
/// check: a batch rejected halfway leaves the earlier half delivered and answers the caller with a
/// `400` that says nothing about which half that was.
///
/// The rule is that **something** has to be renderable — finished text, a template name, or both.
/// Allowing an empty message and trusting the worker to have a layout for it would move the failure
/// to the one place nobody is watching, which is the recipient's inbox.
fn check_messages(
    messages: &[SendMessage],
    type_def: Option<&NotificationTypeDef>,
) -> anyhow::Result<()> {
    for message in messages {
        let user = &message.user_id;
        let subject = message.subject.as_deref().unwrap_or_default().trim();
        let body = message.body.as_deref().unwrap_or_default().trim();
        let template = message.template.as_deref().unwrap_or_default().trim();

        match (subject.is_empty(), body.is_empty()) {
            (false, false) | (true, true) => {}
            // One without the other is a caller that meant to send text and lost half of it — never
            // a deliberate "let the worker do it", which omits both.
            _ => status_bail!(
                StatusCode::BAD_REQUEST,
                "Message for '{user}' has only one of 'subject' and 'body' — they go together"
            ),
        }
        if !template.is_empty() {
            match template_namespace(template) {
                Ok(namespace) if namespace == TEMPLATE_NAMESPACE => status_bail!(
                    StatusCode::BAD_REQUEST,
                    "Template '{template}' for '{user}' is in the '{TEMPLATE_UMAMI_PREFIX}' \
                     namespace, which is reserved for the mails umami sends itself — a worker \
                     keying off the name would render yours as one of those"
                ),
                Ok(_) => {}
                Err(reason) => status_bail!(StatusCode::BAD_REQUEST, "{reason} (for '{user}')"),
            }
        }
        if subject.is_empty() && template.is_empty() {
            status_bail!(
                StatusCode::BAD_REQUEST,
                "Message for '{user}' has neither 'subject'/'body' nor 'template' — there would be \
                 nothing to deliver"
            );
        }

        if let Some(context) = &message.context {
            let size = serde_json::to_vec(context)
                .context("Failed to measure a message's 'context'")?
                .len();
            if size > MAX_CONTEXT_BYTES {
                status_bail!(
                    StatusCode::BAD_REQUEST,
                    "The 'context' for '{user}' is {size} bytes, over the {MAX_CONTEXT_BYTES}-byte \
                     cap — it renders a template, it does not carry a payload"
                );
            }
        }

        if let Some(cadence) = &message.cadence {
            let cadence = normalize_cadence(cadence);
            match type_def {
                Some(type_def) if type_def.fires_at(&cadence) => {}
                Some(type_def) => status_bail!(
                    StatusCode::BAD_REQUEST,
                    "'{}' is never fired at cadence '{cadence}'",
                    type_def.code
                ),
                None => status_bail!(
                    StatusCode::BAD_REQUEST,
                    "Message for '{user}' names a cadence, but the send names no type — a \
                     transactional message has no rhythm"
                ),
            }
        }
    }
    Ok(())
}

/// What a worker is told about the notification a mail belongs to: the codes, normalized.
fn notification_meta(type_def: &NotificationTypeDef, cadence: Option<&str>) -> NotificationMeta {
    NotificationMeta {
        type_code: type_def.code.clone(),
        cadence: cadence.map(normalize_cadence),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::types::CadenceDef;

    /// A type with a rhythm, to check a send against.
    fn rhythmic() -> NotificationTypeDef {
        NotificationTypeDef {
            code: "wsc-new-content".to_owned(),
            name: "New content".into(),
            description: None,
            cadences: vec![
                CadenceDef {
                    code: "daily".to_owned(),
                    name: "Daily".into(),
                },
                CadenceDef {
                    code: "weekly".to_owned(),
                    name: "Weekly".into(),
                },
            ],
            default: None,
            eligible_if: None,
        }
    }

    /// A message with nothing filled in, for a test to fill in one field of.
    fn message() -> SendMessage {
        SendMessage {
            user_id: "user-1".to_owned(),
            subject: None,
            body: None,
            template: None,
            context: None,
            cadence: None,
        }
    }

    fn with_text(mut message: SendMessage) -> SendMessage {
        message.subject = Some("Subject".to_owned());
        message.body = Some("Body".to_owned());
        message
    }

    /// The three renderable shapes, and the two that would arrive empty.
    #[test]
    fn a_message_has_to_carry_something_to_deliver() {
        let type_def = rhythmic();

        assert!(check_messages(&[with_text(message())], Some(&type_def)).is_ok());

        let mut templated = message();
        templated.template = Some("wsc::new-content".to_owned());
        assert!(check_messages(&[templated], Some(&type_def)).is_ok());

        // Both is the robust combination: a worker that does not know the layout still has text.
        let mut both = with_text(message());
        both.template = Some("wsc::new-content".to_owned());
        assert!(check_messages(&[both], Some(&type_def)).is_ok());

        // Every name is namespaced, and the rule is enforced — otherwise a worker keying off this
        // one field would confuse two senders' layouts of the same name.
        let mut unnamespaced = with_text(message());
        unnamespaced.template = Some("new-content".to_owned());
        assert!(check_messages(&[unnamespaced], Some(&type_def)).is_err());

        let mut squatting = with_text(message());
        squatting.template = Some("umami::password-reset".to_owned());
        assert!(check_messages(&[squatting], Some(&type_def)).is_err());

        assert!(check_messages(&[message()], Some(&type_def)).is_err());

        // Half the text is a caller that lost the other half, never a deliberate hand-over.
        let mut half = message();
        half.subject = Some("Subject".to_owned());
        assert!(check_messages(&[half], Some(&type_def)).is_err());

        // Whitespace is not content — it would render as an empty mail all the same.
        let mut blank = message();
        blank.subject = Some("   ".to_owned());
        blank.body = Some("\n".to_owned());
        assert!(check_messages(&[blank], Some(&type_def)).is_err());
    }

    /// A batch is refused as a whole, so nothing is delivered before the caller hears about it.
    #[test]
    fn one_bad_message_refuses_the_whole_batch() {
        let type_def = rhythmic();
        let batch = [with_text(message()), message(), with_text(message())];
        assert!(check_messages(&batch, Some(&type_def)).is_err());
    }

    /// `context` renders a template; it is not a way to move a payload through umami into a queue.
    #[test]
    fn an_oversized_context_is_refused() {
        let type_def = rhythmic();

        let mut fits = with_text(message());
        fits.context = Some(json!({ "pages": 3, "since": "2026-09-01" }));
        assert!(check_messages(&[fits], Some(&type_def)).is_ok());

        let mut oversized = with_text(message());
        oversized.context = Some(json!({ "blob": "x".repeat(MAX_CONTEXT_BYTES) }));
        assert!(check_messages(&[oversized], Some(&type_def)).is_err());
    }

    /// A cadence the type is never fired at means the caller and the catalogue disagree, and the
    /// disagreement is otherwise invisible — the mail goes out worded for a rhythm nobody chose.
    #[test]
    fn a_cadence_is_checked_against_the_type() {
        let type_def = rhythmic();

        let mut weekly = with_text(message());
        weekly.cadence = Some("Weekly".to_owned());
        assert!(check_messages(&[weekly], Some(&type_def)).is_ok());

        let mut quarterly = with_text(message());
        quarterly.cadence = Some("quarterly".to_owned());
        assert!(check_messages(&[quarterly], Some(&type_def)).is_err());

        // A transactional send has no type, and therefore no rhythm to name.
        let mut untyped = with_text(message());
        untyped.cadence = Some("weekly".to_owned());
        assert!(check_messages(&[untyped], None).is_err());
    }

    /// A transactional send names no type at all, which is what the endpoint's contract promises.
    #[test]
    fn a_send_without_a_type_is_accepted() {
        assert!(check_messages(&[with_text(message())], None).is_ok());
    }

    /// The cadence reaches the worker normalized, so `Weekly` from a caller and `weekly` from the
    /// catalogue cannot select two different layouts.
    #[test]
    fn the_notification_meta_carries_normalized_codes() {
        let type_def = rhythmic();

        let meta = notification_meta(&type_def, Some(" Weekly "));
        assert_eq!(meta.type_code, "wsc-new-content");
        assert_eq!(meta.cadence.as_deref(), Some("weekly"));

        assert!(notification_meta(&type_def, None).cadence.is_none());
    }
}
