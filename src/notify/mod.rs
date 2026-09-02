//! The single outbound seam: how a transactional mail leaves umami.
//!
//! ## Why this exists at all, and why it is this small
//!
//! umami is not a mail service and must not become one. Templates, bounce handling, retries,
//! provider credentials and reputation are somebody else's problem — a worker's. But two flows
//! *cannot* be delegated, because delegating them would be a privilege escalation:
//!
//! - **Address verification.** Hand the challenge token to another service and that service can
//!   verify an address it controls onto somebody else's account.
//! - **Password recovery.** Hand the reset token out and the holder can take over any account.
//!
//! So umami mints those tokens and hands over only the **finished message**. That is the whole job
//! of this module: one message shape, one write, no queueing logic of its own.
//!
//! ## Why a queue and not an HTTP call
//!
//! A synchronous call to a relay would put umami's login path at the mercy of that relay's latency:
//! a hanging endpoint would consume connections in the service nothing else in the fleet can log in
//! without. An SQS write is a single fast call, and retries plus a dead-letter queue come from the
//! queue rather than from code here. Delivery is somebody else's problem *after* the write, which is
//! exactly the boundary we want.
//!
//! ## When nothing is configured
//!
//! [`NoopNotifier`] logs and drops. It is honest rather than convenient: with no queue there is no
//! way to verify an address or recover a password, so the routes that need it say so instead of
//! accepting a request that silently goes nowhere. Callers check
//! [`Notifier::is_configured`] to decide.

pub mod render;
pub mod service;
pub mod types;

use crate::boot::aws::Aws;
use crate::boot::seam::{self, Selection};
use anyhow::Context;
use async_trait::async_trait;
use serde::Serialize;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use wasabi::aws::dynamodb::generate_id;

/// Which notification a mail is, for a worker that renders its own layout.
///
/// Present exactly when the mail came through `POST /notifications/send` naming a type. **Codes
/// only.** The catalogue's labels are one string each, in whatever language the deployment wrote
/// them — sending them along would look like a translation without being one, and a worker picking
/// a layout wants the stable code anyway.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NotificationMeta {
    /// The type's stable code, as the app fired it.
    #[serde(rename = "type")]
    pub type_code: String,
    /// Which cadence this recipient matched, absent for a type with no rhythm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cadence: Option<String>,
}

/// Who the mail is for, in the parts a template addresses them by.
///
/// Every form umami can compose, because which one a layout wants is the layout's business: a
/// formal letter opens with `addressableName`, a friendly one with `firstName`, and one that
/// branches on gender needs `salutationKey` — the stable code — rather than the word, which is
/// already translated into the reader's language and therefore useless in a condition.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Recipient {
    /// `salutation title lastname` — how you would address them ("Frau Dr. Doe").
    pub addressable_name: String,
    /// `salutation title firstname lastname` ("Frau Dr. Jane Doe").
    pub full_name: String,
    /// `title firstname lastname`, with **no** salutation — what a layout prepends its own word to.
    pub name: String,
    /// The salutation word in the reader's language ("Frau", "Ms"). Absent when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salutation: Option<String>,
    /// The stable salutation code — `""`, `SIR` or `MADAM`. **This** is what a condition compares
    /// against; the word above changes with the language.
    pub salutation_key: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
}

impl Recipient {
    /// Composes every name form for `user`, in the language the mail is written in.
    ///
    /// `locale` is the mail's, not the deployment's: the salutation word has to match the text it
    /// stands in front of.
    pub fn of(user: &crate::users::User, locale: &str) -> Self {
        Recipient::from_parts(
            user.title.as_deref(),
            user.salutation,
            user.firstname.as_deref(),
            user.lastname.as_deref(),
            locale,
        )
    }

    /// The same from loose name parts, so this type does not have to know the user record — the
    /// split [`crate::users::compose_display_names`] already makes, for the same reason.
    pub fn from_parts(
        title: Option<&str>,
        salutation: crate::users::Salutation,
        firstname: Option<&str>,
        lastname: Option<&str>,
        locale: &str,
    ) -> Self {
        let names =
            crate::users::compose_display_names(title, salutation, firstname, lastname, locale);
        Recipient {
            addressable_name: names.addressable_name,
            full_name: names.full_name,
            name: names.name,
            salutation: crate::users::salutation_word(salutation, locale),
            salutation_key: salutation.code(),
            first_name: firstname.map(str::to_owned),
            last_name: lastname.map(str::to_owned),
        }
    }
}

/// A finished transactional mail, ready to send. Rendered by umami — the worker only delivers.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OutboundMail {
    /// Idempotency key. SQS is at-least-once, so a worker that retries must be able to recognise a
    /// message it already delivered; it is also the handle for "did that reset mail go out?".
    pub message_id: String,
    /// The recipient address.
    pub to: String,
    /// Subject line. Empty only when [`OutboundMail::template`] names something to render instead.
    pub subject: String,
    /// Plain-text body. Empty only when [`OutboundMail::template`] names something to render
    /// instead.
    pub body: String,
    /// Which layout renders this mail — the single selector a worker keys off.
    ///
    /// umami fills it with its own name for its own mails ([`TEMPLATE_CONTACT_VERIFICATION`],
    /// [`TEMPLATE_PASSWORD_RESET`]) and forwards the app's name for anything sent through
    /// `/notifications/send`. It never interprets either: a worker that does not know the name falls
    /// back to `subject`/`body`, which is why a caller may send both and why one of the two is
    /// always required.
    ///
    /// One field rather than one per sender, so a worker has one thing to switch on. What keeps
    /// them apart in it is a **namespace on every name** — `umami::`, `wsc::`, `abc::` — checked by
    /// [`template_namespace`]. [`OutboundMail::notification`] says which side a mail came from, when
    /// a worker needs to know more than the name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Opaque data for that template, straight from the caller.
    ///
    /// **Never log this.** For umami's own mails it carries the single-use link the body already
    /// contains, and for an app's it carries whatever the app put there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    /// Which notification this is, for a mail that came through `/notifications/send` with a type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification: Option<NotificationMeta>,
    /// Who the mail is for, so a worker templating a greeting does not have to ask umami for the
    /// user — and could not be told an address by asking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<Recipient>,
    /// The deployment's imprint in the mail's language.
    ///
    /// Already appended to `body`, so a worker that only delivers is complete. It travels as its own
    /// field for the one that renders: a layout wants it in a footer block, not stuck to the end of
    /// a text it is not using.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer: Option<String>,
    /// The deployment's constants for a worker's templates — base URLs, a support address.
    ///
    /// Separate from [`OutboundMail::context`] rather than merged into it, so a key in both cannot
    /// silently overwrite the other.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub global_context: std::collections::BTreeMap<String, String>,
    /// The recipient's resolved language (BCP-47) — a worker may need it for a sender identity or a
    /// footer it owns.
    pub locale: String,
    /// Who the mail is about, for the worker's own audit trail. Never used for addressing.
    pub user_id: String,
    /// That user's tenant.
    pub tenant_id: String,
}

/// The namespace umami's own layouts live in. Reserved — no caller may send under it.
pub const TEMPLATE_NAMESPACE: &str = "umami";

/// What separates a template's namespace from the rest of its name.
pub const TEMPLATE_SEPARATOR: &str = "::";

/// Checks that a template name is namespaced, and that the namespace is the caller's to use.
///
/// One field carries every sender's layout names — umami's own and each app's — so they need a way
/// not to collide. Every name therefore starts with a namespace: `umami::password-reset`,
/// `wsc::new-content`, `abc::report-ready`. The rule is enforced rather than documented, because a
/// worker keys its layout off this field alone: an unnamespaced `password-reset` from an app would
/// otherwise be rendered as umami's, and two apps that both invent `digest` would silently share a
/// layout.
///
/// What follows the separator is the sender's own business — this only requires that there is
/// something and that it is one token. Returns the namespace on success and the reason on failure,
/// as plain text rather than an HTTP error: the rule belongs here, the status code to the route.
pub fn template_namespace(template: &str) -> Result<&str, String> {
    let Some((namespace, rest)) = template.split_once(TEMPLATE_SEPARATOR) else {
        return Err(format!(
            "Template '{template}' has no namespace — write '<yours>{TEMPLATE_SEPARATOR}{template}'              (for example 'wsc{TEMPLATE_SEPARATOR}{template}'), so a worker cannot confuse it with              another sender's layout of the same name"
        ));
    };
    if namespace.is_empty()
        || !namespace
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "Template '{template}' has the namespace '{namespace}', which has to be lowercase              letters, digits or '-' — it names a sender, so it stays as short and stable as one"
        ));
    }
    if rest.trim().is_empty() || rest.chars().any(char::is_whitespace) {
        return Err(format!(
            "Template '{template}' has nothing usable after the namespace"
        ));
    }
    Ok(namespace)
}

/// The layout name umami puts on its own address-confirmation mail.
pub const TEMPLATE_CONTACT_VERIFICATION: &str = "umami::contact-verification";

/// The layout name umami puts on its own password-reset mail.
pub const TEMPLATE_PASSWORD_RESET: &str = "umami::password-reset";

/// The namespace umami's own layouts live in, with its separator — what a caller is refused.
pub const TEMPLATE_UMAMI_PREFIX: &str = "umami::";

/// The `globalContext` key umami fills in itself: its own public base URL, **without** a trailing
/// slash — `https://iam.example.com`, so a template writes `{{ globalContext.umamiBaseUrl }}/app/`.
///
/// The slash is dropped here and only here. [`public_base_url`] keeps it, because every link umami
/// builds is a concatenation where a missing slash silently yields the wrong URL. A template is the
/// opposite case: the author can see the separator they are writing, and a base URL that brings its
/// own is the one that ends up doubled.
///
/// Reserved — [`crate::config::validate_mail`] refuses a config that sets it. umami already knows
/// this value (it is `UMAMI_ISSUER`, the same string every link in every mail is built from), and a
/// deployment typing it a second time into the config is a second place for it to be wrong.
pub const GLOBAL_CONTEXT_BASE_URL: &str = "umamiBaseUrl";

impl OutboundMail {
    /// Builds a mail with a fresh idempotency key.
    pub fn new(
        to: String,
        subject: String,
        body: String,
        locale: String,
        user_id: String,
        tenant_id: String,
    ) -> Self {
        OutboundMail {
            message_id: generate_id(),
            to,
            subject,
            body,
            template: None,
            context: None,
            notification: None,
            recipient: None,
            footer: None,
            global_context: std::collections::BTreeMap::new(),
            locale,
            user_id,
            tenant_id,
        }
    }

    /// Adds every name form a template might greet the reader by.
    #[must_use]
    pub fn with_recipient(mut self, recipient: Recipient) -> Self {
        self.recipient = Some(recipient);
        self
    }

    /// Folds in what the deployment adds to every mail: the imprint for this mail's language, and
    /// the global template constants — umami's own base URL among them.
    ///
    /// The footer is a **template**, rendered here against those constants, so an imprint can name
    /// the deployment's URLs without repeating them. It is only ever the deployment's own text, and
    /// [`crate::config::validate_mail`] has already rendered it once at publish time, so a failure
    /// here is not something a caller can cause.
    ///
    /// It is **appended to the body** as well as carried as a field — but only when there is a body
    /// to append it to, so a template-only message does not go out as a lone imprint. The separator
    /// is the RFC 3676 signature marker, which mail clients recognise and fold away.
    ///
    /// **Call this last.** It is what assembles the body, so anything that sets the body has to have
    /// run already.
    pub fn with_deployment(
        mut self,
        mail: &crate::config::MailConfig,
        public_base_url: &str,
    ) -> anyhow::Result<Self> {
        self.global_context = mail.global_context.clone();
        let _ = self.global_context.insert(
            GLOBAL_CONTEXT_BASE_URL.to_owned(),
            public_base_url.trim_end_matches('/').to_owned(),
        );

        if let Some(footer) = mail.footer_for(&self.locale) {
            let footer = render::render(
                footer,
                &render::MailContext {
                    global_context: &self.global_context,
                    ..render::MailContext::default()
                },
            )?;
            if !self.body.trim().is_empty() {
                self.body = format!("{}\n\n-- \n{footer}", self.body.trim_end());
            }
            self.footer = Some(footer);
        }
        Ok(self)
    }

    /// Names the layout a worker may render instead of the finished text.
    #[must_use]
    pub fn with_template(mut self, template: Option<String>) -> Self {
        self.template = template;
        self
    }

    /// Attaches the data that layout renders from.
    #[must_use]
    pub fn with_context(mut self, context: Option<serde_json::Value>) -> Self {
        self.context = context;
        self
    }

    /// Marks the mail as one notification of a declared type.
    #[must_use]
    pub fn with_notification(mut self, notification: NotificationMeta) -> Self {
        self.notification = Some(notification);
        self
    }
}

/// The outbound seam. One method, deliberately.
#[async_trait]
pub trait Notifier: Send + Sync {
    /// Hands a finished mail over for delivery. Returns once it is durably queued — **not** once it
    /// is delivered, which umami never learns.
    async fn send(&self, mail: OutboundMail) -> anyhow::Result<()>;

    /// Whether this notifier can actually deliver. `false` for [`NoopNotifier`], and the reason the
    /// verification and recovery routes can refuse up front instead of accepting a request that
    /// goes nowhere.
    fn is_configured(&self) -> bool;
}

/// The seam's name in the boot report.
const SEAM: &str = "mail transport";
/// The variable that names the transport.
pub const VARIABLE: &str = "UMAMI_MAIL_TRANSPORT";
/// One SQS message per mail; a worker delivers.
const SQS: &str = "sqs";
/// Straight to Amazon SES, no worker in between.
const SES: &str = "ses";
/// Print each mail to the log instead of sending it. Local development.
const STDOUT: &str = "stdout";
/// No transport — mail is dropped and the routes that need it refuse.
const NONE: &str = "none";
/// Every transport this build accepts.
const PROVIDERS: &[&str] = &[SQS, SES, STDOUT, NONE];

/// What running without a transport costs.
const MAIL_DISABLED: &str = "outbound mail is DISABLED: address verification and password \
                             recovery refuse requests";

/// What the direct transport costs. Short form for the boot report; [`SesNotifier`] spells it out.
const MAIL_WITHOUT_A_WAY_BACK: &str = "no worker, so an asynchronous bounce is never reported and \
                                       a dead address stays confirmed";

/// What the console transport costs. Short form for the boot report; the `WARN` in
/// [`StdoutNotifier::announce`] spells it out.
const MAIL_TO_LOG: &str = "mail is printed to the log, single-use links included — never in \
                           production";

/// Resolves the outbound mail transport.
///
/// Explicit `sqs` and `ses` are strict in both directions: without their own setting, and with AWS
/// unusable, the boot fails. A deployment that configured mail and silently got a different
/// transport is the bad outcome — it does not reject anything, it just stops being able to verify
/// an address or recover a password, and nobody notices until a user reports it.
///
/// With nothing configured the transport follows what is actually available: a queue plus working
/// AWS gives `sqs`, a sender address plus working AWS gives `ses`, and otherwise a **debug build**
/// prints to the console while a **release build** disables mail. That split is deliberate — see
/// [`default_transport`].
pub async fn from_env(aws: &Aws) -> anyhow::Result<(Arc<dyn Notifier>, Selection)> {
    match seam::requested(VARIABLE).as_deref() {
        Some(name) if name == SQS => {
            let url = queue_url().with_context(|| {
                format!("{VARIABLE}={SQS} requires UMAMI_MAIL_SQS_QUEUE_URL to be set")
            })?;
            check_queue_url(&url)?;
            aws.require()
                .await
                .with_context(|| format!("{VARIABLE}={SQS} needs a usable AWS client"))?;
            Ok((
                sqs_notifier(url).await,
                Selection::explicit(SEAM, VARIABLE, SQS),
            ))
        }
        Some(name) if name == SES => {
            let from = ses_from().with_context(|| {
                format!("{VARIABLE}={SES} requires UMAMI_MAIL_SES_FROM to be set")
            })?;
            check_from_address(&from)?;
            aws.require()
                .await
                .with_context(|| format!("{VARIABLE}={SES} needs a usable AWS client"))?;
            Ok((
                ses_notifier(from).await,
                Selection::explicit(SEAM, VARIABLE, SES).with_note(MAIL_WITHOUT_A_WAY_BACK),
            ))
        }
        Some(name) if name == STDOUT => Ok((
            stdout_notifier(),
            Selection::explicit(SEAM, VARIABLE, STDOUT).with_note(MAIL_TO_LOG),
        )),
        // Asked for explicitly, so no warning: the operator knows mail is off. The report still
        // says what it costs.
        Some(name) if name == NONE => Ok((
            Arc::new(NoopNotifier),
            Selection::explicit(SEAM, VARIABLE, NONE).with_note(MAIL_DISABLED),
        )),
        Some(other) => Err(seam::unknown_provider(VARIABLE, other, PROVIDERS)),
        None => detect(aws).await,
    }
}

/// Auto-detection: an AWS transport umami can actually reach, else the build's default.
///
/// The queue wins over SES when both are configured. Not because it is better, but because it has
/// to be *some* fixed answer and the queue is the one with a way back for a bounce — an operator who
/// meant the other one is told, and says so with [`VARIABLE`].
async fn detect(aws: &Aws) -> anyhow::Result<(Arc<dyn Notifier>, Selection)> {
    let queue = queue_url();
    let from = ses_from();
    // A malformed setting is a typo, not an absence — it fails the boot here rather than making
    // umami fall back to a transport nobody asked for.
    if let Some(url) = &queue {
        check_queue_url(url)?;
    }
    if let Some(address) = &from {
        check_from_address(address)?;
    }

    if queue.is_some() || from.is_some() {
        if queue.is_some() && from.is_some() {
            tracing::warn!(
                "both UMAMI_MAIL_SQS_QUEUE_URL and UMAMI_MAIL_SES_FROM are set — auto-detection \
                 takes the queue. Set {VARIABLE}={SQS} or {VARIABLE}={SES} to say which one you \
                 mean."
            );
        }
        if aws.is_usable().await {
            if let Some(url) = queue {
                return Ok((
                    sqs_notifier(url).await,
                    Selection::detected(SEAM, VARIABLE, SQS),
                ));
            }
            if let Some(address) = from {
                return Ok((
                    ses_notifier(address).await,
                    Selection::detected(SEAM, VARIABLE, SES).with_note(MAIL_WITHOUT_A_WAY_BACK),
                ));
            }
        }
        // Mail was clearly meant to work — but with AWS unusable it cannot. Loud, because this is
        // the one auto-detected outcome an operator did not ask for.
        tracing::warn!(
            "a mail transport is configured but AWS is not usable — falling back. Fix the AWS \
             credentials, or set {VARIABLE} explicitly to say which transport you want."
        );
    }

    match default_transport() {
        STDOUT => Ok((
            stdout_notifier(),
            Selection::detected(SEAM, VARIABLE, STDOUT).with_note(MAIL_TO_LOG),
        )),
        _ => {
            tracing::warn!(
                "no mail transport configured — {MAIL_DISABLED}. Set \
                 UMAMI_MAIL_SQS_QUEUE_URL or UMAMI_MAIL_SES_FROM, or {VARIABLE}={STDOUT} to print \
                 mail to the log, or {VARIABLE}={NONE} to say this was intended."
            );
            Ok((
                Arc::new(NoopNotifier),
                Selection::detected(SEAM, VARIABLE, NONE).with_note(MAIL_DISABLED),
            ))
        }
    }
}

/// The transport to use when nothing is configured and no queue is reachable.
///
/// A **debug build** prints mail to the console: that is a `cargo run`, where the alternative is a
/// developer who cannot confirm an address or reset a password without standing up SQS, and where
/// clicking the link out of the log is exactly the point.
///
/// A **release build** disables mail instead, and does so for a security reason rather than a
/// stylistic one. A verification or reset body carries a single-use secret; printed into a
/// production log it becomes an account takeover for anyone who can read logs. A release binary is
/// what ships in the container, so its default must be the safe one — a forgotten queue URL then
/// *refuses* recovery (visible immediately, `/auth/capabilities` reports `passwordRecovery: false`)
/// instead of quietly leaking reset links. `UMAMI_MAIL_TRANSPORT=stdout` remains available in a
/// release build for anyone who genuinely wants it, because that is then a decision on the record.
fn default_transport() -> &'static str {
    if cfg!(debug_assertions) { STDOUT } else { NONE }
}

/// The configured queue URL, trimmed; `None` when unset or empty.
fn queue_url() -> Option<String> {
    env::var("UMAMI_MAIL_SQS_QUEUE_URL")
        .ok()
        .map(|url| url.trim().to_owned())
        .filter(|url| !url.is_empty())
}

/// Builds the SQS notifier and says which queue mail goes to.
async fn sqs_notifier(url: String) -> Arc<dyn Notifier> {
    let notifier = SqsNotifier::new(url).await;
    tracing::info!("outbound mail goes to SQS queue {}", notifier.queue_url);
    Arc::new(notifier)
}

/// Rejects a queue URL that cannot be one.
///
/// Only the shape, never a call to the queue: `sqs:GetQueueAttributes` would prove more, but a
/// policy granting only `sqs:SendMessage` is a legitimate least-privilege setup that must not fail
/// the boot. What this does catch is the common paste error — a queue *name* or ARN where a URL
/// belongs — which otherwise surfaces on the first password reset.
fn check_queue_url(url: &str) -> anyhow::Result<()> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .with_context(|| {
            format!(
                "UMAMI_MAIL_SQS_QUEUE_URL must be the queue's URL \
                 (https://sqs.<region>.amazonaws.com/<account>/<queue>), got '{url}'"
            )
        })?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    if host.is_empty() || path.is_empty() {
        anyhow::bail!(
            "UMAMI_MAIL_SQS_QUEUE_URL '{url}' has no queue path — it looks like a host, not a \
             queue URL"
        );
    }
    Ok(())
}

/// The configured SES sender, trimmed; `None` when unset or empty.
fn ses_from() -> Option<String> {
    env::var("UMAMI_MAIL_SES_FROM")
        .ok()
        .map(|from| from.trim().to_owned())
        .filter(|from| !from.is_empty())
}

/// The configuration set to send under, if the deployment has one.
fn ses_configuration_set() -> Option<String> {
    env::var("UMAMI_MAIL_SES_CONFIGURATION_SET")
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
}

/// Builds the SES notifier and says who mail comes from.
async fn ses_notifier(from: String) -> Arc<dyn Notifier> {
    let notifier = SesNotifier::new(from).await;
    match &notifier.configuration_set {
        Some(name) => tracing::info!(
            "outbound mail goes straight to SES as {} (configuration set {name})",
            notifier.from
        ),
        None => tracing::info!("outbound mail goes straight to SES as {}", notifier.from),
    }
    Arc::new(notifier)
}

/// Rejects a sender address that cannot be one.
///
/// Only the shape, and for the same reason as [`check_queue_url`]: proving the identity is verified
/// would take `ses:GetEmailIdentity`, which a least-privilege policy granting only `ses:SendEmail`
/// legitimately withholds. What this catches is the paste error — a bare domain, a display name with
/// no address — which otherwise surfaces on the first password reset.
///
/// Both RFC 5322 forms are accepted, because both are what people write into a deployment manifest:
/// `no-reply@example.com` and `umami <no-reply@example.com>`.
fn check_from_address(raw: &str) -> anyhow::Result<()> {
    let complain = |why: &str| {
        anyhow::anyhow!(
            "UMAMI_MAIL_SES_FROM must be a sender address \
             (no-reply@example.com, or 'umami <no-reply@example.com>'), got '{raw}' — {why}"
        )
    };
    let address = match (raw.find('<'), raw.rfind('>')) {
        (Some(open), Some(close)) if close > open => raw
            .get(open + 1..close)
            .ok_or_else(|| complain("the angle brackets do not enclose an address"))?
            .trim(),
        (None, None) => raw,
        _ => return Err(complain("the angle brackets are unbalanced")),
    };

    let (local, domain) = address
        .split_once('@')
        .ok_or_else(|| complain("there is no '@'"))?;
    if local.is_empty() || domain.is_empty() {
        return Err(complain("there is nothing on one side of the '@'"));
    }
    if domain.contains('@') {
        return Err(complain("there is more than one '@'"));
    }
    if !domain.contains('.') {
        return Err(complain("the domain has no dot"));
    }
    if address.chars().any(char::is_whitespace) {
        return Err(complain("the address itself contains whitespace"));
    }
    Ok(())
}

/// The client configuration both AWS transports use.
///
/// The timeouts are tight on purpose, and they are what makes the claim in the module docs true: a
/// single fast call only stays one if a stuck request cannot sit there. A queue or a mail provider
/// having a bad day must surface as a failed verification, never as a stalled request handler in the
/// one service the whole fleet logs in through. Same bounds wasabi puts on DynamoDB.
async fn aws_client_config() -> aws_config::SdkConfig {
    let timeout_config = aws_config::timeout::TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(3))
        .operation_attempt_timeout(Duration::from_secs(5))
        .operation_timeout(Duration::from_secs(10))
        .build();
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .timeout_config(timeout_config)
        .load()
        .await
}

/// Builds the console transport, warning once about what it does.
fn stdout_notifier() -> Arc<dyn Notifier> {
    StdoutNotifier::announce();
    Arc::new(StdoutNotifier)
}

/// umami's own public base URL, with exactly one trailing slash.
///
/// Read from `UMAMI_ISSUER` rather than a second setting: the issuer already *is* the public base a
/// browser reaches umami at, and two settings that must agree eventually will not. A link in a mail
/// that points at the wrong host is a dead end nobody notices until a user reports it.
pub fn public_base_url() -> anyhow::Result<String> {
    let issuer = env::var("UMAMI_ISSUER")
        .context("UMAMI_ISSUER is required to build links for outbound mail")?;
    normalize_base_url(&issuer)
}

/// Normalizes a base URL to exactly one trailing slash. Split out from the env read so it can be
/// tested without touching process environment — which `deny(unsafe_code)` rules out anyway.
fn normalize_base_url(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        anyhow::bail!("UMAMI_ISSUER must not be empty");
    }
    Ok(format!("{trimmed}/"))
}

/// Drops every mail, loudly. Selected explicitly with `UMAMI_MAIL_TRANSPORT=none`, and the default
/// in a release build with nothing configured.
pub struct NoopNotifier;

#[async_trait]
impl Notifier for NoopNotifier {
    async fn send(&self, mail: OutboundMail) -> anyhow::Result<()> {
        // Never log the body: a verification or reset body contains a single-use secret, and a log
        // line is the wrong place for one.
        tracing::warn!(
            "outbound mail dropped (no transport configured): template={} messageId={}",
            mail.template.as_deref().unwrap_or("<none>"),
            mail.message_id
        );
        Ok(())
    }

    fn is_configured(&self) -> bool {
        false
    }
}

/// Prints each mail to the log instead of sending it — **body included**.
///
/// The point of a development transport is that the link works: a developer confirms an address or
/// resets a password by copying it out of the console, with no SQS and no worker in the loop. Which
/// is also precisely why this must never run in production. Every verification and recovery body
/// carries a single-use secret, so with this transport the log *is* the credential store: anyone
/// who can read logs can take over any account. [`default_transport`] therefore only makes it the
/// default in a debug build.
///
/// It reports itself as configured, because it can genuinely deliver to its audience of one.
pub struct StdoutNotifier;

impl StdoutNotifier {
    /// Says what this transport does. Called once, when the seam selects it — repeating it per
    /// mail would bury the mails it is printing.
    fn announce() {
        tracing::warn!(
            "outbound mail is PRINTED TO THE LOG, bodies and single-use links included. Fine for \
             local development; in production this hands every account to anyone who can read \
             logs. Set UMAMI_MAIL_SQS_QUEUE_URL, or UMAMI_MAIL_TRANSPORT=none to disable mail."
        );
    }
}

#[async_trait]
impl Notifier for StdoutNotifier {
    async fn send(&self, mail: OutboundMail) -> anyhow::Result<()> {
        // One multi-line block rather than fields on one line: the body has newlines and a link
        // that has to survive a copy-paste out of a terminal.
        tracing::info!(
            "\n──────── outbound mail (printed, not sent) ────────\n\
             template  : {}\n\
             to        : {}\n\
             subject   : {}\n\
             locale    : {}\n\
             messageId : {}\n\
             ─────────────────────────────────────────────────\n\
             {}\n\
             ─────────────────────────────────────────────────",
            mail.template.as_deref().unwrap_or("<none>"),
            mail.to,
            mail.subject,
            mail.locale,
            mail.message_id,
            mail.body
        );
        Ok(())
    }

    fn is_configured(&self) -> bool {
        true
    }
}

/// Writes each mail as one SQS message. Retries and the dead-letter queue belong to the queue.
pub struct SqsNotifier {
    client: aws_sdk_sqs::Client,
    queue_url: String,
}

impl SqsNotifier {
    /// Builds the client from the ambient AWS environment (region, credentials).
    pub async fn new(queue_url: String) -> Self {
        SqsNotifier {
            client: aws_sdk_sqs::Client::new(&aws_client_config().await),
            queue_url,
        }
    }
}

#[async_trait]
impl Notifier for SqsNotifier {
    #[tracing::instrument(level = "debug", skip(self, mail), err(Display))]
    async fn send(&self, mail: OutboundMail) -> anyhow::Result<()> {
        // Serialize before the call so a malformed message is a local error, not a queue write that
        // a worker later fails to parse.
        let body = serde_json::to_string(&mail).context("Failed to serialize an outbound mail")?;
        let _ = self
            .client
            .send_message()
            .queue_url(&self.queue_url)
            .message_body(body)
            .send()
            .await
            .with_context(|| format!("Failed to queue mail {}", mail.message_id))?;
        Ok(())
    }

    fn is_configured(&self) -> bool {
        true
    }
}

/// Calls SES directly — no queue, no worker, no way back.
///
/// The transport for a deployment small enough that a worker is more machinery than the mail is
/// worth. It costs three things, and an operator choosing it should know all three:
///
/// - **Nothing retries.** The SQS transport hands a mail to a queue whose redrive policy owns the
///   retry; here a failed `SendEmail` is a failed request, and the user is told to try again.
/// - **An asynchronous bounce is never learned.** SES accepts the message and reports the failure
///   minutes later, to an event destination that does not exist in this setup. So a dead address
///   stays `verified` and umami goes on sending reset links into nothing — the exact failure
///   [`crate::notify::service`]'s `POST /notifications/undeliverable` exists to prevent.
/// - **The login path waits on SES.** Bounded by [`aws_client_config`], but non-zero.
///
/// A synchronous rejection *is* visible, and logged with the recipient — it is the one hard signal
/// this transport gets, and reading it is currently a human's job. Wiring it to withdraw the
/// address's confirmation would mean handing a contact repository to a transport, which is the
/// dependency this seam exists to avoid; the worker reports through the API instead.
///
/// Message tags carry `messageId` and `userId` into SES's event stream, so a deployment that later
/// adds a configuration set and an event destination can correlate a bounce back to a user without
/// umami changing.
pub struct SesNotifier {
    client: aws_sdk_sesv2::Client,
    from: String,
    configuration_set: Option<String>,
}

impl SesNotifier {
    /// Builds the client from the ambient AWS environment (region, credentials).
    pub async fn new(from: String) -> Self {
        SesNotifier {
            client: aws_sdk_sesv2::Client::new(&aws_client_config().await),
            from,
            configuration_set: ses_configuration_set(),
        }
    }

    /// Builds one UTF-8 text part.
    ///
    /// The charset is load-bearing rather than decorative: without it SES encodes as 7-bit ASCII and
    /// every umlaut in a German subject line arrives as a replacement character.
    fn utf8(data: &str) -> anyhow::Result<aws_sdk_sesv2::types::Content> {
        Ok(aws_sdk_sesv2::types::Content::builder()
            .data(data)
            .charset("UTF-8")
            .build()?)
    }

    /// One message tag, or `None` when the value is not one SES accepts.
    ///
    /// SES allows `[A-Za-z0-9_-]` in a tag value and rejects the **whole send** over a stray
    /// character. Every id umami mints is safe, so this never fires today — but a tag is a
    /// convenience and a mail is not, so an id from some later source drops the tag rather than the
    /// message.
    fn tag(name: &'static str, value: &str) -> Option<aws_sdk_sesv2::types::MessageTag> {
        if value.is_empty()
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            tracing::debug!("dropping SES message tag {name}: value is not tag-safe");
            return None;
        }
        aws_sdk_sesv2::types::MessageTag::builder()
            .name(name)
            .value(value)
            .build()
            .ok()
    }
}

#[async_trait]
impl Notifier for SesNotifier {
    #[tracing::instrument(level = "debug", skip(self, mail), err(Display))]
    async fn send(&self, mail: OutboundMail) -> anyhow::Result<()> {
        let body = aws_sdk_sesv2::types::Body::builder()
            .text(SesNotifier::utf8(&mail.body)?)
            .build();
        let message = aws_sdk_sesv2::types::Message::builder()
            .subject(SesNotifier::utf8(&mail.subject)?)
            .body(body)
            .build();
        let content = aws_sdk_sesv2::types::EmailContent::builder()
            .simple(message)
            .build();

        let mut request = self
            .client
            .send_email()
            .from_email_address(&self.from)
            .destination(
                aws_sdk_sesv2::types::Destination::builder()
                    .to_addresses(&mail.to)
                    .build(),
            )
            .content(content)
            .set_configuration_set_name(self.configuration_set.clone());
        for tag in [
            SesNotifier::tag("umamiMessageId", &mail.message_id),
            SesNotifier::tag("umamiUserId", &mail.user_id),
        ]
        .into_iter()
        .flatten()
        {
            request = request.email_tags(tag);
        }

        match request.send().await {
            Ok(_) => Ok(()),
            Err(err) => {
                // The one hard signal this transport gets. Loud and with the address, because
                // nothing else in the deployment will ever mention it — see the type's docs.
                tracing::warn!(
                    "SES refused mail {} to {}: {}",
                    mail.message_id,
                    mail.to,
                    aws_error(&err)
                );
                Err(anyhow::Error::new(err)
                    .context(format!("Failed to send mail {} via SES", mail.message_id)))
            }
        }
    }

    fn is_configured(&self) -> bool {
        true
    }
}

/// The service's own message for an SDK error, which is the half worth reading. Falls back to the
/// SDK's rendering when the failure never reached the service (a timeout, a bad credential chain).
fn aws_error<E, R>(err: &aws_sdk_sesv2::error::SdkError<E, R>) -> String
where
    E: std::error::Error,
{
    match err.as_service_error() {
        Some(service) => service.to_string(),
        None => err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mail to hand a notifier, when what is under test is the notifier rather than the mail.
    fn a_mail() -> OutboundMail {
        OutboundMail::new(
            "jane@example.com".to_owned(),
            "subject".to_owned(),
            "body".to_owned(),
            "de".to_owned(),
            "user-1".to_owned(),
            "tenant-1".to_owned(),
        )
        .with_template(Some(TEMPLATE_CONTACT_VERIFICATION.to_owned()))
    }

    /// A recipient with every name part filled in.
    fn a_recipient() -> Recipient {
        Recipient::from_parts(
            Some("Dr."),
            crate::users::Salutation::Madam,
            Some("Jane"),
            Some("Doe"),
            "de",
        )
    }

    /// umami's own names have to satisfy the rule it enforces on everybody else — a reserved
    /// namespace that its own constants did not use would be a rule with no example.
    #[test]
    fn umamis_own_templates_are_in_its_own_namespace() {
        for template in [TEMPLATE_CONTACT_VERIFICATION, TEMPLATE_PASSWORD_RESET] {
            assert_eq!(template_namespace(template), Ok(TEMPLATE_NAMESPACE));
            assert!(template.starts_with(TEMPLATE_UMAMI_PREFIX));
        }
    }

    /// Every layout name carries a sender's namespace, because one field holds all of them: two
    /// senders inventing `digest` would otherwise silently share a layout.
    #[test]
    fn a_template_without_a_usable_namespace_is_refused() {
        assert_eq!(template_namespace("wsc::new-content"), Ok("wsc"));
        assert_eq!(template_namespace("abc-2::report.ready"), Ok("abc-2"));
        // Only the first separator splits; what follows is the sender's own business.
        assert_eq!(template_namespace("wsc::mail::footer"), Ok("wsc"));

        assert!(template_namespace("new-content").is_err());
        assert!(template_namespace("::new-content").is_err());
        assert!(template_namespace("WSC::new-content").is_err());
        assert!(template_namespace("my app::new-content").is_err());
        assert!(template_namespace("wsc::").is_err());
        assert!(template_namespace("wsc::new content").is_err());
    }

    /// umami's own public base URL, as `UMAMI_ISSUER` yields it — trailing slash included.
    const BASE_URL: &str = "https://iam.noonu.dev/";

    /// A deployment that has filled in both halves of the mail block.
    fn a_mail_config() -> crate::config::MailConfig {
        let mut config = crate::config::MailConfig::default();
        let _ = config
            .footer
            .insert("de".to_owned(), "noonu GmbH · Stuttgart".to_owned());
        let _ = config
            .global_context
            .insert("supportMail".to_owned(), "hilfe@noonu.dev".to_owned());
        config
    }

    /// A queue *name* or ARN pasted where a URL belongs is the common mistake, and it otherwise
    /// surfaces on the first password reset rather than at boot.
    #[test]
    fn a_queue_url_that_cannot_be_one_is_refused() {
        assert!(
            check_queue_url("https://sqs.eu-central-1.amazonaws.com/123456789012/umami-mail")
                .is_ok()
        );
        // A localstack or VPC-endpoint URL is just as valid — only the shape is checked.
        assert!(check_queue_url("http://localhost:4566/000000000000/umami-mail").is_ok());

        assert!(check_queue_url("umami-mail").is_err());
        assert!(check_queue_url("arn:aws:sqs:eu-central-1:123456789012:umami-mail").is_err());
        assert!(check_queue_url("https://sqs.eu-central-1.amazonaws.com").is_err());
        assert!(check_queue_url("https://sqs.eu-central-1.amazonaws.com/").is_err());
    }

    /// A sender address is the one SES setting a deployment types by hand, and getting it wrong
    /// otherwise surfaces on the first password reset rather than at boot.
    #[test]
    fn a_sender_address_that_cannot_be_one_is_refused() {
        assert!(check_from_address("no-reply@example.com").is_ok());
        assert!(check_from_address("umami <no-reply@example.com>").is_ok());
        assert!(check_from_address("umami IAM <no-reply@mail.example.co.uk>").is_ok());

        assert!(check_from_address("example.com").is_err());
        assert!(check_from_address("no-reply@localhost").is_err());
        assert!(check_from_address("umami <no-reply@example.com").is_err());
        assert!(check_from_address("@example.com").is_err());
        assert!(check_from_address("no-reply@").is_err());
        assert!(check_from_address("a@b@example.com").is_err());
        assert!(check_from_address("no reply@example.com").is_err());
    }

    /// A tag value SES would reject takes the whole send with it, so an unsafe one has to drop the
    /// tag instead. Every id umami mints is already safe — this guards the next source of ids.
    #[test]
    fn an_unsafe_message_tag_is_dropped_rather_than_sent() {
        assert!(SesNotifier::tag("umamiMessageId", &generate_id()).is_some());
        assert!(SesNotifier::tag("umamiUserId", "user-1_A").is_some());

        assert!(SesNotifier::tag("umamiUserId", "user 1").is_none());
        assert!(SesNotifier::tag("umamiUserId", "jane@example.com").is_none());
        assert!(SesNotifier::tag("umamiUserId", "").is_none());
    }

    /// The optional half of a mail must not appear in the payload at all when it is absent — a
    /// worker branching on presence should not have to tell `null` from missing.
    #[test]
    fn the_optional_fields_are_absent_rather_than_null() {
        let json = serde_json::to_value(a_mail()).unwrap();
        for field in [
            "context",
            "notification",
            "recipient",
            "footer",
            "globalContext",
        ] {
            assert!(
                json.get(field).is_none(),
                "{field} should not be serialized"
            );
        }
        // umami's own mails name their layout in the same field an app's do; `notification` is what
        // says which side a mail came from.
        assert_eq!(json["template"], TEMPLATE_CONTACT_VERIFICATION);

        let enriched = a_mail()
            .with_recipient(a_recipient())
            .with_context(Some(serde_json::json!({ "link": "https://example.com/x" })))
            .with_notification(NotificationMeta {
                type_code: "wsc-new-content".to_owned(),
                cadence: Some("weekly".to_owned()),
            });
        let json = serde_json::to_value(enriched).unwrap();
        assert_eq!(json["recipient"]["addressableName"], "Frau Dr. Doe");
        assert_eq!(json["context"]["link"], "https://example.com/x");
        // The type travels as `type`, which is what the catalogue and the firing both call it.
        assert_eq!(json["notification"]["type"], "wsc-new-content");
    }

    /// A template branching on gender needs the stable code; the word beside it is already in the
    /// reader's language and would make every condition locale-dependent.
    #[test]
    fn a_recipient_carries_every_name_form_and_a_stable_salutation_key() {
        let json = serde_json::to_value(a_recipient()).unwrap();
        assert_eq!(json["addressableName"], "Frau Dr. Doe");
        assert_eq!(json["fullName"], "Frau Dr. Jane Doe");
        // `name` is the one without the salutation, for a layout that prepends its own word.
        assert_eq!(json["name"], "Dr. Jane Doe");
        assert_eq!(json["salutation"], "Frau");
        assert_eq!(json["salutationKey"], "MADAM");
        assert_eq!(json["firstName"], "Jane");
        assert_eq!(json["lastName"], "Doe");
    }

    /// The imprint has to reach a plain-text mail too, or a worker that only delivers sends one
    /// without it. `de-AT` finds the `de` entry, the way the message catalogue resolves.
    #[test]
    fn the_footer_lands_in_the_body_and_beside_it() {
        let mail = a_mail()
            .with_deployment(&a_mail_config(), BASE_URL)
            .unwrap();
        assert_eq!(mail.body, "body\n\n-- \nnoonu GmbH · Stuttgart");
        assert_eq!(mail.footer.as_deref(), Some("noonu GmbH · Stuttgart"));

        // A template-only message has no body to append to, and must not go out as a lone imprint.
        let mut templated = a_mail();
        templated.body = String::new();
        let templated = templated
            .with_deployment(&a_mail_config(), BASE_URL)
            .unwrap();
        assert!(templated.body.is_empty());
        assert_eq!(templated.footer.as_deref(), Some("noonu GmbH · Stuttgart"));
    }

    /// A footer is a template like any other, and the values it renders from are the ones the
    /// payload carries — so an imprint can name a URL the deployment configured once.
    #[test]
    fn the_footer_renders_against_the_global_context() {
        let mut config = a_mail_config();
        let _ = config.footer.insert(
            "de".to_owned(),
            "noonu GmbH · {{ globalContext.supportMail }} · {{ globalContext.umamiBaseUrl }}/app/"
                .to_owned(),
        );

        let mail = a_mail().with_deployment(&config, BASE_URL).unwrap();
        assert_eq!(
            mail.footer.as_deref(),
            Some("noonu GmbH · hilfe@noonu.dev · https://iam.noonu.dev/app/")
        );
    }

    /// umami knows its own public URL; a deployment typing it into the config a second time is a
    /// second thing to keep in step, so umami fills it in instead — and without the trailing slash
    /// the issuer carries, so a template writes the separator it can see.
    #[test]
    fn every_mail_carries_umamis_own_base_url() {
        let mail = a_mail()
            .with_deployment(&a_mail_config(), BASE_URL)
            .unwrap();
        assert_eq!(
            mail.global_context
                .get(GLOBAL_CONTEXT_BASE_URL)
                .map(String::as_str),
            Some("https://iam.noonu.dev")
        );
        // What the deployment configured is still there beside it.
        assert_eq!(
            mail.global_context.get("supportMail").map(String::as_str),
            Some("hilfe@noonu.dev")
        );
    }

    /// The point of the engine: a typo has to be an error, not an empty string in a mail nobody
    /// re-reads. `validate_mail` runs this same render at publish time, so it never reaches a send.
    #[test]
    fn an_unknown_placeholder_fails_rather_than_rendering_empty() {
        let mut config = a_mail_config();
        let _ = config.footer.insert(
            "de".to_owned(),
            "noonu GmbH · {{ globalContext.supprtMail }}".to_owned(),
        );
        assert!(a_mail().with_deployment(&config, BASE_URL).is_err());
    }

    /// A locale with no entry gets no footer — an imprint in a language the reader did not ask for
    /// is worse than none.
    #[test]
    fn a_footer_is_never_borrowed_from_another_language() {
        let mut config = crate::config::MailConfig::default();
        let _ = config
            .footer
            .insert("de".to_owned(), "Impressum".to_owned());

        assert_eq!(config.footer_for("de-AT"), Some("Impressum"));
        assert_eq!(config.footer_for("DE"), Some("Impressum"));
        assert_eq!(config.footer_for("en"), None);
        assert_eq!(crate::config::MailConfig::default().footer_for("de"), None);
    }

    /// The console transport must never become the default in a release build: a reset link in a
    /// production log is an account takeover for anyone who can read logs.
    #[test]
    fn the_default_transport_prints_only_in_debug_builds() {
        if cfg!(debug_assertions) {
            assert_eq!(default_transport(), STDOUT);
        } else {
            assert_eq!(default_transport(), NONE);
        }
    }

    /// The console transport has to report itself as able to deliver, or the flows it exists for
    /// (confirm an address, reset a password) refuse before printing anything.
    #[tokio::test]
    async fn the_console_transport_delivers_and_says_so() {
        let notifier = StdoutNotifier;
        assert!(notifier.is_configured());
        assert!(notifier.send(a_mail()).await.is_ok());
    }

    /// The noop path must be recognisable as "cannot deliver" — otherwise the routes that depend on
    /// mail would accept requests and drop them, which is the failure mode with no error to see.
    #[tokio::test]
    async fn noop_reports_itself_unconfigured_and_swallows() {
        let notifier = NoopNotifier;
        assert!(!notifier.is_configured());
        assert!(notifier.send(a_mail()).await.is_ok());
    }

    /// One trailing slash, whatever the operator typed — the link builder concatenates, so a
    /// missing or doubled slash lands in every mail.
    #[test]
    fn base_url_normalises_the_trailing_slash() {
        for input in [
            "https://umami.example.com",
            "https://umami.example.com/",
            "https://umami.example.com///",
            "  https://umami.example.com/  ",
        ] {
            assert_eq!(
                normalize_base_url(input).unwrap(),
                "https://umami.example.com/",
                "input '{input}'"
            );
        }
        assert!(normalize_base_url("   ").is_err());
        assert!(normalize_base_url("///").is_err());
    }

    #[test]
    fn each_mail_gets_its_own_idempotency_key() {
        let build = || {
            OutboundMail::new(
                "jane@example.com".to_owned(),
                "s".to_owned(),
                "b".to_owned(),
                "en".to_owned(),
                "u".to_owned(),
                "t".to_owned(),
            )
        };
        assert_ne!(build().message_id, build().message_id);
    }
}
