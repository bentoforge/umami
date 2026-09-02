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

/// What a worker needs to word a notification itself, when it would rather render than forward.
///
/// Present exactly when the mail came through `POST /notifications/send` naming a type. The names
/// are the **catalogue's** labels, in whatever language the deployment wrote them — the same strings
/// the profile screen shows. They are deliberately not per-recipient translations: a deployment
/// invents these codes, so nothing in umami could know what `on-publish` reads as in Portuguese.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NotificationMeta {
    /// The type's stable code, as the app fired it.
    #[serde(rename = "type")]
    pub type_code: String,
    /// The type's label from the catalogue.
    pub type_name: String,
    /// Which cadence this recipient matched, absent for a type with no rhythm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cadence: Option<String>,
    /// That cadence's label from the catalogue — what lets a worker word "your week" differently
    /// from "today" without a table of its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cadence_name: Option<String>,
}

/// A finished transactional mail, ready to send. Rendered by umami — the worker only delivers.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OutboundMail {
    /// Idempotency key. SQS is at-least-once, so a worker that retries must be able to recognise a
    /// message it already delivered; it is also the handle for "did that reset mail go out?".
    pub message_id: String,
    /// What this mail is (`contact-verification`, `password-reset`). Lets a worker route or
    /// rate-limit by kind without parsing the body.
    pub kind: &'static str,
    /// The recipient address.
    pub to: String,
    /// Subject line. Empty only when [`OutboundMail::template`] names something to render instead.
    pub subject: String,
    /// Plain-text body. Empty only when [`OutboundMail::template`] names something to render
    /// instead.
    pub body: String,
    /// What the **app** wants rendered, when it would rather template than hand over finished text.
    ///
    /// umami never interprets it — it is the app's own name for one of its layouts, the way
    /// [`OutboundMail::kind`] is umami's name for one of its own mails. A worker that does not know
    /// the name falls back to `subject`/`body`, which is why a caller is allowed to send both and
    /// why one of the two is always required.
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
    /// How to address the recipient ("Ms Doe") — the same string `/notifications/audience` returns,
    /// so a worker templating a greeting does not have to ask umami for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addressable_name: Option<String>,
    /// The recipient's resolved language (BCP-47) — a worker may need it for a sender identity or a
    /// footer it owns.
    pub locale: String,
    /// Who the mail is about, for the worker's own audit trail. Never used for addressing.
    pub user_id: String,
    /// That user's tenant.
    pub tenant_id: String,
}

impl OutboundMail {
    /// Builds a mail with a fresh idempotency key.
    pub fn new(
        kind: &'static str,
        to: String,
        subject: String,
        body: String,
        locale: String,
        user_id: String,
        tenant_id: String,
    ) -> Self {
        OutboundMail {
            message_id: generate_id(),
            kind,
            to,
            subject,
            body,
            template: None,
            context: None,
            notification: None,
            addressable_name: None,
            locale,
            user_id,
            tenant_id,
        }
    }

    /// Adds the name to greet the recipient by.
    #[must_use]
    pub fn with_recipient_name(mut self, name: impl Into<String>) -> Self {
        self.addressable_name = Some(name.into());
        self
    }

    /// Names the app-side layout a worker may render instead of the finished text.
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
            "outbound mail dropped (no transport configured): kind={} messageId={}",
            mail.kind,
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
             kind      : {}\n\
             to        : {}\n\
             subject   : {}\n\
             locale    : {}\n\
             messageId : {}\n\
             ─────────────────────────────────────────────────\n\
             {}\n\
             ─────────────────────────────────────────────────",
            mail.kind,
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
            "contact-verification",
            "jane@example.com".to_owned(),
            "subject".to_owned(),
            "body".to_owned(),
            "de".to_owned(),
            "user-1".to_owned(),
            "tenant-1".to_owned(),
        )
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
        for field in ["template", "context", "notification", "addressableName"] {
            assert!(
                json.get(field).is_none(),
                "{field} should not be serialized"
            );
        }

        let enriched = a_mail()
            .with_recipient_name("Ms Doe")
            .with_context(Some(serde_json::json!({ "link": "https://example.com/x" })))
            .with_notification(NotificationMeta {
                type_code: "wsc-new-content".to_owned(),
                type_name: "Neue Inhalte".to_owned(),
                cadence: Some("weekly".to_owned()),
                cadence_name: Some("Wöchentlich".to_owned()),
            });
        let json = serde_json::to_value(enriched).unwrap();
        assert_eq!(json["addressableName"], "Ms Doe");
        assert_eq!(json["context"]["link"], "https://example.com/x");
        // The type travels as `type`, which is what the catalogue and the firing both call it.
        assert_eq!(json["notification"]["type"], "wsc-new-content");
        assert_eq!(json["notification"]["cadenceName"], "Wöchentlich");
        assert!(json["notification"].get("template").is_none());
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
                "password-reset",
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
