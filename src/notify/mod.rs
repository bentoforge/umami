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
    /// Subject line.
    pub subject: String,
    /// Plain-text body.
    pub body: String,
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
            locale,
            user_id,
            tenant_id,
        }
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
/// Print each mail to the log instead of sending it. Local development.
const STDOUT: &str = "stdout";
/// No transport — mail is dropped and the routes that need it refuse.
const NONE: &str = "none";
/// Every transport this build accepts.
const PROVIDERS: &[&str] = &[SQS, STDOUT, NONE];

/// What running without a transport costs.
const MAIL_DISABLED: &str = "outbound mail is DISABLED: address verification and password \
                             recovery refuse requests";

/// What the console transport costs. Short form for the boot report; the `WARN` in
/// [`StdoutNotifier::announce`] spells it out.
const MAIL_TO_LOG: &str = "mail is printed to the log, single-use links included — never in \
                           production";

/// Resolves the outbound mail transport.
///
/// Explicit `sqs` is strict in both directions: without a queue URL, and with AWS unusable, the
/// boot fails. A deployment that configured mail and silently got a different transport is the bad
/// outcome — it does not reject anything, it just stops being able to verify an address or recover
/// a password, and nobody notices until a user reports it.
///
/// With nothing configured the transport follows what is actually available: a queue plus working
/// AWS gives `sqs`, and otherwise a **debug build** prints to the console while a **release build**
/// disables mail. That split is deliberate — see [`default_transport`].
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

/// Auto-detection: a queue umami can actually reach, else the build's default.
async fn detect(aws: &Aws) -> anyhow::Result<(Arc<dyn Notifier>, Selection)> {
    if let Some(url) = queue_url() {
        // A malformed URL is a typo, not an absence — it fails the boot here rather than making
        // umami fall back to a transport nobody asked for.
        check_queue_url(&url)?;
        if aws.is_usable().await {
            return Ok((
                sqs_notifier(url).await,
                Selection::detected(SEAM, VARIABLE, SQS),
            ));
        }
        // A queue is configured, so mail was clearly meant to work — but with AWS unusable it
        // cannot. Loud, because this is the one auto-detected outcome an operator did not ask for.
        tracing::warn!(
            "UMAMI_MAIL_SQS_QUEUE_URL is set but AWS is not usable — falling back. Fix the AWS \
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
                 UMAMI_MAIL_SQS_QUEUE_URL, or {VARIABLE}={STDOUT} to print mail to the log, or \
                 {VARIABLE}={NONE} to say this was intended."
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
    ///
    /// The timeouts are tight on purpose, and they are what makes the claim in the module docs true:
    /// "an SQS write is a single fast call" only holds if a stuck request cannot sit there. A queue
    /// having a bad day must surface as a failed verification, never as a stalled request handler in
    /// the one service the whole fleet logs in through. Same bounds wasabi puts on DynamoDB.
    pub async fn new(queue_url: String) -> Self {
        let timeout_config = aws_config::timeout::TimeoutConfig::builder()
            .connect_timeout(Duration::from_secs(3))
            .operation_attempt_timeout(Duration::from_secs(5))
            .operation_timeout(Duration::from_secs(10))
            .build();
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .timeout_config(timeout_config)
            .load()
            .await;
        SqsNotifier {
            client: aws_sdk_sqs::Client::new(&config),
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
