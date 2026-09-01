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

use anyhow::Context;
use async_trait::async_trait;
use serde::Serialize;
use std::env;
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

/// Builds the configured notifier: an [`SqsNotifier`] when `UMAMI_MAIL_QUEUE_URL` is set, else a
/// [`NoopNotifier`].
pub async fn from_env() -> anyhow::Result<Box<dyn Notifier>> {
    match env::var("UMAMI_MAIL_QUEUE_URL") {
        Ok(url) if !url.trim().is_empty() => {
            let notifier = SqsNotifier::new(url.trim().to_owned()).await;
            tracing::info!("outbound mail goes to SQS queue {}", notifier.queue_url);
            Ok(Box::new(notifier))
        }
        _ => {
            tracing::warn!(
                "UMAMI_MAIL_QUEUE_URL is not set — outbound mail is DISABLED. Address verification \
                 and password recovery will refuse requests until a queue is configured."
            );
            Ok(Box::new(NoopNotifier))
        }
    }
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

/// Drops every mail, loudly. The default when no queue is configured.
pub struct NoopNotifier;

#[async_trait]
impl Notifier for NoopNotifier {
    async fn send(&self, mail: OutboundMail) -> anyhow::Result<()> {
        // Never log the body: a verification or reset body contains a single-use secret, and a log
        // line is the wrong place for one.
        tracing::warn!(
            "outbound mail dropped (no queue configured): kind={} messageId={}",
            mail.kind,
            mail.message_id
        );
        Ok(())
    }

    fn is_configured(&self) -> bool {
        false
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

    /// The noop path must be recognisable as "cannot deliver" — otherwise the routes that depend on
    /// mail would accept requests and drop them, which is the failure mode with no error to see.
    #[tokio::test]
    async fn noop_reports_itself_unconfigured_and_swallows() {
        let notifier = NoopNotifier;
        assert!(!notifier.is_configured());
        let mail = OutboundMail::new(
            "contact-verification",
            "jane@example.com".to_owned(),
            "subject".to_owned(),
            "body".to_owned(),
            "de".to_owned(),
            "user-1".to_owned(),
            "tenant-1".to_owned(),
        );
        assert!(notifier.send(mail).await.is_ok());
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
