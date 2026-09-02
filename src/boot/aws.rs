//! Is AWS actually usable in this process?
//!
//! ## Why this exists
//!
//! Every AWS-backed provider — DynamoDB storage, the S3 config catalog, the SQS mail transport —
//! needs the same precondition, and none of them can tell whether it holds by looking at
//! environment variables. `aws_config::load()` always succeeds: it builds a credential *chain*, and
//! whether that chain can produce credentials is only discovered on the first real API call. So a
//! deployment with an expired SSO session, no role, or no network looks perfectly configured right
//! up to the moment it provisions its first table.
//!
//! That matters most for auto-detection. With one storage backend, "AWS is broken" surfaces as a
//! confusing error from the first DynamoDB call; once Postgres or Mongo sit next to it, the choice
//! is *between* backends, and AWS may only win when it actually works. Same for the config catalog
//! and outbound mail: falling back to the in-memory store or the console transport is right when
//! there is no usable AWS, and wrong when there is.
//!
//! ## What the probe is
//!
//! One `sts:GetCallerIdentity` call. It is the canonical answer to "does this client work": it
//! resolves the credential chain, signs a request and talks to AWS, so it catches expired
//! sessions, a missing region and an unreachable network in one go. Critically, **it requires no
//! IAM permission** — every principal may call it — so probing can never lock out a
//! least-privilege deployment the way `dynamodb:DescribeTable` or `sqs:GetQueueAttributes` would.
//!
//! ## Where it lives
//!
//! [`Aws`] is built once in [`Platform::boot`](crate::boot::Platform::boot) and handed to every
//! seam that might pick an AWS provider, so the dependency is visible in their signatures rather
//! than hidden in a process global. The answer is cached inside it: four seams asking is one call,
//! and the identity line ("which account am I actually running against?") is logged once.
//!
//! The probe is lazy on purpose. A deployment that runs Postgres storage, a memory catalog and no
//! mail never touches AWS, and should not pay a credential lookup — worst case a multi-second
//! timeout — to find that out.

use anyhow::Context;
use std::time::Duration;
use tokio::sync::OnceCell;

/// The one "is AWS usable here?" answer, resolved at most once.
#[derive(Default)]
pub struct Aws {
    /// The cached outcome. The error is a string because `anyhow::Error` is not `Clone` and every
    /// later caller needs the same answer.
    probe: OnceCell<Result<Identity, String>>,
}

impl Aws {
    /// A handle that has not probed yet.
    #[must_use]
    pub fn new() -> Self {
        Aws::default()
    }

    /// Probes AWS on first call, then answers from cache.
    ///
    /// Returns the caller identity when AWS is usable, and the reason it is not otherwise. Callers
    /// deciding eligibility want [`Aws::is_usable`]; callers that must fail the boot want this
    /// error as the cause, so an operator sees *why* AWS was refused rather than only that it was.
    pub async fn identity(&self) -> anyhow::Result<Identity> {
        match self.probe.get_or_init(probe).await {
            Ok(identity) => Ok(identity.clone()),
            Err(reason) => Err(anyhow::anyhow!("{reason}")),
        }
    }

    /// Whether AWS is usable. `false` makes an AWS-backed provider ineligible for auto-detection.
    pub async fn is_usable(&self) -> bool {
        self.identity().await.is_ok()
    }

    /// Fails unless AWS is usable, carrying the probe's reason as the cause.
    ///
    /// What an explicitly configured AWS provider calls: the identity itself is of no interest
    /// there, only that there is one.
    pub async fn require(&self) -> anyhow::Result<()> {
        self.identity().await.map(|_| ())
    }
}

/// Who the process is, once AWS has confirmed it.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The AWS account the credentials belong to.
    pub account: String,
    /// The caller's ARN — the role or user actually in use.
    pub arn: String,
    /// The resolved region.
    pub region: String,
}

/// The actual call, run once behind the cell.
///
/// The timeouts are deliberately tighter than the service clients': a boot that hangs on a
/// credential lookup is worse than one that fails, because an orchestrator can restart a failure
/// and cannot distinguish a hang from a slow start.
async fn probe() -> Result<Identity, String> {
    match run_probe().await {
        Ok(identity) => {
            tracing::info!(
                "AWS is usable: account {} in {} as {}",
                identity.account,
                identity.region,
                identity.arn
            );
            Ok(identity)
        }
        Err(err) => {
            let reason = format!("{err:#}");
            tracing::warn!("AWS is NOT usable: {reason}");
            Err(reason)
        }
    }
}

/// Resolves the region and calls `sts:GetCallerIdentity`.
async fn run_probe() -> anyhow::Result<Identity> {
    let timeout_config = aws_config::timeout::TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(3))
        .operation_attempt_timeout(Duration::from_secs(3))
        .operation_timeout(Duration::from_secs(6))
        .build();
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .timeout_config(timeout_config)
        .load()
        .await;

    // No region means no endpoint to sign for; the SDK would fail every call with a message that
    // does not mention the region, so say it here.
    let region = config
        .region()
        .map(|region| region.to_string())
        .context("no AWS region resolved (set AWS_REGION or a region in the active profile)")?;

    let answer = aws_sdk_sts::Client::new(&config)
        .get_caller_identity()
        .send()
        .await
        .context(
            "sts:GetCallerIdentity failed — credentials are missing, expired or unreachable",
        )?;

    Ok(Identity {
        account: answer.account().unwrap_or("<unknown>").to_owned(),
        arn: answer.arn().unwrap_or("<unknown>").to_owned(),
        region,
    })
}
