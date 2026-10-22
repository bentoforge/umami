//! The storage seam: every persistence port umami depends on, resolved as one bundle.
//!
//! ## Why a bundle and not one argument per repository
//!
//! umami talks to its store through a dozen narrow repository traits, and every one of them is
//! answered by the *same* backend (`dynamodb` or `postgres`). Nobody keeps users in DynamoDB and sessions in Postgres — a
//! mixed set is not a deployment anyone wants, and pretending it is one costs a constructor
//! argument at every call site (the boot path used to carry each one).
//!
//! Resolving them together also makes a second backend a bounded piece of work: implement the
//! traits, return a [`Repositories`], and the compiler lists what is still missing. A backend that
//! covers all ports but one does not compile, rather than starting and failing on the tenth.
//!
//! The repositories themselves stay independent traits — that is what keeps handlers mockable.
//! This bundle exists for the wiring layer only.

pub mod dynamodb;
pub mod postgres;

use crate::boot::aws::Aws;
use crate::boot::postgres::{Postgres, URL_VARIABLE as POSTGRES_URL};
use crate::boot::seam::{self, Selection};

use crate::audit::repository::AuditRepository;
use crate::auth::apikeys::repository::ApiKeyRepository;
use crate::auth::challenge::ChallengeRepository;
use crate::auth::ratelimit::repository::RateLimitRepository;
use crate::auth::session::repository::SessionRepository;
use crate::auth::webauthn::repository::WebauthnRepository;
use crate::contacts::repository::ContactRepository;
use crate::limits::repository::LimitRepository;
use crate::messaging::repository::MessagingRepository;
use crate::recipients::repository::RecipientRepository;
use crate::tenants::repository::TenantRepository;
use crate::users::repository::UserRepository;
use anyhow::Context;
use std::sync::Arc;
use wasabi::aws::dynamodb::client::DynamoClient;

/// The seam's name in the boot report.
const SEAM: &str = "storage";
/// The variable that names the backend.
pub const VARIABLE: &str = "UMAMI_STORAGE";
/// DynamoDB.
const DYNAMODB: &str = "dynamodb";
/// PostgreSQL, on the pool `POSTGRES_URL` names.
const POSTGRES: &str = "postgres";
/// Every backend name this build accepts.
const PROVIDERS: &[&str] = &[DYNAMODB, POSTGRES];
/// Every repository umami needs, from one backend.
///
/// Cloning clones a dozen `Arc`s and nothing else, so the wiring layer hands copies out freely.
#[derive(Clone)]
pub struct Repositories {
    /// User identities, credentials and profiles.
    pub users: Arc<dyn UserRepository>,
    /// Refresh sessions backing `/auth/refresh`.
    pub sessions: Arc<dyn SessionRepository>,
    /// Tenants and their features.
    pub tenants: Arc<dyn TenantRepository>,
    /// Tenant service keys and personal access tokens.
    pub api_keys: Arc<dyn ApiKeyRepository>,
    /// Append-only security audit trail.
    pub audit: Arc<dyn AuditRepository>,
    /// Email contacts and their verification state.
    pub contacts: Arc<dyn ContactRepository>,
    /// Pending single-use challenges (address verification, password recovery).
    pub challenges: Arc<dyn ChallengeRepository>,
    /// Messaging links (code ↔ external identity).
    pub messaging: Arc<dyn MessagingRepository>,
    /// Rate-limit counters and blocks.
    pub rate_limits: Arc<dyn RateLimitRepository>,
    /// Registered passkeys and in-flight WebAuthn ceremonies.
    pub webauthn: Arc<dyn WebauthnRepository>,
    /// Per-tenant limit counters (consumable budgets + gauges).
    pub limits: Arc<dyn LimitRepository>,
    /// External notification recipients: tenant-owned addresses with no identity.
    pub recipients: Arc<dyn RecipientRepository>,
}

/// Resolves the storage backend and builds its repositories.
///
/// Auto-detection takes Postgres when `POSTGRES_URL` is set and DynamoDB otherwise. A connection
/// string is a deliberate act — nobody sets one by accident — while AWS credentials are often
/// just lying around on a developer machine, so the URL is the stronger signal. It is not a
/// probe: a set but broken URL fails the boot instead of quietly landing on DynamoDB.
///
/// For DynamoDB the AWS probe is checked before any table is touched. Failing there says *why*
/// ("credentials are expired"), while failing on the first `with_client` says "Cannot access
/// DynamoDB table 'umami-dev-users'", which reads like a missing table or a bad IAM policy.
pub async fn from_env(aws: &Aws, postgres: &Postgres) -> anyhow::Result<(Repositories, Selection)> {
    let selection = match seam::requested(VARIABLE) {
        Some(name) if name == DYNAMODB => Selection::explicit(SEAM, VARIABLE, DYNAMODB),
        Some(name) if name == POSTGRES => Selection::explicit(SEAM, VARIABLE, POSTGRES),
        Some(other) => return Err(seam::unknown_provider(VARIABLE, &other, PROVIDERS)),
        None if postgres.is_configured() => Selection::detected(SEAM, VARIABLE, POSTGRES),
        None => Selection::detected(SEAM, VARIABLE, DYNAMODB),
    };

    if selection.provider == POSTGRES {
        let database = postgres.database().await.with_context(|| {
            format!("{POSTGRES} storage needs a reachable database at {POSTGRES_URL}")
        })?;
        return Ok((postgres::repositories(&database).await?, selection));
    }

    aws.require().await.with_context(|| {
        format!(
            "{DYNAMODB} storage needs a usable AWS client. Set {POSTGRES_URL} to run on \
             PostgreSQL instead."
        )
    })?;
    let client = DynamoClient::from_env().await?;
    Ok((dynamodb::repositories(&client).await?, selection))
}
