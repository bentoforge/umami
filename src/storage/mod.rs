//! The storage seam: every persistence port umami depends on, resolved as one bundle.
//!
//! ## Why a bundle and not one argument per repository
//!
//! umami talks to its store through ten narrow repository traits, and every one of them is
//! answered by the *same* backend. Nobody keeps users in DynamoDB and sessions in Postgres — a
//! mixed set is not a deployment anyone wants, and pretending it is one costs a constructor
//! argument at every call site (the boot path used to carry ten).
//!
//! Resolving them together also makes a second backend a bounded piece of work: implement the
//! traits, return a [`Repositories`], and the compiler lists what is still missing. A backend that
//! covers nine of ten ports does not compile, rather than starting and failing on the tenth.
//!
//! The repositories themselves stay independent traits — that is what keeps handlers mockable.
//! This bundle exists for the wiring layer only.

pub mod dynamodb;

use crate::boot::aws::Aws;
use crate::boot::seam::{self, Selection};

use crate::audit::repository::AuditRepository;
use crate::auth::apikeys::repository::ApiKeyRepository;
use crate::auth::challenge::ChallengeRepository;
use crate::auth::ratelimit::repository::RateLimitRepository;
use crate::auth::session::repository::SessionRepository;
use crate::auth::webauthn::repository::WebauthnRepository;
use crate::contacts::repository::ContactRepository;
use crate::messaging::repository::MessagingRepository;
use crate::tenants::repository::TenantRepository;
use crate::users::repository::UserRepository;
use anyhow::Context;
use std::sync::Arc;
use wasabi::aws::dynamodb::client::DynamoClient;

/// The seam's name in the boot report.
const SEAM: &str = "storage";
/// The variable that names the backend.
pub const VARIABLE: &str = "UMAMI_STORAGE";
/// DynamoDB, the only backend implemented today.
const DYNAMODB: &str = "dynamodb";
/// Every backend name this build accepts.
const PROVIDERS: &[&str] = &[DYNAMODB];

/// Every repository umami needs, from one backend.
///
/// Cloning clones ten `Arc`s and nothing else, so the wiring layer hands copies out freely.
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
}

/// Resolves the storage backend and builds its repositories.
///
/// The AWS probe is checked before any table is touched. umami cannot run without storage, so an
/// unusable AWS is fatal either way — but failing here says *why* ("credentials are expired"),
/// while failing on the first `with_client` says "Cannot access DynamoDB table
/// 'umami-dev-users'", which reads like a missing table or a bad IAM policy. Once a non-AWS
/// backend exists, this same check is what keeps DynamoDB from winning auto-detection on a host
/// where it could never work.
pub async fn from_env(aws: &Aws) -> anyhow::Result<(Repositories, Selection)> {
    let selection = match seam::requested(VARIABLE) {
        Some(name) if name == DYNAMODB => Selection::explicit(SEAM, VARIABLE, DYNAMODB),
        Some(other) => return Err(seam::unknown_provider(VARIABLE, &other, PROVIDERS)),
        // Nothing to auto-detect while there is one backend — an operator has no choice to make
        // yet, so this is a default rather than a detection.
        None => Selection::default_for(SEAM, VARIABLE, DYNAMODB),
    };

    // A second backend turns this into a match on `selection.provider`, and the check below into
    // "is DynamoDB eligible" rather than "must DynamoDB work".
    aws.require().await.with_context(|| {
        format!("{DYNAMODB} storage needs a usable AWS client, and it is umami's only backend")
    })?;
    let client = DynamoClient::from_env().await?;
    Ok((dynamodb::repositories(&client).await?, selection))
}
