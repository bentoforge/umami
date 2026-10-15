//! Persistence for messaging links + per-user link codes.

pub mod dynamodb;
pub mod postgres;

use crate::messaging::MessagingLink;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A stored per-user link code (`messaging-codes`).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct CodeEntity {
    code: String,
    user_id: String,
    tenant_id: String,
    created: String,
    /// DynamoDB TTL — **cleanup only**, never the authority on whether a code still works.
    ///
    /// TTL deletion is eventual (AWS allows up to 48 hours), so an expired row can outlive its own
    /// expiry by a day; [`is_fresh`] is what decides, on every read. Same split as the auth
    /// challenges. Without this the row for somebody who generated a code and never used it simply
    /// stayed forever.
    ttl: i64,
}

/// The subject a resolved external identity or code maps to.
#[derive(Debug, Clone)]
pub struct LinkSubject {
    pub user_id: String,
    pub tenant_id: String,
}

/// Persistence for messaging codes + links.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait MessagingRepository: Send + Sync {
    /// Returns the user's current code when it is younger than `ttl_secs`; otherwise mints a fresh
    /// one. The bool is `true` when a new code was generated (so callers can audit only real mints).
    async fn current_code(
        &self,
        user_id: &str,
        tenant_id: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<(String, bool)>;

    /// Replaces the user's code with a fresh one (invalidating the old), returning it.
    async fn regenerate_code(
        &self,
        user_id: &str,
        tenant_id: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<String>;

    /// Atomically **consumes** a link code (single-use): deletes it and, when it existed and was
    /// still within `ttl_secs`, returns its owning subject. Expired/absent → `None` (⇒ reject).
    async fn consume_code(&self, code: &str, ttl_secs: i64) -> anyhow::Result<Option<LinkSubject>>;

    /// Creates a `(platform, externalId) → user` mapping. Idempotent for the same user; a conflict
    /// (already mapped to a different user) is a client error.
    /// Binds `(platform, externalId)` to `subject`, taking it over from whoever held it.
    ///
    /// Returns the subject it displaced, if any — nothing else can learn that afterwards, and it is
    /// what the caller writes into the audit trail.
    async fn create_link(
        &self,
        subject: &LinkSubject,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<Option<LinkSubject>>;

    /// Resolves a `(platform, externalId)` to its subject.
    async fn subject_for_external(
        &self,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<Option<LinkSubject>>;

    /// Lists a user's external-identity mappings.
    async fn list_links(&self, user_id: &str) -> anyhow::Result<Vec<MessagingLink>>;

    /// Removes a `(platform, externalId)` mapping (only if it belongs to `user_id`).
    async fn delete_link(
        &self,
        user_id: &str,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<()>;

    /// Removes every link a user holds **and their pending code**, returning how many links there
    /// were.
    ///
    /// For deleting the user themselves. The code goes with them for a reason of its own: it is a
    /// live bearer token that binds whoever redeems it to this user, so a row outliving the account
    /// is a claim that can still be made on behalf of somebody who no longer exists.
    async fn delete_all_for_user(&self, user_id: &str) -> anyhow::Result<usize>;
}

/// Whether an RFC3339 `created` timestamp is within `ttl_secs` of now (unparseable → expired).
fn is_fresh(created: &str, ttl_secs: i64) -> bool {
    match DateTime::parse_from_rfc3339(created) {
        Ok(ts) => (Utc::now() - ts.with_timezone(&Utc)).num_seconds() < ttl_secs,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_fresh;
    use chrono::{Duration, SecondsFormat, Utc};

    #[test]
    fn freshness_respects_ttl() {
        let recent =
            (Utc::now() - Duration::seconds(60)).to_rfc3339_opts(SecondsFormat::Millis, true);
        let old =
            (Utc::now() - Duration::seconds(1200)).to_rfc3339_opts(SecondsFormat::Millis, true);
        assert!(is_fresh(&recent, 600));
        assert!(!is_fresh(&old, 600));
        assert!(!is_fresh("not-a-timestamp", 600));
    }
}
