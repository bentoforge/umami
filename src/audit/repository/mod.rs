//! Persistence for the audit log: the [`AuditRepository`] trait, the page cursor its backends
//! share, and best-effort recording.

pub mod dynamodb;
pub mod postgres;

use crate::audit::{AuditEntry, NewAuditEntry};
use anyhow::Context;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Default retention before an entry expires (override with `UMAMI_AUDIT_RETENTION_DAYS`).
const DEFAULT_RETENTION_DAYS: i64 = 365;

/// Persistence for the audit log.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait AuditRepository: Send + Sync {
    /// Appends an audit entry (stamps `id`/`timestamp`/`ttl`).
    async fn record(&self, entry: NewAuditEntry) -> anyhow::Result<()>;

    /// One page of a user's entries, newest first (`limit` per page). `cursor` resumes after a prior
    /// page; returns the page plus the next cursor (`None` when the trail is exhausted).
    async fn list_by_user(
        &self,
        user_id: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> anyhow::Result<(Vec<AuditEntry>, Option<String>)>;

    /// One page of a tenant's entries, newest first (`limit` per page). See `list_by_user`.
    async fn list_by_tenant(
        &self,
        tenant_id: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> anyhow::Result<(Vec<AuditEntry>, Option<String>)>;
}

/// Opaque page cursor over `(timestamp, id)` — unique even across equal timestamps, since `id` is
/// the table PK. Encoded base64url so it survives a query string untouched.
fn encode_cursor(timestamp: &str, id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{timestamp}|{id}"))
}

fn decode_cursor(cursor: &str) -> anyhow::Result<(String, String)> {
    let raw = URL_SAFE_NO_PAD
        .decode(cursor)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .context("Invalid audit cursor")?;
    let (timestamp, id) = raw.split_once('|').context("Invalid audit cursor")?;
    Ok((timestamp.to_owned(), id.to_owned()))
}

/// Fire-and-forget audit recording: logs a warning on failure instead of propagating, so auditing
/// never breaks the request it describes. Callers use this for the happy/most paths.
pub async fn record_best_effort(audit: &std::sync::Arc<dyn AuditRepository>, entry: NewAuditEntry) {
    let severity = entry.severity;
    if let Err(err) = audit.record(entry).await {
        tracing::warn!("failed to write audit entry ({severity:?}): {err:#}");
    }
}
