//! Audit log: an append-only trail of security-relevant events (logins, token exchanges, …).
//!
//! Backed by DynamoDB via [`repository::AuditRepository`]. Each entry has a unique `id` (table PK)
//! and is queryable by `user` or `tenant` (each a GSI, sorted by `timestamp`). A numeric `ttl`
//! epoch is written on every entry so DynamoDB can expire old rows — **TTL is enabled on the table
//! out-of-band (Terraform), not via wasabi's `create_table`** (same approach as backups).

pub mod repository;
pub mod service;

use serde::{Deserialize, Serialize};

/// Outcome flavour of an audited event.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    /// A successful, expected security event (e.g. login with the correct password).
    Good,
    /// A routine, non-judgemental event (e.g. a token exchange).
    Neutral,
    /// A failed or suspicious event (e.g. a login attempt with the wrong password).
    Bad,
}

/// A persisted audit entry.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    /// Primary key — 32-char generated id.
    pub id: String,
    /// RFC 3339 (millis, UTC, `Z`) event time — also the range key of both GSIs, so the fixed
    /// format sorts chronologically.
    pub timestamp: String,
    /// Owning tenant, when known (GSI hash key; absent → not queryable by tenant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Acting user, when known (GSI hash key; absent → not queryable by user).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Outcome flavour.
    pub severity: AuditSeverity,
    /// Human-readable description. **Never** include secrets/tokens/password hashes.
    pub message: String,
    /// Epoch-seconds expiry for a DynamoDB TTL (enabled out-of-band).
    pub ttl: i64,
}

/// Parameters for recording a new audit entry (the repository stamps `id`, `timestamp`, `ttl`).
#[derive(Debug)]
pub struct NewAuditEntry {
    pub tenant: Option<String>,
    pub user: Option<String>,
    pub severity: AuditSeverity,
    pub message: String,
}

impl NewAuditEntry {
    /// Convenience constructor.
    pub fn new(
        severity: AuditSeverity,
        tenant: Option<String>,
        user: Option<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            tenant,
            user,
            severity,
            message: message.into(),
        }
    }
}
