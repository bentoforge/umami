//! Global user identities.
//!
//! A user is a single identity reusable across tenants; the relationship to tenants and teams is
//! modeled separately via memberships (Phase 3). This module owns the `User` entity, its
//! persistence (`repository`), and the (dev-bootstrap) creation route (`service`).

pub mod repository;
pub mod service;

use serde::{Deserialize, Serialize};

/// Lifecycle state of a user identity.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    /// Normal, usable account.
    Active,
    /// Locked out (e.g. too many failed logins, or an admin action) — cannot log in.
    Locked,
    /// Invited but not yet activated (e.g. no password set) — cannot log in yet.
    Invited,
}

/// A global user identity as stored in DynamoDB.
///
/// Credentials (`password_hash`) and the revocation counter (`token_version`) live here; the
/// `email` is normalized (trimmed + lowercased) and additionally guarded for uniqueness by the
/// `user-emails` lookup table (see [`repository`]).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// Primary key — 32-char generated id.
    pub user_id: String,
    /// The owning (home) tenant. A user belongs to exactly one tenant.
    pub tenant_id: String,
    /// Role codes within the owning tenant (defined in the config catalog); resolve to the token's
    /// permissions. `#[serde(default)]` tolerates older records written before roles were a list.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Normalized login identifier (trimmed + lowercased).
    pub email: String,
    /// Display name.
    pub name: String,
    /// BCP-47 locale tag (e.g. `en-US`), baked into the `locale` token claim.
    pub locale: String,
    /// argon2id hash string. `None` for SSO-only users that never set a password.
    pub password_hash: Option<String>,
    /// Lifecycle state; only [`UserStatus::Active`] users may log in.
    pub status: UserStatus,
    /// Global revocation counter. Bumping it invalidates every session at its next refresh
    /// (see the `sessions` reuse/rotation logic).
    pub token_version: u32,
    /// Values for the config-defined custom user fields.
    #[serde(default)]
    pub custom_fields: std::collections::BTreeMap<String, serde_json::Value>,
    /// RFC 3339 creation timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// RFC 3339 timestamp of the last update to this record.
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Normalizes an email for lookup and uniqueness: trims surrounding whitespace and lowercases.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}
