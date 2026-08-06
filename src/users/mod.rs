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
/// Credentials (`password_hash`) and the revocation counter (`token_version`) live here. The login
/// identifier is the **`username`** — required and globally unique (case-insensitively), guarded by
/// the `user-usernames` lookup table (see [`repository`]). The `email` is optional contact info and
/// is **not** unique.
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
    /// Login identifier — required, globally unique (case-insensitively via the `user-usernames`
    /// guard). Stored as entered (trimmed); uniqueness/lookup use the normalized form.
    pub username: String,
    /// Optional contact email — **not** unique, may be absent. Normalized (trimmed + lowercased)
    /// when present.
    #[serde(default)]
    pub email: Option<String>,
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
    /// Active TOTP secret (AES-GCM encrypted). `Some` means TOTP MFA is enabled.
    #[serde(default)]
    pub totp_secret: Option<String>,
    /// Pending TOTP secret during setup (encrypted), before it is confirmed by a valid code.
    #[serde(default)]
    pub totp_pending: Option<String>,
    /// Values for the config-defined custom user fields.
    #[serde(default)]
    pub custom_fields: std::collections::BTreeMap<String, serde_json::Value>,
    /// RFC 3339 creation timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// RFC 3339 timestamp of the last update to this record.
    pub last_updated: chrono::DateTime<chrono::Utc>,
    /// RFC 3339 timestamp of the user's last authentication (login or refresh); range key of the
    /// per-tenant listing GSI so a tenant's users sort by recency of activity. Defaults to the
    /// epoch for records written before this field existed.
    #[serde(default = "epoch")]
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// The Unix epoch — the `last_seen` fallback for user records predating the field.
fn epoch() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::UNIX_EPOCH
}

/// Normalizes a username for lookup and uniqueness: trims surrounding whitespace and lowercases,
/// so `UMAMI`, `umami`, and ` Umami ` all collide.
pub fn normalize_username(username: &str) -> String {
    username.trim().to_lowercase()
}

/// Normalizes an email for storage: trims surrounding whitespace and lowercases.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}
