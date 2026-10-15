//! Persistence for login sessions.

pub mod dynamodb;
pub mod postgres;

use crate::auth::session::Session;
use async_trait::async_trait;

/// How long the immediately-previous refresh secret stays valid after a rotation, so a racing or
/// retried refresh (concurrent tabs, network retry) is honored instead of flagged as token reuse.
const REFRESH_GRACE_SECS: i64 = 30;

/// Parameters for creating a new session.
pub struct NewSession {
    /// The user this session authenticates.
    pub user_id: String,
    /// Tenant the session is scoped to, if any.
    pub active_tenant_id: Option<String>,
    /// SHA-256 (base64url) of the initial refresh secret.
    pub refresh_hash: String,
    /// Snapshot of `user.tokenVersion` at issue.
    pub token_version_at_issue: u32,
    /// Whether the login used a passkey / a TOTP second factor (persisted for refresh re-minting).
    pub mfa_passkey: bool,
    pub mfa_totp: bool,
    /// Session lifetime in seconds.
    pub ttl_secs: i64,
    /// Best-effort captured `User-Agent`.
    pub user_agent: Option<String>,
    /// Best-effort captured client IP.
    pub ip: Option<String>,
}

/// Persistence interface for login sessions.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait SessionRepository: Send + Sync {
    /// Creates a session from the given parameters, returning the stored row.
    async fn create_session(&self, new_session: NewSession) -> anyhow::Result<Session>;

    /// Fetches a session by id. `None` if unknown or already deleted.
    async fn get_session(&self, session_id: &str) -> anyhow::Result<Option<Session>>;

    /// Lists all of a user's sessions (via the `ByUserIndex` GSI), newest activity first.
    async fn list_by_user(&self, user_id: &str) -> anyhow::Result<Vec<Session>>;

    /// Rotates a session's refresh secret and extends its lifetime (bumps `lastSeen`).
    async fn rotate_session(
        &self,
        session_id: &str,
        new_refresh_hash: String,
        ttl_secs: i64,
    ) -> anyhow::Result<()>;

    /// Re-scopes a session to another tenant (cross-tenant admin, `POST /auth/switch-tenant`).
    ///
    /// The switch is session state rather than a one-off token, so every later
    /// `/auth/refresh` follows it and a page reload does not lose it. `rotate_session`
    /// deliberately does not touch this field, so the switch survives refresh rotation.
    ///
    /// Passing the user's home tenant switches back.
    async fn set_active_tenant(&self, session_id: &str, tenant_id: &str) -> anyhow::Result<()>;

    /// Deletes a session (single-device logout, or reuse-detection response).
    async fn delete_session(&self, session_id: &str) -> anyhow::Result<()>;

    /// Deletes every session a user holds, returning how many there were. For deleting the user.
    async fn delete_all_for_user(&self, user_id: &str) -> anyhow::Result<usize>;
}
