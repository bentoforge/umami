//! Server-side sessions backing the refresh-cookie flow.
//!
//! One `sessions` row per active login (device/browser). The refresh cookie carries
//! `"<sessionId>.<refreshSecret>"`; only the SHA-256 hash of the secret is stored, and refresh
//! rotates the secret. `expiresAt` bounds the session in code; a numeric `ttl` attribute is
//! written so a DynamoDB TTL can self-clean expired rows once enabled out-of-band.

pub mod repository;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Number of random bytes in a refresh secret (256 bits of entropy).
const REFRESH_SECRET_BYTES: usize = 32;

/// Default target API for sessions created before `api_code` existed: the umami admin API.
fn default_session_api() -> String {
    "umami".to_owned()
}

/// A persisted login session.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    /// Primary key — the id carried (in plaintext) by the refresh cookie.
    pub session_id: String,
    /// The user this session authenticates.
    pub user_id: String,
    /// Tenant the session is currently scoped to (drives the token's `tenant` claim). `None`
    /// until the user selects/has a tenant (memberships arrive in Phase 3).
    pub active_tenant_id: Option<String>,
    /// Target API code this session mints access tokens for (see `docs/AUDIENCES.md`), chosen at
    /// login. `refresh` re-mints for the same API. Defaults to `"umami"` for older rows.
    #[serde(default = "default_session_api")]
    pub api_code: String,
    /// SHA-256 (base64url) of the current refresh secret. The secret itself is never stored.
    pub refresh_hash: String,
    /// The immediately-previous refresh hash, kept briefly after a rotation so a racing/retried
    /// refresh presenting the just-rotated-out secret is honored (grace) instead of mistaken for
    /// token theft. `None` before the first rotation.
    #[serde(default)]
    pub prev_refresh_hash: Option<String>,
    /// Deadline until which [`prev_refresh_hash`] is accepted. `None` = no grace window active.
    #[serde(default)]
    pub prev_refresh_expires_at: Option<DateTime<Utc>>,
    /// Snapshot of `user.tokenVersion` at issue; a global bump invalidates this session at refresh.
    pub token_version_at_issue: u32,
    /// Whether this session authenticated with a passkey — re-applied as `is:passkey`/`is:2fa` on
    /// every refresh so the auth-strength markers survive token rotation.
    #[serde(default)]
    pub mfa_passkey: bool,
    /// Whether this session authenticated with a TOTP second factor (re-applied as `is:totp`/`is:2fa`).
    #[serde(default)]
    pub mfa_totp: bool,
    /// Optional best-effort device metadata for a future device list.
    pub user_agent: Option<String>,
    /// Best-effort client IP captured at creation.
    pub ip: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created: DateTime<Utc>,
    /// Updated on every successful refresh.
    pub last_seen: DateTime<Utc>,
    /// Absolute expiry; refresh past this fails.
    pub expires_at: DateTime<Utc>,
    /// Epoch-seconds mirror of `expires_at` for a DynamoDB TTL (enabled out-of-band).
    pub ttl: i64,
}

impl Session {
    /// Returns `true` if the session's absolute expiry has passed.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// Generates a high-entropy refresh secret (base64url, no padding).
pub fn generate_refresh_secret() -> String {
    let mut bytes = [0u8; REFRESH_SECRET_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hashes a refresh secret for storage (SHA-256, base64url).
pub fn hash_refresh_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Constant-time check of a candidate secret against a stored hash.
pub fn verify_refresh_secret(secret: &str, stored_hash: &str) -> bool {
    let computed = hash_refresh_secret(secret);
    computed.as_bytes().ct_eq(stored_hash.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_secret_roundtrips_and_rejects_tampering() {
        let secret = generate_refresh_secret();
        let hash = hash_refresh_secret(&secret);
        assert!(verify_refresh_secret(&secret, &hash));
        assert!(!verify_refresh_secret("tampered", &hash));
    }

    #[test]
    fn distinct_secrets_have_distinct_hashes() {
        let a = generate_refresh_secret();
        let b = generate_refresh_secret();
        assert_ne!(a, b);
        assert_ne!(hash_refresh_secret(&a), hash_refresh_secret(&b));
    }
}
