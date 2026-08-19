//! Server-side sessions backing the refresh-cookie flow.
//!
//! One `sessions` row per active login (device/browser). The refresh cookie carries
//! `"<sessionId>.<refreshSecret>"`; only the SHA-256 hash of the secret is stored, and refresh
//! rotates the secret. `expiresAt` bounds the session in code; a numeric `ttl` attribute is
//! written so a DynamoDB TTL can self-clean expired rows once enabled out-of-band.

use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, find_all, generate_id, str};

/// Number of random bytes in a refresh secret (256 bits of entropy).
const REFRESH_SECRET_BYTES: usize = 32;

/// Default target API for sessions created before `api_code` existed: the umami admin API.
fn default_session_api() -> String {
    "umami".to_owned()
}

// ── Table + field names ─────────────────────────────────────────────────────────

/// Table storing one row per active login.
const TABLE_SESSIONS: &str = "sessions";

/// Hash key of the `sessions` table.
const FIELD_SESSION_ID: &str = "sessionId";

/// GSI hash key — the owning user, to list all of a user's sessions.
const FIELD_USER_ID: &str = "userId";

/// GSI range key — recency (`lastSeen`), so a user's sessions sort newest-first.
const FIELD_LAST_SEEN: &str = "lastSeen";

/// GSI listing a user's sessions by recent activity.
const INDEX_BY_USER: &str = "ByUserIndex";

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
    /// Snapshot of `user.tokenVersion` at issue; a global bump invalidates this session at refresh.
    pub token_version_at_issue: u32,
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

/// Parameters for creating a new session.
pub struct NewSession {
    /// The user this session authenticates.
    pub user_id: String,
    /// Tenant the session is scoped to, if any.
    pub active_tenant_id: Option<String>,
    /// Target API code this session mints tokens for (`refresh` reuses it).
    pub api_code: String,
    /// SHA-256 (base64url) of the initial refresh secret.
    pub refresh_hash: String,
    /// Snapshot of `user.tokenVersion` at issue.
    pub token_version_at_issue: u32,
    /// Session lifetime in seconds.
    pub ttl_secs: i64,
    /// Best-effort captured `User-Agent`.
    pub user_agent: Option<String>,
    /// Best-effort captured client IP.
    pub ip: Option<String>,
}

/// Persistence interface for login sessions.
#[async_trait]
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

    /// Deletes a session (single-device logout, or reuse-detection response).
    async fn delete_session(&self, session_id: &str) -> anyhow::Result<()>;
}

/// DynamoDB-backed implementation of [`SessionRepository`].
#[derive(Clone)]
pub struct DynamoSessionRepository {
    client: DynamoClient,
}

impl DynamoSessionRepository {
    #[tracing::instrument(skip(client), err(Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_SESSIONS, |table| {
                let by_user = GlobalSecondaryIndex::builder()
                    .index_name(INDEX_BY_USER)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(FIELD_USER_ID)
                            .key_type(KeyType::Hash)
                            .build()?,
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(FIELD_LAST_SEEN)
                            .key_type(KeyType::Range)
                            .build()?,
                    )
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .build()?;

                let table = table
                    .attribute_definitions(str_attribute(FIELD_SESSION_ID)?)
                    .attribute_definitions(str_attribute(FIELD_USER_ID)?)
                    .attribute_definitions(str_attribute(FIELD_LAST_SEEN)?);
                let table = with_hash_index(table, FIELD_SESSION_ID)?;
                Ok(table
                    .global_secondary_indexes(by_user)
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        Ok(Self {
            client: client.clone(),
        })
    }
}

#[async_trait]
impl SessionRepository for DynamoSessionRepository {
    #[tracing::instrument(level = "debug", skip(self, new_session), err(Display))]
    async fn create_session(&self, new_session: NewSession) -> anyhow::Result<Session> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(new_session.ttl_secs);

        let session = Session {
            session_id: generate_id(),
            user_id: new_session.user_id,
            active_tenant_id: new_session.active_tenant_id,
            api_code: new_session.api_code,
            refresh_hash: new_session.refresh_hash,
            token_version_at_issue: new_session.token_version_at_issue,
            user_agent: new_session.user_agent,
            ip: new_session.ip,
            created: now,
            last_seen: now,
            expires_at,
            ttl: expires_at.timestamp(),
        };

        // Defensive: the id is the PK — `attribute_not_exists` makes an id collision fail loudly
        // instead of clobbering an existing session, for free.
        let _ = self
            .client
            .put_entity(TABLE_SESSIONS, &session)?
            .condition_expression("attribute_not_exists(#sessionId)")
            .expression_attribute_names("#sessionId", FIELD_SESSION_ID)
            .send()
            .await
            .context("Error inserting entity into 'sessions' table (id collision?)")?;

        Ok(session)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn get_session(&self, session_id: &str) -> anyhow::Result<Option<Session>> {
        let result = self
            .client
            .get_item(TABLE_SESSIONS)
            .key(FIELD_SESSION_ID, str(session_id))
            .send()
            .await
            .context("Error searching table 'sessions'")?;

        deserialize_entity(result.item)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn list_by_user(&self, user_id: &str) -> anyhow::Result<Vec<Session>> {
        let query = self
            .client
            .query(TABLE_SESSIONS)
            .index_name(INDEX_BY_USER)
            .key_condition_expression("#userId = :userId")
            .expression_attribute_names("#userId", FIELD_USER_ID)
            .expression_attribute_values(":userId", str(user_id))
            .scan_index_forward(false)
            .limit(100);

        find_all(query)
            .await
            .context("Error listing sessions by user")
    }

    #[tracing::instrument(level = "debug", skip(self, new_refresh_hash), err(Display))]
    async fn rotate_session(
        &self,
        session_id: &str,
        new_refresh_hash: String,
        ttl_secs: i64,
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_secs);

        let _ = self
            .client
            .update_item(TABLE_SESSIONS)
            .key(FIELD_SESSION_ID, str(session_id))
            .update_expression(
                "SET #refreshHash = :refreshHash, \
                       #lastSeen = :lastSeen, \
                       #expiresAt = :expiresAt, \
                       #ttl = :ttl",
            )
            .condition_expression("attribute_exists(#sessionId)")
            .expression_attribute_names("#sessionId", FIELD_SESSION_ID)
            .expression_attribute_names("#refreshHash", "refreshHash")
            .expression_attribute_names("#lastSeen", "lastSeen")
            .expression_attribute_names("#expiresAt", "expiresAt")
            .expression_attribute_names("#ttl", "ttl")
            .expression_attribute_values(":refreshHash", str(new_refresh_hash))
            .expression_attribute_values(
                ":lastSeen",
                str(now.to_rfc3339_opts(SecondsFormat::Millis, true)),
            )
            .expression_attribute_values(
                ":expiresAt",
                str(expires_at.to_rfc3339_opts(SecondsFormat::Millis, true)),
            )
            .expression_attribute_values(
                ":ttl",
                AttributeValue::N(expires_at.timestamp().to_string()),
            )
            .send()
            .await
            .context("Error updating table 'sessions'")?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn delete_session(&self, session_id: &str) -> anyhow::Result<()> {
        let _ = self
            .client
            .delete_item(TABLE_SESSIONS)
            .key(FIELD_SESSION_ID, str(session_id))
            .send()
            .await
            .context("Error deleting from table 'sessions'")?;

        Ok(())
    }
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
