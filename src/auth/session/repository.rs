//! DynamoDB persistence for login sessions.

use crate::auth::session::Session;
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType,
};
use chrono::{Duration, SecondsFormat, Utc};
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, find_all, generate_id, str};

/// How long the immediately-previous refresh secret stays valid after a rotation, so a racing or
/// retried refresh (concurrent tabs, network retry) is honored instead of flagged as token reuse.
const REFRESH_GRACE_SECS: i64 = 30;

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
            refresh_hash: new_session.refresh_hash,
            prev_refresh_hash: None,
            prev_refresh_expires_at: None,
            token_version_at_issue: new_session.token_version_at_issue,
            mfa_passkey: new_session.mfa_passkey,
            mfa_totp: new_session.mfa_totp,
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
        let grace_until = now + Duration::seconds(REFRESH_GRACE_SECS);

        let _ = self
            .client
            .update_item(TABLE_SESSIONS)
            .key(FIELD_SESSION_ID, str(session_id))
            // RHS reads pre-update values, so `#prevRefreshHash = #refreshHash` snapshots the
            // outgoing hash before it is overwritten — that's the short grace window.
            .update_expression(
                "SET #prevRefreshHash = #refreshHash, \
                       #prevRefreshExpiresAt = :graceUntil, \
                       #refreshHash = :refreshHash, \
                       #lastSeen = :lastSeen, \
                       #expiresAt = :expiresAt, \
                       #ttl = :ttl",
            )
            .condition_expression("attribute_exists(#sessionId)")
            .expression_attribute_names("#sessionId", FIELD_SESSION_ID)
            .expression_attribute_names("#refreshHash", "refreshHash")
            .expression_attribute_names("#prevRefreshHash", "prevRefreshHash")
            .expression_attribute_names("#prevRefreshExpiresAt", "prevRefreshExpiresAt")
            .expression_attribute_names("#lastSeen", "lastSeen")
            .expression_attribute_names("#expiresAt", "expiresAt")
            .expression_attribute_names("#ttl", "ttl")
            .expression_attribute_values(":refreshHash", str(new_refresh_hash))
            .expression_attribute_values(
                ":graceUntil",
                str(grace_until.to_rfc3339_opts(SecondsFormat::Millis, true)),
            )
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
