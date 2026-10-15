//! PostgreSQL persistence for login sessions.

use super::{NewSession, REFRESH_GRACE_SECS, SessionRepository};
use crate::auth::session::Session;
use crate::storage::postgres::{COLUMN_DATA, ensure_table, from_row, to_data};
use anyhow::Context;
use async_trait::async_trait;
use chrono::{Duration, SecondsFormat, Utc};
use std::sync::LazyLock;
use wasabi::aws::dynamodb::generate_id;
use wasabi::postgres::{self, Client, Column, ColumnType, Database, Index, Record, Table};
use wasabi::record;

const TABLE_SESSIONS: &str = "sessions";
const COLUMN_SESSION_ID: &str = "session_id";
const COLUMN_USER_ID: &str = "user_id";
/// Sort key of a user's session list, newest activity first.
const COLUMN_LAST_SEEN: &str = "last_seen";
const COLUMN_EXPIRES_AT: &str = "expires_at";

static SESSIONS: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_SESSIONS)
        .column(Column::new(COLUMN_SESSION_ID, ColumnType::Text))
        .column(Column::new(COLUMN_USER_ID, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_LAST_SEEN, ColumnType::TimestampTz).not_null())
        .column(Column::new(COLUMN_EXPIRES_AT, ColumnType::TimestampTz).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_SESSION_ID])
        .index(Index::new("by_user", [COLUMN_USER_ID, COLUMN_LAST_SEEN]))
        .index(Index::new("by_expiry", [COLUMN_EXPIRES_AT]))
});

/// PostgreSQL-backed implementation of [`SessionRepository`].
#[derive(Clone)]
pub struct PostgresSessionRepository {
    database: Database,
}

impl PostgresSessionRepository {
    /// Builds the repository, creating or migrating its table.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &SESSIONS).await?;
        Ok(Self {
            database: database.clone(),
        })
    }

    fn row(session: &Session) -> anyhow::Result<Record> {
        Ok(record! {
            COLUMN_SESSION_ID => session.session_id.as_str(),
            COLUMN_USER_ID => session.user_id.as_str(),
            COLUMN_LAST_SEEN => session.last_seen,
            COLUMN_EXPIRES_AT => session.expires_at,
            COLUMN_DATA => to_data(session)?,
        })
    }

    /// Deletes expired sessions — the job DynamoDB's TTL does for the other backend. Reads already
    /// ignore them, so this only keeps the table from growing.
    async fn sweep_expired(client: &Client) -> anyhow::Result<()> {
        let _ = client
            .execute("DELETE FROM sessions WHERE expires_at <= now()", &[])
            .await
            .context("Error sweeping expired 'sessions'")?;
        Ok(())
    }

    /// Runs an update on one live session and fails if there is none. Like the DynamoDB
    /// `attribute_exists` condition, this keeps a write racing a logout from resurrecting the
    /// session; an expired session counts as gone.
    async fn update_live(
        &self,
        sql: &str,
        params: &[&(dyn wasabi::postgres::tokio_postgres::types::ToSql + Sync)],
    ) -> anyhow::Result<()> {
        let client = self.database.client().await?;
        let updated = client
            .execute(sql, params)
            .await
            .context("Error updating table 'sessions'")?;
        if updated == 0 {
            anyhow::bail!("Session does not exist or has expired");
        }
        Ok(())
    }
}

/// A timestamp as stored inside `data`, matching the DynamoDB backend's string form.
fn text(time: chrono::DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    #[tracing::instrument(
        level = "debug",
        skip(self, new_session),
        err(level = "debug", Display)
    )]
    async fn create_session(&self, new_session: NewSession) -> anyhow::Result<Session> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(new_session.ttl_secs);

        let session = Session {
            session_id: String::new(),
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

        let client = self.database.client().await?;
        Self::sweep_expired(&client).await?;
        // The id is the primary key, so a collision fails instead of clobbering a session — and is
        // then drawn again, since the id is ours to choose.
        let (client, template) = (&client, &session);
        let session = postgres::retry(|| async move {
            let session = Session {
                session_id: generate_id(),
                ..template.clone()
            };
            let _ = SESSIONS.insert(client, Self::row(&session)?).await?;
            Ok(session)
        })
        .await
        .context("Error inserting into 'sessions'")?;
        Ok(session)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn get_session(&self, session_id: &str) -> anyhow::Result<Option<Session>> {
        let client = self.database.client().await?;
        client
            .query_opt(
                "SELECT data FROM sessions WHERE session_id = $1 AND expires_at > now()",
                &[&session_id],
            )
            .await
            .context("Error reading 'sessions'")?
            .map(|row| from_row(&row))
            .transpose()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_by_user(&self, user_id: &str) -> anyhow::Result<Vec<Session>> {
        let client = self.database.client().await?;
        client
            .query(
                "SELECT data FROM sessions
                 WHERE user_id = $1 AND expires_at > now()
                 ORDER BY last_seen DESC, session_id",
                &[&user_id],
            )
            .await
            .context("Error listing sessions by user")?
            .iter()
            .map(from_row)
            .collect()
    }

    #[tracing::instrument(
        level = "debug",
        skip(self, new_refresh_hash),
        err(level = "debug", Display)
    )]
    async fn rotate_session(
        &self,
        session_id: &str,
        new_refresh_hash: String,
        ttl_secs: i64,
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_secs);
        let grace_until = now + Duration::seconds(REFRESH_GRACE_SECS);

        // `data->'refreshHash'` on the right-hand side reads the pre-update row, so the outgoing
        // hash is snapshotted into `prevRefreshHash` in the same atomic statement — that is the
        // short grace window.
        self.update_live(
            "UPDATE sessions
             SET last_seen = $2,
                 expires_at = $3,
                 data = data || jsonb_build_object(
                     'prevRefreshHash', data->'refreshHash',
                     'prevRefreshExpiresAt', $4::text,
                     'refreshHash', $5::text,
                     'lastSeen', $6::text,
                     'expiresAt', $7::text,
                     'ttl', $8::bigint)
             WHERE session_id = $1 AND expires_at > now()",
            &[
                &session_id,
                &now,
                &expires_at,
                &text(grace_until),
                &new_refresh_hash,
                &text(now),
                &text(expires_at),
                &expires_at.timestamp(),
            ],
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn set_active_tenant(&self, session_id: &str, tenant_id: &str) -> anyhow::Result<()> {
        // Touches `activeTenantId` and nothing else: the refresh hash, the grace window and the
        // lifetime must survive a tenant switch untouched, or switching would silently log the
        // admin out of every other tab.
        self.update_live(
            "UPDATE sessions
             SET data = data || jsonb_build_object('activeTenantId', $2::text)
             WHERE session_id = $1 AND expires_at > now()",
            &[&session_id, &tenant_id],
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_session(&self, session_id: &str) -> anyhow::Result<()> {
        let client = self.database.client().await?;
        let _ = SESSIONS
            .delete(&client, record! { COLUMN_SESSION_ID => session_id })
            .await
            .context("Error deleting from table 'sessions'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_all_for_user(&self, user_id: &str) -> anyhow::Result<usize> {
        // One statement removes expired leftovers too, but only live sessions count — those are
        // the ones the caller could have seen in `list_by_user`.
        let client = self.database.client().await?;
        let row = client
            .query_one(
                "WITH gone AS (DELETE FROM sessions WHERE user_id = $1 RETURNING expires_at)
                 SELECT count(*) FROM gone WHERE expires_at > now()",
                &[&user_id],
            )
            .await
            .context("Error deleting a user's 'sessions'")?;
        let count: i64 = row.try_get(0).context("Unreadable session count")?;
        usize::try_from(count).context("Session count out of range")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::postgres::test::database;

    fn new_session(user_id: &str, ttl_secs: i64) -> NewSession {
        NewSession {
            user_id: user_id.to_owned(),
            active_tenant_id: Some("t1".to_owned()),
            refresh_hash: "hash-0".to_owned(),
            token_version_at_issue: 3,
            mfa_passkey: true,
            mfa_totp: false,
            ttl_secs,
            user_agent: Some("test".to_owned()),
            ip: None,
        }
    }

    #[tokio::test]
    async fn sessions_rotate_switch_and_expire() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresSessionRepository::with_database(&database)
            .await
            .unwrap();

        let session = repository
            .create_session(new_session("u1", 3600))
            .await
            .unwrap();
        let loaded = repository
            .get_session(&session.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.refresh_hash, "hash-0");
        assert_eq!(loaded.token_version_at_issue, 3);
        assert!(loaded.mfa_passkey);

        repository
            .rotate_session(&session.session_id, "hash-1".to_owned(), 7200)
            .await
            .unwrap();
        let rotated = repository
            .get_session(&session.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rotated.refresh_hash, "hash-1");
        assert_eq!(rotated.prev_refresh_hash.as_deref(), Some("hash-0"));
        assert!(rotated.prev_refresh_expires_at.is_some());
        assert!(rotated.expires_at > loaded.expires_at);
        assert_eq!(rotated.ttl, rotated.expires_at.timestamp());

        repository
            .set_active_tenant(&session.session_id, "t2")
            .await
            .unwrap();
        let switched = repository
            .get_session(&session.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(switched.active_tenant_id.as_deref(), Some("t2"));
        assert_eq!(switched.refresh_hash, "hash-1", "a switch keeps the secret");

        // An already-expired session is invisible and cannot be revived by a write.
        let expired = repository
            .create_session(new_session("u1", -1))
            .await
            .unwrap();
        assert!(
            repository
                .get_session(&expired.session_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .rotate_session(&expired.session_id, "x".to_owned(), 60)
                .await
                .is_err()
        );
        assert!(repository.set_active_tenant("missing", "t2").await.is_err());

        let newer = repository
            .create_session(new_session("u1", 3600))
            .await
            .unwrap();
        let _ = repository
            .create_session(new_session("u2", 3600))
            .await
            .unwrap();
        let listed = repository.list_by_user("u1").await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].session_id, newer.session_id, "newest first");

        repository.delete_session(&newer.session_id).await.unwrap();
        assert_eq!(repository.list_by_user("u1").await.unwrap().len(), 1);
        assert_eq!(repository.delete_all_for_user("u1").await.unwrap(), 1);
        assert!(repository.list_by_user("u1").await.unwrap().is_empty());
        assert_eq!(repository.list_by_user("u2").await.unwrap().len(), 1);
    }
}
