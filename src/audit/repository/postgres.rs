//! PostgreSQL persistence for the audit log.
//!
//! One append-only table, `audit_log`, keyed by `id`. The DynamoDB GSIs become the indices
//! `(user_id, recorded_at, id)` and `(tenant_id, recorded_at, id)`: a page is a keyset scan newest
//! first, and the cursor is the `(timestamp, id)` of the last entry handed out, encoded exactly
//! like the DynamoDB backend's. Retention is `expires_at`, filtered on every read and swept on
//! every append.

use super::{AuditRepository, DEFAULT_RETENTION_DAYS, decode_cursor, encode_cursor};
use crate::audit::{AuditEntry, NewAuditEntry};
use crate::storage::postgres::{COLUMN_DATA, ensure_table, from_row, to_data};
use anyhow::Context;
use async_trait::async_trait;
use chrono::{DateTime, Duration, SecondsFormat, SubsecRound, Utc};
use std::env;
use std::sync::LazyLock;
use wasabi::aws::dynamodb::generate_id;
use wasabi::postgres::tokio_postgres::types::ToSql;
use wasabi::postgres::{self, Column, ColumnType, Database, Index, Table};
use wasabi::record;

const TABLE_AUDIT: &str = "audit_log";
const COLUMN_ID: &str = "id";
/// The acting user; `NULL` when unknown, which keeps the entry out of every per-user listing.
const COLUMN_USER_ID: &str = "user_id";
/// The owning tenant; `NULL` when unknown, which keeps the entry out of every per-tenant listing.
const COLUMN_TENANT_ID: &str = "tenant_id";
/// The entry's `timestamp`, typed. Truncated to the millisecond precision of the RFC 3339 string
/// in `data`, so a cursor rebuilt from that string compares equal to the column it came from.
const COLUMN_RECORDED_AT: &str = "recorded_at";
const COLUMN_EXPIRES_AT: &str = "expires_at";

/// Expired rows removed per append. Every expired row was once an append, so a bounded batch per
/// append keeps pace with expiry without ever turning one write into a long delete.
const SWEEP_BATCH: i64 = 100;

static AUDIT: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_AUDIT)
        .column(Column::new(COLUMN_ID, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_USER_ID, ColumnType::Text))
        .column(Column::new(COLUMN_TENANT_ID, ColumnType::Text))
        .column(Column::new(COLUMN_RECORDED_AT, ColumnType::TimestampTz).not_null())
        .column(Column::new(COLUMN_EXPIRES_AT, ColumnType::TimestampTz).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_ID])
        .index(Index::new(
            "by_user",
            [COLUMN_USER_ID, COLUMN_RECORDED_AT, COLUMN_ID],
        ))
        .index(Index::new(
            "by_tenant",
            [COLUMN_TENANT_ID, COLUMN_RECORDED_AT, COLUMN_ID],
        ))
        .index(Index::new("by_expiry", [COLUMN_EXPIRES_AT]))
});

/// PostgreSQL-backed implementation of [`AuditRepository`].
#[derive(Clone)]
pub struct PostgresAuditRepository {
    database: Database,
    retention_days: i64,
}

impl PostgresAuditRepository {
    /// Builds the repository, creating or migrating its table. Retention follows
    /// `UMAMI_AUDIT_RETENTION_DAYS` like the DynamoDB backend.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &AUDIT).await?;
        let retention_days = env::var("UMAMI_AUDIT_RETENTION_DAYS")
            .ok()
            .and_then(|raw| raw.trim().parse::<i64>().ok())
            .filter(|days| *days > 0)
            .unwrap_or(DEFAULT_RETENTION_DAYS);
        Ok(Self {
            database: database.clone(),
            retention_days,
        })
    }

    /// Removes a batch of expired entries. Best effort: a failed sweep only delays cleanup, and
    /// auditing must never fail the request it describes over housekeeping.
    async fn sweep_expired(&self, client: &wasabi::postgres::Client) {
        let result = client
            .execute(
                "DELETE FROM audit_log WHERE id IN (
                     SELECT id FROM audit_log WHERE expires_at <= now() LIMIT $1)",
                &[&SWEEP_BATCH],
            )
            .await;
        if let Err(err) = result {
            tracing::debug!("Sweeping expired 'audit_log' rows failed: {err}");
        }
    }

    /// One page of entries whose `key_column` is `key_value`, newest first, resuming after
    /// `cursor`. One row beyond `limit` is read so the next cursor is only offered when another
    /// entry really follows.
    async fn list_page(
        &self,
        key_column: &'static str,
        key_value: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> anyhow::Result<(Vec<AuditEntry>, Option<String>)> {
        let page_size = usize::try_from(limit.max(1)).context("Invalid audit page size")?;
        let fetch_size = i64::from(limit.max(1)) + 1;
        let after = cursor
            .map(|cursor| -> anyhow::Result<(DateTime<Utc>, String)> {
                let (timestamp, id) = decode_cursor(cursor)?;
                let timestamp = DateTime::parse_from_rfc3339(&timestamp)
                    .context("Invalid audit cursor")?
                    .with_timezone(&Utc);
                Ok((timestamp, id))
            })
            .transpose()?;

        // `key_column` is one of this module's constants, never input, so formatting it into the
        // statement is safe; every value is bound.
        let client = self.database.client().await?;
        let rows = match &after {
            Some((timestamp, id)) => {
                let sql = format!(
                    "SELECT data FROM audit_log
                     WHERE {key_column} = $1 AND expires_at > now()
                       AND (recorded_at, id) < ($2, $3)
                     ORDER BY recorded_at DESC, id DESC LIMIT $4"
                );
                let params: [&(dyn ToSql + Sync); 4] = [&key_value, timestamp, id, &fetch_size];
                client.query(&sql, &params).await
            }
            None => {
                let sql = format!(
                    "SELECT data FROM audit_log
                     WHERE {key_column} = $1 AND expires_at > now()
                     ORDER BY recorded_at DESC, id DESC LIMIT $2"
                );
                client.query(&sql, &[&key_value, &fetch_size]).await
            }
        }
        .context("Error listing 'audit_log'")?;

        let mut entries = rows
            .iter()
            .map(from_row)
            .collect::<anyhow::Result<Vec<AuditEntry>>>()?;
        let has_more = entries.len() > page_size;
        entries.truncate(page_size);
        let next = match entries.last() {
            Some(last) if has_more => Some(encode_cursor(&last.timestamp, &last.id)),
            _ => None,
        };
        Ok((entries, next))
    }
}

#[async_trait]
impl AuditRepository for PostgresAuditRepository {
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn record(&self, entry: NewAuditEntry) -> anyhow::Result<()> {
        let now = Utc::now().trunc_subsecs(3);
        let expires_at = (now + Duration::days(self.retention_days)).trunc_subsecs(0);
        let audit = AuditEntry {
            id: String::new(),
            timestamp: now.to_rfc3339_opts(SecondsFormat::Millis, true),
            tenant: entry.tenant,
            user: entry.user,
            severity: entry.severity,
            message: entry.message,
            ip: entry.ip,
            ttl: expires_at.timestamp(),
        };

        let client = self.database.client().await?;
        self.sweep_expired(&client).await;
        // An entry is never worth losing to an id collision: each attempt draws a fresh id.
        let (client, audit) = (&client, &audit);
        let _ = postgres::retry(|| async move {
            let audit = AuditEntry {
                id: generate_id(),
                ..audit.clone()
            };
            AUDIT
                .insert(
                    client,
                    record! {
                        COLUMN_ID => audit.id.as_str(),
                        COLUMN_USER_ID => audit.user.clone(),
                        COLUMN_TENANT_ID => audit.tenant.clone(),
                        COLUMN_RECORDED_AT => now,
                        COLUMN_EXPIRES_AT => expires_at,
                        COLUMN_DATA => to_data(&audit)?,
                    },
                )
                .await
        })
        .await
        .context("Error inserting into 'audit_log'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_by_user(
        &self,
        user_id: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> anyhow::Result<(Vec<AuditEntry>, Option<String>)> {
        self.list_page(COLUMN_USER_ID, user_id, limit, cursor).await
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_by_tenant(
        &self,
        tenant_id: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> anyhow::Result<(Vec<AuditEntry>, Option<String>)> {
        self.list_page(COLUMN_TENANT_ID, tenant_id, limit, cursor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditSeverity;
    use crate::storage::postgres::test::database;

    fn entry(tenant: Option<&str>, user: Option<&str>, message: &str) -> NewAuditEntry {
        NewAuditEntry::new(
            AuditSeverity::Neutral,
            tenant.map(str::to_owned),
            user.map(str::to_owned),
            message,
        )
        .with_ip(Some("127.0.0.1".to_owned()))
    }

    /// Plants an entry with a chosen time and id, to pin down ordering and expiry.
    async fn plant(database: &Database, id: &str, user: &str, at: DateTime<Utc>, expired: bool) {
        let expires_at = if expired {
            Utc::now() - Duration::seconds(1)
        } else {
            Utc::now() + Duration::days(1)
        };
        let audit = AuditEntry {
            id: id.to_owned(),
            timestamp: at.to_rfc3339_opts(SecondsFormat::Millis, true),
            tenant: None,
            user: Some(user.to_owned()),
            severity: AuditSeverity::Good,
            message: id.to_owned(),
            ip: None,
            ttl: expires_at.timestamp(),
        };
        let client = database.client().await.unwrap();
        let _ = AUDIT
            .insert(
                &client,
                record! {
                    COLUMN_ID => id,
                    COLUMN_USER_ID => user,
                    COLUMN_TENANT_ID => None::<String>,
                    COLUMN_RECORDED_AT => at,
                    COLUMN_EXPIRES_AT => expires_at,
                    COLUMN_DATA => to_data(&audit).unwrap(),
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn entries_page_newest_first_per_user_and_tenant() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresAuditRepository::with_database(&database)
            .await
            .unwrap();

        for index in 0..5 {
            repository
                .record(entry(Some("t1"), Some("u1"), &format!("event {index}")))
                .await
                .unwrap();
            // Distinct milliseconds, so the expected order does not hinge on the id tie-break.
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        repository
            .record(entry(None, Some("u2"), "no tenant"))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        repository
            .record(entry(Some("t1"), None, "no user"))
            .await
            .unwrap();

        let mut messages = Vec::new();
        let mut cursor = None;
        loop {
            let (page, next) = repository
                .list_by_user("u1", 2, cursor.as_deref())
                .await
                .unwrap();
            assert!(page.len() <= 2);
            messages.extend(page.into_iter().map(|entry| entry.message));
            match next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        assert_eq!(
            messages,
            ["event 4", "event 3", "event 2", "event 1", "event 0"]
        );

        let (page, next) = repository.list_by_tenant("t1", 10, None).await.unwrap();
        assert_eq!(page.len(), 6);
        assert!(next.is_none());
        assert_eq!(page[0].message, "no user");
        assert_eq!(page[0].ip.as_deref(), Some("127.0.0.1"));

        // An exactly full page offers no cursor when nothing follows.
        let (page, next) = repository.list_by_user("u2", 1, None).await.unwrap();
        assert_eq!(page.len(), 1);
        assert!(page[0].tenant.is_none());
        assert!(next.is_none());

        assert!(
            repository
                .list_by_user("u1", 2, Some("not a cursor"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn equal_timestamps_page_without_loss_and_expired_entries_vanish() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresAuditRepository::with_database(&database)
            .await
            .unwrap();

        let at = Utc::now().trunc_subsecs(3);
        for id in ["a", "b", "c", "d"] {
            plant(&database, id, "u1", at, false).await;
        }
        plant(&database, "old", "u1", at - Duration::seconds(10), true).await;

        let (first, cursor) = repository.list_by_user("u1", 3, None).await.unwrap();
        let (second, last) = repository
            .list_by_user("u1", 3, cursor.as_deref())
            .await
            .unwrap();
        let ids = first
            .iter()
            .chain(&second)
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["d", "c", "b", "a"]);
        assert!(last.is_none());

        // The next append sweeps the expired row out of the table.
        repository
            .record(entry(None, Some("u9"), "trigger"))
            .await
            .unwrap();
        let client = database.client().await.unwrap();
        assert!(
            AUDIT
                .select(&client, record! { COLUMN_ID => "old" })
                .await
                .unwrap()
                .is_empty()
        );
    }
}
