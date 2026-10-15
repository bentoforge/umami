//! PostgreSQL persistence for rate-limit counters and blocks.
//!
//! One table, keyed by the opaque item id the [`RateLimiter`](crate::auth::ratelimit::RateLimiter)
//! builds, holding counters and blocks side by side exactly like the DynamoDB `rate-limits` table.
//!
//! There is no `data` column: an item is nothing but a handful of scalars that every statement
//! reads or writes individually (the counter is bumped in place, never rewritten whole), so typed
//! columns *are* the entity and a JSON copy would only be a second place to keep in sync.
//!
//! Expiry stands in for DynamoDB's TTL: every read ignores rows past `expires_at`, and an expired
//! row that is written again starts from scratch instead of resuming its old count — which is what
//! the TTL means. Dead rows are swept opportunistically by a sample of writes, so the hot
//! `increment` path does not pay for a sweep on every login.

use super::{BlockRecord, RateLimitRepository, StoredItem};
use crate::storage::postgres::ensure_table;
use anyhow::Context;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::LazyLock;
use wasabi::postgres::{Column, ColumnType, Database, Index, Table};

const TABLE_RATE_LIMITS: &str = "rate_limits";
const COLUMN_ID: &str = "id";
const COLUMN_COUNT: &str = "count";
const COLUMN_BLOCKED_UNTIL: &str = "blocked_until";
const COLUMN_BLOCKED_AT: &str = "blocked_at";
const COLUMN_POLICY: &str = "policy";
const COLUMN_SUBJECT: &str = "subject";
const COLUMN_EXPIRES_AT: &str = "expires_at";

/// One in this many writes sweeps expired rows. Counters are written on every login and token
/// exchange, so sweeping on each would double the statements of the hottest path for no gain.
const SWEEP_ONE_IN: u32 = 32;
/// Upper bound on rows one sweep deletes, so a sweep never turns into a long-running statement.
const SWEEP_BATCH: i64 = 500;

static RATE_LIMITS: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_RATE_LIMITS)
        .column(Column::new(COLUMN_ID, ColumnType::Text))
        .column(Column::new(COLUMN_COUNT, ColumnType::BigInt))
        .column(Column::new(COLUMN_BLOCKED_UNTIL, ColumnType::BigInt))
        .column(Column::new(COLUMN_BLOCKED_AT, ColumnType::BigInt))
        .column(Column::new(COLUMN_POLICY, ColumnType::Text))
        .column(Column::new(COLUMN_SUBJECT, ColumnType::Text))
        .column(Column::new(COLUMN_EXPIRES_AT, ColumnType::TimestampTz).not_null())
        .primary_key([COLUMN_ID])
        // Serves the admin overview only; counters carry no policy, so they never match it.
        .index(Index::new(
            "blocks_by_policy",
            [COLUMN_POLICY, COLUMN_BLOCKED_AT],
        ))
        .index(Index::new("by_expiry", [COLUMN_EXPIRES_AT]))
});

/// PostgreSQL-backed implementation of [`RateLimitRepository`].
#[derive(Clone)]
pub struct PostgresRateLimitRepository {
    database: Database,
}

impl PostgresRateLimitRepository {
    /// Builds the repository, creating or migrating its table.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &RATE_LIMITS).await?;
        Ok(Self {
            database: database.clone(),
        })
    }

    /// Sweeps on a sample of calls. Best-effort: a failed sweep leaves rows that every read
    /// already ignores, so it must never fail the write it rides on.
    async fn maybe_sweep(&self) {
        if rand::random_range(0..SWEEP_ONE_IN) != 0 {
            return;
        }
        if let Err(err) = self.sweep().await {
            tracing::warn!("rate-limit sweep failed (ignored): {err:#}");
        }
    }

    /// Deletes a bounded batch of expired rows, returning how many went.
    async fn sweep(&self) -> anyhow::Result<u64> {
        let client = self.database.client().await?;
        // SKIP LOCKED: a row an `increment` is reviving right now is left to it, so the sweep
        // neither waits on nor deletes from under a live write. A row it does lock and delete is
        // simply re-inserted by an `increment` waiting on it.
        client
            .execute(
                "DELETE FROM rate_limits WHERE id IN (
                     SELECT id FROM rate_limits WHERE expires_at <= now()
                     LIMIT $1 FOR UPDATE SKIP LOCKED)",
                &[&SWEEP_BATCH],
            )
            .await
            .context("Error sweeping expired rows from 'rate_limits'")
    }
}

/// An epoch-seconds TTL as the timestamp the `expires_at` column stores.
fn expiry(ttl_epoch: i64) -> anyhow::Result<DateTime<Utc>> {
    DateTime::from_timestamp(ttl_epoch, 0)
        .with_context(|| format!("TTL epoch {ttl_epoch} is out of range"))
}

#[async_trait]
impl RateLimitRepository for PostgresRateLimitRepository {
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn increment(&self, id: &str, ttl_epoch: i64) -> anyhow::Result<u64> {
        // One statement, so concurrent increments serialise on the row lock and each sees the
        // count its own +1 produced — the equivalent of DynamoDB's `ADD`. An expired row is
        // logically gone, so it restarts at 1 and sheds any stale block columns with it.
        let client = self.database.client().await?;
        let row = client
            .query_one(
                "INSERT INTO rate_limits AS t (id, count, expires_at) VALUES ($1, 1, $2)
                 ON CONFLICT (id) DO UPDATE SET
                     count = CASE WHEN t.expires_at <= now() THEN 1
                                  ELSE COALESCE(t.count, 0) + 1 END,
                     blocked_until = CASE WHEN t.expires_at <= now() THEN NULL
                                          ELSE t.blocked_until END,
                     blocked_at = CASE WHEN t.expires_at <= now() THEN NULL ELSE t.blocked_at END,
                     policy = CASE WHEN t.expires_at <= now() THEN NULL ELSE t.policy END,
                     subject = CASE WHEN t.expires_at <= now() THEN NULL ELSE t.subject END,
                     expires_at = EXCLUDED.expires_at
                 RETURNING count",
                &[&id, &expiry(ttl_epoch)?],
            )
            .await
            .context("Error incrementing rate-limit counter")?;
        drop(client);

        let count: i64 = row
            .try_get(COLUMN_COUNT)
            .context("Increment did not return the new rate-limit count")?;
        let count = u64::try_from(count).context("Rate-limit count is negative")?;
        self.maybe_sweep().await;
        Ok(count)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn get_block(&self, id: &str) -> anyhow::Result<Option<i64>> {
        let client = self.database.client().await?;
        let row = client
            .query_opt(
                "SELECT blocked_until FROM rate_limits WHERE id = $1 AND expires_at > now()",
                &[&id],
            )
            .await
            .context("Error reading rate-limit block")?;
        match row {
            Some(row) => row
                .try_get::<_, Option<i64>>(COLUMN_BLOCKED_UNTIL)
                .context("Unreadable 'blocked_until' in 'rate_limits'"),
            None => Ok(None),
        }
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn set_block(
        &self,
        id: &str,
        policy: &str,
        subject: &str,
        blocked_at: i64,
        blocked_until: i64,
        ttl_epoch: i64,
    ) -> anyhow::Result<()> {
        // Like DynamoDB's `SET`, a live counter on the same id keeps its value; an expired one is
        // dropped rather than resurrected by the block's fresh expiry.
        let client = self.database.client().await?;
        let _ = client
            .execute(
                "INSERT INTO rate_limits AS t
                     (id, blocked_until, blocked_at, policy, subject, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (id) DO UPDATE SET
                     count = CASE WHEN t.expires_at <= now() THEN NULL ELSE t.count END,
                     blocked_until = EXCLUDED.blocked_until,
                     blocked_at = EXCLUDED.blocked_at,
                     policy = EXCLUDED.policy,
                     subject = EXCLUDED.subject,
                     expires_at = EXCLUDED.expires_at",
                &[
                    &id,
                    &blocked_until,
                    &blocked_at,
                    &policy,
                    &subject,
                    &expiry(ttl_epoch)?,
                ],
            )
            .await
            .context("Error setting rate-limit block")?;
        drop(client);
        self.maybe_sweep().await;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn clear(&self, id: &str) -> anyhow::Result<()> {
        let client = self.database.client().await?;
        let _ = client
            .execute("DELETE FROM rate_limits WHERE id = $1", &[&id])
            .await
            .context("Error clearing rate-limit item")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn get_items(&self, ids: &[String]) -> anyhow::Result<HashMap<String, StoredItem>> {
        let client = self.database.client().await?;
        let rows = client
            .query(
                "SELECT id, count, blocked_until, expires_at FROM rate_limits
                 WHERE id = ANY($1) AND expires_at > now()",
                &[&ids],
            )
            .await
            .context("Error reading rate-limit items")?;

        rows.iter()
            .map(|row| {
                let id: String = row.try_get(COLUMN_ID)?;
                let count: Option<i64> = row.try_get(COLUMN_COUNT)?;
                let expires_at: DateTime<Utc> = row.try_get(COLUMN_EXPIRES_AT)?;
                let stored = StoredItem {
                    count: count.map(u64::try_from).transpose()?,
                    blocked_until: row.try_get(COLUMN_BLOCKED_UNTIL)?,
                    expires_at: Some(expires_at.timestamp()),
                };
                Ok((id, stored))
            })
            .collect::<anyhow::Result<_>>()
            .context("Unreadable row in 'rate_limits'")
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_blocks(
        &self,
        policy: &str,
        since_epoch: i64,
        limit: i32,
    ) -> anyhow::Result<Vec<BlockRecord>> {
        let client = self.database.client().await?;
        let rows = client
            .query(
                "SELECT policy, subject, blocked_at, blocked_until FROM rate_limits
                 WHERE policy = $1 AND blocked_at >= $2 AND expires_at > now()
                       AND subject IS NOT NULL AND blocked_until IS NOT NULL
                 ORDER BY blocked_at DESC
                 LIMIT $3",
                &[&policy, &since_epoch, &i64::from(limit.max(1))],
            )
            .await
            .context("Error listing rate-limit blocks")?;

        rows.iter()
            .map(|row| {
                Ok(BlockRecord {
                    policy: row.try_get(COLUMN_POLICY)?,
                    subject: row.try_get(COLUMN_SUBJECT)?,
                    blocked_at: row.try_get(COLUMN_BLOCKED_AT)?,
                    blocked_until: row.try_get(COLUMN_BLOCKED_UNTIL)?,
                })
            })
            .collect::<anyhow::Result<_>>()
            .context("Unreadable block in 'rate_limits'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::postgres::test::database;
    use std::sync::Arc;

    fn in_one_hour() -> i64 {
        Utc::now().timestamp() + 3600
    }

    #[tokio::test]
    async fn counters_and_blocks_round_trip() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresRateLimitRepository::with_database(&database)
            .await
            .unwrap();
        let ttl = in_one_hour();

        assert_eq!(
            repository.increment("v#ip#1.2.3.4#7", ttl).await.unwrap(),
            1
        );
        assert_eq!(
            repository.increment("v#ip#1.2.3.4#7", ttl).await.unwrap(),
            2
        );
        assert_eq!(repository.get_block("b#ip#1.2.3.4").await.unwrap(), None);

        let now = Utc::now().timestamp();
        repository
            .set_block("b#ip#1.2.3.4", "ip", "1.2.3.4", now, now + 300, now + 360)
            .await
            .unwrap();
        repository
            .set_block(
                "b#ip#5.6.7.8",
                "ip",
                "5.6.7.8",
                now - 10,
                now + 290,
                now + 350,
            )
            .await
            .unwrap();
        repository
            .set_block("b#key#k1", "key", "k1", now, now + 300, now + 360)
            .await
            .unwrap();
        assert_eq!(
            repository.get_block("b#ip#1.2.3.4").await.unwrap(),
            Some(now + 300)
        );

        let items = repository
            .get_items(&[
                "v#ip#1.2.3.4#7".to_owned(),
                "b#ip#1.2.3.4".to_owned(),
                "missing".to_owned(),
            ])
            .await
            .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items["v#ip#1.2.3.4#7"],
            StoredItem {
                count: Some(2),
                blocked_until: None,
                expires_at: Some(ttl),
            }
        );
        assert_eq!(items["b#ip#1.2.3.4"].blocked_until, Some(now + 300));
        assert_eq!(items["b#ip#1.2.3.4"].count, None);

        let blocks = repository.list_blocks("ip", now - 60, 10).await.unwrap();
        let subjects: Vec<_> = blocks.iter().map(|block| block.subject.as_str()).collect();
        assert_eq!(subjects, ["1.2.3.4", "5.6.7.8"], "newest first, one policy");
        assert_eq!(
            repository
                .list_blocks("ip", now - 60, 1)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            repository
                .list_blocks("ip", now - 5, 10)
                .await
                .unwrap()
                .len(),
            1
        );

        repository.clear("b#ip#1.2.3.4").await.unwrap();
        repository.clear("v#ip#1.2.3.4#7").await.unwrap();
        assert_eq!(repository.get_block("b#ip#1.2.3.4").await.unwrap(), None);
        assert_eq!(
            repository.increment("v#ip#1.2.3.4#7", ttl).await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn expired_items_are_invisible_and_restart() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresRateLimitRepository::with_database(&database)
            .await
            .unwrap();
        let past = Utc::now().timestamp() - 10;

        assert_eq!(repository.increment("f#login#u1", past).await.unwrap(), 1);
        assert_eq!(repository.increment("f#login#u1", past).await.unwrap(), 1);
        assert!(
            repository
                .get_items(&["f#login#u1".to_owned()])
                .await
                .unwrap()
                .is_empty()
        );

        repository
            .set_block("b#login#u1", "login", "u1", past - 100, past - 50, past)
            .await
            .unwrap();
        assert_eq!(repository.get_block("b#login#u1").await.unwrap(), None);
        assert!(
            repository
                .list_blocks("login", 0, 10)
                .await
                .unwrap()
                .is_empty()
        );

        // The sweep removes only what has expired (a sampled sweep may already have run).
        let _ = repository
            .increment("v#ip#live#1", in_one_hour())
            .await
            .unwrap();
        let _ = repository.sweep().await.unwrap();
        assert_eq!(repository.sweep().await.unwrap(), 0);
        let client = database.client().await.unwrap();
        let ids: Vec<String> = client
            .query("SELECT id FROM rate_limits", &[])
            .await
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(ids, ["v#ip#live#1"]);

        // A live write over an expired counter starts it afresh.
        assert_eq!(
            repository
                .increment("f#login#u1", in_one_hour())
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn concurrent_increments_are_exact() {
        let Some(database) = database().await else {
            return;
        };
        let repository = Arc::new(
            PostgresRateLimitRepository::with_database(&database)
                .await
                .unwrap(),
        );
        let ttl = in_one_hour();

        let tasks: Vec<_> = (0..40)
            .map(|_| {
                let repository = repository.clone();
                tokio::spawn(async move { repository.increment("v#ip#hot#1", ttl).await.unwrap() })
            })
            .collect();
        let mut counts = Vec::new();
        for task in tasks {
            counts.push(task.await.unwrap());
        }
        counts.sort_unstable();

        // Every caller saw a distinct count, so a limit of N lets exactly N through.
        assert_eq!(counts, (1..=40).collect::<Vec<u64>>());
        let allowed = counts.iter().filter(|count| **count <= 10).count();
        assert_eq!(allowed, 10);
    }
}
