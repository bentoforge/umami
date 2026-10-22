//! PostgreSQL persistence for single-use mailed challenges.
//!
//! One table, `auth_challenges`, keyed by `sha256(secret)` so a table dump redeems nothing.
//! Consuming is a `DELETE … RETURNING`: the delete *is* the consumption, so of two concurrent
//! clicks on one link exactly one gets the row back.

use super::{
    Challenge, ChallengeRepository, Proven, Purpose, generate_secret, hash_secret, redeemable,
};
use crate::storage::postgres::{COLUMN_DATA, ensure_table, from_row, to_data};
use anyhow::Context;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::sync::LazyLock;
use wasabi::postgres::{Column, ColumnType, Database, Index, Table};
use wasabi::record;

const TABLE_CHALLENGES: &str = "auth_challenges";
const COLUMN_SECRET_HASH: &str = "secret_hash";
const COLUMN_EXPIRES_AT: &str = "expires_at";

/// Expired rows removed per write; bounded so a backlog never turns one issue into a long delete.
const SWEEP_BATCH: i64 = 100;

static CHALLENGES: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_CHALLENGES)
        .column(Column::new(COLUMN_SECRET_HASH, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_EXPIRES_AT, ColumnType::TimestampTz).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_SECRET_HASH])
        .index(Index::new("by_expiry", [COLUMN_EXPIRES_AT]))
});

/// PostgreSQL-backed implementation of [`ChallengeRepository`].
#[derive(Clone)]
pub struct PostgresChallengeRepository {
    database: Database,
}

impl PostgresChallengeRepository {
    /// Builds the repository, creating or migrating its table.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &CHALLENGES).await?;
        Ok(Self {
            database: database.clone(),
        })
    }

    /// Removes a batch of expired challenges. Best effort: a failed sweep only delays cleanup, so
    /// it must not fail the issue that triggered it.
    async fn sweep_expired(&self, client: &wasabi::postgres::Client) {
        let result = client
            .execute(
                "DELETE FROM auth_challenges WHERE secret_hash IN (
                     SELECT secret_hash FROM auth_challenges WHERE expires_at <= now() LIMIT $1)",
                &[&SWEEP_BATCH],
            )
            .await;
        if let Err(err) = result {
            tracing::debug!("Sweeping expired 'auth_challenges' failed: {err}");
        }
    }
}

#[async_trait]
impl ChallengeRepository for PostgresChallengeRepository {
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn issue(
        &self,
        purpose: Purpose,
        subject_id: &str,
        tenant_id: &str,
        address: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<String> {
        let secret = generate_secret();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_secs);
        let challenge = Challenge {
            secret_hash: hash_secret(&secret),
            subject_id: subject_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            purpose,
            address: address.to_owned(),
            created: now,
            ttl: expires_at.timestamp(),
        };

        // A plain insert rather than DynamoDB's overwriting put: a hash collision of two 256-bit
        // secrets will not happen, and if it did, failing beats silently replacing someone else's
        // pending challenge.
        let client = self.database.client().await?;
        self.sweep_expired(&client).await;
        let _ = CHALLENGES
            .insert(
                &client,
                record! {
                    COLUMN_SECRET_HASH => challenge.secret_hash.as_str(),
                    COLUMN_EXPIRES_AT => expires_at,
                    COLUMN_DATA => to_data(&challenge)?,
                },
            )
            .await
            .context("Error inserting into 'auth_challenges'")?;
        Ok(secret)
    }

    #[tracing::instrument(level = "debug", skip(self, secret), err(level = "debug", Display))]
    async fn consume(&self, purpose: Purpose, secret: &str) -> anyhow::Result<Option<Proven>> {
        // Single-use by construction: under concurrency only one DELETE returns the row.
        let client = self.database.client().await?;
        let row = client
            .query_opt(
                "DELETE FROM auth_challenges WHERE secret_hash = $1 RETURNING data",
                &[&hash_secret(secret)],
            )
            .await
            .context("Error consuming an 'auth_challenges' row")?;
        let challenge: Option<Challenge> = row.as_ref().map(from_row).transpose()?;

        // Expiry and purpose are judged on the deleted row, so a secret that was expired or
        // offered to the wrong ceremony is spent all the same — exactly as with DynamoDB, where a
        // legitimate holder still has the other link.
        let now = Utc::now().timestamp();
        Ok(challenge.and_then(|challenge| {
            if redeemable(challenge.purpose, purpose, challenge.ttl, now) {
                Some(Proven {
                    subject_id: challenge.subject_id,
                    tenant_id: challenge.tenant_id,
                    address: challenge.address,
                })
            } else {
                None
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::postgres::test::database;
    use chrono::DateTime;

    /// The expiry instant of an epoch-seconds TTL, for planting rows directly.
    fn expiry(ttl: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(ttl, 0).unwrap()
    }

    #[tokio::test]
    async fn a_challenge_is_consumed_exactly_once_and_only_for_its_purpose() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresChallengeRepository::with_database(&database)
            .await
            .unwrap();

        let secret = repository
            .issue(Purpose::ConfirmAddress, "u1", "t1", "a@example.com", 600)
            .await
            .unwrap();
        let proven = repository
            .consume(Purpose::ConfirmAddress, &secret)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            proven,
            Proven {
                subject_id: "u1".to_owned(),
                tenant_id: "t1".to_owned(),
                address: "a@example.com".to_owned(),
            }
        );
        assert!(
            repository
                .consume(Purpose::ConfirmAddress, &secret)
                .await
                .unwrap()
                .is_none(),
            "a second click on the same link must not prove anything"
        );

        // A confirmation secret never resets a password, and offering it there spends it.
        let secret = repository
            .issue(Purpose::ConfirmAddress, "u1", "t1", "a@example.com", 600)
            .await
            .unwrap();
        assert!(
            repository
                .consume(Purpose::ResetPassword, &secret)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .consume(Purpose::ConfirmAddress, &secret)
                .await
                .unwrap()
                .is_none()
        );

        assert!(
            repository
                .consume(Purpose::ResetPassword, "unknown")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn concurrent_consumes_yield_one_winner() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresChallengeRepository::with_database(&database)
            .await
            .unwrap();
        let secret = repository
            .issue(Purpose::ResetPassword, "u1", "t1", "a@example.com", 600)
            .await
            .unwrap();

        let attempts = (0..8).map(|_| {
            let repository = repository.clone();
            let secret = secret.clone();
            tokio::spawn(async move { repository.consume(Purpose::ResetPassword, &secret).await })
        });
        let mut winners = 0;
        for attempt in attempts.collect::<Vec<_>>() {
            if attempt.await.unwrap().unwrap().is_some() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
    }

    #[tokio::test]
    async fn an_expired_challenge_is_rejected_and_swept() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresChallengeRepository::with_database(&database)
            .await
            .unwrap();

        let secret = repository
            .issue(Purpose::ResetPassword, "u1", "t1", "a@example.com", -5)
            .await
            .unwrap();
        assert!(
            repository
                .consume(Purpose::ResetPassword, &secret)
                .await
                .unwrap()
                .is_none()
        );

        // An expired row left behind is removed by the next write.
        let stale = Challenge {
            secret_hash: "stale".to_owned(),
            subject_id: "u1".to_owned(),
            tenant_id: "t1".to_owned(),
            purpose: Purpose::ResetPassword,
            address: "a@example.com".to_owned(),
            created: Utc::now(),
            ttl: Utc::now().timestamp() - 60,
        };
        let client = database.client().await.unwrap();
        let _ = CHALLENGES
            .insert(
                &client,
                record! {
                    COLUMN_SECRET_HASH => "stale",
                    COLUMN_EXPIRES_AT => expiry(stale.ttl),
                    COLUMN_DATA => to_data(&stale).unwrap(),
                },
            )
            .await
            .unwrap();
        let _ = repository
            .issue(Purpose::ResetPassword, "u1", "t1", "a@example.com", 600)
            .await
            .unwrap();
        let remaining = CHALLENGES
            .select(&client, record! { COLUMN_SECRET_HASH => "stale" })
            .await
            .unwrap();
        assert!(remaining.is_empty());
    }
}
