//! PostgreSQL persistence for messaging link codes and external-identity links.
//!
//! Two tables, mirroring the DynamoDB layout:
//! - `messaging_codes` (PK `code`, indexed by `user_id`) — the per-user, single-use link code.
//!   `expires_at` is cleanup and a read filter; whether a code still works is decided by
//!   [`is_fresh`] against the caller's TTL, exactly as in the DynamoDB backend.
//! - `messaging_links` (PK `link_key` = `<platform>#<externalId>`, indexed by
//!   `(user_id, created)`) — the composite key makes a mapping unique and a keyed lookup.

use super::{CodeEntity, LinkSubject, MessagingRepository, is_fresh};
use crate::messaging::{MessagingLink, generate_code, link_key};
use crate::storage::postgres::{COLUMN_DATA, ensure_table, from_row, to_data};
use anyhow::Context;
use async_trait::async_trait;
use chrono::{DateTime, Duration, SecondsFormat, SubsecRound, Utc};
use std::sync::LazyLock;
use warp::http::StatusCode;
use wasabi::postgres::sea_query::Order;
use wasabi::postgres::{Client, Column, ColumnType, Database, Index, Record, Table, fetch};
use wasabi::{record, status_bail};

const TABLE_CODES: &str = "messaging_codes";
const COLUMN_CODE: &str = "code";
const COLUMN_EXPIRES_AT: &str = "expires_at";

const TABLE_LINKS: &str = "messaging_links";
const COLUMN_LINK_KEY: &str = "link_key";
const COLUMN_CREATED: &str = "created";

const COLUMN_USER_ID: &str = "user_id";

/// Expired codes removed per write; bounded so a backlog never turns one mint into a long delete.
const SWEEP_BATCH: i64 = 100;

/// Attempts at a fresh code before giving up; collisions in a 31^8 space are astronomically rare.
const CODE_ATTEMPTS: usize = 5;

/// Rounds of the read-then-write in [`MessagingRepository::create_link`]. A round only repeats
/// when a concurrent claim inserted the very row in between, so a second round always settles it.
const LINK_ATTEMPTS: usize = 3;

static CODES: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_CODES)
        .column(Column::new(COLUMN_CODE, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_USER_ID, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_EXPIRES_AT, ColumnType::TimestampTz).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_CODE])
        .index(Index::new("by_user", [COLUMN_USER_ID]))
        .index(Index::new("by_expiry", [COLUMN_EXPIRES_AT]))
});

static LINKS: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_LINKS)
        .column(Column::new(COLUMN_LINK_KEY, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_USER_ID, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_CREATED, ColumnType::TimestampTz).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_LINK_KEY])
        .index(Index::new("by_user", [COLUMN_USER_ID, COLUMN_CREATED]))
});

/// PostgreSQL-backed implementation of [`MessagingRepository`].
#[derive(Clone)]
pub struct PostgresMessagingRepository {
    database: Database,
}

impl PostgresMessagingRepository {
    /// Builds the repository, creating or migrating both tables.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &CODES).await?;
        ensure_table(database, &LINKS).await?;
        Ok(Self {
            database: database.clone(),
        })
    }

    /// The user's unexpired code, newest first should a race ever have left two.
    async fn code_entity(
        &self,
        client: &Client,
        user_id: &str,
    ) -> anyhow::Result<Option<CodeEntity>> {
        client
            .query_opt(
                "SELECT data FROM messaging_codes
                 WHERE user_id = $1 AND expires_at > now()
                 ORDER BY expires_at DESC LIMIT 1",
                &[&user_id],
            )
            .await
            .context("Error querying 'messaging_codes' by user")?
            .map(|row| from_row(&row))
            .transpose()
    }

    /// Removes a batch of expired codes. Best effort: a failed sweep only delays cleanup, so it
    /// must not fail the mint that triggered it.
    async fn sweep_expired(&self, client: &Client) {
        let result = client
            .execute(
                "DELETE FROM messaging_codes WHERE code IN (
                     SELECT code FROM messaging_codes WHERE expires_at <= now() LIMIT $1)",
                &[&SWEEP_BATCH],
            )
            .await;
        if let Err(err) = result {
            tracing::debug!("Sweeping expired 'messaging_codes' failed: {err}");
        }
    }

    /// Inserts a fresh unique code for the user, returning it.
    async fn put_new_code(
        &self,
        client: &Client,
        user_id: &str,
        tenant_id: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<String> {
        self.sweep_expired(client).await;
        for _ in 0..CODE_ATTEMPTS {
            let now = Utc::now();
            let expires_at = now + Duration::seconds(ttl_secs);
            let entity = CodeEntity {
                code: generate_code(),
                user_id: user_id.to_owned(),
                tenant_id: tenant_id.to_owned(),
                created: now.to_rfc3339_opts(SecondsFormat::Millis, true),
                ttl: expires_at.timestamp(),
            };
            let inserted = CODES
                .insert_if_absent(
                    client,
                    record! {
                        COLUMN_CODE => entity.code.as_str(),
                        COLUMN_USER_ID => user_id,
                        COLUMN_EXPIRES_AT => expires_at,
                        COLUMN_DATA => to_data(&entity)?,
                    },
                )
                .await
                .context("Error inserting into 'messaging_codes'")?;
            if inserted {
                return Ok(entity.code);
            }
        }
        status_bail!(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not allocate a unique messaging code"
        )
    }

    /// Deletes every code the user holds, expired or not.
    async fn delete_codes(&self, client: &Client, user_id: &str) -> anyhow::Result<()> {
        let _ = CODES
            .delete(client, record! { COLUMN_USER_ID => user_id })
            .await
            .context("Error deleting from 'messaging_codes'")?;
        Ok(())
    }
}

#[async_trait]
impl MessagingRepository for PostgresMessagingRepository {
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn current_code(
        &self,
        user_id: &str,
        tenant_id: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<(String, bool)> {
        let client = self.database.client().await?;
        if let Some(entity) = self.code_entity(&client, user_id).await?
            && is_fresh(&entity.created, ttl_secs)
        {
            return Ok((entity.code, false));
        }
        drop(client);
        let code = self.regenerate_code(user_id, tenant_id, ttl_secs).await?;
        Ok((code, true))
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn regenerate_code(
        &self,
        user_id: &str,
        tenant_id: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<String> {
        // Every old code goes, not just the newest: the user is meant to hold exactly one, and a
        // leftover from a race would otherwise stay redeemable.
        let client = self.database.client().await?;
        self.delete_codes(&client, user_id).await?;
        self.put_new_code(&client, user_id, tenant_id, ttl_secs)
            .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn consume_code(&self, code: &str, ttl_secs: i64) -> anyhow::Result<Option<LinkSubject>> {
        // Single-use by construction: under concurrency only one DELETE returns the row. Expired
        // rows are deleted too (cleanup) but still rejected.
        let client = self.database.client().await?;
        let row = client
            .query_opt(
                "DELETE FROM messaging_codes WHERE code = $1 RETURNING data, expires_at",
                &[&code],
            )
            .await
            .context("Error consuming 'messaging_codes'")?;
        let Some(row) = row else {
            return Ok(None);
        };
        let expires_at: DateTime<Utc> = row
            .try_get(COLUMN_EXPIRES_AT)
            .context("Row has no readable 'expires_at' column")?;
        let entity: CodeEntity = from_row(&row)?;
        if expires_at > Utc::now() && is_fresh(&entity.created, ttl_secs) {
            Ok(Some(LinkSubject {
                user_id: entity.user_id,
                tenant_id: entity.tenant_id,
            }))
        } else {
            Ok(None)
        }
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn create_link(
        &self,
        subject: &LinkSubject,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<Option<LinkSubject>> {
        let created = Utc::now().trunc_subsecs(3);
        let link = MessagingLink {
            link_key: link_key(platform, external_id),
            user_id: subject.user_id.clone(),
            tenant_id: subject.tenant_id.clone(),
            platform: platform.to_owned(),
            external_id: external_id.to_owned(),
            created: created.to_rfc3339_opts(SecondsFormat::Millis, true),
        };
        let values = record! {
            COLUMN_LINK_KEY => link.link_key.as_str(),
            COLUMN_USER_ID => link.user_id.as_str(),
            COLUMN_CREATED => created,
            COLUMN_DATA => to_data(&link)?,
        };

        // The displaced holder must come from the write itself, not a read before it: two claims
        // arriving together would otherwise both report the same displaced user. The row lock
        // serializes them, so each sees the holder it actually replaced. An absent row cannot be
        // locked, so a concurrent first claim shows as an insert that did nothing — and the next
        // round finds and locks the row that claim wrote.
        let mut client = self.database.client().await?;
        let transaction = client
            .transaction()
            .await
            .context("Error starting a 'messaging_links' transaction")?;
        for _ in 0..LINK_ATTEMPTS {
            let previous = transaction
                .query_opt(
                    "SELECT data FROM messaging_links WHERE link_key = $1 FOR UPDATE",
                    &[&link.link_key],
                )
                .await
                .context("Error locking 'messaging_links'")?;
            if let Some(previous) = previous {
                let previous: MessagingLink = from_row(&previous)?;
                let _ = LINKS
                    .update(
                        &transaction,
                        values.clone(),
                        record! { COLUMN_LINK_KEY => link.link_key.as_str() },
                    )
                    .await
                    .context("Error updating 'messaging_links'")?;
                transaction
                    .commit()
                    .await
                    .context("Error committing 'messaging_links'")?;
                return Ok(
                    (previous.user_id != subject.user_id).then_some(LinkSubject {
                        user_id: previous.user_id,
                        tenant_id: previous.tenant_id,
                    }),
                );
            }
            if LINKS
                .insert_if_absent(&transaction, values.clone())
                .await
                .context("Error inserting into 'messaging_links'")?
            {
                transaction
                    .commit()
                    .await
                    .context("Error committing 'messaging_links'")?;
                return Ok(None);
            }
        }
        status_bail!(
            StatusCode::CONFLICT,
            "The messaging identity is being claimed concurrently — retry"
        )
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn subject_for_external(
        &self,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<Option<LinkSubject>> {
        let client = self.database.client().await?;
        let link: Option<MessagingLink> = LINKS
            .select_one(
                &client,
                record! { COLUMN_LINK_KEY => link_key(platform, external_id) },
            )
            .await
            .context("Error reading 'messaging_links'")?
            .map(|row| from_row(&row))
            .transpose()?;
        Ok(link.map(|link| LinkSubject {
            user_id: link.user_id,
            tenant_id: link.tenant_id,
        }))
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_links(&self, user_id: &str) -> anyhow::Result<Vec<MessagingLink>> {
        let client = self.database.client().await?;
        let mut statement = LINKS.select_statement(&Record::new().with(COLUMN_USER_ID, user_id));
        let _ = statement
            .order_by(COLUMN_CREATED, Order::Desc)
            .order_by(COLUMN_LINK_KEY, Order::Asc);
        fetch(&client, &statement)
            .await
            .context("Error listing 'messaging_links' by user")?
            .iter()
            .map(from_row)
            .collect()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_link(
        &self,
        user_id: &str,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<()> {
        // Keyed on the owner too, so a foreign or missing mapping is simply "nothing to delete".
        let client = self.database.client().await?;
        let _ = LINKS
            .delete(
                &client,
                record! {
                    COLUMN_LINK_KEY => link_key(platform, external_id),
                    COLUMN_USER_ID => user_id,
                },
            )
            .await
            .context("Error deleting from 'messaging_links'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_all_for_user(&self, user_id: &str) -> anyhow::Result<usize> {
        // The code first: it is the only one of the two that can still *create* something.
        let client = self.database.client().await?;
        self.delete_codes(&client, user_id).await?;
        let deleted = LINKS
            .delete(&client, record! { COLUMN_USER_ID => user_id })
            .await
            .context("Error deleting a departing user's 'messaging_links'")?;
        usize::try_from(deleted).context("Deleted row count exceeds usize")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::postgres::test::database;

    fn subject(user_id: &str) -> LinkSubject {
        LinkSubject {
            user_id: user_id.to_owned(),
            tenant_id: "t1".to_owned(),
        }
    }

    #[tokio::test]
    async fn codes_are_stable_until_regenerated_and_consumed_once() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresMessagingRepository::with_database(&database)
            .await
            .unwrap();

        let (code, minted) = repository.current_code("u1", "t1", 600).await.unwrap();
        assert!(minted);
        let (again, minted) = repository.current_code("u1", "t1", 600).await.unwrap();
        assert_eq!(again, code);
        assert!(!minted);

        let fresh = repository.regenerate_code("u1", "t1", 600).await.unwrap();
        assert_ne!(fresh, code);
        assert!(
            repository.consume_code(&code, 600).await.unwrap().is_none(),
            "a regenerated code must stop resolving"
        );

        let consumed = repository.consume_code(&fresh, 600).await.unwrap().unwrap();
        assert_eq!(consumed.user_id, "u1");
        assert_eq!(consumed.tenant_id, "t1");
        assert!(
            repository
                .consume_code(&fresh, 600)
                .await
                .unwrap()
                .is_none()
        );

        // A code past the caller's TTL is rejected even though its row still exists.
        let (stale, _) = repository.current_code("u1", "t1", 600).await.unwrap();
        assert!(repository.consume_code(&stale, 0).await.unwrap().is_none());

        // An expired code is replaced on the next look.
        let (expired, _) = repository.current_code("u2", "t1", -1).await.unwrap();
        let (replacement, minted) = repository.current_code("u2", "t1", 600).await.unwrap();
        assert!(minted);
        assert_ne!(replacement, expired);
    }

    #[tokio::test]
    async fn links_report_who_they_displaced() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresMessagingRepository::with_database(&database)
            .await
            .unwrap();

        assert!(
            repository
                .create_link(&subject("u1"), "telegram", "42")
                .await
                .unwrap()
                .is_none()
        );
        // Idempotent for the same user: nobody was displaced.
        assert!(
            repository
                .create_link(&subject("u1"), "telegram", "42")
                .await
                .unwrap()
                .is_none()
        );
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        let _ = repository
            .create_link(&subject("u1"), "whatsapp", "+49")
            .await
            .unwrap();

        let links = repository.list_links("u1").await.unwrap();
        assert_eq!(
            links
                .iter()
                .map(|l| l.link_key.as_str())
                .collect::<Vec<_>>(),
            ["whatsapp#+49", "telegram#42"]
        );

        let displaced = repository
            .create_link(&subject("u2"), "telegram", "42")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(displaced.user_id, "u1");
        let resolved = repository
            .subject_for_external("telegram", "42")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved.user_id, "u2");

        // Only the owner can unlink.
        repository
            .delete_link("u1", "telegram", "42")
            .await
            .unwrap();
        assert!(
            repository
                .subject_for_external("telegram", "42")
                .await
                .unwrap()
                .is_some()
        );
        repository
            .delete_link("u2", "telegram", "42")
            .await
            .unwrap();
        assert!(
            repository
                .subject_for_external("telegram", "42")
                .await
                .unwrap()
                .is_none()
        );

        let (code, _) = repository.current_code("u1", "t1", 600).await.unwrap();
        assert_eq!(repository.delete_all_for_user("u1").await.unwrap(), 1);
        assert!(repository.list_links("u1").await.unwrap().is_empty());
        assert!(repository.consume_code(&code, 600).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn concurrent_claims_each_report_a_distinct_displacement() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresMessagingRepository::with_database(&database)
            .await
            .unwrap();

        let claims = (0..6).map(|index| {
            let repository = repository.clone();
            tokio::spawn(async move {
                repository
                    .create_link(&subject(&format!("u{index}")), "telegram", "7")
                    .await
            })
        });
        let mut displaced = Vec::new();
        for claim in claims.collect::<Vec<_>>() {
            if let Some(previous) = claim.await.unwrap().unwrap() {
                displaced.push(previous.user_id);
            }
        }
        // Serialized claims form a chain: every claim but the first displaced exactly one
        // predecessor, and no predecessor is reported twice.
        assert_eq!(displaced.len(), 5);
        displaced.sort();
        displaced.dedup();
        assert_eq!(displaced.len(), 5);
    }
}
