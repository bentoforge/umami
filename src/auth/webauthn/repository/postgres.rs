//! PostgreSQL persistence for WebAuthn credentials and short-lived ceremony state.

use super::{CeremonyRecord, CredentialRecord, StoredCeremony, WebauthnRepository};
use crate::storage::postgres::{COLUMN_DATA, ensure_table, from_row, to_data};
use anyhow::Context;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::LazyLock;
use wasabi::postgres::sea_query::Order;
use wasabi::postgres::{Column, ColumnType, Database, Index, Table, fetch};
use wasabi::record;

const TABLE_CREDENTIALS: &str = "webauthn_credentials";
const TABLE_CEREMONIES: &str = "webauthn_ceremonies";
const COLUMN_USER_ID: &str = "user_id";
const COLUMN_CREDENTIAL_ID: &str = "credential_id";
const COLUMN_CEREMONY_ID: &str = "ceremony_id";
const COLUMN_EXPIRES_AT: &str = "expires_at";

static CREDENTIALS: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_CREDENTIALS)
        .column(Column::new(COLUMN_USER_ID, ColumnType::Text))
        .column(Column::new(COLUMN_CREDENTIAL_ID, ColumnType::Text))
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_USER_ID, COLUMN_CREDENTIAL_ID])
        // The reverse lookup of a discoverable login: the authenticator names a credential, the
        // owner has to be found from it.
        .index(Index::new("by_credential", [COLUMN_CREDENTIAL_ID]))
});

static CEREMONIES: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_CEREMONIES)
        .column(Column::new(COLUMN_CEREMONY_ID, ColumnType::Text))
        .column(Column::new(COLUMN_EXPIRES_AT, ColumnType::TimestampTz).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_CEREMONY_ID])
        .index(Index::new("by_expiry", [COLUMN_EXPIRES_AT]))
});

/// PostgreSQL-backed implementation of [`WebauthnRepository`].
#[derive(Clone)]
pub struct PostgresWebauthnRepository {
    database: Database,
}

impl PostgresWebauthnRepository {
    /// Builds the repository, creating or migrating its tables.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &CREDENTIALS).await?;
        ensure_table(database, &CEREMONIES).await?;
        Ok(Self {
            database: database.clone(),
        })
    }
}

#[async_trait]
impl WebauthnRepository for PostgresWebauthnRepository {
    #[tracing::instrument(level = "debug", skip(self, passkey), err(level = "debug", Display))]
    async fn put_credential(
        &self,
        user_id: &str,
        credential_id: &str,
        passkey: String,
    ) -> anyhow::Result<()> {
        let credential = CredentialRecord {
            user_id: user_id.to_owned(),
            credential_id: credential_id.to_owned(),
            passkey,
            created: Utc::now(),
        };
        // An overwrite on purpose: re-registering updates the stored passkey (e.g. its counter).
        let client = self.database.client().await?;
        let _ = CREDENTIALS
            .upsert(
                &client,
                record! {
                    COLUMN_USER_ID => user_id,
                    COLUMN_CREDENTIAL_ID => credential_id,
                    COLUMN_DATA => to_data(&credential)?,
                },
            )
            .await
            .context("Error writing 'webauthn_credentials'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_passkeys(&self, user_id: &str) -> anyhow::Result<Vec<String>> {
        let client = self.database.client().await?;
        let mut statement = CREDENTIALS.select_statement(&record! { COLUMN_USER_ID => user_id });
        let _ = statement.order_by(COLUMN_CREDENTIAL_ID, Order::Asc);
        fetch(&client, &statement)
            .await
            .context("Error listing 'webauthn_credentials'")?
            .iter()
            .map(|row| from_row::<CredentialRecord>(row).map(|credential| credential.passkey))
            .collect()
    }

    #[tracing::instrument(level = "debug", skip(self, state), err(level = "debug", Display))]
    async fn store_ceremony(
        &self,
        ceremony_id: &str,
        user_id: Option<&str>,
        state: String,
        ttl_secs: i64,
    ) -> anyhow::Result<()> {
        let expires_at = Utc::now() + Duration::seconds(ttl_secs);
        let ceremony = CeremonyRecord {
            ceremony_id: ceremony_id.to_owned(),
            user_id: user_id.map(str::to_owned),
            state,
            ttl: expires_at.timestamp(),
        };

        let client = self.database.client().await?;
        // Expired ceremonies are invisible to `take_ceremony` already; this keeps the abandoned
        // ones (a browser closed mid-ceremony) from piling up, as DynamoDB's TTL does.
        let _ = client
            .execute(
                "DELETE FROM webauthn_ceremonies WHERE expires_at <= now()",
                &[],
            )
            .await
            .context("Error sweeping expired 'webauthn_ceremonies'")?;
        let _ = CEREMONIES
            .upsert(
                &client,
                record! {
                    COLUMN_CEREMONY_ID => ceremony_id,
                    COLUMN_EXPIRES_AT => expires_at,
                    COLUMN_DATA => to_data(&ceremony)?,
                },
            )
            .await
            .context("Error writing 'webauthn_ceremonies'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn find_user_by_credential(&self, credential_id: &str) -> anyhow::Result<Option<String>> {
        let client = self.database.client().await?;
        CREDENTIALS
            .select_one(&client, record! { COLUMN_CREDENTIAL_ID => credential_id })
            .await
            .context("Error querying 'webauthn_credentials' by credential id")?
            .map(|row| from_row::<CredentialRecord>(&row).map(|credential| credential.user_id))
            .transpose()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn take_ceremony(&self, ceremony_id: &str) -> anyhow::Result<Option<StoredCeremony>> {
        // Delete-and-return in one statement, so two concurrent finishes cannot both consume the
        // same ceremony (replay safety). An expired row is deleted too, but yields nothing.
        let client = self.database.client().await?;
        let Some(row) = client
            .query_opt(
                "DELETE FROM webauthn_ceremonies WHERE ceremony_id = $1
                 RETURNING data, expires_at",
                &[&ceremony_id],
            )
            .await
            .context("Error consuming from 'webauthn_ceremonies'")?
        else {
            return Ok(None);
        };
        let expires_at: DateTime<Utc> = row
            .try_get(COLUMN_EXPIRES_AT)
            .context("Ceremony row has no readable expiry")?;
        if expires_at <= Utc::now() {
            return Ok(None);
        }
        let ceremony: CeremonyRecord = from_row(&row)?;
        Ok(Some(StoredCeremony {
            user_id: ceremony.user_id,
            state: ceremony.state,
        }))
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_all_for_user(&self, user_id: &str) -> anyhow::Result<usize> {
        let client = self.database.client().await?;
        let deleted = CREDENTIALS
            .delete(&client, record! { COLUMN_USER_ID => user_id })
            .await
            .context("Error deleting a departing user's 'webauthn_credentials'")?;
        usize::try_from(deleted).context("Deleted credential count out of range")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::postgres::test::database;

    #[tokio::test]
    async fn credentials_are_listed_found_and_deleted() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresWebauthnRepository::with_database(&database)
            .await
            .unwrap();

        repository
            .put_credential("u1", "c1", "pk-1".to_owned())
            .await
            .unwrap();
        repository
            .put_credential("u1", "c2", "pk-2".to_owned())
            .await
            .unwrap();
        // Same key: overwritten, not duplicated.
        repository
            .put_credential("u1", "c1", "pk-1b".to_owned())
            .await
            .unwrap();
        repository
            .put_credential("u2", "c3", "pk-3".to_owned())
            .await
            .unwrap();

        assert_eq!(
            repository.list_passkeys("u1").await.unwrap(),
            vec!["pk-1b", "pk-2"]
        );
        assert_eq!(
            repository
                .find_user_by_credential("c3")
                .await
                .unwrap()
                .as_deref(),
            Some("u2")
        );
        assert!(
            repository
                .find_user_by_credential("nope")
                .await
                .unwrap()
                .is_none()
        );

        assert_eq!(repository.delete_all_for_user("u1").await.unwrap(), 2);
        assert!(repository.list_passkeys("u1").await.unwrap().is_empty());
        assert_eq!(repository.list_passkeys("u2").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn ceremonies_are_consumed_once_and_expire() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresWebauthnRepository::with_database(&database)
            .await
            .unwrap();

        repository
            .store_ceremony("c1", Some("u1"), "state-1".to_owned(), 300)
            .await
            .unwrap();
        repository
            .store_ceremony("c2", None, "state-2".to_owned(), 300)
            .await
            .unwrap();
        repository
            .store_ceremony("old", None, "state-old".to_owned(), -1)
            .await
            .unwrap();

        // Concurrent finishes: exactly one gets the ceremony.
        let (a, b) = tokio::join!(
            repository.take_ceremony("c1"),
            repository.take_ceremony("c1")
        );
        let taken: Vec<StoredCeremony> = [a.unwrap(), b.unwrap()].into_iter().flatten().collect();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].user_id.as_deref(), Some("u1"));
        assert_eq!(taken[0].state, "state-1");

        let discoverable = repository.take_ceremony("c2").await.unwrap().unwrap();
        assert!(discoverable.user_id.is_none());

        assert!(repository.take_ceremony("old").await.unwrap().is_none());
        assert!(repository.take_ceremony("unknown").await.unwrap().is_none());
    }
}
