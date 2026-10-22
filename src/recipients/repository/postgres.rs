//! PostgreSQL persistence for external recipients.
//!
//! One table, `tenant_recipients`, keyed by `recipient_id` like the DynamoDB table. Where DynamoDB
//! has to query before it writes, Postgres carries the per-tenant uniqueness of an address as a
//! **unique index** on `(tenant_id, address)`, so the insert itself refuses a duplicate. The same
//! index serves the listing and the bounce report's lookup.

use super::RecipientRepository;
use crate::recipients::ExternalRecipient;
use crate::storage::postgres::{COLUMN_DATA, ensure_table, from_row, to_data};
use anyhow::Context;
use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use std::sync::LazyLock;
use warp::http::StatusCode;
use wasabi::postgres::sea_query::Order;
use wasabi::postgres::{Column, ColumnType, Database, Index, Table, fetch};
use wasabi::{record, status_bail};

const TABLE_RECIPIENTS: &str = "tenant_recipients";
const COLUMN_RECIPIENT_ID: &str = "recipient_id";
const COLUMN_TENANT_ID: &str = "tenant_id";
const COLUMN_ADDRESS: &str = "address";

static RECIPIENTS: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_RECIPIENTS)
        .column(Column::new(COLUMN_RECIPIENT_ID, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_TENANT_ID, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_ADDRESS, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_RECIPIENT_ID])
        .index(Index::new("by_tenant_address", [COLUMN_TENANT_ID, COLUMN_ADDRESS]).unique())
});

/// PostgreSQL-backed implementation of [`RecipientRepository`].
#[derive(Clone)]
pub struct PostgresRecipientRepository {
    database: Database,
}

impl PostgresRecipientRepository {
    /// Builds the repository, creating or migrating its table.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &RECIPIENTS).await?;
        Ok(Self {
            database: database.clone(),
        })
    }

    /// Sets or clears the confirmation flag on one row; `false` when there is no such row.
    async fn set_confirmed(&self, recipient_id: &str, confirmed: bool) -> anyhow::Result<bool> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let client = self.database.client().await?;
        let sql = if confirmed {
            "UPDATE tenant_recipients
             SET data = data || jsonb_build_object('confirmed', true, 'confirmedAt', $2::text,
                                                   'lastUpdated', $2::text)
             WHERE recipient_id = $1"
        } else {
            "UPDATE tenant_recipients
             SET data = (data || jsonb_build_object('confirmed', false, 'lastUpdated', $2::text))
                        - 'confirmedAt'
             WHERE recipient_id = $1"
        };
        let updated = client
            .execute(sql, &[&recipient_id, &now])
            .await
            .context("Error updating a recipient's confirmation")?;
        Ok(updated > 0)
    }
}

#[async_trait]
impl RecipientRepository for PostgresRecipientRepository {
    #[tracing::instrument(level = "debug", skip(self, recipient), err(level = "debug", Display))]
    async fn add_recipient(&self, recipient: ExternalRecipient) -> anyhow::Result<()> {
        let client = self.database.client().await?;
        // The unique index does the check, so one insert both writes the row and refuses a
        // duplicate address in the tenant.
        let inserted = RECIPIENTS
            .insert_if_absent(
                &client,
                record! {
                    COLUMN_RECIPIENT_ID => recipient.recipient_id.as_str(),
                    COLUMN_TENANT_ID => recipient.tenant_id.as_str(),
                    COLUMN_ADDRESS => recipient.address.as_str(),
                    COLUMN_DATA => to_data(&recipient)?,
                },
            )
            .await
            .context("Error inserting into 'tenant_recipients'")?;
        if !inserted {
            status_bail!(
                StatusCode::CONFLICT,
                "This tenant already has a recipient with that address"
            );
        }
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn get_recipient(&self, recipient_id: &str) -> anyhow::Result<Option<ExternalRecipient>> {
        let client = self.database.client().await?;
        RECIPIENTS
            .select_one(&client, record! { COLUMN_RECIPIENT_ID => recipient_id })
            .await
            .context("Error reading 'tenant_recipients'")?
            .map(|row| from_row(&row))
            .transpose()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_recipients(&self, tenant_id: &str) -> anyhow::Result<Vec<ExternalRecipient>> {
        let client = self.database.client().await?;
        let mut statement = RECIPIENTS.select_statement(&record! { COLUMN_TENANT_ID => tenant_id });
        let _ = statement.order_by(COLUMN_ADDRESS, Order::Asc);
        fetch(&client, &statement)
            .await
            .context("Error listing 'tenant_recipients'")?
            .iter()
            .map(from_row)
            .collect()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn find_by_address(
        &self,
        tenant_id: &str,
        address: &str,
    ) -> anyhow::Result<Option<ExternalRecipient>> {
        let client = self.database.client().await?;
        RECIPIENTS
            .select_one(
                &client,
                record! { COLUMN_TENANT_ID => tenant_id, COLUMN_ADDRESS => address },
            )
            .await
            .context("Error reading 'tenant_recipients' by address")?
            .map(|row| from_row(&row))
            .transpose()
    }

    #[tracing::instrument(level = "debug", skip(self, recipient), err(level = "debug", Display))]
    async fn put_recipient(&self, recipient: ExternalRecipient) -> anyhow::Result<()> {
        let client = self.database.client().await?;
        // Only `data` changes: the address and the tenant are fixed for the life of the row.
        let _ = RECIPIENTS
            .update(
                &client,
                record! { COLUMN_DATA => to_data(&recipient)? },
                record! { COLUMN_RECIPIENT_ID => recipient.recipient_id.as_str() },
            )
            .await
            .context("Error updating 'tenant_recipients'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn mark_confirmed(&self, recipient_id: &str) -> anyhow::Result<()> {
        if !self.set_confirmed(recipient_id, true).await? {
            status_bail!(StatusCode::NOT_FOUND, "No such recipient");
        }
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn mark_unconfirmed(&self, recipient_id: &str) -> anyhow::Result<()> {
        let _ = self.set_confirmed(recipient_id, false).await?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_recipient(&self, recipient_id: &str) -> anyhow::Result<()> {
        let client = self.database.client().await?;
        let _ = RECIPIENTS
            .delete(&client, record! { COLUMN_RECIPIENT_ID => recipient_id })
            .await
            .context("Error deleting from 'tenant_recipients'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_all_for_tenant(&self, tenant_id: &str) -> anyhow::Result<usize> {
        let client = self.database.client().await?;
        let deleted = RECIPIENTS
            .delete(&client, record! { COLUMN_TENANT_ID => tenant_id })
            .await
            .context("Error deleting a tenant's 'tenant_recipients'")?;
        usize::try_from(deleted).context("Deleted row count exceeds usize")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::postgres::test::database;
    use std::collections::BTreeMap;

    fn recipient(id: &str, tenant_id: &str, address: &str) -> ExternalRecipient {
        let now = Utc::now();
        ExternalRecipient {
            recipient_id: id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            address: address.to_owned(),
            display_name: "Front desk".to_owned(),
            locale: "de".to_owned(),
            choices: BTreeMap::from([("form-submission".to_owned(), "on".to_owned())]),
            confirmed: false,
            confirmed_at: None,
            manage_secret: "encrypted".to_owned(),
            created: now,
            last_updated: now,
        }
    }

    #[tokio::test]
    async fn addresses_are_unique_per_tenant_and_listed_in_order() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresRecipientRepository::with_database(&database)
            .await
            .unwrap();

        repository
            .add_recipient(recipient("r1", "t1", "b@example.com"))
            .await
            .unwrap();
        repository
            .add_recipient(recipient("r2", "t1", "a@example.com"))
            .await
            .unwrap();
        let duplicate = repository
            .add_recipient(recipient("r3", "t1", "b@example.com"))
            .await
            .unwrap_err();
        assert!(format!("{duplicate:#}").contains("already has"));

        // Another tenant may hold the same mailbox.
        repository
            .add_recipient(recipient("r4", "t2", "b@example.com"))
            .await
            .unwrap();

        let listed = repository.list_recipients("t1").await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|r| r.address.as_str())
                .collect::<Vec<_>>(),
            ["a@example.com", "b@example.com"]
        );
        let found = repository
            .find_by_address("t1", "b@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.recipient_id, "r1");
        assert!(
            repository
                .find_by_address("t3", "b@example.com")
                .await
                .unwrap()
                .is_none()
        );

        repository.delete_recipient("r2").await.unwrap();
        repository.delete_recipient("r2").await.unwrap();
        assert_eq!(repository.delete_all_for_tenant("t1").await.unwrap(), 1);
        assert!(repository.list_recipients("t1").await.unwrap().is_empty());
        assert_eq!(repository.list_recipients("t2").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn confirmation_and_edits_are_written_in_place() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresRecipientRepository::with_database(&database)
            .await
            .unwrap();
        repository
            .add_recipient(recipient("r1", "t1", "a@example.com"))
            .await
            .unwrap();

        repository.mark_confirmed("r1").await.unwrap();
        let confirmed = repository.get_recipient("r1").await.unwrap().unwrap();
        assert!(confirmed.confirmed);
        assert!(confirmed.confirmed_at.is_some());
        assert!(repository.mark_confirmed("gone").await.is_err());

        let mut edited = confirmed.clone();
        edited.display_name = "Reception".to_owned();
        let _ = edited
            .choices
            .insert("form-submission".to_owned(), "off".to_owned());
        repository.put_recipient(edited).await.unwrap();
        let stored = repository.get_recipient("r1").await.unwrap().unwrap();
        assert_eq!(stored.display_name, "Reception");
        assert_eq!(stored.choices.get("form-submission").unwrap(), "off");
        assert!(stored.confirmed, "an edit must not touch the confirmation");

        repository.mark_unconfirmed("r1").await.unwrap();
        let withdrawn = repository.get_recipient("r1").await.unwrap().unwrap();
        assert!(!withdrawn.confirmed);
        assert!(withdrawn.confirmed_at.is_none());
        repository.mark_unconfirmed("gone").await.unwrap();
    }
}
