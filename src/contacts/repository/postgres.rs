//! PostgreSQL persistence for email contacts.
//!
//! One table, `user_contacts`, keyed `(user_id, address)` exactly like the DynamoDB table: the
//! composite key is the per-user uniqueness constraint and the by-user listing at once. An index
//! on `address` answers "who holds this address" for password recovery. `verified` lives in `data`
//! only — no query filters on it.

use super::{ContactRepository, NewContact};
use crate::contacts::{Contact, normalize_label};
use crate::storage::postgres::{COLUMN_DATA, ensure_table, from_row, to_data};
use anyhow::Context;
use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use std::sync::LazyLock;
use warp::http::StatusCode;
use wasabi::postgres::sea_query::Order;
use wasabi::postgres::{Column, ColumnType, Database, Index, Record, Table, fetch};
use wasabi::{record, status_bail};

const TABLE_CONTACTS: &str = "user_contacts";
const COLUMN_USER_ID: &str = "user_id";
const COLUMN_ADDRESS: &str = "address";

static CONTACTS: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_CONTACTS)
        .column(Column::new(COLUMN_USER_ID, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_ADDRESS, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_USER_ID, COLUMN_ADDRESS])
        .index(Index::new("by_address", [COLUMN_ADDRESS, COLUMN_USER_ID]))
});

/// PostgreSQL-backed implementation of [`ContactRepository`].
#[derive(Clone)]
pub struct PostgresContactRepository {
    database: Database,
}

impl PostgresContactRepository {
    /// Builds the repository, creating or migrating its table.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &CONTACTS).await?;
        Ok(Self {
            database: database.clone(),
        })
    }

    /// Every contact matching `filter`, sorted by `order` — the one shape both listings share.
    async fn select_sorted(
        &self,
        filter: Record,
        order: &'static str,
    ) -> anyhow::Result<Vec<Contact>> {
        let client = self.database.client().await?;
        let mut statement = CONTACTS.select_statement(&filter);
        let _ = statement.order_by(order, Order::Asc);
        fetch(&client, &statement)
            .await
            .context("Error listing 'user_contacts'")?
            .iter()
            .map(from_row)
            .collect()
    }
}

#[async_trait]
impl ContactRepository for PostgresContactRepository {
    #[tracing::instrument(
        level = "debug",
        skip(self, new_contact),
        err(level = "debug", Display)
    )]
    async fn add_contact(&self, new_contact: NewContact) -> anyhow::Result<Contact> {
        // An address a user typed is never verified on arrival: typing a string proves nothing
        // about who owns the mailbox.
        let contact = Contact {
            user_id: new_contact.user_id,
            address: new_contact.address,
            tenant_id: new_contact.tenant_id,
            label: normalize_label(new_contact.label),
            verified: false,
            verified_at: None,
            created: Utc::now(),
        };

        // The composite key is the uniqueness constraint, so one conditional insert both writes
        // the row and rejects a duplicate — no read-then-write window.
        let client = self.database.client().await?;
        let inserted = CONTACTS
            .insert_if_absent(
                &client,
                record! {
                    COLUMN_USER_ID => contact.user_id.as_str(),
                    COLUMN_ADDRESS => contact.address.as_str(),
                    COLUMN_DATA => to_data(&contact)?,
                },
            )
            .await
            .context("Error inserting into 'user_contacts'")?;
        if !inserted {
            status_bail!(
                StatusCode::CONFLICT,
                "You already have that address on file"
            );
        }
        Ok(contact)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn get_contact(&self, user_id: &str, address: &str) -> anyhow::Result<Option<Contact>> {
        let client = self.database.client().await?;
        CONTACTS
            .select_one(
                &client,
                record! { COLUMN_USER_ID => user_id, COLUMN_ADDRESS => address },
            )
            .await
            .context("Error reading 'user_contacts'")?
            .map(|row| from_row(&row))
            .transpose()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_contacts(&self, user_id: &str) -> anyhow::Result<Vec<Contact>> {
        self.select_sorted(record! { COLUMN_USER_ID => user_id }, COLUMN_ADDRESS)
            .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn contacts_for_address(&self, address: &str) -> anyhow::Result<Vec<Contact>> {
        // Sorted by user, like the DynamoDB index's range key, so an ambiguous address resolves
        // to the same list in the same order on every attempt.
        self.select_sorted(record! { COLUMN_ADDRESS => address }, COLUMN_USER_ID)
            .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn mark_verified(&self, user_id: &str, address: &str) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let client = self.database.client().await?;
        let updated = client
            .execute(
                "UPDATE user_contacts
                 SET data = data || jsonb_build_object('verified', true, 'verifiedAt', $3::text)
                 WHERE user_id = $1 AND address = $2",
                &[&user_id, &address, &now],
            )
            .await
            .context("Error verifying a contact")?;
        // Both key halves are known, so a miss only means the row was deleted between the
        // challenge being issued and the link being clicked.
        if updated == 0 {
            status_bail!(StatusCode::NOT_FOUND, "You have no such address on file");
        }
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn mark_unverified(&self, user_id: &str, address: &str) -> anyhow::Result<()> {
        // A bounce for an address the user deleted in the meantime matches no row, which is
        // fine: there is simply nothing left to withdraw.
        let client = self.database.client().await?;
        let _ = client
            .execute(
                "UPDATE user_contacts
                 SET data = (data || jsonb_build_object('verified', false)) - 'verifiedAt'
                 WHERE user_id = $1 AND address = $2",
                &[&user_id, &address],
            )
            .await
            .context("Error withdrawing a contact's confirmation")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_contact(&self, user_id: &str, address: &str) -> anyhow::Result<()> {
        // Both halves of the key come from the caller's own session, so a foreign address is
        // simply not in this user's rows.
        let client = self.database.client().await?;
        let _ = CONTACTS
            .delete(
                &client,
                record! { COLUMN_USER_ID => user_id, COLUMN_ADDRESS => address },
            )
            .await
            .context("Error deleting from 'user_contacts'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_all_for_user(&self, user_id: &str) -> anyhow::Result<usize> {
        let client = self.database.client().await?;
        let deleted = CONTACTS
            .delete(&client, record! { COLUMN_USER_ID => user_id })
            .await
            .context("Error deleting a user's 'user_contacts'")?;
        usize::try_from(deleted).context("Deleted row count exceeds usize")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::postgres::test::database;

    fn new_contact(user_id: &str, address: &str) -> NewContact {
        NewContact {
            user_id: user_id.to_owned(),
            tenant_id: "t1".to_owned(),
            address: address.to_owned(),
            label: Some("  work ".to_owned()),
        }
    }

    #[tokio::test]
    async fn contacts_are_unique_per_user_and_listed_by_address() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresContactRepository::with_database(&database)
            .await
            .unwrap();

        let added = repository
            .add_contact(new_contact("u1", "b@example.com"))
            .await
            .unwrap();
        assert_eq!(added.label.as_deref(), Some("work"));
        assert!(!added.verified);
        let _ = repository
            .add_contact(new_contact("u1", "a@example.com"))
            .await
            .unwrap();
        let duplicate = repository
            .add_contact(new_contact("u1", "b@example.com"))
            .await
            .unwrap_err();
        assert!(format!("{duplicate:#}").contains("already have"));

        // Another user may hold the same address; recovery must see both.
        let _ = repository
            .add_contact(new_contact("u0", "b@example.com"))
            .await
            .unwrap();
        let holders = repository
            .contacts_for_address("b@example.com")
            .await
            .unwrap();
        assert_eq!(
            holders
                .iter()
                .map(|c| c.user_id.as_str())
                .collect::<Vec<_>>(),
            ["u0", "u1"]
        );

        let listed = repository.list_contacts("u1").await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|c| c.address.as_str())
                .collect::<Vec<_>>(),
            ["a@example.com", "b@example.com"]
        );

        let fetched = repository
            .get_contact("u1", "b@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.created, added.created);
        assert!(
            repository
                .get_contact("u1", "c@example.com")
                .await
                .unwrap()
                .is_none()
        );

        repository
            .delete_contact("u1", "a@example.com")
            .await
            .unwrap();
        repository
            .delete_contact("u1", "a@example.com")
            .await
            .unwrap();
        assert_eq!(repository.delete_all_for_user("u1").await.unwrap(), 1);
        assert!(repository.list_contacts("u1").await.unwrap().is_empty());
        assert_eq!(repository.list_contacts("u0").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn verification_is_set_and_withdrawn_in_place() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresContactRepository::with_database(&database)
            .await
            .unwrap();
        let _ = repository
            .add_contact(new_contact("u1", "a@example.com"))
            .await
            .unwrap();

        repository
            .mark_verified("u1", "a@example.com")
            .await
            .unwrap();
        let verified = repository
            .get_contact("u1", "a@example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(verified.verified);
        assert!(verified.verified_at.is_some());
        assert_eq!(verified.label.as_deref(), Some("work"));

        // A missing row must not pass for a successful verification.
        assert!(
            repository
                .mark_verified("u1", "gone@example.com")
                .await
                .is_err()
        );

        repository
            .mark_unverified("u1", "a@example.com")
            .await
            .unwrap();
        let withdrawn = repository
            .get_contact("u1", "a@example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(!withdrawn.verified);
        assert!(withdrawn.verified_at.is_none());

        // A bounce for an address already deleted is nothing to do, not an error.
        repository
            .mark_unverified("u1", "gone@example.com")
            .await
            .unwrap();
    }
}
