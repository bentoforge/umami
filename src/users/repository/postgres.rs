//! PostgreSQL persistence for user identities.
//!
//! `users` holds the entity, `user_usernames` the global username-uniqueness guard — the same split
//! as the DynamoDB backend, because [`UserRepository::rename_username`] moves the guard on its own
//! and leaves writing `user.username` to a later [`UserRepository::put_user`]. A unique column on
//! `users` would have to change before `data` does, which the storage layout forbids.

use super::{NewUser, UserName, UserRepository, new_user_records, user_haystack};
use crate::search::query_matches;
use crate::storage::postgres::{COLUMN_DATA, ensure_table, from_row, to_data};
use crate::users::{User, normalize_username};
use anyhow::Context;
use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use std::sync::LazyLock;
use wasabi::postgres::sea_query::Order;
use wasabi::postgres::tokio_postgres::types::ToSql;
use wasabi::postgres::{Column, ColumnType, Database, Index, Record, Table, fetch};
use wasabi::{client_bail, record};

const TABLE_USERS: &str = "users";
const TABLE_USER_USERNAMES: &str = "user_usernames";
const COLUMN_USER_ID: &str = "user_id";
const COLUMN_TENANT_ID: &str = "tenant_id";
/// Sort key of the per-tenant listing: activity first, inactive users stably by creation.
const COLUMN_LAST_ACTIVE_OR_CREATED: &str = "last_active_or_created";
/// The normalized username — key of the guard table.
const COLUMN_USERNAME: &str = "username";

/// Page size for the listing; [`UserRepository::find_users`] filters in memory and stops as soon
/// as it has enough, so an unfiltered listing never reads a whole tenant.
const LIST_PAGE_SIZE: u64 = 100;

static USERS: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_USERS)
        .column(Column::new(COLUMN_USER_ID, ColumnType::Text))
        .column(Column::new(COLUMN_TENANT_ID, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_LAST_ACTIVE_OR_CREATED, ColumnType::TimestampTz).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_USER_ID])
        .index(Index::new(
            "by_tenant",
            [COLUMN_TENANT_ID, COLUMN_LAST_ACTIVE_OR_CREATED],
        ))
});

static USER_USERNAMES: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_USER_USERNAMES)
        .column(Column::new(COLUMN_USERNAME, ColumnType::Text))
        .column(Column::new(COLUMN_USER_ID, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_USERNAME])
});

/// PostgreSQL-backed implementation of [`UserRepository`].
#[derive(Clone)]
pub struct PostgresUserRepository {
    database: Database,
}

impl PostgresUserRepository {
    /// Builds the repository, creating or migrating its tables.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &USERS).await?;
        ensure_table(database, &USER_USERNAMES).await?;
        Ok(Self {
            database: database.clone(),
        })
    }

    fn row(user: &User) -> anyhow::Result<Record> {
        Ok(record! {
            COLUMN_USER_ID => user.user_id.as_str(),
            COLUMN_TENANT_ID => user.tenant_id.as_str(),
            COLUMN_LAST_ACTIVE_OR_CREATED => user.last_active_or_created,
            COLUMN_DATA => to_data(user)?,
        })
    }

    fn guard_row(guard: &UserName) -> anyhow::Result<Record> {
        Ok(record! {
            COLUMN_USERNAME => guard.username.as_str(),
            COLUMN_USER_ID => guard.user_id.as_str(),
            COLUMN_DATA => to_data(guard)?,
        })
    }

    /// Runs a `data`-only update of one user. A missing user is an error, as the DynamoDB backend's
    /// `attribute_exists` condition makes it: these writes must never conjure up a partial row.
    async fn update_user_data(
        &self,
        user_id: &str,
        sql: &str,
        extra: &[&(dyn ToSql + Sync)],
        what: &str,
    ) -> anyhow::Result<()> {
        let client = self.database.client().await?;
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&user_id];
        params.extend_from_slice(extra);
        let updated = client
            .execute(sql, &params)
            .await
            .with_context(|| format!("Error updating {what} in 'users'"))?;
        if updated == 0 {
            anyhow::bail!("Cannot update {what}: user '{user_id}' does not exist");
        }
        Ok(())
    }
}

/// Current time as stored inside `data`, matching the DynamoDB backend's string form.
fn now_text(now: chrono::DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    #[tracing::instrument(level = "debug", skip(self, new_user), err(level = "debug", Display))]
    async fn create_user(&self, new_user: NewUser) -> anyhow::Result<User> {
        let (user, guard) = new_user_records(new_user)?;

        // Guard and user commit together, so a failed user insert cannot strand a reserved name.
        let mut client = self.database.client().await?;
        let transaction = client
            .transaction()
            .await
            .context("Failed to start a transaction for creating a user")?;
        if !USER_USERNAMES
            .insert_if_absent(&transaction, Self::guard_row(&guard)?)
            .await
            .context("Error reserving username in 'user_usernames'")?
        {
            client_bail!("A user with this username already exists");
        }
        let _ = USERS
            .insert(&transaction, Self::row(&user)?)
            .await
            .context("Error inserting into 'users' (id collision?)")?;
        transaction
            .commit()
            .await
            .context("Failed to commit the new user")?;
        Ok(user)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn find_by_username(&self, username: &str) -> anyhow::Result<Option<User>> {
        let client = self.database.client().await?;
        client
            .query_opt(
                "SELECT u.data FROM user_usernames g
                 JOIN users u ON u.user_id = g.user_id
                 WHERE g.username = $1",
                &[&normalize_username(username)],
            )
            .await
            .context("Error looking up 'user_usernames'")?
            .map(|row| from_row(&row))
            .transpose()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn get_user(&self, user_id: &str) -> anyhow::Result<Option<User>> {
        let client = self.database.client().await?;
        USERS
            .select_one(&client, record! { COLUMN_USER_ID => user_id })
            .await
            .context("Error reading 'users'")?
            .map(|row| from_row(&row))
            .transpose()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn find_users(
        &self,
        tenant_id: &str,
        query: &str,
        limit: usize,
    ) -> anyhow::Result<(Vec<User>, bool)> {
        // Same contract as the DynamoDB backend: newest-active first, matched in memory with the
        // shared search semantics, stopping at `limit` + 1.
        let client = self.database.client().await?;
        let mut matched = Vec::new();
        let mut offset = 0;
        loop {
            let mut statement = USERS.select_statement(&record! { COLUMN_TENANT_ID => tenant_id });
            let _ = statement
                .order_by(COLUMN_LAST_ACTIVE_OR_CREATED, Order::Desc)
                .order_by(COLUMN_USER_ID, Order::Asc)
                .limit(LIST_PAGE_SIZE)
                .offset(offset);
            let rows = fetch(&client, &statement)
                .await
                .context("Error listing 'users' by tenant")?;
            let exhausted = (rows.len() as u64) < LIST_PAGE_SIZE;

            for row in rows {
                let user: User = from_row(&row)?;
                if query_matches(&user_haystack(&user), query) {
                    if matched.len() >= limit {
                        return Ok((matched, true));
                    }
                    matched.push(user);
                }
            }
            if exhausted {
                return Ok((matched, false));
            }
            offset += LIST_PAGE_SIZE;
        }
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn put_user(&self, mut user: User) -> anyhow::Result<User> {
        // An unconditional overwrite, like the DynamoDB `PutItem` it mirrors.
        user.last_updated = Utc::now();
        let client = self.database.client().await?;
        let _ = USERS
            .upsert(&client, Self::row(&user)?)
            .await
            .context("Error updating 'users'")?;
        Ok(user)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn bump_token_version(&self, user_id: &str) -> anyhow::Result<()> {
        // Incremented inside the database so concurrent bumps both count, as `ADD` does.
        let now = now_text(Utc::now());
        self.update_user_data(
            user_id,
            "UPDATE users
             SET data = data || jsonb_build_object(
                 'tokenVersion', COALESCE((data->>'tokenVersion')::bigint, 0) + 1,
                 'lastUpdated', $2::text)
             WHERE user_id = $1",
            &[&now],
            "tokenVersion",
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn touch_last_seen(&self, user_id: &str) -> anyhow::Result<()> {
        let now = Utc::now();
        let text = now_text(now);
        self.update_user_data(
            user_id,
            "UPDATE users
             SET last_active_or_created = $2,
                 data = data || jsonb_build_object('lastSeen', $3::text,
                                                   'lastActiveOrCreated', $3::text)
             WHERE user_id = $1",
            &[&now, &text],
            "lastSeen",
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn set_has_passkey(&self, user_id: &str) -> anyhow::Result<()> {
        self.update_user_data(
            user_id,
            "UPDATE users SET data = data || '{\"hasPasskey\": true}'::jsonb WHERE user_id = $1",
            &[],
            "hasPasskey",
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn rename_username(
        &self,
        user_id: &str,
        old_username: &str,
        new_username: &str,
    ) -> anyhow::Result<()> {
        let normalized_new = normalize_username(new_username);
        let normalized_old = normalize_username(old_username);
        if normalized_new == normalized_old {
            // Only the display form (case/spacing) changed — the guard key is unchanged.
            return Ok(());
        }

        let guard = UserName {
            username: normalized_new,
            user_id: user_id.to_owned(),
            created: Utc::now(),
        };
        // Reserve and release in one transaction, so a failure never leaves the user holding both
        // names or neither.
        let mut client = self.database.client().await?;
        let transaction = client
            .transaction()
            .await
            .context("Failed to start a transaction for renaming a user")?;
        if !USER_USERNAMES
            .insert_if_absent(&transaction, Self::guard_row(&guard)?)
            .await
            .context("Error reserving username in 'user_usernames'")?
        {
            client_bail!("A user with this username already exists");
        }
        let _ = USER_USERNAMES
            .delete(
                &transaction,
                record! { COLUMN_USERNAME => normalized_old.as_str() },
            )
            .await
            .context("Error releasing old username in 'user_usernames'")?;
        transaction
            .commit()
            .await
            .context("Failed to commit the username change")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_user(&self, user_id: &str, username: &str) -> anyhow::Result<()> {
        let mut client = self.database.client().await?;
        let transaction = client
            .transaction()
            .await
            .context("Failed to start a transaction for deleting a user")?;
        let _ = USERS
            .delete(&transaction, record! { COLUMN_USER_ID => user_id })
            .await
            .context("Error deleting from 'users'")?;
        let _ = USER_USERNAMES
            .delete(
                &transaction,
                record! { COLUMN_USERNAME => normalize_username(username) },
            )
            .await
            .context("Error deleting from 'user_usernames'")?;
        transaction
            .commit()
            .await
            .context("Failed to commit the user deletion")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::postgres::test::database;
    use crate::users::Salutation;
    use std::collections::BTreeMap;

    fn new_user(tenant_id: &str, username: &str) -> NewUser {
        NewUser {
            tenant_id: tenant_id.to_owned(),
            roles: vec!["admin".to_owned()],
            username: username.to_owned(),
            title: None,
            salutation: Salutation::Unspecified,
            firstname: Some(" Ada ".to_owned()),
            lastname: Some("Lovelace".to_owned()),
            locale: None,
            password_hash: None,
            custom_fields: BTreeMap::new(),
            created_by: None,
            password_generated: false,
        }
    }

    #[tokio::test]
    async fn usernames_are_unique_and_movable() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresUserRepository::with_database(&database)
            .await
            .unwrap();

        let ada = repository
            .create_user(new_user("t1", " Ada "))
            .await
            .unwrap();
        assert_eq!(ada.username, "Ada");
        assert_eq!(ada.firstname.as_deref(), Some("Ada"));
        assert!(repository.create_user(new_user("t2", "ADA")).await.is_err());
        assert!(repository.create_user(new_user("t1", "  ")).await.is_err());

        let found = repository.find_by_username(" ada").await.unwrap().unwrap();
        assert_eq!(found.user_id, ada.user_id);
        assert!(repository.find_by_username("bob").await.unwrap().is_none());

        let bob = repository.create_user(new_user("t1", "bob")).await.unwrap();
        // A case-only edit keeps the guard; a taken name is refused and changes nothing.
        repository
            .rename_username(&ada.user_id, "Ada", "ADA")
            .await
            .unwrap();
        assert!(
            repository
                .rename_username(&ada.user_id, "Ada", "Bob")
                .await
                .is_err()
        );
        assert!(repository.find_by_username("ada").await.unwrap().is_some());

        repository
            .rename_username(&ada.user_id, "Ada", "Countess")
            .await
            .unwrap();
        assert!(repository.find_by_username("ada").await.unwrap().is_none());
        assert_eq!(
            repository
                .find_by_username("countess")
                .await
                .unwrap()
                .unwrap()
                .user_id,
            ada.user_id
        );

        repository.delete_user(&bob.user_id, "bob").await.unwrap();
        assert!(repository.get_user(&bob.user_id).await.unwrap().is_none());
        // The released name is free again.
        let _ = repository.create_user(new_user("t1", "Bob")).await.unwrap();
    }

    #[tokio::test]
    async fn counters_flags_and_activity_listing() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresUserRepository::with_database(&database)
            .await
            .unwrap();

        let first = repository
            .create_user(new_user("t1", "first"))
            .await
            .unwrap();
        let second = repository
            .create_user(new_user("t1", "second"))
            .await
            .unwrap();
        let _ = repository
            .create_user(new_user("t2", "other"))
            .await
            .unwrap();

        repository.bump_token_version(&first.user_id).await.unwrap();
        repository.bump_token_version(&first.user_id).await.unwrap();
        repository.set_has_passkey(&first.user_id).await.unwrap();
        let reloaded = repository.get_user(&first.user_id).await.unwrap().unwrap();
        assert_eq!(reloaded.token_version, 2);
        assert!(reloaded.has_passkey);
        assert!(repository.bump_token_version("missing").await.is_err());
        assert!(repository.touch_last_seen("missing").await.is_err());
        assert!(repository.set_has_passkey("missing").await.is_err());

        // `second` was created last and leads until `first` is active.
        let (users, truncated) = repository.find_users("t1", "", 10).await.unwrap();
        assert_eq!(users.len(), 2);
        assert!(!truncated);
        assert_eq!(users[0].user_id, second.user_id);

        repository.touch_last_seen(&first.user_id).await.unwrap();
        let (users, _) = repository.find_users("t1", "", 10).await.unwrap();
        assert_eq!(users[0].user_id, first.user_id);
        assert!(users[0].last_seen.is_some());

        let (some, truncated) = repository.find_users("t1", "", 1).await.unwrap();
        assert_eq!(some.len(), 1);
        assert!(truncated);
        let (matched, _) = repository.find_users("t1", "SECOND", 10).await.unwrap();
        assert_eq!(matched.len(), 1);

        let mut edited = reloaded;
        edited.lastname = Some("Byron".to_owned());
        let saved = repository.put_user(edited).await.unwrap();
        let stored = repository.get_user(&first.user_id).await.unwrap().unwrap();
        assert_eq!(stored.lastname.as_deref(), Some("Byron"));
        assert_eq!(stored.last_updated, saved.last_updated);
    }
}
