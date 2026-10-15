//! PostgreSQL persistence for API keys.
//!
//! A key's own `expiresAt` is a business rule the exchange checks (and the listing shows), not a
//! storage lifetime — the DynamoDB table has no TTL either — so it stays inside `data` and the
//! table carries no `expires_at` column.

use super::{ApiKey, ApiKeyRepository, ApiKeyStatus, NewApiKey};
use crate::storage::postgres::{COLUMN_DATA, ensure_table, from_row, to_data};
use anyhow::Context;
use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use std::sync::LazyLock;
use wasabi::postgres::sea_query::Order;
use wasabi::postgres::{Column, ColumnType, Database, Index, Record, Table, fetch};
use wasabi::record;

const TABLE_API_KEYS: &str = "api_keys";
const COLUMN_KEY_ID: &str = "key_id";
const COLUMN_TENANT_ID: &str = "tenant_id";
/// The acting user of a personal access token; `NULL` for a service key.
const COLUMN_USER_ID: &str = "user_id";

static API_KEYS: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_API_KEYS)
        .column(Column::new(COLUMN_KEY_ID, ColumnType::Text))
        .column(Column::new(COLUMN_TENANT_ID, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_USER_ID, ColumnType::Text))
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_KEY_ID])
        .index(Index::new("by_tenant", [COLUMN_TENANT_ID, COLUMN_USER_ID]))
});

/// PostgreSQL-backed implementation of [`ApiKeyRepository`].
#[derive(Clone)]
pub struct PostgresApiKeyRepository {
    database: Database,
}

impl PostgresApiKeyRepository {
    /// Builds the repository, creating or migrating its table.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &API_KEYS).await?;
        Ok(Self {
            database: database.clone(),
        })
    }

    fn row(key: &ApiKey) -> anyhow::Result<Record> {
        Ok(record! {
            COLUMN_KEY_ID => key.key_id.as_str(),
            COLUMN_TENANT_ID => key.tenant_id.as_str(),
            COLUMN_USER_ID => key.user_id.clone(),
            COLUMN_DATA => to_data(key)?,
        })
    }
}

#[async_trait]
impl ApiKeyRepository for PostgresApiKeyRepository {
    #[tracing::instrument(level = "debug", skip(self, new_key), err(level = "debug", Display))]
    async fn create(&self, new_key: NewApiKey) -> anyhow::Result<()> {
        let key = ApiKey {
            key_id: new_key.key_id,
            tenant_id: new_key.tenant_id,
            secret_hash: new_key.secret_hash,
            name: new_key.name,
            user_id: new_key.user_id,
            roles: new_key.roles,
            scopes: new_key.scopes,
            allow_secret_login: new_key.allow_secret_login,
            status: ApiKeyStatus::Active,
            allowed_origins: new_key.allowed_origins,
            rate_limit: new_key.rate_limit,
            access_ttl_secs: new_key.access_ttl_secs,
            expires_at: new_key.expires_at,
            last_used_at: None,
            created: Utc::now(),
        };
        // The id is the primary key, so an id collision fails instead of clobbering a key.
        let client = self.database.client().await?;
        let _ = API_KEYS
            .insert(&client, Self::row(&key)?)
            .await
            .context("Error inserting into 'api_keys' (id collision?)")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn get(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>> {
        let client = self.database.client().await?;
        API_KEYS
            .select_one(&client, record! { COLUMN_KEY_ID => key_id })
            .await
            .context("Error reading 'api_keys'")?
            .map(|row| from_row(&row))
            .transpose()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<ApiKey>> {
        // The DynamoDB index has no sort key, so callers rely on no order; the id merely keeps
        // the listing stable between calls.
        let client = self.database.client().await?;
        let mut statement = API_KEYS.select_statement(&record! { COLUMN_TENANT_ID => tenant_id });
        let _ = statement.order_by(COLUMN_KEY_ID, Order::Asc);
        fetch(&client, &statement)
            .await
            .context("Error listing 'api_keys'")?
            .iter()
            .map(from_row)
            .collect()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete(&self, key_id: &str) -> anyhow::Result<()> {
        let client = self.database.client().await?;
        let _ = API_KEYS
            .delete(&client, record! { COLUMN_KEY_ID => key_id })
            .await
            .context("Error deleting from 'api_keys'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_all_for_user(&self, tenant_id: &str, user_id: &str) -> anyhow::Result<usize> {
        // Only rows whose `user_id` is theirs: a service key carries `NULL` there and belongs to
        // the tenant, so it survives the person who happened to create it.
        let client = self.database.client().await?;
        let deleted = API_KEYS
            .delete(
                &client,
                record! { COLUMN_TENANT_ID => tenant_id, COLUMN_USER_ID => user_id },
            )
            .await
            .context("Error deleting a departing user's 'api_keys'")?;
        usize::try_from(deleted).context("Deleted key count out of range")
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn touch_last_used(&self, key_id: &str) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let client = self.database.client().await?;
        let updated = client
            .execute(
                "UPDATE api_keys
                 SET data = data || jsonb_build_object('lastUsedAt', $2::text)
                 WHERE key_id = $1",
                &[&key_id, &now],
            )
            .await
            .context("Error updating 'api_keys'")?;
        // A key deleted meanwhile must not come back as a stub; the DynamoDB backend fails the
        // same way through its `attribute_exists` condition.
        if updated == 0 {
            anyhow::bail!("API key does not exist");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::postgres::test::database;

    fn new_key(key_id: &str, tenant_id: &str, user_id: Option<&str>) -> NewApiKey {
        NewApiKey {
            key_id: key_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            secret_hash: "hash".to_owned(),
            name: format!("key {key_id}"),
            user_id: user_id.map(str::to_owned),
            roles: Vec::new(),
            scopes: vec!["scope:read".to_owned()],
            allow_secret_login: false,
            allowed_origins: Vec::new(),
            rate_limit: None,
            access_ttl_secs: Some(600),
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn keys_round_trip_and_pats_leave_with_their_user() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresApiKeyRepository::with_database(&database)
            .await
            .unwrap();

        repository.create(new_key("k1", "t1", None)).await.unwrap();
        assert!(repository.create(new_key("k1", "t1", None)).await.is_err());
        repository
            .create(new_key("k2", "t1", Some("u1")))
            .await
            .unwrap();
        repository
            .create(new_key("k3", "t1", Some("u2")))
            .await
            .unwrap();
        repository
            .create(new_key("k4", "t2", Some("u1")))
            .await
            .unwrap();

        let key = repository.get("k1").await.unwrap().unwrap();
        assert_eq!(key.status, ApiKeyStatus::Active);
        assert_eq!(key.access_ttl_secs, Some(600));
        assert!(key.last_used_at.is_none());

        repository.touch_last_used("k1").await.unwrap();
        assert!(
            repository
                .get("k1")
                .await
                .unwrap()
                .unwrap()
                .last_used_at
                .is_some()
        );
        assert!(repository.touch_last_used("missing").await.is_err());

        let listed = repository.list_by_tenant("t1").await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|key| key.key_id.as_str())
                .collect::<Vec<_>>(),
            vec!["k1", "k2", "k3"]
        );

        assert_eq!(repository.delete_all_for_user("t1", "u1").await.unwrap(), 1);
        let remaining = repository.list_by_tenant("t1").await.unwrap();
        assert_eq!(remaining.len(), 2, "the service key and u2's token stay");
        assert!(repository.get("k4").await.unwrap().is_some());

        repository.delete("k1").await.unwrap();
        assert!(repository.get("k1").await.unwrap().is_none());
    }
}
