//! PostgreSQL persistence for tenants.

use super::{TenantRepository, new_tenant, tenant_haystack};
use crate::search::query_matches;
use crate::storage::postgres::{COLUMN_DATA, ensure_table, from_row, to_bigint, to_data};
use crate::tenants::Tenant;
use anyhow::Context;
use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use std::sync::LazyLock;
use warp::http::StatusCode;
use wasabi::aws::dynamodb::generate_id;
use wasabi::postgres::sea_query::Order;
use wasabi::postgres::{self, Column, ColumnType, Database, Index, Record, Table, fetch};
use wasabi::{record, status_bail};

const TABLE_TENANTS: &str = "tenants";
const COLUMN_TENANT_ID: &str = "tenant_id";
const COLUMN_VERSION: &str = "version";
/// Sort key of the listing: activity first, inactive tenants stably by creation.
const COLUMN_LAST_ACTIVE_OR_CREATED: &str = "last_active_or_created";

/// Page size for the listing; [`TenantRepository::find_tenants`] filters in memory and stops as
/// soon as it has enough, so an unfiltered listing never reads the whole table.
const LIST_PAGE_SIZE: u64 = 100;

static TENANTS: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_TENANTS)
        .column(Column::new(COLUMN_TENANT_ID, ColumnType::Text))
        .column(Column::new(COLUMN_VERSION, ColumnType::BigInt).not_null())
        .column(Column::new(COLUMN_LAST_ACTIVE_OR_CREATED, ColumnType::TimestampTz).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_TENANT_ID])
        .index(Index::new(
            "by_last_active",
            [COLUMN_LAST_ACTIVE_OR_CREATED],
        ))
});

/// PostgreSQL-backed implementation of [`TenantRepository`].
#[derive(Clone)]
pub struct PostgresTenantRepository {
    database: Database,
}

impl PostgresTenantRepository {
    /// Builds the repository, creating or migrating its table.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &TENANTS).await?;
        Ok(Self {
            database: database.clone(),
        })
    }

    fn row(tenant: &Tenant) -> anyhow::Result<Record> {
        Ok(record! {
            COLUMN_TENANT_ID => tenant.tenant_id.as_str(),
            COLUMN_VERSION => to_bigint(tenant.version)?,
            COLUMN_LAST_ACTIVE_OR_CREATED => tenant.last_active_or_created,
            COLUMN_DATA => to_data(tenant)?,
        })
    }
}

#[async_trait]
impl TenantRepository for PostgresTenantRepository {
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn create_tenant(
        &self,
        name: &str,
        slug: &str,
        created_by: Option<&str>,
    ) -> anyhow::Result<Tenant> {
        // A generated id that happens to collide is drawn again rather than failing the create.
        let client = &self.database.client().await?;
        let tenant = postgres::retry(|| async move {
            let tenant = new_tenant(&generate_id(), name, slug, created_by);
            let _ = TENANTS.insert(client, Self::row(&tenant)?).await?;
            Ok(tenant)
        })
        .await
        .context("Error inserting into 'tenants'")?;
        Ok(tenant)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn create_tenant_with_id(
        &self,
        tenant_id: &str,
        name: &str,
        slug: &str,
        created_by: Option<&str>,
    ) -> anyhow::Result<Tenant> {
        let tenant = new_tenant(tenant_id, name, slug, created_by);

        // The id is the primary key, so a caller-chosen id racing another create fails here
        // instead of overwriting a tenant.
        let client = self.database.client().await?;
        let _ = TENANTS
            .insert(&client, Self::row(&tenant)?)
            .await
            .context("Error inserting into 'tenants' (id collision?)")?;
        Ok(tenant)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn touch_last_active(&self, tenant_id: &str) -> anyhow::Result<()> {
        // Not a logical change: `version` and `lastUpdated` stay, only the activity stamp moves —
        // in the sort column and in the entity alike.
        let now = Utc::now();
        let client = self.database.client().await?;
        let _ = client
            .execute(
                "UPDATE tenants
                 SET last_active_or_created = $2,
                     data = data || jsonb_build_object('lastActive', $3::text,
                                                       'lastActiveOrCreated', $3::text)
                 WHERE tenant_id = $1",
                &[
                    &tenant_id,
                    &now,
                    &now.to_rfc3339_opts(SecondsFormat::Millis, true),
                ],
            )
            .await
            .context("Error updating lastActive in 'tenants'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn get_tenant(&self, tenant_id: &str) -> anyhow::Result<Option<Tenant>> {
        let client = self.database.client().await?;
        TENANTS
            .select_one(&client, record! { COLUMN_TENANT_ID => tenant_id })
            .await
            .context("Error reading 'tenants'")?
            .map(|row| from_row(&row))
            .transpose()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn find_tenants(&self, query: &str, limit: usize) -> anyhow::Result<(Vec<Tenant>, bool)> {
        // Same contract as the DynamoDB backend: newest-active first, matched in memory with the
        // shared search semantics, stopping at `limit` + 1.
        let client = self.database.client().await?;
        let mut matched = Vec::new();
        let mut offset = 0;
        loop {
            let mut statement = TENANTS.select_statement(&Record::new());
            let _ = statement
                .order_by(COLUMN_LAST_ACTIVE_OR_CREATED, Order::Desc)
                .order_by(COLUMN_TENANT_ID, Order::Asc)
                .limit(LIST_PAGE_SIZE)
                .offset(offset);
            let rows = fetch(&client, &statement)
                .await
                .context("Error listing 'tenants'")?;
            let exhausted = (rows.len() as u64) < LIST_PAGE_SIZE;

            for row in rows {
                let tenant: Tenant = from_row(&row)?;
                if query_matches(&tenant_haystack(&tenant), query) {
                    if matched.len() >= limit {
                        return Ok((matched, true));
                    }
                    matched.push(tenant);
                }
            }
            if exhausted {
                return Ok((matched, false));
            }
            offset += LIST_PAGE_SIZE;
        }
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn put_tenant(&self, mut tenant: Tenant) -> anyhow::Result<Tenant> {
        // Optimistic lock: only the row still at the version we read is overwritten; a concurrent
        // writer that bumped it first leaves nothing to match → 409, forcing a reload.
        let expected_version = to_bigint(tenant.version)?;
        tenant.version += 1;
        tenant.last_updated = Utc::now();

        let client = self.database.client().await?;
        let updated = TENANTS
            .update(
                &client,
                Self::row(&tenant)?,
                record! {
                    COLUMN_TENANT_ID => tenant.tenant_id.as_str(),
                    COLUMN_VERSION => expected_version,
                },
            )
            .await
            .context("Error updating 'tenants'")?;
        if updated == 0 {
            status_bail!(
                StatusCode::CONFLICT,
                "Tenant was modified concurrently — reload and retry"
            );
        }
        Ok(tenant)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_tenant(&self, tenant_id: &str) -> anyhow::Result<()> {
        let client = self.database.client().await?;
        let _ = TENANTS
            .delete(&client, record! { COLUMN_TENANT_ID => tenant_id })
            .await
            .context("Error deleting from 'tenants'")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::postgres::test::database;

    #[tokio::test]
    async fn tenants_round_trip_with_optimistic_locking() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresTenantRepository::with_database(&database)
            .await
            .unwrap();

        let tenant = repository
            .create_tenant_with_id("t1", "Acme Corp", "acme", Some("u1"))
            .await
            .unwrap();
        assert!(
            repository
                .create_tenant_with_id("t1", "Other", "other", None)
                .await
                .is_err()
        );

        let mut edited = repository.get_tenant("t1").await.unwrap().unwrap();
        assert_eq!(edited.name, tenant.name);
        assert_eq!(edited.created, tenant.created);
        edited.name = "Acme Inc".to_owned();
        let saved = repository.put_tenant(edited.clone()).await.unwrap();
        assert_eq!(saved.version, 1);

        // A second save from the same stale read must be refused.
        assert!(repository.put_tenant(edited).await.is_err());

        repository.touch_last_active("t1").await.unwrap();
        let touched = repository.get_tenant("t1").await.unwrap().unwrap();
        assert!(touched.last_active.is_some());
        assert_eq!(touched.version, 1);

        // Beta is created after t1's activity, so it leads until t1 is active again.
        let _ = repository
            .create_tenant("Beta", "beta", None)
            .await
            .unwrap();
        repository.touch_last_active("t1").await.unwrap();
        let (all, truncated) = repository.find_tenants("", 10).await.unwrap();
        assert_eq!(all.len(), 2);
        assert!(!truncated);
        assert_eq!(all[0].tenant_id, "t1", "the active tenant sorts first");
        let (some, truncated) = repository.find_tenants("", 1).await.unwrap();
        assert_eq!(some.len(), 1);
        assert!(truncated);
        let (acme, _) = repository.find_tenants("ACME inc", 10).await.unwrap();
        assert_eq!(acme.len(), 1);

        repository.delete_tenant("t1").await.unwrap();
        assert!(repository.get_tenant("t1").await.unwrap().is_none());
    }
}
