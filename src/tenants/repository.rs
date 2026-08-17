//! DynamoDB persistence for tenants.

use crate::tenants::Tenant;
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType,
};
use chrono::Utc;
use std::collections::BTreeMap;
use warp::http::StatusCode;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, find_all, generate_id, str};
use wasabi::status_bail;

/// Table storing tenants.
const TABLE_TENANTS: &str = "tenants";

/// Hash key of the `tenants` table.
const FIELD_TENANT_ID: &str = "tenantId";

/// Optimistic-concurrency attribute.
const FIELD_VERSION: &str = "version";

/// `lastUpdated` attribute — range key of the listing GSI (sort tenants newest-first).
const FIELD_LAST_UPDATED: &str = "lastUpdated";

/// Constant partition attribute injected at write time so all tenants share one GSI partition,
/// making "list every tenant, sorted by `lastUpdated`" a single query (no table scan). Kept out of
/// the [`Tenant`] model — it's storage-only and never surfaces in API responses.
const FIELD_LIST_SHARD: &str = "listShard";

/// The single value written to [`FIELD_LIST_SHARD`].
const LIST_SHARD_VALUE: &str = "tenant";

/// GSI listing all tenants ordered by `lastUpdated`.
const INDEX_BY_LAST_UPDATED: &str = "ByLastUpdatedIndex";

/// Page size for the listing query (paginated internally by `find_all`).
const LIST_PAGE_SIZE: i32 = 100;

/// Persistence interface for tenants.
#[async_trait]
pub trait TenantRepository: Send + Sync {
    /// Creates a tenant with sensible defaults (status `Active`, plan `free`), returning it.
    async fn create_tenant(&self, name: &str, slug: &str) -> anyhow::Result<Tenant>;

    /// Creates a tenant with a caller-supplied id (used by auto-init to materialise the configured
    /// system tenant). Same defaults as [`create_tenant`].
    async fn create_tenant_with_id(
        &self,
        tenant_id: &str,
        name: &str,
        slug: &str,
    ) -> anyhow::Result<Tenant>;

    /// Fetches a tenant by id. `None` if unknown.
    async fn get_tenant(&self, tenant_id: &str) -> anyhow::Result<Option<Tenant>>;

    /// Lists every tenant (full table scan; system-admin / bootstrap use only).
    async fn list_all(&self) -> anyhow::Result<Vec<Tenant>>;

    /// Overwrites a tenant record (used by PATCH after a read-modify), bumping `lastUpdated`.
    async fn put_tenant(&self, tenant: Tenant) -> anyhow::Result<Tenant>;

    /// Deletes a tenant by id. Callers must enforce any preconditions (e.g. no remaining users).
    async fn delete_tenant(&self, tenant_id: &str) -> anyhow::Result<()>;
}

/// DynamoDB-backed implementation of [`TenantRepository`].
#[derive(Clone)]
pub struct DynamoTenantRepository {
    client: DynamoClient,
}

impl DynamoTenantRepository {
    #[tracing::instrument(skip(client), err(Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_TENANTS, |table| {
                let by_last_updated = GlobalSecondaryIndex::builder()
                    .index_name(INDEX_BY_LAST_UPDATED)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(FIELD_LIST_SHARD)
                            .key_type(KeyType::Hash)
                            .build()?,
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(FIELD_LAST_UPDATED)
                            .key_type(KeyType::Range)
                            .build()?,
                    )
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .build()?;

                let table = table
                    .attribute_definitions(str_attribute(FIELD_TENANT_ID)?)
                    .attribute_definitions(str_attribute(FIELD_LIST_SHARD)?)
                    .attribute_definitions(str_attribute(FIELD_LAST_UPDATED)?);
                let table = with_hash_index(table, FIELD_TENANT_ID)?;

                Ok(table
                    .global_secondary_indexes(by_last_updated)
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        Ok(Self {
            client: client.clone(),
        })
    }
}

#[async_trait]
impl TenantRepository for DynamoTenantRepository {
    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn create_tenant(&self, name: &str, slug: &str) -> anyhow::Result<Tenant> {
        self.create_tenant_with_id(&generate_id(), name, slug).await
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn create_tenant_with_id(
        &self,
        tenant_id: &str,
        name: &str,
        slug: &str,
    ) -> anyhow::Result<Tenant> {
        let now = Utc::now();
        let tenant = Tenant {
            tenant_id: tenant_id.to_owned(),
            version: 0,
            features: Vec::new(),
            custom_fields: BTreeMap::new(),
            name: name.to_owned(),
            slug: slug.to_owned(),
            created: now,
            last_updated: now,
        };

        // Defensive: the id is the PK, so `attribute_not_exists` makes a (near-impossible) id
        // collision fail loudly instead of silently overwriting an existing tenant — for free.
        let _ = self
            .client
            .put_entity(TABLE_TENANTS, &tenant)?
            .item(FIELD_LIST_SHARD, str(LIST_SHARD_VALUE))
            .condition_expression("attribute_not_exists(#tenantId)")
            .expression_attribute_names("#tenantId", FIELD_TENANT_ID)
            .send()
            .await
            .context("Error inserting entity into 'tenants' table (id collision?)")?;

        Ok(tenant)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn get_tenant(&self, tenant_id: &str) -> anyhow::Result<Option<Tenant>> {
        // Strongly consistent: accounting mutations read-modify-write this record, so a stale read
        // must never be the basis of a write.
        let result = self
            .client
            .get_item(TABLE_TENANTS)
            .key(FIELD_TENANT_ID, str(tenant_id))
            .consistent_read(true)
            .send()
            .await
            .context("Error searching table 'tenants'")?;

        deserialize_entity(result.item)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn list_all(&self) -> anyhow::Result<Vec<Tenant>> {
        // Single query on the constant-partition GSI, newest `lastUpdated` first, paginated by
        // `find_all`. No table scan.
        let query = self
            .client
            .query(TABLE_TENANTS)
            .index_name(INDEX_BY_LAST_UPDATED)
            .key_condition_expression("#shard = :shard")
            .expression_attribute_names("#shard", FIELD_LIST_SHARD)
            .expression_attribute_values(":shard", str(LIST_SHARD_VALUE))
            .scan_index_forward(false)
            .limit(LIST_PAGE_SIZE);
        find_all(query).await.context("Error listing 'tenants'")
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn put_tenant(&self, mut tenant: Tenant) -> anyhow::Result<Tenant> {
        // Optimistic lock: require the stored version to equal the one we read, then bump it. A
        // concurrent writer that already bumped it makes this fail → 409, forcing a reload.
        let expected_version = tenant.version;
        tenant.version = expected_version + 1;
        tenant.last_updated = Utc::now();

        let result = self
            .client
            .put_entity(TABLE_TENANTS, &tenant)?
            .item(FIELD_LIST_SHARD, str(LIST_SHARD_VALUE))
            .condition_expression("#version = :expected")
            .expression_attribute_names("#version", FIELD_VERSION)
            .expression_attribute_values(
                ":expected",
                AttributeValue::N(expected_version.to_string()),
            )
            .send()
            .await;

        if let Err(err) = result {
            if err
                .as_service_error()
                .map(|service_err| service_err.is_conditional_check_failed_exception())
                .unwrap_or(false)
            {
                status_bail!(
                    StatusCode::CONFLICT,
                    "Tenant was modified concurrently — reload and retry"
                );
            }
            return Err(anyhow::Error::new(err).context("Error updating 'tenants' table"));
        }

        Ok(tenant)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn delete_tenant(&self, tenant_id: &str) -> anyhow::Result<()> {
        let _ = self
            .client
            .delete_item(TABLE_TENANTS)
            .key(FIELD_TENANT_ID, str(tenant_id))
            .send()
            .await
            .context("Error deleting from 'tenants' table")?;
        Ok(())
    }
}
