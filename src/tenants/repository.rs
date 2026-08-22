//! DynamoDB persistence for tenants.

use crate::search::{query_matches, value_search_text};
use crate::tenants::Tenant;
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType,
};
use chrono::{SecondsFormat, Utc};
use futures_util::StreamExt;
use std::collections::BTreeMap;
use warp::http::StatusCode;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, generate_id, str, stream_all};
use wasabi::status_bail;

/// Table storing tenants.
const TABLE_TENANTS: &str = "tenants";

/// Hash key of the `tenants` table.
const FIELD_TENANT_ID: &str = "tenantId";

/// Optimistic-concurrency attribute.
const FIELD_VERSION: &str = "version";

/// `lastActive` attribute — bumped by [`TenantRepository::touch_last_active`] on token activity.
const FIELD_LAST_ACTIVE: &str = "lastActive";

/// `lastActiveOrCreated` attribute — range key of the listing GSI (`last_active` else `created`;
/// bumped on activity), so tenants sort activity-first and inactive ones stably by creation.
const FIELD_LAST_ACTIVE_OR_CREATED: &str = "lastActiveOrCreated";

/// Constant partition attribute injected at write time so all tenants share one GSI partition,
/// making "list every tenant, sorted by `lastUpdated`" a single query (no table scan). Kept out of
/// the [`Tenant`] model — it's storage-only and never surfaces in API responses.
const FIELD_LIST_SHARD: &str = "listShard";

/// The single value written to [`FIELD_LIST_SHARD`].
const LIST_SHARD_VALUE: &str = "tenant";

/// GSI listing all tenants ordered by `lastActiveOrCreated`.
const INDEX_BY_LAST_ACTIVE: &str = "ByLastActiveIndex";

/// Page size for the listing query (paginated internally by `find_all`).
const LIST_PAGE_SIZE: i32 = 100;

/// Persistence interface for tenants.
#[async_trait]
pub trait TenantRepository: Send + Sync {
    /// Creates a tenant, returning it. `created_by` records the acting user id (`None` for
    /// system/auto-init).
    async fn create_tenant(
        &self,
        name: &str,
        slug: &str,
        created_by: Option<&str>,
    ) -> anyhow::Result<Tenant>;

    /// Creates a tenant with a caller-supplied id (used by auto-init to materialise the configured
    /// system tenant). Same defaults as `create_tenant`.
    async fn create_tenant_with_id(
        &self,
        tenant_id: &str,
        name: &str,
        slug: &str,
        created_by: Option<&str>,
    ) -> anyhow::Result<Tenant>;

    /// Best-effort bump of the tenant's `lastActive` timestamp (token activity heartbeat). Does not
    /// touch `version`/`lastUpdated` — it is not a logical change.
    async fn touch_last_active(&self, tenant_id: &str) -> anyhow::Result<()>;

    /// Fetches a tenant by id. `None` if unknown.
    async fn get_tenant(&self, tenant_id: &str) -> anyhow::Result<Option<Tenant>>;

    /// Finds tenants matching `query` (case-insensitive over name/slug/custom fields; empty = all),
    /// newest-active first, returning at most `limit` plus a `truncated` flag when more matched.
    /// The DynamoDB backend streams the listing GSI and stops as soon as the cap is reached; a
    /// smarter store can push the filter + limit down to the server.
    async fn find_tenants(&self, query: &str, limit: usize) -> anyhow::Result<(Vec<Tenant>, bool)>;

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
                let by_last_active = GlobalSecondaryIndex::builder()
                    .index_name(INDEX_BY_LAST_ACTIVE)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(FIELD_LIST_SHARD)
                            .key_type(KeyType::Hash)
                            .build()?,
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(FIELD_LAST_ACTIVE_OR_CREATED)
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
                    .attribute_definitions(str_attribute(FIELD_LAST_ACTIVE_OR_CREATED)?);
                let table = with_hash_index(table, FIELD_TENANT_ID)?;

                Ok(table
                    .global_secondary_indexes(by_last_active)
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
    async fn create_tenant(
        &self,
        name: &str,
        slug: &str,
        created_by: Option<&str>,
    ) -> anyhow::Result<Tenant> {
        self.create_tenant_with_id(&generate_id(), name, slug, created_by)
            .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn create_tenant_with_id(
        &self,
        tenant_id: &str,
        name: &str,
        slug: &str,
        created_by: Option<&str>,
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
            last_active: None,
            last_active_or_created: now,
            created_by: created_by.map(str::to_owned),
            last_changed_by: created_by.map(str::to_owned),
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
        // Strongly consistent: tenant PATCH (name / features / custom fields) read-modify-writes
        // this record under an optimistic version, so a stale read must never be the basis of a write.
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
    async fn find_tenants(&self, query: &str, limit: usize) -> anyhow::Result<(Vec<Tenant>, bool)> {
        // Constant-partition GSI, newest-active first. We *stream* the pages and filter in-memory —
        // DynamoDB can't search — stopping the moment we have `limit`+1 matches, so an unfiltered
        // (or quickly-matched) query never drains the whole partition.
        let request = self
            .client
            .query(TABLE_TENANTS)
            .index_name(INDEX_BY_LAST_ACTIVE)
            .key_condition_expression("#shard = :shard")
            .expression_attribute_names("#shard", FIELD_LIST_SHARD)
            .expression_attribute_values(":shard", str(LIST_SHARD_VALUE))
            .scan_index_forward(false)
            .limit(LIST_PAGE_SIZE);

        let mut stream = stream_all::<Tenant>(request)?;
        let mut matched = Vec::new();
        let mut truncated = false;
        while let Some(item) = stream.next().await {
            let tenant = item.context("Error listing 'tenants'")?;
            if query_matches(&tenant_haystack(&tenant), query) {
                if matched.len() >= limit {
                    truncated = true;
                    break;
                }
                matched.push(tenant);
            }
        }
        Ok((matched, truncated))
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
    async fn touch_last_active(&self, tenant_id: &str) -> anyhow::Result<()> {
        let _ = self
            .client
            .update_item(TABLE_TENANTS)
            .key(FIELD_TENANT_ID, str(tenant_id))
            .update_expression("SET #lastActive = :now, #lastActiveOrCreated = :now")
            .condition_expression("attribute_exists(#tenantId)")
            .expression_attribute_names("#tenantId", FIELD_TENANT_ID)
            .expression_attribute_names("#lastActive", FIELD_LAST_ACTIVE)
            .expression_attribute_names("#lastActiveOrCreated", FIELD_LAST_ACTIVE_OR_CREATED)
            .expression_attribute_values(
                ":now",
                str(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
            )
            .send()
            .await
            .context("Error updating lastActive in 'tenants' table")?;

        Ok(())
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

/// Concatenates a tenant's searchable text: name, slug, and every custom-field value (customer
/// number / address live in custom fields). Fed to `query_matches` for the in-memory filter.
fn tenant_haystack(tenant: &Tenant) -> String {
    let mut haystack = format!("{} {}", tenant.name, tenant.slug);
    for value in tenant.custom_fields.values() {
        haystack.push(' ');
        haystack.push_str(&value_search_text(value));
    }
    haystack
}
