//! DynamoDB persistence for tenants.

use crate::tenants::{Tenant, TenantStatus};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::BillingMode;
use chrono::Utc;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, generate_id, str};

/// Table storing tenants.
const TABLE_TENANTS: &str = "tenants";

/// Hash key of the `tenants` table.
const FIELD_TENANT_ID: &str = "tenantId";

/// Default plan assigned to a freshly created tenant.
const DEFAULT_PLAN: &str = "free";

/// Persistence interface for tenants.
#[async_trait]
pub trait TenantRepository: Send + Sync {
    /// Creates a tenant with sensible defaults (status `Active`, plan `free`), returning it.
    async fn create_tenant(&self, name: &str, slug: &str) -> anyhow::Result<Tenant>;

    /// Fetches a tenant by id. `None` if unknown.
    async fn get_tenant(&self, tenant_id: &str) -> anyhow::Result<Option<Tenant>>;

    /// Overwrites a tenant record (used by PATCH after a read-modify), bumping `lastUpdated`.
    async fn put_tenant(&self, tenant: Tenant) -> anyhow::Result<Tenant>;
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
                let table = table.attribute_definitions(str_attribute(FIELD_TENANT_ID)?);
                let table = with_hash_index(table, FIELD_TENANT_ID)?;
                Ok(table.billing_mode(BillingMode::PayPerRequest))
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
        let now = Utc::now();
        let tenant = Tenant {
            tenant_id: generate_id(),
            name: name.to_owned(),
            slug: slug.to_owned(),
            status: TenantStatus::Active,
            plan: DEFAULT_PLAN.to_owned(),
            billed_until: None,
            seats_limit: None,
            usage_period_start: None,
            ai_tokens_used: 0,
            ai_tokens_quota: None,
            created: now,
            last_updated: now,
        };

        let _ = self
            .client
            .put_entity(TABLE_TENANTS, &tenant)?
            .send()
            .await
            .context("Error inserting entity into 'tenants' table")?;

        Ok(tenant)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn get_tenant(&self, tenant_id: &str) -> anyhow::Result<Option<Tenant>> {
        let result = self
            .client
            .get_item(TABLE_TENANTS)
            .key(FIELD_TENANT_ID, str(tenant_id))
            .send()
            .await
            .context("Error searching table 'tenants'")?;

        deserialize_entity(result.item)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn put_tenant(&self, mut tenant: Tenant) -> anyhow::Result<Tenant> {
        tenant.last_updated = Utc::now();

        let _ = self
            .client
            .put_entity(TABLE_TENANTS, &tenant)?
            .send()
            .await
            .context("Error updating 'tenants' table")?;

        Ok(tenant)
    }
}
