//! DynamoDB persistence for API keys.
//!
//! `api-keys` (PK `keyId`, GSI `ByTenantIndex` on `tenantId`) stores each key's metadata + the
//! SHA-256 hash of its secret. The secret itself is never stored.

use super::{ApiKey, ApiKeyRepository, ApiKeyStatus, NewApiKey};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType,
};
use chrono::{SecondsFormat, Utc};
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, find_all, str};

const TABLE_API_KEYS: &str = "api-keys";
const FIELD_KEY_ID: &str = "keyId";
const FIELD_TENANT_ID: &str = "tenantId";
const FIELD_LAST_USED_AT: &str = "lastUsedAt";
const INDEX_BY_TENANT: &str = "ByTenantIndex";

/// DynamoDB-backed implementation of [`ApiKeyRepository`].
#[derive(Clone)]
pub struct DynamoApiKeyRepository {
    client: DynamoClient,
}

impl DynamoApiKeyRepository {
    #[tracing::instrument(skip(client), err(level = "debug", Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_API_KEYS, |table| {
                let by_tenant = GlobalSecondaryIndex::builder()
                    .index_name(INDEX_BY_TENANT)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(FIELD_TENANT_ID)
                            .key_type(KeyType::Hash)
                            .build()?,
                    )
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .build()?;

                let table = table
                    .attribute_definitions(str_attribute(FIELD_KEY_ID)?)
                    .attribute_definitions(str_attribute(FIELD_TENANT_ID)?);
                let table = with_hash_index(table, FIELD_KEY_ID)?;

                Ok(table
                    .global_secondary_indexes(by_tenant)
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        Ok(Self {
            client: client.clone(),
        })
    }
}

#[async_trait]
impl ApiKeyRepository for DynamoApiKeyRepository {
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
        // Defensive: the id is the PK — `attribute_not_exists` makes an id collision fail loudly
        // instead of clobbering an existing key, for free.
        let _ = self
            .client
            .put_entity(TABLE_API_KEYS, &key)?
            .condition_expression("attribute_not_exists(#keyId)")
            .expression_attribute_names("#keyId", FIELD_KEY_ID)
            .send()
            .await
            .context("Error inserting into 'api-keys' (id collision?)")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn get(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>> {
        let result = self
            .client
            .get_item(TABLE_API_KEYS)
            .key(FIELD_KEY_ID, str(key_id))
            .send()
            .await
            .context("Error searching 'api-keys'")?;
        deserialize_entity(result.item)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<ApiKey>> {
        let query = self
            .client
            .query(TABLE_API_KEYS)
            .index_name(INDEX_BY_TENANT)
            .key_condition_expression("#tenantId = :tenantId")
            .expression_attribute_names("#tenantId", FIELD_TENANT_ID)
            .expression_attribute_values(":tenantId", str(tenant_id))
            .limit(100);
        find_all(query).await.context("Error listing 'api-keys'")
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_all_for_user(&self, tenant_id: &str, user_id: &str) -> anyhow::Result<usize> {
        // Listing by tenant and filtering beats a `ByUser` index nothing else would read: a tenant's
        // key list is small, and the filter is the same one that decides PAT versus service key.
        let keys: Vec<ApiKey> = self
            .list_by_tenant(tenant_id)
            .await?
            .into_iter()
            .filter(|key| key.user_id.as_deref() == Some(user_id))
            .collect();

        let count = keys.len();
        for key in keys {
            self.delete(&key.key_id).await?;
        }
        Ok(count)
    }

    async fn delete(&self, key_id: &str) -> anyhow::Result<()> {
        let _ = self
            .client
            .delete_item(TABLE_API_KEYS)
            .key(FIELD_KEY_ID, str(key_id))
            .send()
            .await
            .context("Error deleting from 'api-keys'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn touch_last_used(&self, key_id: &str) -> anyhow::Result<()> {
        let _ = self
            .client
            .update_item(TABLE_API_KEYS)
            .key(FIELD_KEY_ID, str(key_id))
            .update_expression("SET #lastUsedAt = :now")
            .condition_expression("attribute_exists(#keyId)")
            .expression_attribute_names("#keyId", FIELD_KEY_ID)
            .expression_attribute_names("#lastUsedAt", FIELD_LAST_USED_AT)
            .expression_attribute_values(
                ":now",
                AttributeValue::S(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
            )
            .send()
            .await
            .context("Error updating 'api-keys'")?;
        Ok(())
    }
}
