//! DynamoDB persistence for API keys.
//!
//! `api-keys` (PK `keyId`, GSI `ByTenantIndex` on `tenantId`) stores each key's metadata + the
//! SHA-256 hash of its secret. The secret itself is never stored.

use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, find_all, str};

const TABLE_API_KEYS: &str = "api-keys";
const FIELD_KEY_ID: &str = "keyId";
const FIELD_TENANT_ID: &str = "tenantId";
const FIELD_LAST_USED_AT: &str = "lastUsedAt";
const INDEX_BY_TENANT: &str = "ByTenantIndex";

/// Lifecycle state of an API key.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyStatus {
    /// Usable.
    Active,
    /// Revoked — exchange rejected.
    Revoked,
}

/// Per-key override of the global `tokenExchange` rate-limit policy (see `docs/API-KEYS.md`).
/// Mainly used to **raise** the cap for a legitimate high-fanout backend, or to **disable** the
/// per-key cap for a controlled public-token flow (the per-IP cap still applies). Any unset field
/// falls back to the global `security.rateLimits.tokenExchange` value.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct KeyRateLimit {
    /// When true, the per-key volume cap is switched off for this key entirely.
    #[serde(default)]
    pub disabled: bool,
    /// Overrides `tokenExchange.maxPerWindow` for this key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_window: Option<u32>,
    /// Overrides `tokenExchange.windowSecs` for this key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_secs: Option<u32>,
    /// Overrides `tokenExchange.blockSecs` for this key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_secs: Option<u32>,
}

/// A persisted API key (metadata + secret hash).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApiKey {
    /// Primary key.
    pub key_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// SHA-256 (base64url) of the secret.
    pub secret_hash: String,
    /// Human-readable label.
    pub name: String,
    /// **Subject discriminator.** `None` → a *service key* that acts as itself (subjects are its
    /// `scopes`). `Some(userId)` → a *personal access token* that acts as that user (its `role:*`,
    /// optionally restricted by `roles`). See `docs/API-KEYS.md`.
    #[serde(default)]
    pub user_id: Option<String>,
    /// PAT role restriction: when non-empty, the token acts with the user's roles **intersected**
    /// with this set (never an escalation). Empty = the user's full roles. Ignored for service keys.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Service-key subjects: the `scope:*` codes this machine key carries at exchange. Ignored for
    /// PATs (which derive their subjects from the acting user).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Lifecycle state.
    pub status: ApiKeyStatus,
    /// Whether the raw-secret exchange (Mode 1) is accepted for this key. Default **false** ⇒ the key
    /// is HMAC-only (Mode 2): presenting the raw secret is refused even if it is correct.
    #[serde(default)]
    pub allow_secret_login: bool,
    /// Origins permitted to exchange this key (Mode 1); empty = unrestricted.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Optional per-key override of the `tokenExchange` rate-limit policy. `None` = use the global
    /// policy (see [`KeyRateLimit`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<KeyRateLimit>,
    /// Optional expiry.
    pub expires_at: Option<DateTime<Utc>>,
    /// Last successful exchange.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created: DateTime<Utc>,
}

/// Parameters for creating an API key.
pub struct NewApiKey {
    pub key_id: String,
    pub tenant_id: String,
    pub secret_hash: String,
    pub name: String,
    /// `Some(userId)` → personal access token; `None` → tenant service key.
    pub user_id: Option<String>,
    pub roles: Vec<String>,
    /// PAT down-scoping (ignored for service keys).
    pub scopes: Vec<String>,
    /// Whether the raw-secret exchange (Mode 1) is allowed; `false` ⇒ HMAC-only.
    pub allow_secret_login: bool,
    pub allowed_origins: Vec<String>,
    /// Optional per-key rate-limit override (`None` = use the global `tokenExchange` policy).
    pub rate_limit: Option<KeyRateLimit>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Persistence for API keys.
#[async_trait]
pub trait ApiKeyRepository: Send + Sync {
    /// Stores a new key.
    async fn create(&self, new_key: NewApiKey) -> anyhow::Result<()>;

    /// Fetches a key by id.
    async fn get(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>>;

    /// Lists a tenant's keys (via `ByTenantIndex`).
    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<ApiKey>>;

    /// Deletes (revokes) a key.
    async fn delete(&self, key_id: &str) -> anyhow::Result<()>;

    /// Best-effort `lastUsedAt` bump after a successful exchange.
    async fn touch_last_used(&self, key_id: &str) -> anyhow::Result<()>;
}

/// DynamoDB-backed implementation of [`ApiKeyRepository`].
#[derive(Clone)]
pub struct DynamoApiKeyRepository {
    client: DynamoClient,
}

impl DynamoApiKeyRepository {
    #[tracing::instrument(skip(client), err(Display))]
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
    #[tracing::instrument(level = "debug", skip(self, new_key), err(Display))]
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

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
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

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
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

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
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

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
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
