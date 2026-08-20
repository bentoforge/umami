//! DynamoDB persistence for the audit log.
//!
//! `audit-log` (PK `id`) with two GSIs — `ByUserIndex` (hash `user`, range `timestamp`) and
//! `ByTenantIndex` (hash `tenant`, range `timestamp`) — so events are listable per user or per
//! tenant, newest first. A numeric `ttl` epoch is written per row; enabling the DynamoDB TTL that
//! actually deletes expired rows is done out-of-band (Terraform).

use crate::audit::{AuditEntry, NewAuditEntry};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection, ProjectionType,
};
use chrono::{Duration, SecondsFormat, Utc};
use std::env;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{find_all, generate_id, str};

const TABLE_AUDIT: &str = "audit-log";
const FIELD_ID: &str = "id";
const FIELD_USER: &str = "user";
const FIELD_TENANT: &str = "tenant";
const FIELD_TIMESTAMP: &str = "timestamp";
const INDEX_BY_USER: &str = "ByUserIndex";
const INDEX_BY_TENANT: &str = "ByTenantIndex";

/// Default retention before an entry's `ttl` lets DynamoDB expire it (override with
/// `UMAMI_AUDIT_RETENTION_DAYS`).
const DEFAULT_RETENTION_DAYS: i64 = 365;

/// Persistence for the audit log.
#[async_trait]
pub trait AuditRepository: Send + Sync {
    /// Appends an audit entry (stamps `id`/`timestamp`/`ttl`).
    async fn record(&self, entry: NewAuditEntry) -> anyhow::Result<()>;

    /// Lists a user's entries, newest first (capped by `limit`).
    async fn list_by_user(&self, user_id: &str, limit: i32) -> anyhow::Result<Vec<AuditEntry>>;

    /// Lists a tenant's entries, newest first (capped by `limit`).
    async fn list_by_tenant(&self, tenant_id: &str, limit: i32) -> anyhow::Result<Vec<AuditEntry>>;
}

/// DynamoDB-backed [`AuditRepository`].
#[derive(Clone)]
pub struct DynamoAuditRepository {
    client: DynamoClient,
    retention_days: i64,
}

impl DynamoAuditRepository {
    #[tracing::instrument(skip(client), err(Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_AUDIT, |table| {
                let by_user = gsi(INDEX_BY_USER, FIELD_USER)?;
                let by_tenant = gsi(INDEX_BY_TENANT, FIELD_TENANT)?;
                let table = table
                    .attribute_definitions(str_attribute(FIELD_ID)?)
                    .attribute_definitions(str_attribute(FIELD_USER)?)
                    .attribute_definitions(str_attribute(FIELD_TENANT)?)
                    .attribute_definitions(str_attribute(FIELD_TIMESTAMP)?);
                let table = with_hash_index(table, FIELD_ID)?;
                Ok(table
                    .global_secondary_indexes(by_user)
                    .global_secondary_indexes(by_tenant)
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        let retention_days = env::var("UMAMI_AUDIT_RETENTION_DAYS")
            .ok()
            .and_then(|raw| raw.trim().parse::<i64>().ok())
            .filter(|days| *days > 0)
            .unwrap_or(DEFAULT_RETENTION_DAYS);

        Ok(Self {
            client: client.clone(),
            retention_days,
        })
    }

    /// Query one of the GSIs (hash on `key_field`, range `timestamp`), newest first.
    async fn list_by(
        &self,
        index: &str,
        key_field: &str,
        key_value: &str,
        limit: i32,
    ) -> anyhow::Result<Vec<AuditEntry>> {
        let query = self
            .client
            .query(TABLE_AUDIT)
            .index_name(index)
            .key_condition_expression("#k = :v")
            .expression_attribute_names("#k", key_field)
            .expression_attribute_values(":v", str(key_value))
            .scan_index_forward(false)
            .limit(limit.max(1));
        // `.limit(..)` is only the page size; `find_all` paginates every page. Truncate to the
        // requested cap so callers get at most `limit` (newest-first) entries.
        let mut entries = find_all(query).await.context("Error listing 'audit-log'")?;
        entries.truncate(limit.max(1) as usize);
        Ok(entries)
    }
}

/// Builds a GSI keyed `(key_field, timestamp)` projecting all attributes.
fn gsi(
    index_name: &str,
    key_field: &str,
) -> Result<GlobalSecondaryIndex, aws_sdk_dynamodb::error::BuildError> {
    GlobalSecondaryIndex::builder()
        .index_name(index_name)
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(key_field)
                .key_type(KeyType::Hash)
                .build()?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(FIELD_TIMESTAMP)
                .key_type(KeyType::Range)
                .build()?,
        )
        .projection(
            Projection::builder()
                .projection_type(ProjectionType::All)
                .build(),
        )
        .build()
}

#[async_trait]
impl AuditRepository for DynamoAuditRepository {
    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn record(&self, entry: NewAuditEntry) -> anyhow::Result<()> {
        let now = Utc::now();
        let audit = AuditEntry {
            id: generate_id(),
            timestamp: now.to_rfc3339_opts(SecondsFormat::Millis, true),
            tenant: entry.tenant,
            user: entry.user,
            severity: entry.severity,
            message: entry.message,
            ttl: (now + Duration::days(self.retention_days)).timestamp(),
        };
        let _ = self
            .client
            .put_entity(TABLE_AUDIT, &audit)?
            .condition_expression("attribute_not_exists(#id)")
            .expression_attribute_names("#id", FIELD_ID)
            .send()
            .await
            .context("Error inserting into 'audit-log' (id collision?)")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn list_by_user(&self, user_id: &str, limit: i32) -> anyhow::Result<Vec<AuditEntry>> {
        self.list_by(INDEX_BY_USER, FIELD_USER, user_id, limit)
            .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn list_by_tenant(&self, tenant_id: &str, limit: i32) -> anyhow::Result<Vec<AuditEntry>> {
        self.list_by(INDEX_BY_TENANT, FIELD_TENANT, tenant_id, limit)
            .await
    }
}

/// Fire-and-forget audit recording: logs a warning on failure instead of propagating, so auditing
/// never breaks the request it describes. Callers use this for the happy/most paths.
pub async fn record_best_effort(audit: &std::sync::Arc<dyn AuditRepository>, entry: NewAuditEntry) {
    let severity = entry.severity;
    if let Err(err) = audit.record(entry).await {
        tracing::warn!("failed to write audit entry ({severity:?}): {err:#}");
    }
}
