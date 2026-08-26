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
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, SecondsFormat, Utc};
use std::collections::HashMap;
use std::env;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, generate_id, str};

const TABLE_AUDIT: &str = "audit-log";
const FIELD_ID: &str = "id";
const FIELD_USER: &str = "user";
const FIELD_TENANT: &str = "tenant";
const FIELD_TIMESTAMP: &str = "timestamp";

/// Epoch-seconds attribute DynamoDB expires entries on (retention window).
const FIELD_TTL: &str = "ttl";
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

    /// One page of a user's entries, newest first (`limit` per page). `cursor` resumes after a prior
    /// page; returns the page plus the next cursor (`None` when the trail is exhausted).
    async fn list_by_user(
        &self,
        user_id: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> anyhow::Result<(Vec<AuditEntry>, Option<String>)>;

    /// One page of a tenant's entries, newest first (`limit` per page). See `list_by_user`.
    async fn list_by_tenant(
        &self,
        tenant_id: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> anyhow::Result<(Vec<AuditEntry>, Option<String>)>;
}

/// Opaque page cursor over `(timestamp, id)` — unique even across equal timestamps, since `id` is
/// the table PK. Encoded base64url so it survives a query string untouched.
fn encode_cursor(timestamp: &str, id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{timestamp}|{id}"))
}

fn decode_cursor(cursor: &str) -> anyhow::Result<(String, String)> {
    let raw = URL_SAFE_NO_PAD
        .decode(cursor)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .context("Invalid audit cursor")?;
    let (timestamp, id) = raw.split_once('|').context("Invalid audit cursor")?;
    Ok((timestamp.to_owned(), id.to_owned()))
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
            .create_table_with_ttl(TABLE_AUDIT, FIELD_TTL, |table| {
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

    /// Query one page of a GSI (hash on `key_field`, range `timestamp`), newest first. `.limit(n)`
    /// caps what DynamoDB reads, and `cursor` resumes after a prior page via `ExclusiveStartKey` —
    /// so we only ever read one page, never the whole trail. Returns the page + the next cursor.
    async fn list_page(
        &self,
        index: &str,
        key_field: &str,
        key_value: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> anyhow::Result<(Vec<AuditEntry>, Option<String>)> {
        let mut query = self
            .client
            .query(TABLE_AUDIT)
            .index_name(index)
            .key_condition_expression("#k = :v")
            .expression_attribute_names("#k", key_field)
            .expression_attribute_values(":v", str(key_value))
            .scan_index_forward(false)
            .limit(limit.max(1));

        if let Some(cursor) = cursor {
            let (timestamp, id) = decode_cursor(cursor)?;
            // A GSI query's LastEvaluatedKey carries the GSI keys + the table PK.
            let start = HashMap::from([
                (key_field.to_owned(), str(key_value)),
                (FIELD_TIMESTAMP.to_owned(), str(&timestamp)),
                (FIELD_ID.to_owned(), str(&id)),
            ]);
            query = query.set_exclusive_start_key(Some(start));
        }

        let result = query.send().await.context("Error listing 'audit-log'")?;
        let has_more = result.last_evaluated_key.is_some();
        let entries: Vec<AuditEntry> = result
            .items
            .unwrap_or_default()
            .into_iter()
            .filter_map(|item| deserialize_entity::<AuditEntry>(Some(item)).transpose())
            .collect::<anyhow::Result<_>>()?;

        // Only offer a next cursor when DynamoDB says more may follow (and we have an anchor).
        let next = match entries.last() {
            Some(last) if has_more => Some(encode_cursor(&last.timestamp, &last.id)),
            _ => None,
        };
        Ok((entries, next))
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
            ip: entry.ip,
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
    async fn list_by_user(
        &self,
        user_id: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> anyhow::Result<(Vec<AuditEntry>, Option<String>)> {
        self.list_page(INDEX_BY_USER, FIELD_USER, user_id, limit, cursor)
            .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn list_by_tenant(
        &self,
        tenant_id: &str,
        limit: i32,
        cursor: Option<&str>,
    ) -> anyhow::Result<(Vec<AuditEntry>, Option<String>)> {
        self.list_page(INDEX_BY_TENANT, FIELD_TENANT, tenant_id, limit, cursor)
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
