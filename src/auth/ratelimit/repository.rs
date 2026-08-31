//! DynamoDB persistence for rate-limit counters and blocks.
//!
//! `rate-limits` (PK `id`) stores two kinds of small items, distinguished only by their id (built by
//! the [`RateLimiter`](super::RateLimiter), never here):
//! - a **counter** — a numeric `count` for one `(policy, subject, window-bucket)`, bumped with a
//!   single atomic `ADD` so concurrent nodes never race;
//! - a **block** — a numeric `blockedUntil` epoch for one `(policy, subject)`, set once a counter
//!   trips its threshold.
//!
//! Every item carries a numeric `ttl` epoch so DynamoDB self-cleans expired rows (same pattern as
//! the `sessions`/`audit-log` tables; enabling the table TTL is done out-of-band). The trait exposes
//! only DB-agnostic primitives, so the store can be swapped for another backend later.
//!
//! # Why only blocks are indexed
//! `BlocksByPolicyIndex` (hash `policy`, range `blockedAt`) exists for exactly one caller: the admin
//! overview, which must list subjects it cannot name in advance (which IPs tripped?). Everything
//! else is looked up by a known subject and therefore reads the hash key directly — no index.
//!
//! The index attributes are written **only** by [`RateLimitRepository::set_block`], which runs when
//! a subject actually trips a threshold — rare by construction. Putting them on `increment` instead
//! would add a GSI write to every login and token exchange and funnel all of them into the one
//! partition per policy name, i.e. build the hot partition the rate limiter exists to prevent.
//! Counters stay out of the index (a sparse GSI ignores items without its keys).

use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, CreateGlobalSecondaryIndexAction,
    GlobalSecondaryIndex, GlobalSecondaryIndexUpdate, KeySchemaElement, KeyType, Projection,
    ProjectionType, ReturnValue,
};
use std::collections::HashMap;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{numeric_attribute, str_attribute, with_hash_index};
use wasabi::aws::dynamodb::str;

const TABLE_RATE_LIMITS: &str = "rate-limits";
const FIELD_ID: &str = "id";
const FIELD_COUNT: &str = "count";
const FIELD_BLOCKED_UNTIL: &str = "blockedUntil";
const FIELD_BLOCKED_AT: &str = "blockedAt";
const FIELD_POLICY: &str = "policy";
const FIELD_SUBJECT: &str = "subject";
const FIELD_TTL: &str = "ttl";
const INDEX_BLOCKS_BY_POLICY: &str = "BlocksByPolicyIndex";

/// A block as read back for the admin overview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRecord {
    /// Policy that tripped.
    pub policy: String,
    /// The blocked subject (IP, user id or key id).
    pub subject: String,
    /// When the block was set (epoch seconds).
    pub blocked_at: i64,
    /// When the block lifts (epoch seconds) — already in the past for an expired-but-recent block.
    pub blocked_until: i64,
}

/// A stored item, read for inspection: a counter, a block, or (after a block on a subject whose
/// counter still lives) both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredItem {
    /// The counter value, for a counter item.
    pub count: Option<u64>,
    /// The `blockedUntil` epoch, for a block item.
    pub blocked_until: Option<i64>,
    /// The item's own TTL epoch — for the rolling failure counter this is the only record of when
    /// the window started, so inspection derives the reset time from it.
    pub expires_at: Option<i64>,
}

/// Persistence for rate-limit counters and blocks. DB-agnostic primitives only — the id strings and
/// all policy logic live in [`RateLimiter`](super::RateLimiter), so a different backend can be
/// dropped in behind this trait.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait RateLimitRepository: Send + Sync {
    /// Atomically increments the counter item `id` by one (creating it at 1), refreshes its `ttl`,
    /// and returns the **new** count. One round-trip; safe under concurrency.
    async fn increment(&self, id: &str, ttl_epoch: i64) -> anyhow::Result<u64>;

    /// Reads the `blockedUntil` epoch of the block item `id`, or `None` if there is no block.
    async fn get_block(&self, id: &str) -> anyhow::Result<Option<i64>>;

    /// Sets the block item `id`: when it lifts (`blocked_until`), when it was set (`blocked_at`),
    /// and the `policy`/`subject` that make the row self-describing in the admin overview. The
    /// latter two double as the `BlocksByPolicyIndex` keys — this is the only write that indexes.
    async fn set_block(
        &self,
        id: &str,
        policy: &str,
        subject: &str,
        blocked_at: i64,
        blocked_until: i64,
        ttl_epoch: i64,
    ) -> anyhow::Result<()>;

    /// Deletes an item by id (used to reset a counter / lift a block on a successful login).
    async fn clear(&self, id: &str) -> anyhow::Result<()>;

    /// Reads several items by id, omitting the ones that do not exist. **Inspection only** — the
    /// enforcement paths read a single known key.
    async fn get_items(&self, ids: &[String]) -> anyhow::Result<HashMap<String, StoredItem>>;

    /// Blocks set for `policy` at or after `since_epoch`, newest first, at most `limit` of them.
    /// Backed by `BlocksByPolicyIndex`, so this reads one bounded page and never scans.
    async fn list_blocks(
        &self,
        policy: &str,
        since_epoch: i64,
        limit: i32,
    ) -> anyhow::Result<Vec<BlockRecord>>;
}

/// DynamoDB-backed implementation of [`RateLimitRepository`].
#[derive(Clone)]
pub struct DynamoRateLimitRepository {
    client: DynamoClient,
}

impl DynamoRateLimitRepository {
    #[tracing::instrument(skip(client), err(Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table_with_ttl(TABLE_RATE_LIMITS, FIELD_TTL, |table| {
                let table = table
                    .attribute_definitions(str_attribute(FIELD_ID)?)
                    .attribute_definitions(str_attribute(FIELD_POLICY)?)
                    .attribute_definitions(numeric_attribute(FIELD_BLOCKED_AT)?);
                let table = with_hash_index(table, FIELD_ID)?;
                Ok(table
                    .global_secondary_indexes(
                        GlobalSecondaryIndex::builder()
                            .index_name(INDEX_BLOCKS_BY_POLICY)
                            .set_key_schema(Some(blocks_index_key_schema()?))
                            .projection(
                                Projection::builder()
                                    .projection_type(ProjectionType::All)
                                    .build(),
                            )
                            .build()?,
                    )
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        ensure_blocks_index(client).await;

        Ok(Self {
            client: client.clone(),
        })
    }
}

/// The `BlocksByPolicyIndex` key schema — shared so `CreateTable` and the convergence below cannot
/// drift apart.
fn blocks_index_key_schema() -> Result<Vec<KeySchemaElement>, aws_sdk_dynamodb::error::BuildError> {
    Ok(vec![
        KeySchemaElement::builder()
            .attribute_name(FIELD_POLICY)
            .key_type(KeyType::Hash)
            .build()?,
        KeySchemaElement::builder()
            .attribute_name(FIELD_BLOCKED_AT)
            .key_type(KeyType::Range)
            .build()?,
    ])
}

/// The `UpdateTable` payload that adds `BlocksByPolicyIndex`: the index itself plus the definitions
/// of the two attributes it keys on, which `UpdateTable` requires for a new index.
fn build_blocks_index_update() -> Result<
    (
        GlobalSecondaryIndexUpdate,
        AttributeDefinition,
        AttributeDefinition,
    ),
    aws_sdk_dynamodb::error::BuildError,
> {
    let action = CreateGlobalSecondaryIndexAction::builder()
        .index_name(INDEX_BLOCKS_BY_POLICY)
        .set_key_schema(Some(blocks_index_key_schema()?))
        .projection(
            Projection::builder()
                .projection_type(ProjectionType::All)
                .build(),
        )
        .build()?;
    Ok((
        GlobalSecondaryIndexUpdate::builder().create(action).build(),
        str_attribute(FIELD_POLICY)?,
        numeric_attribute(FIELD_BLOCKED_AT)?,
    ))
}

/// Adds `BlocksByPolicyIndex` to a `rate-limits` table that predates it.
///
/// `create_table` is a no-op on an existing table, so a deployment that ran before the overview
/// existed would keep an index-less table and answer every overview query with a DynamoDB
/// `ValidationException`. Convergence therefore runs on **every** boot, exactly like the TTL —
/// the same reasoning, the same failure mode if it didn't.
///
/// **Never fatal.** The index serves one read-only screen; a missing `dynamodb:UpdateTable`
/// permission (or an index still backfilling) must not stop umami from issuing tokens. On failure
/// this logs the manual command and carries on.
///
/// Note that only rows written *after* the index exists appear in it: the block metadata the index
/// keys on was not written before, and DynamoDB's backfill can only index what an item carries.
async fn ensure_blocks_index(client: &DynamoClient) {
    let table = client.effective_name(TABLE_RATE_LIMITS);

    let described = match client
        .client
        .describe_table()
        .table_name(&table)
        .send()
        .await
    {
        Ok(described) => described,
        Err(err) => {
            tracing::warn!("Could not describe '{table}' to check its indexes: {err}");
            return;
        }
    };
    let present = described
        .table()
        .map(|description| description.global_secondary_indexes())
        .unwrap_or_default()
        .iter()
        .any(|index| index.index_name() == Some(INDEX_BLOCKS_BY_POLICY));
    if present {
        return;
    }

    // Building the request is infallible in practice (the field names are constants), so a failure
    // here is a programming error, not an operational one — log it and leave the index alone.
    let request = build_blocks_index_update();
    let (update, policy_attribute, blocked_at_attribute) = match request {
        Ok(parts) => parts,
        Err(err) => {
            tracing::warn!("Could not build the '{INDEX_BLOCKS_BY_POLICY}' update: {err}");
            return;
        }
    };

    tracing::info!("Adding '{INDEX_BLOCKS_BY_POLICY}' to the existing table '{table}'…");
    match client
        .client
        .update_table()
        .table_name(&table)
        // UpdateTable needs the definitions of the attributes the new index keys on.
        .attribute_definitions(policy_attribute)
        .attribute_definitions(blocked_at_attribute)
        .global_secondary_index_updates(update)
        .send()
        .await
    {
        // The index backfills in the background; queries against it fail until it is ACTIVE.
        Ok(_) => tracing::info!("'{INDEX_BLOCKS_BY_POLICY}' is being created on '{table}'"),
        Err(err) => tracing::warn!(
            "Could not add '{INDEX_BLOCKS_BY_POLICY}' to '{table}' ({err}). Auth is unaffected, \
             but the rate-limit overview stays empty until the index exists — add it manually \
             (see docs/CONFIG.md §8.1) or grant dynamodb:UpdateTable on the table prefix."
        ),
    }
}

/// Reads a numeric attribute out of a raw item.
fn number<T: std::str::FromStr>(item: &HashMap<String, AttributeValue>, field: &str) -> Option<T> {
    item.get(field)
        .and_then(|value| value.as_n().ok())
        .and_then(|raw| raw.parse::<T>().ok())
}

/// Reads a string attribute out of a raw item.
fn text(item: &HashMap<String, AttributeValue>, field: &str) -> Option<String> {
    item.get(field).and_then(|value| value.as_s().ok()).cloned()
}

#[async_trait]
impl RateLimitRepository for DynamoRateLimitRepository {
    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn increment(&self, id: &str, ttl_epoch: i64) -> anyhow::Result<u64> {
        let output = self
            .client
            .update_item(TABLE_RATE_LIMITS)
            .key(FIELD_ID, str(id))
            .update_expression("ADD #count :one SET #ttl = :ttl")
            .expression_attribute_names("#count", FIELD_COUNT)
            .expression_attribute_names("#ttl", FIELD_TTL)
            .expression_attribute_values(":one", AttributeValue::N("1".to_owned()))
            .expression_attribute_values(":ttl", AttributeValue::N(ttl_epoch.to_string()))
            .return_values(ReturnValue::UpdatedNew)
            .send()
            .await
            .context("Error incrementing rate-limit counter")?;

        let count = output
            .attributes()
            .and_then(|attrs| attrs.get(FIELD_COUNT))
            .and_then(|value| value.as_n().ok())
            .and_then(|raw| raw.parse::<u64>().ok())
            .context("UpdateItem did not return the new rate-limit count")?;
        Ok(count)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn get_block(&self, id: &str) -> anyhow::Result<Option<i64>> {
        let result = self
            .client
            .get_item(TABLE_RATE_LIMITS)
            .key(FIELD_ID, str(id))
            .send()
            .await
            .context("Error reading rate-limit block")?;

        let blocked_until = result
            .item()
            .and_then(|item| item.get(FIELD_BLOCKED_UNTIL))
            .and_then(|value| value.as_n().ok())
            .and_then(|raw| raw.parse::<i64>().ok());
        Ok(blocked_until)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn set_block(
        &self,
        id: &str,
        policy: &str,
        subject: &str,
        blocked_at: i64,
        blocked_until: i64,
        ttl_epoch: i64,
    ) -> anyhow::Result<()> {
        let _ = self
            .client
            .update_item(TABLE_RATE_LIMITS)
            .key(FIELD_ID, str(id))
            .update_expression(
                "SET #blockedUntil = :blockedUntil, #blockedAt = :blockedAt, \
                 #policy = :policy, #subject = :subject, #ttl = :ttl",
            )
            .expression_attribute_names("#blockedUntil", FIELD_BLOCKED_UNTIL)
            .expression_attribute_names("#blockedAt", FIELD_BLOCKED_AT)
            .expression_attribute_names("#policy", FIELD_POLICY)
            .expression_attribute_names("#subject", FIELD_SUBJECT)
            .expression_attribute_names("#ttl", FIELD_TTL)
            .expression_attribute_values(
                ":blockedUntil",
                AttributeValue::N(blocked_until.to_string()),
            )
            .expression_attribute_values(":blockedAt", AttributeValue::N(blocked_at.to_string()))
            .expression_attribute_values(":policy", str(policy))
            .expression_attribute_values(":subject", str(subject))
            .expression_attribute_values(":ttl", AttributeValue::N(ttl_epoch.to_string()))
            .send()
            .await
            .context("Error setting rate-limit block")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn clear(&self, id: &str) -> anyhow::Result<()> {
        let _ = self
            .client
            .delete_item(TABLE_RATE_LIMITS)
            .key(FIELD_ID, str(id))
            .send()
            .await
            .context("Error clearing rate-limit item")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn get_items(&self, ids: &[String]) -> anyhow::Result<HashMap<String, StoredItem>> {
        // Reads run concurrently rather than as one BatchGetItem: the wasabi client exposes
        // GetItem, and inspection is a handful of keys at a time (never a list-sized fan-out).
        let reads = ids.iter().map(|id| async move {
            let result = self
                .client
                .get_item(TABLE_RATE_LIMITS)
                .key(FIELD_ID, str(id.as_str()))
                .send()
                .await
                .context("Error reading rate-limit item")?;
            let stored = result.item().map(|item| StoredItem {
                count: number(item, FIELD_COUNT),
                blocked_until: number(item, FIELD_BLOCKED_UNTIL),
                expires_at: number(item, FIELD_TTL),
            });
            anyhow::Ok(stored.map(|stored| (id.clone(), stored)))
        });

        let found = futures_util::future::try_join_all(reads).await?;
        Ok(found.into_iter().flatten().collect())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn list_blocks(
        &self,
        policy: &str,
        since_epoch: i64,
        limit: i32,
    ) -> anyhow::Result<Vec<BlockRecord>> {
        let result = self
            .client
            .query(TABLE_RATE_LIMITS)
            .index_name(INDEX_BLOCKS_BY_POLICY)
            .key_condition_expression("#policy = :policy AND #blockedAt >= :since")
            .expression_attribute_names("#policy", FIELD_POLICY)
            .expression_attribute_names("#blockedAt", FIELD_BLOCKED_AT)
            .expression_attribute_values(":policy", str(policy))
            .expression_attribute_values(":since", AttributeValue::N(since_epoch.to_string()))
            .scan_index_forward(false)
            .limit(limit.max(1))
            .send()
            .await
            .context("Error listing rate-limit blocks")?;

        // A row without the metadata cannot be rendered, so it is dropped rather than guessed at:
        // blocks written before this index existed carry no `subject`.
        Ok(result
            .items
            .unwrap_or_default()
            .into_iter()
            .filter_map(|item| {
                Some(BlockRecord {
                    policy: text(&item, FIELD_POLICY)?,
                    subject: text(&item, FIELD_SUBJECT)?,
                    blocked_at: number(&item, FIELD_BLOCKED_AT)?,
                    blocked_until: number(&item, FIELD_BLOCKED_UNTIL)?,
                })
            })
            .collect())
    }
}
