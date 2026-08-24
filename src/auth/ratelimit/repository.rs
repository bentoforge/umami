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

use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{AttributeValue, BillingMode, ReturnValue};
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::str;

const TABLE_RATE_LIMITS: &str = "rate-limits";
const FIELD_ID: &str = "id";
const FIELD_COUNT: &str = "count";
const FIELD_BLOCKED_UNTIL: &str = "blockedUntil";
const FIELD_TTL: &str = "ttl";

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

    /// Sets the block item `id`'s `blockedUntil` epoch (and its `ttl`).
    async fn set_block(&self, id: &str, blocked_until: i64, ttl_epoch: i64) -> anyhow::Result<()>;

    /// Deletes an item by id (used to reset a counter / lift a block on a successful login).
    async fn clear(&self, id: &str) -> anyhow::Result<()>;
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
            .create_table(TABLE_RATE_LIMITS, |table| {
                let table = table.attribute_definitions(str_attribute(FIELD_ID)?);
                let table = with_hash_index(table, FIELD_ID)?;
                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        Ok(Self {
            client: client.clone(),
        })
    }
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
    async fn set_block(&self, id: &str, blocked_until: i64, ttl_epoch: i64) -> anyhow::Result<()> {
        let _ = self
            .client
            .update_item(TABLE_RATE_LIMITS)
            .key(FIELD_ID, str(id))
            .update_expression("SET #blockedUntil = :blockedUntil, #ttl = :ttl")
            .expression_attribute_names("#blockedUntil", FIELD_BLOCKED_UNTIL)
            .expression_attribute_names("#ttl", FIELD_TTL)
            .expression_attribute_values(
                ":blockedUntil",
                AttributeValue::N(blocked_until.to_string()),
            )
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
}
