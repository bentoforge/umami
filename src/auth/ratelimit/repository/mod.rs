//! Persistence for rate-limit counters and blocks.
//!
//! The store holds two kinds of small items, distinguished only by their id (built by the
//! [`RateLimiter`](super::RateLimiter), never here):
//! - a **counter** — a numeric `count` for one `(policy, subject, window-bucket)`, bumped with a
//!   single atomic `ADD` so concurrent nodes never race;
//! - a **block** — a numeric `blockedUntil` epoch for one `(policy, subject)`, set once a counter
//!   trips its threshold.
//!
//! The trait exposes only DB-agnostic primitives, so the store can be swapped for another backend.

pub mod dynamodb;
pub mod postgres;

use async_trait::async_trait;
use std::collections::HashMap;

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
