//! Rate limiting for the auth endpoints.
//!
//! Two request profiles, both backed by the swappable [`RateLimitRepository`]:
//! - **Volume** ([`RateLimiter::check`]) — counts *all* requests for a subject in a fixed window and
//!   blocks it once the cap is exceeded. Used for the per-IP caps (`/auth/login`, `/auth/token`) and
//!   the per-API-key `/auth/token` cap. This is the primary brake on a "dumb" client that exchanges
//!   an API key on every call instead of caching the short-lived access token.
//! - **Brute-force** ([`RateLimiter::record_failure`] / [`RateLimiter::record_success`]) — counts
//!   *failed* `/auth/login` attempts per account, resets on success, and blocks after too many.
//!
//! # Store protection & fail-open
//! A per-node **bounded LRU** caches known blocks so that, once a subject is blocked, further
//! requests are answered `429` locally with **zero** DynamoDB traffic — which is exactly the abuse
//! (a hot key hammering one subject) we are throttling. The bound stops many distinct subjects from
//! memory-DoSing a node. Every store call is **fail-open**: on error we log and *allow* the request,
//! so an unavailable store never takes auth down; the LRU still short-circuits already-known blocks.
//!
//! DynamoDB is the source of truth for *setting* blocks; the LRU is only an optimization for *known*
//! blocks. Across nodes, the shared counter itself carries the signal (a node whose increment lands
//! over-threshold sets and caches the block independently); after a window rolls over, a block set
//! elsewhere is re-hydrated on the fresh window's first request (`count == 1`).

pub mod repository;

use chrono::{DateTime, Utc};
use lru::LruCache;
use repository::RateLimitRepository;
use std::env;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use warp::http::StatusCode;
use warp::http::header::{CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use warp::reply::Response;

use crate::constants::DEFAULT_RATELIMIT_CACHE_CAP;

/// Small grace added to every item's TTL (seconds) so a row always outlives the window/block it
/// represents before DynamoDB may expire it.
const TTL_GRACE_SECS: i64 = 60;

/// A resolved rate-limit policy (from a config `RateLimitPolicy`). `max == 0` disables the policy.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Requests (volume) or failures (brute-force) tolerated before a block.
    pub max: u32,
    /// The counting window, in seconds (kept positive by [`Policy::new`]).
    pub window_secs: i64,
    /// How long a tripped subject stays blocked, in seconds.
    pub block_secs: i64,
}

impl Policy {
    /// Builds a policy from config values, clamping the window to at least 1 second so the bucket
    /// math (`timestamp / window`) never divides by zero.
    pub fn new(max: u32, window_secs: u32, block_secs: u32) -> Self {
        Policy {
            max,
            window_secs: (window_secs as i64).max(1),
            block_secs: block_secs as i64,
        }
    }

    /// Whether this policy is switched off (a `max` of 0 ⇒ never limit).
    fn disabled(&self) -> bool {
        self.max == 0
    }
}

/// The outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request may proceed.
    Allow,
    /// The request is blocked; `retry_after` is the advertised `Retry-After`, in seconds.
    Block {
        /// Seconds until the block lifts (for the `Retry-After` header).
        retry_after: i64,
    },
}

/// Rate limiter: policy logic + the per-node LRU block cache in front of a [`RateLimitRepository`].
pub struct RateLimiter {
    repo: Arc<dyn RateLimitRepository>,
    /// `block_id → blockedUntil` epoch. Bounded (LRU) so distinct subjects can't grow it unbounded.
    blocks: Mutex<LruCache<String, i64>>,
}

impl RateLimiter {
    /// Builds a limiter with an explicit LRU capacity (rounded up to at least 1).
    pub fn new(repo: Arc<dyn RateLimitRepository>, cache_cap: usize) -> Self {
        let cap = NonZeroUsize::new(cache_cap.max(1)).unwrap_or(NonZeroUsize::MIN);
        RateLimiter {
            repo,
            blocks: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Builds a limiter, reading the LRU capacity from `UMAMI_RATELIMIT_CACHE_CAP`
    /// (default [`DEFAULT_RATELIMIT_CACHE_CAP`]).
    pub fn from_env(repo: Arc<dyn RateLimitRepository>) -> Self {
        let cap = env::var("UMAMI_RATELIMIT_CACHE_CAP")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .filter(|cap| *cap > 0)
            .unwrap_or(DEFAULT_RATELIMIT_CACHE_CAP);
        Self::new(repo, cap)
    }

    // ── Volume path (per-IP, per-key) ───────────────────────────────────────────

    /// Volume check: counts this request against the window and returns whether it is blocked.
    /// Order: LRU short-circuit → atomic increment (fail-open) → re-hydrate a cross-node block on a
    /// fresh window → block when the count exceeds `policy.max`.
    pub async fn check(
        &self,
        policy_name: &str,
        policy: &Policy,
        subject: &str,
        now: DateTime<Utc>,
    ) -> Decision {
        if policy.disabled() {
            return Decision::Allow;
        }
        let block_id = block_id(policy_name, subject);
        let now_epoch = now.timestamp();

        // 1. Known-block short-circuit: no store traffic while a subject is blocked.
        if let Some(decision) = self.cached_block_decision(&block_id, now_epoch) {
            return decision;
        }

        // 2. Atomic increment (fail-open: an unavailable store must not take auth down).
        let bucket = now_epoch.div_euclid(policy.window_secs);
        let counter_id = counter_id(policy_name, subject, bucket);
        let counter_ttl = (bucket + 1) * policy.window_secs + policy.block_secs + TTL_GRACE_SECS;
        let count = match self.repo.increment(&counter_id, counter_ttl).await {
            Ok(count) => count,
            Err(err) => {
                tracing::warn!("rate-limit increment failed (fail-open, allowing): {err:#}");
                return Decision::Allow;
            }
        };

        // 3. Fresh window: re-hydrate a block another node may have set (covers block_secs > window).
        if count == 1
            && let Some(decision) = self.rehydrate_block(&block_id, now_epoch).await
        {
            return decision;
        }

        // 4. Over the cap → set + cache a block and reject this request.
        if count > u64::from(policy.max) {
            return self
                .trip_block(&block_id, now_epoch, policy.block_secs)
                .await;
        }

        Decision::Allow
    }

    // ── Brute-force path (per-account login failures) ────────────────────────────

    /// Pre-check for the brute-force path: is this subject currently blocked? Consults the LRU first,
    /// then the store on a miss (fail-open). Called *before* verifying credentials.
    pub async fn is_blocked(
        &self,
        policy_name: &str,
        policy: &Policy,
        subject: &str,
        now: DateTime<Utc>,
    ) -> Decision {
        if policy.disabled() {
            return Decision::Allow;
        }
        let block_id = block_id(policy_name, subject);
        let now_epoch = now.timestamp();

        if let Some(decision) = self.cached_block_decision(&block_id, now_epoch) {
            return decision;
        }
        self.rehydrate_block(&block_id, now_epoch)
            .await
            .unwrap_or(Decision::Allow)
    }

    /// Records a failed attempt (rolling counter with a window-length TTL) and blocks the subject
    /// once `policy.max` failures accumulate. Fail-open on any store error.
    pub async fn record_failure(
        &self,
        policy_name: &str,
        policy: &Policy,
        subject: &str,
        now: DateTime<Utc>,
    ) -> Decision {
        if policy.disabled() {
            return Decision::Allow;
        }
        let now_epoch = now.timestamp();
        let counter_id = failure_counter_id(policy_name, subject);
        // A rolling counter: each failure refreshes the TTL, so a quiet period auto-resets it.
        let counter_ttl = now_epoch + policy.window_secs + TTL_GRACE_SECS;
        let count = match self.repo.increment(&counter_id, counter_ttl).await {
            Ok(count) => count,
            Err(err) => {
                tracing::warn!("rate-limit failure-increment failed (fail-open): {err:#}");
                return Decision::Allow;
            }
        };
        if count >= u64::from(policy.max) {
            let block_id = block_id(policy_name, subject);
            return self
                .trip_block(&block_id, now_epoch, policy.block_secs)
                .await;
        }
        Decision::Allow
    }

    /// Clears the failure counter and any block for this subject after a successful login.
    pub async fn record_success(&self, policy_name: &str, policy: &Policy, subject: &str) {
        if policy.disabled() {
            return;
        }
        let counter_id = failure_counter_id(policy_name, subject);
        let block_id = block_id(policy_name, subject);
        if let Err(err) = self.repo.clear(&counter_id).await {
            tracing::warn!("rate-limit counter clear failed (ignored): {err:#}");
        }
        if let Err(err) = self.repo.clear(&block_id).await {
            tracing::warn!("rate-limit block clear failed (ignored): {err:#}");
        }
        self.evict_block(&block_id);
    }

    // ── Shared helpers ───────────────────────────────────────────────────────────

    /// Returns a `Block` decision if the LRU holds a still-valid block for `block_id`, else `None`
    /// (evicting a stale entry it finds).
    fn cached_block_decision(&self, block_id: &str, now_epoch: i64) -> Option<Decision> {
        let mut blocks = match self.blocks.lock() {
            Ok(blocks) => blocks,
            Err(poisoned) => poisoned.into_inner(),
        };
        match blocks.get(block_id).copied() {
            Some(until) if now_epoch < until => Some(Decision::Block {
                retry_after: until - now_epoch,
            }),
            Some(_) => {
                let _ = blocks.pop(block_id);
                None
            }
            None => None,
        }
    }

    /// Reads a block from the store (fail-open) and caches it if still valid; returns the decision.
    async fn rehydrate_block(&self, block_id: &str, now_epoch: i64) -> Option<Decision> {
        match self.repo.get_block(block_id).await {
            Ok(Some(until)) if now_epoch < until => {
                self.cache_block(block_id, until);
                Some(Decision::Block {
                    retry_after: until - now_epoch,
                })
            }
            Ok(_) => None,
            Err(err) => {
                tracing::warn!("rate-limit block read failed (fail-open): {err:#}");
                None
            }
        }
    }

    /// Sets a block in the store (best-effort) and caches it locally, returning the `Block` decision.
    async fn trip_block(&self, block_id: &str, now_epoch: i64, block_secs: i64) -> Decision {
        let until = now_epoch + block_secs;
        if let Err(err) = self
            .repo
            .set_block(block_id, until, until + TTL_GRACE_SECS)
            .await
        {
            // Fail-open on the write, but still cache locally so this node protects itself.
            tracing::warn!("rate-limit set-block failed (caching locally): {err:#}");
        }
        self.cache_block(block_id, until);
        Decision::Block {
            retry_after: block_secs,
        }
    }

    /// Inserts/updates a block in the LRU.
    fn cache_block(&self, block_id: &str, until: i64) {
        let mut blocks = match self.blocks.lock() {
            Ok(blocks) => blocks,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _ = blocks.put(block_id.to_owned(), until);
    }

    /// Removes a block from the LRU (on a successful login).
    fn evict_block(&self, block_id: &str) {
        let mut blocks = match self.blocks.lock() {
            Ok(blocks) => blocks,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _ = blocks.pop(block_id);
    }
}

// ── Item ids (opaque; built here so the repository stays a dumb key-value store) ──

/// Volume counter id: one per `(policy, subject, window-bucket)`.
fn counter_id(policy_name: &str, subject: &str, bucket: i64) -> String {
    format!("v#{policy_name}#{subject}#{bucket}")
}

/// Brute-force failure counter id: one rolling counter per `(policy, subject)`.
fn failure_counter_id(policy_name: &str, subject: &str) -> String {
    format!("f#{policy_name}#{subject}")
}

/// Block id: one per `(policy, subject)`.
fn block_id(policy_name: &str, subject: &str) -> String {
    format!("b#{policy_name}#{subject}")
}

/// Builds a uniform `429 Too Many Requests` response with a `Retry-After` header. The body mirrors
/// wasabi's `ApiError` shape (`{ "message": … }`) and is deliberately generic (no account-existence
/// leak).
pub fn too_many_requests(retry_after: i64) -> Response {
    let body = serde_json::json!({ "message": "Too many requests" }).to_string();
    let mut response = Response::new(body.into());
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    let headers = response.headers_mut();
    let _ = headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Ok(value) = HeaderValue::from_str(&retry_after.max(0).to_string()) {
        let _ = headers.insert(RETRY_AFTER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::repository::MockRateLimitRepository;
    use super::*;

    fn limiter(repo: MockRateLimitRepository) -> RateLimiter {
        RateLimiter::new(Arc::new(repo), 128)
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[tokio::test]
    async fn volume_allows_under_cap_and_blocks_over() {
        let policy = Policy::new(3, 60, 300);

        // Under the cap: increment returns 2, no block read (fresh-window only), allow.
        let mut repo = MockRateLimitRepository::new();
        repo.expect_increment()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(2) }));
        let decision = limiter(repo)
            .check("perIp:login", &policy, "1.2.3.4", now())
            .await;
        assert_eq!(decision, Decision::Allow);

        // Over the cap: increment returns 4 (> 3) → set_block + Block with retry_after == block_secs.
        let mut repo = MockRateLimitRepository::new();
        repo.expect_increment()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(4) }));
        repo.expect_set_block()
            .times(1)
            .returning(|_, _, _| Box::pin(async { Ok(()) }));
        let decision = limiter(repo)
            .check("perIp:login", &policy, "1.2.3.4", now())
            .await;
        assert_eq!(decision, Decision::Block { retry_after: 300 });
    }

    #[tokio::test]
    async fn volume_window_rollover_rehydrates_block() {
        let policy = Policy::new(3, 60, 300);
        let now = now();
        // A fresh window (count == 1) triggers a block read; a still-valid block short-circuits.
        let until = now.timestamp() + 120;
        let mut repo = MockRateLimitRepository::new();
        repo.expect_increment()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(1) }));
        repo.expect_get_block()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(Some(until)) }));
        let decision = limiter(repo)
            .check("tokenExchange", &policy, "key1", now)
            .await;
        assert_eq!(decision, Decision::Block { retry_after: 120 });
    }

    #[tokio::test]
    async fn known_block_short_circuits_without_store() {
        let policy = Policy::new(3, 60, 300);
        let now = now();
        // First request trips the block (increment 4 → set_block). The mock allows exactly one
        // increment and one set_block; a second request must be served purely from the LRU.
        let mut repo = MockRateLimitRepository::new();
        repo.expect_increment()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(4) }));
        repo.expect_set_block()
            .times(1)
            .returning(|_, _, _| Box::pin(async { Ok(()) }));
        let limiter = limiter(repo);
        assert!(matches!(
            limiter.check("perIp:token", &policy, "9.9.9.9", now).await,
            Decision::Block { .. }
        ));
        // No further store calls are expected (the mock would panic on an extra increment).
        assert!(matches!(
            limiter.check("perIp:token", &policy, "9.9.9.9", now).await,
            Decision::Block { .. }
        ));
    }

    #[tokio::test]
    async fn fail_open_when_store_errors() {
        let policy = Policy::new(3, 60, 300);
        let mut repo = MockRateLimitRepository::new();
        repo.expect_increment()
            .times(1)
            .returning(|_, _| Box::pin(async { Err(anyhow::anyhow!("dynamo down")) }));
        let decision = limiter(repo)
            .check("perIp:login", &policy, "1.2.3.4", now())
            .await;
        assert_eq!(decision, Decision::Allow);
    }

    #[tokio::test]
    async fn brute_force_blocks_at_threshold_and_resets_on_success() {
        let policy = Policy::new(5, 300, 900);
        let now = now();

        // 5th failure (count == 5 == max) trips the block.
        let mut repo = MockRateLimitRepository::new();
        repo.expect_increment()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(5) }));
        repo.expect_set_block()
            .times(1)
            .returning(|_, _, _| Box::pin(async { Ok(()) }));
        let decision = limiter(repo)
            .record_failure("login", &policy, "alice", now)
            .await;
        assert_eq!(decision, Decision::Block { retry_after: 900 });

        // A failure below the threshold does not block.
        let mut repo = MockRateLimitRepository::new();
        repo.expect_increment()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(2) }));
        let decision = limiter(repo)
            .record_failure("login", &policy, "alice", now)
            .await;
        assert_eq!(decision, Decision::Allow);

        // Success clears both the counter and the block.
        let mut repo = MockRateLimitRepository::new();
        repo.expect_clear()
            .times(2)
            .returning(|_| Box::pin(async { Ok(()) }));
        limiter(repo)
            .record_success("login", &policy, "alice")
            .await;
    }

    #[tokio::test]
    async fn is_blocked_consults_store_on_cache_miss() {
        let policy = Policy::new(5, 300, 900);
        let now = now();
        let until = now.timestamp() + 600;
        let mut repo = MockRateLimitRepository::new();
        repo.expect_get_block()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(Some(until)) }));
        let decision = limiter(repo).is_blocked("login", &policy, "bob", now).await;
        assert_eq!(decision, Decision::Block { retry_after: 600 });
    }

    #[tokio::test]
    async fn disabled_policy_never_limits() {
        let policy = Policy::new(0, 60, 300);
        // No store calls expected at all.
        let repo = MockRateLimitRepository::new();
        let limiter = limiter(repo);
        assert_eq!(
            limiter
                .check("perIp:login", &policy, "1.2.3.4", now())
                .await,
            Decision::Allow
        );
        assert_eq!(
            limiter
                .record_failure("login", &policy, "alice", now())
                .await,
            Decision::Allow
        );
        assert_eq!(
            limiter.is_blocked("login", &policy, "alice", now()).await,
            Decision::Allow
        );
    }
}
