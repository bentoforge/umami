//! Persistence for limit state, ledger and history.
//!
//! The trait is deliberately thin: `compare_and_swap` (the one atomic write) plus reads, and nothing
//! that knows the cascade or the rollover — that logic lives in [`crate::limits::accounting`], and
//! the retry loop around the CAS lives in the service. A second backend implements these and
//! inherits every booking rule for free.
//!
//! `compare_and_swap` commits an [`Outcome`] atomically: the state row under its
//! version guard, the ledger entry appended, and — when a month rolled over — the history row put
//! if-not-exists. All-or-nothing, so state and ledger never drift apart.

pub mod dynamodb;
pub mod postgres;

use crate::limits::accounting::Outcome;
use crate::limits::{HistoryRow, LedgerEntry, LimitState};
use anyhow::Context;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Upper bound on rows a single ledger/history read returns.
const READ_PAGE_SIZE: i32 = 100;

/// The outcome of a [`LimitRepository::compare_and_swap`]: whether the guarded write landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasOutcome {
    /// The transaction landed; the [`Outcome`] is now stored.
    Committed,
    /// The version guard failed — a concurrent writer won. The caller reloads and retries.
    Conflict,
}

/// Persistence interface for limit state — the atomic primitive plus the ledger/history reads.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait LimitRepository: Send + Sync {
    /// Loads the state for `(tenant, code)`. `None` when the limit has never been touched.
    async fn load_state(&self, tenant_id: &str, code: &str) -> anyhow::Result<Option<LimitState>>;

    /// Atomically commits an [`Outcome`] — state (version-guarded), ledger (appended) and, when a
    /// month closed, history (if-not-exists). `expected_version`: `None` requires the state row not
    /// to exist yet, `Some(v)` requires the stored version to equal `v`. Returns
    /// [`CasOutcome::Conflict`] when the guard fails, so the caller reloads and retries.
    async fn compare_and_swap(
        &self,
        outcome: &Outcome,
        expected_version: Option<u64>,
    ) -> anyhow::Result<CasOutcome>;

    /// One page of a limit's ledger, newest first. `cursor` resumes after a prior page; `limit` is
    /// clamped to `[1, READ_PAGE_SIZE]`. Returns the page plus the next cursor (`None` when the trail
    /// is exhausted).
    async fn read_ledger(
        &self,
        tenant_id: &str,
        code: &str,
        cursor: Option<&str>,
        limit: i32,
    ) -> anyhow::Result<(Vec<LedgerEntry>, Option<String>)>;

    /// A limit's closed-month history, newest month first, capped at [`READ_PAGE_SIZE`].
    async fn read_history(&self, tenant_id: &str, code: &str) -> anyhow::Result<Vec<HistoryRow>>;

    /// One closed month for billing: the history row(s) for `(tenant, year_month)`. With `code` it
    /// is the single limit's row (empty when that month never closed); without it, every limit's row
    /// for that month. Capped at [`READ_PAGE_SIZE`].
    async fn read_month_history(
        &self,
        tenant_id: &str,
        code: Option<&str>,
        year_month: &str,
    ) -> anyhow::Result<Vec<HistoryRow>>;
}

/// Opaque page cursor over a limit's ledger — the last-seen ledger sort key (`{code}#{ts}#{id}`),
/// base64url-encoded so it survives a query string untouched.
fn encode_ledger_cursor(ledger_sk: &str) -> String {
    URL_SAFE_NO_PAD.encode(ledger_sk)
}

fn decode_ledger_cursor(cursor: &str) -> anyhow::Result<String> {
    let raw = URL_SAFE_NO_PAD
        .decode(cursor)
        .context("Invalid ledger cursor")?;
    String::from_utf8(raw).context("Invalid ledger cursor")
}

/// The ledger sort key: `"{code}#{timestamp}#{id}"`, so one limit's entries are contiguous and
/// ordered by time.
fn ledger_sort_key(entry: &LedgerEntry) -> String {
    format!("{}#{}#{}", entry.code, entry.timestamp, entry.id)
}
