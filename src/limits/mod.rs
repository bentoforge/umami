//! Limits — per-tenant quotas: consumable budgets booked down on every call, and absolute-bound
//! gauges whose current value is set and read back.
//!
//! The three layers (see `docs/LIMITS.md`): the **catalogue** lives in the config
//! ([`crate::config::LimitDef`]), the per-tenant **values** on the tenant
//! ([`crate::config::LimitSettings`] in `Tenant.limits`), and the runtime **counters** here.
//!
//! This slice covers the booking path — the [`LimitState`] row, the pure [`accounting`] logic, and
//! the atomic [`repository`] — without the transaction ledger and monthly history, which bolt on as
//! additional writes inside the same compare-and-swap.

pub mod accounting;
pub mod repository;
pub mod service;

use serde::{Deserialize, Serialize};

/// The live counters for one `(tenant, limit)`, the row the hot path reads and writes.
///
/// A consumable uses the monthly/overuse/custom fields; a gauge uses only `gauge_*`. One struct
/// serves both because a limit code is one kind or the other, and a shared row keeps the store
/// uniform. `monthly_snapshot`/`overuse_snapshot` record the budget in force at the period's start,
/// so `used = snapshot - remaining` stays well-defined even when the settings change mid-month.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LimitState {
    /// Partition key.
    pub tenant_id: String,
    /// Sort key — the limit's config code.
    #[serde(rename = "limitCode")]
    pub code: String,
    /// The month (`"YYYY-MM"`) the monthly/overuse counters currently belong to.
    pub period_year_month: String,
    /// Remaining included allowance this month (expires at month end).
    pub monthly_remaining: i64,
    /// Remaining overuse allowance this month (expires at month end).
    pub overuse_remaining: i64,
    /// Included allowance in force at the start of `period_year_month`.
    pub monthly_snapshot: i64,
    /// Overuse allowance in force at the start of `period_year_month`.
    pub overuse_snapshot: i64,
    /// Persistent top-up balance — does not expire at month end.
    pub custom_balance: i64,
    /// Daily throttle: consumption still allowed today. Reset each day from the tenant's `daily`
    /// setting; a parallel cap, not a spendable bucket. `0` and `daily_date` unset when the limit
    /// has no daily throttle.
    #[serde(default)]
    pub daily_remaining: i64,
    /// The day (`"YYYY-MM-DD"`) `daily_remaining` belongs to. `None` until a daily throttle is first
    /// applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_date: Option<String>,
    /// Gauge: the last value set. `None` until first set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gauge_value: Option<i64>,
    /// Gauge: the month the value was last set in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gauge_month: Option<String>,
    /// Optimistic-concurrency counter, bumped on every write.
    #[serde(default)]
    pub version: u64,
}

impl LimitState {
    /// A zeroed row for `(tenant, limit)` in `month`, with the monthly/overuse counters filled from
    /// `settings`. The starting point when a limit is first touched.
    pub fn fresh(
        tenant_id: &str,
        code: &str,
        month: &str,
        settings: &crate::config::LimitSettings,
    ) -> Self {
        let monthly = settings.monthly.unwrap_or(0);
        let overuse = settings.overuse.unwrap_or(0);
        LimitState {
            tenant_id: tenant_id.to_owned(),
            code: code.to_owned(),
            period_year_month: month.to_owned(),
            monthly_remaining: monthly,
            overuse_remaining: overuse,
            monthly_snapshot: monthly,
            overuse_snapshot: overuse,
            custom_balance: 0,
            daily_remaining: 0,
            daily_date: None,
            gauge_value: None,
            gauge_month: None,
            version: 0,
        }
    }

    /// Total spendable now: this month's monthly + overuse remaining plus the persistent balance.
    pub fn available(&self) -> i64 {
        self.monthly_remaining + self.custom_balance + self.overuse_remaining
    }
}

/// The kind of ledger movement, as stored in the entry's `type`.
pub mod ledger_type {
    /// A booking that drew across the buckets.
    pub const CONSUME: &str = "consume";
    /// A top-up of the persistent custom balance.
    pub const TOPUP: &str = "topup";
    /// A gauge value set.
    pub const GAUGE_SET: &str = "gaugeSet";
}

/// One append-only transaction in a limit's ledger — what came in, what went out, and how much from
/// which bucket. Written atomically alongside the state it produced (see [`repository`]). The actor
/// fields are optional, caller-provided pass-through — not validated against umami users; a strict
/// deployment omits the name and links only by id (see `docs/LIMITS.md`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LedgerEntry {
    /// Partition of the owning limit.
    pub tenant_id: String,
    /// The limit's config code.
    #[serde(rename = "limitCode")]
    pub code: String,
    /// Unique entry id (the sort-key tiebreaker for same-instant entries).
    pub id: String,
    /// RFC3339 (millis) instant of the movement.
    pub timestamp: String,
    /// One of [`ledger_type`].
    #[serde(rename = "type")]
    pub entry_type: String,
    /// The requested amount (consume/top-up) or the gauge value set.
    pub amount: i64,
    /// Consume: drawn from this month's included allowance.
    #[serde(default)]
    pub monthly_drawn: i64,
    /// Consume: drawn from the persistent custom balance.
    #[serde(default)]
    pub custom_drawn: i64,
    /// Consume: drawn from this month's overuse allowance.
    #[serde(default)]
    pub overuse_drawn: i64,
    /// Consume: the part nothing could cover (booked to zero).
    #[serde(default)]
    pub overdrawn: i64,
    /// Top-up: added to the custom balance.
    #[serde(default)]
    pub custom_added: i64,
    /// Gauge: the value set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gauge_value: Option<i64>,
    /// The monthly-remaining after the movement.
    pub resulting_monthly: i64,
    /// The custom balance after the movement.
    pub resulting_custom: i64,
    /// The overuse-remaining after the movement.
    pub resulting_overuse: i64,
    /// Optional actor/context — pass-through, GDPR-sensitive for the name (see `docs/LIMITS.md`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_user_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// A closed month's aggregates, written once at the rollover that ends it (idempotent). Everything
/// is derivable from the state as it stood at month end, so no per-transaction summing is needed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HistoryRow {
    /// Partition of the owning limit.
    pub tenant_id: String,
    /// The limit's config code.
    #[serde(rename = "limitCode")]
    pub code: String,
    /// The month this row closes, `"YYYY-MM"`.
    pub year_month: String,
    /// Included allowance the month started with.
    pub monthly_included: i64,
    /// Included allowance consumed during the month.
    pub monthly_used: i64,
    /// Included allowance left unspent when the month ended (it expires).
    pub monthly_forfeited: i64,
    /// Overuse allowance the month started with.
    pub overuse_limit: i64,
    /// Overuse allowance consumed during the month.
    pub overuse_used: i64,
    /// Persistent custom balance carried into the next month.
    pub ending_custom_balance: i64,
}
