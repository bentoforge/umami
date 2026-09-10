//! Limits — per-tenant quotas: consumable budgets booked down on every call, and absolute-bound
//! gauges whose current value is set and read back.
//!
//! The three layers (see `docs/LIMITS.md`): the **catalogue** lives in the config
//! ([`crate::config::LimitDef`]), the per-tenant **values** on the tenant
//! ([`crate::config::LimitSettings`] in `Tenant.limits`), and the runtime **counters** here.
//!
//! The booking path is a pure [`accounting`] module over a [`LimitState`] row, committed by a thin
//! [`repository`] whose `compare_and_swap` writes state, ledger entry and (on a rollover) history as
//! one transaction. The service runs the optimistic-concurrency loop and reconciles settings changes
//! against the live counters.

pub mod accounting;
pub mod repository;
pub mod service;

use serde::{Deserialize, Serialize};

/// The live counters for one `(tenant, limit)`, the row the hot path reads and writes.
///
/// A consumable uses the monthly/extra-allowance/custom fields; a gauge uses only `gauge_*`. One struct
/// serves both because a limit code is one kind or the other, and a shared row keeps the store
/// uniform. `monthly_snapshot`/`extra_allowance_snapshot` record the budget in force at the period's start,
/// so `used = snapshot - remaining` stays well-defined even when the settings change mid-month.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LimitState {
    /// Partition key.
    pub tenant_id: String,
    /// Sort key — the limit's config code.
    #[serde(rename = "limitCode")]
    pub code: String,
    /// The month (`"YYYY-MM"`) the monthly/extra-allowance counters currently belong to.
    pub period_year_month: String,
    /// Remaining included allowance this month (expires at month end).
    pub monthly_remaining: i64,
    /// Remaining extra allowance this month (expires at month end).
    pub extra_allowance_remaining: i64,
    /// Included allowance in force at the start of `period_year_month`.
    pub monthly_snapshot: i64,
    /// Extra allowance in force at the start of `period_year_month`.
    pub extra_allowance_snapshot: i64,
    /// Persistent top-up balance — does not expire at month end.
    pub custom_balance: i64,
    /// Consumption booked this month beyond everything available, summed under the `track` overrun
    /// policy. Resets at month end (captured into history). `0` under `reject`/`ignore`.
    #[serde(default)]
    pub overrun: i64,
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
    /// A zeroed row for `(tenant, limit)` in `month`, with the monthly/extra-allowance counters filled from
    /// `settings`. The starting point when a limit is first touched.
    pub fn fresh(
        tenant_id: &str,
        code: &str,
        month: &str,
        settings: &crate::config::LimitSettings,
    ) -> Self {
        let monthly = settings.monthly.unwrap_or(0);
        let extra_allowance = settings.extra_allowance.unwrap_or(0);
        LimitState {
            tenant_id: tenant_id.to_owned(),
            code: code.to_owned(),
            period_year_month: month.to_owned(),
            monthly_remaining: monthly,
            extra_allowance_remaining: extra_allowance,
            monthly_snapshot: monthly,
            extra_allowance_snapshot: extra_allowance,
            custom_balance: 0,
            overrun: 0,
            daily_remaining: 0,
            daily_date: None,
            gauge_value: None,
            gauge_month: None,
            version: 0,
        }
    }

    /// Total spendable now: this month's monthly + extra-allowance remaining plus the persistent balance.
    pub fn available(&self) -> i64 {
        self.monthly_remaining + self.custom_balance + self.extra_allowance_remaining
    }
}

/// The kind of ledger movement, as stored in the entry's `type`.
pub mod ledger_type {
    /// A booking that drew across the buckets.
    pub const CONSUME: &str = "consume";
    /// A top-up of the persistent custom balance.
    pub const TOPUP: &str = "topup";
    /// A per-tenant settings change reconciled against the live counters.
    pub const SETTINGS: &str = "settings";
    /// A prior month's overrun carried into this month (`carry` policy), drawn across the buckets.
    pub const CARRY: &str = "carry";
    /// A month-end rollover that reset the counters (marks the boundary; no draw).
    pub const RESET: &str = "reset";
}

/// One append-only transaction in a limit's ledger — what came in, what went out, and how much from
/// which bucket. Written atomically alongside the state it produced (see [`repository`]). The two
/// actor ids are optional, caller-provided pass-through — not validated against umami users, only
/// length-capped at ingress; opaque ids only, so nothing GDPR-sensitive lands here.
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
    /// Consume: drawn from this month's extra allowance.
    #[serde(default)]
    pub extra_allowance_drawn: i64,
    /// Consume: the part nothing could cover (booked to zero).
    #[serde(default)]
    pub overrun: i64,
    /// Top-up: added to the custom balance.
    #[serde(default)]
    pub custom_added: i64,
    /// The monthly-remaining after the movement.
    pub resulting_monthly: i64,
    /// The custom balance after the movement.
    pub resulting_custom: i64,
    /// The extra-allowance-remaining after the movement.
    pub resulting_extra_allowance: i64,
    /// The overrun debt after the movement — so every booking snapshots it and the ledger reads as
    /// a consistent account.
    #[serde(default)]
    pub resulting_overrun: i64,
    /// Optional actor id — opaque caller-provided pass-through, capped at ingress (see `docs/LIMITS.md`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_user_id: Option<String>,
    /// Optional caller transaction id — opaque pass-through, capped at ingress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txn_id: Option<String>,
    /// Optional calling component/client — opaque pass-through, capped at ingress. With `txn_id` it
    /// pins down which call produced the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
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
    /// Extra allowance the month started with.
    pub extra_allowance_limit: i64,
    /// Extra allowance consumed during the month.
    pub extra_allowance_used: i64,
    /// Consumption booked beyond everything available during the month (`track` policy).
    #[serde(default)]
    pub overrun: i64,
    /// Persistent custom balance carried into the next month.
    pub ending_custom_balance: i64,
    /// Gauge: the value that stood at the month's close (`None` on a consumable row).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gauge_value: Option<i64>,
    /// Gauge: the bound the value was measured against (`None` on a consumable row).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gauge_max: Option<i64>,
}
