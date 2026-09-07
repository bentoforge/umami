//! The booking logic — pure, no I/O, the heart of the limits domain.
//!
//! Every rule lives here: the monthly rollover (and the history row it closes), the consume cascade,
//! the overdraw policy, the top-up, the gauge set — each producing the [`Outcome`] the repository
//! then commits atomically (state + ledger + optional history). The service runs the retry loop
//! around these functions. Keeping the arithmetic free of the store is what makes it exhaustively
//! testable — the tests below carry the weight, not an integration harness.
//!
//! Impurity is pushed to the edge: the caller supplies `now` and a pre-generated `entry_id`, so a
//! function is deterministic given its inputs and a retry recomputes the same result.

use crate::config::LimitSettings;
use crate::limits::{HistoryRow, LedgerEntry, LimitState, ledger_type};
use chrono::{DateTime, Datelike, SecondsFormat, Utc};

/// Optional actor/context for a ledger entry — caller-provided, never validated against umami users.
#[derive(Debug, Clone, Default)]
pub struct Actor {
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub txn_name: Option<String>,
    pub txn_id: Option<String>,
    pub reference: Option<String>,
}

/// The result of one booking operation: the state to persist, the ledger entry it produced, and —
/// when the operation crossed a month boundary — the closed month's history row.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub state: LimitState,
    pub ledger: LedgerEntry,
    pub history: Option<HistoryRow>,
}

/// The calendar month a timestamp falls in, as `"YYYY-MM"` — the key the monthly counters bucket by.
pub fn year_month(now: DateTime<Utc>) -> String {
    format!("{:04}-{:02}", now.year(), now.month())
}

/// The calendar day a timestamp falls in, as `"YYYY-MM-DD"` — the key the daily throttle resets on.
fn year_month_day(now: DateTime<Utc>) -> String {
    format!("{:04}-{:02}-{:02}", now.year(), now.month(), now.day())
}

/// Resets the daily throttle when the day has turned (or on first use), from the tenant's `daily`
/// setting. A no-op when the limit has no daily throttle, so its counters stay dormant.
fn refresh_daily(
    mut state: LimitState,
    settings: &LimitSettings,
    now: DateTime<Utc>,
) -> LimitState {
    let Some(daily) = settings.daily else {
        return state;
    };
    let today = year_month_day(now);
    if state.daily_date.as_deref() != Some(today.as_str()) {
        state.daily_remaining = daily;
        state.daily_date = Some(today);
    }
    state
}

/// The state as it applies to `now`'s month, plus the history row if a stale month was closed.
///
/// If the stored period is stale — a real prior month — its aggregates become a [`HistoryRow`] and
/// the monthly/overuse counters reset from `settings`, while the persistent custom balance and the
/// gauge value carry over. With no state yet, a fresh row and no history. Pure: the caller decides
/// whether to persist (a read projects and discards, a write commits).
pub fn rolled_over(
    existing: Option<LimitState>,
    tenant_id: &str,
    code: &str,
    settings: &LimitSettings,
    now: DateTime<Utc>,
) -> (LimitState, Option<HistoryRow>) {
    let month = year_month(now);
    let (state, history) = match existing {
        Some(state) if state.period_year_month == month => (state, None),
        Some(state) => {
            let history = HistoryRow {
                tenant_id: state.tenant_id.clone(),
                code: state.code.clone(),
                year_month: state.period_year_month.clone(),
                monthly_included: state.monthly_snapshot,
                monthly_used: state.monthly_snapshot - state.monthly_remaining,
                monthly_forfeited: state.monthly_remaining,
                overuse_limit: state.overuse_snapshot,
                overuse_used: state.overuse_snapshot - state.overuse_remaining,
                ending_custom_balance: state.custom_balance,
            };
            let monthly = settings.monthly.unwrap_or(0);
            let overuse = settings.overuse.unwrap_or(0);
            let new_state = LimitState {
                period_year_month: month,
                monthly_remaining: monthly,
                overuse_remaining: overuse,
                monthly_snapshot: monthly,
                overuse_snapshot: overuse,
                // The persistent balance, daily throttle and gauge are not monthly and survive the
                // rollover; the daily throttle is refreshed below on its own (daily) schedule.
                ..state
            };
            (new_state, Some(history))
        }
        None => (LimitState::fresh(tenant_id, code, &month, settings), None),
    };
    (refresh_daily(state, settings, now), history)
}

/// A ledger entry pre-filled with identity, timestamp, actor and the post-movement balances.
fn ledger_base(
    state: &LimitState,
    id: &str,
    now: DateTime<Utc>,
    entry_type: &str,
    amount: i64,
    actor: &Actor,
) -> LedgerEntry {
    LedgerEntry {
        tenant_id: state.tenant_id.clone(),
        code: state.code.clone(),
        id: id.to_owned(),
        timestamp: now.to_rfc3339_opts(SecondsFormat::Millis, true),
        entry_type: entry_type.to_owned(),
        amount,
        monthly_drawn: 0,
        custom_drawn: 0,
        overuse_drawn: 0,
        overdrawn: 0,
        custom_added: 0,
        gauge_value: None,
        resulting_monthly: state.monthly_remaining,
        resulting_custom: state.custom_balance,
        resulting_overuse: state.overuse_remaining,
        actor_user_id: actor.user_id.clone(),
        actor_user_name: actor.user_name.clone(),
        txn_name: actor.txn_name.clone(),
        txn_id: actor.txn_id.clone(),
        reference: actor.reference.clone(),
    }
}

/// Draws up to `*left` from `*pool`, returning what was taken.
fn draw(pool: &mut i64, left: &mut i64) -> i64 {
    let taken = (*pool).min(*left);
    *pool -= taken;
    *left -= taken;
    taken
}

/// Books `amount` against a consumable, drawing **monthly → custom → overuse** in that order.
///
/// `amount` is assumed non-negative (the caller validates). What cannot be covered is booked to zero
/// and reported as `overdrawn` rather than refused — a pre-flight `check` is the gate, and a call
/// that already ran must still be accounted.
#[allow(clippy::too_many_arguments)]
pub fn apply_consume(
    existing: Option<LimitState>,
    tenant_id: &str,
    code: &str,
    settings: &LimitSettings,
    amount: i64,
    now: DateTime<Utc>,
    entry_id: &str,
    actor: &Actor,
) -> Outcome {
    let (mut state, history) = rolled_over(existing, tenant_id, code, settings, now);
    let mut left = amount.max(0);
    let monthly_drawn = draw(&mut state.monthly_remaining, &mut left);
    let custom_drawn = draw(&mut state.custom_balance, &mut left);
    let overuse_drawn = draw(&mut state.overuse_remaining, &mut left);

    // The daily throttle is a parallel usage counter (not a source): what was actually booked is
    // subtracted from today's allowance, floored at zero. `check` gates on it before the call.
    if settings.daily.is_some() {
        let drawn = monthly_drawn + custom_drawn + overuse_drawn;
        state.daily_remaining = (state.daily_remaining - drawn).max(0);
    }

    let mut ledger = ledger_base(&state, entry_id, now, ledger_type::CONSUME, amount, actor);
    ledger.monthly_drawn = monthly_drawn;
    ledger.custom_drawn = custom_drawn;
    ledger.overuse_drawn = overuse_drawn;
    ledger.overdrawn = left;

    Outcome {
        state,
        ledger,
        history,
    }
}

/// Adds `amount` to the persistent custom balance (the non-expiring top-up). Rolls the month over
/// first so the returned state is current; `amount` is assumed non-negative.
#[allow(clippy::too_many_arguments)]
pub fn apply_topup(
    existing: Option<LimitState>,
    tenant_id: &str,
    code: &str,
    settings: &LimitSettings,
    amount: i64,
    now: DateTime<Utc>,
    entry_id: &str,
    actor: &Actor,
) -> Outcome {
    let (mut state, history) = rolled_over(existing, tenant_id, code, settings, now);
    let added = amount.max(0);
    state.custom_balance += added;

    let mut ledger = ledger_base(&state, entry_id, now, ledger_type::TOPUP, amount, actor);
    ledger.custom_added = added;

    Outcome {
        state,
        ledger,
        history,
    }
}

/// Sets a gauge's current value for `now`'s month. A gauge is never booked — only set — so the
/// monthly/overuse counters (and any rollover/history) are untouched.
pub fn set_gauge(
    existing: Option<LimitState>,
    tenant_id: &str,
    code: &str,
    value: i64,
    now: DateTime<Utc>,
    entry_id: &str,
    actor: &Actor,
) -> Outcome {
    let month = year_month(now);
    let mut state = existing
        .unwrap_or_else(|| LimitState::fresh(tenant_id, code, &month, &LimitSettings::default()));
    state.gauge_value = Some(value);
    state.gauge_month = Some(month);

    let mut ledger = ledger_base(&state, entry_id, now, ledger_type::GAUGE_SET, value, actor);
    ledger.gauge_value = Some(value);

    Outcome {
        state,
        ledger,
        history: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).unwrap()
    }

    fn settings(monthly: Option<i64>, overuse: Option<i64>) -> LimitSettings {
        LimitSettings {
            monthly,
            overuse,
            daily: None,
            max: None,
        }
    }

    fn consume(
        existing: Option<LimitState>,
        settings: &LimitSettings,
        amount: i64,
        now: DateTime<Utc>,
    ) -> Outcome {
        apply_consume(
            existing,
            "t1",
            "limit:ai",
            settings,
            amount,
            now,
            "entry-1",
            &Actor::default(),
        )
    }

    #[test]
    fn a_first_consume_creates_the_month_and_draws_from_monthly() {
        let out = consume(None, &settings(Some(1000), Some(200)), 300, at(2026, 9, 7));
        assert_eq!(out.state.period_year_month, "2026-09");
        assert_eq!(out.state.monthly_remaining, 700);
        assert_eq!(out.state.overuse_remaining, 200);
        assert_eq!(out.ledger.entry_type, ledger_type::CONSUME);
        assert_eq!(out.ledger.monthly_drawn, 300);
        assert_eq!(out.ledger.overdrawn, 0);
        assert_eq!(out.ledger.resulting_monthly, 700);
        assert!(out.history.is_none());
    }

    #[test]
    fn the_cascade_is_monthly_then_custom_then_overuse() {
        // 100 monthly + 50 custom + 200 overuse available; draw 320.
        let mut state =
            LimitState::fresh("t1", "limit:ai", "2026-09", &settings(Some(100), Some(200)));
        state.custom_balance = 50;
        let out = consume(
            Some(state),
            &settings(Some(100), Some(200)),
            320,
            at(2026, 9, 7),
        );
        assert_eq!(out.ledger.monthly_drawn, 100);
        assert_eq!(out.ledger.custom_drawn, 50);
        assert_eq!(out.ledger.overuse_drawn, 170);
        assert_eq!(out.ledger.overdrawn, 0);
        assert_eq!(out.state.monthly_remaining, 0);
        assert_eq!(out.state.custom_balance, 0);
        assert_eq!(out.state.overuse_remaining, 30);
    }

    #[test]
    fn an_overdraw_books_to_zero_and_is_recorded() {
        let out = consume(None, &settings(Some(100), None), 250, at(2026, 9, 7));
        assert_eq!(out.ledger.monthly_drawn, 100);
        assert_eq!(out.ledger.overdrawn, 150);
        assert_eq!(out.state.available(), 0);
    }

    #[test]
    fn a_new_month_resets_counters_keeps_custom_and_closes_a_history_row() {
        let mut prior = LimitState::fresh(
            "t1",
            "limit:ai",
            "2026-09",
            &settings(Some(1000), Some(100)),
        );
        prior.monthly_remaining = 10; // 990 used
        prior.overuse_remaining = 100; // untouched
        prior.custom_balance = 500; // topped up
        let out = consume(
            Some(prior),
            &settings(Some(1000), Some(100)),
            50,
            at(2026, 10, 1),
        );

        assert_eq!(out.state.period_year_month, "2026-10");
        // Fresh 1000 for the new month, minus the 50 just drawn; the stale 10 did not carry.
        assert_eq!(out.state.monthly_remaining, 950);
        // The custom balance is not monthly and survives the rollover untouched.
        assert_eq!(out.state.custom_balance, 500);

        let history = out.history.expect("a stale month is closed");
        assert_eq!(history.year_month, "2026-09");
        assert_eq!(history.monthly_included, 1000);
        assert_eq!(history.monthly_used, 990);
        assert_eq!(history.monthly_forfeited, 10);
        assert_eq!(history.overuse_used, 0);
        assert_eq!(history.ending_custom_balance, 500);
    }

    #[test]
    fn a_topup_adds_to_the_persistent_balance_and_logs_it() {
        let out = apply_topup(
            None,
            "t1",
            "limit:ai",
            &settings(Some(0), None),
            250,
            at(2026, 9, 7),
            "entry-1",
            &Actor::default(),
        );
        assert_eq!(out.state.custom_balance, 250);
        assert_eq!(out.ledger.entry_type, ledger_type::TOPUP);
        assert_eq!(out.ledger.custom_added, 250);
        assert_eq!(out.ledger.resulting_custom, 250);
    }

    #[test]
    fn a_gauge_records_a_value_without_touching_the_counters() {
        let out = set_gauge(
            None,
            "t1",
            "limit:seats",
            42,
            at(2026, 9, 7),
            "entry-1",
            &Actor::default(),
        );
        assert_eq!(out.state.gauge_value, Some(42));
        assert_eq!(out.state.gauge_month, Some("2026-09".to_owned()));
        assert_eq!(out.state.monthly_remaining, 0);
        assert_eq!(out.ledger.entry_type, ledger_type::GAUGE_SET);
        assert_eq!(out.ledger.gauge_value, Some(42));
        assert!(out.history.is_none());
    }

    #[test]
    fn the_actor_context_rides_along_on_the_ledger() {
        let actor = Actor {
            user_id: Some("u-42".to_owned()),
            txn_name: Some("qa-answer".to_owned()),
            txn_id: Some("req-999".to_owned()),
            ..Actor::default()
        };
        let out = apply_consume(
            None,
            "t1",
            "limit:ai",
            &settings(Some(100), None),
            10,
            at(2026, 9, 7),
            "entry-1",
            &actor,
        );
        assert_eq!(out.ledger.actor_user_id.as_deref(), Some("u-42"));
        assert_eq!(out.ledger.txn_name.as_deref(), Some("qa-answer"));
        assert_eq!(out.ledger.txn_id.as_deref(), Some("req-999"));
        assert_eq!(out.ledger.actor_user_name, None);
    }

    #[test]
    fn the_daily_throttle_decrements_and_resets_each_day() {
        let daily = LimitSettings {
            monthly: Some(1000),
            overuse: None,
            daily: Some(100),
            max: None,
        };
        // First consume today: 100 daily -> 70, and 1000 monthly -> 970.
        let out = apply_consume(
            None,
            "t1",
            "limit:ai",
            &daily,
            30,
            at(2026, 9, 7),
            "e1",
            &Actor::default(),
        );
        assert_eq!(out.state.daily_remaining, 70);
        assert_eq!(out.state.daily_date.as_deref(), Some("2026-09-07"));
        assert_eq!(out.state.monthly_remaining, 970);

        // Same day, draw the rest of the day's allowance and then some — daily floors at 0.
        let out = apply_consume(
            Some(out.state),
            "t1",
            "limit:ai",
            &daily,
            90,
            at(2026, 9, 7),
            "e2",
            &Actor::default(),
        );
        assert_eq!(out.state.daily_remaining, 0);

        // A new day (same month) resets the throttle to 100 without touching the monthly counter.
        let out = apply_consume(
            Some(out.state),
            "t1",
            "limit:ai",
            &daily,
            40,
            at(2026, 9, 8),
            "e3",
            &Actor::default(),
        );
        assert_eq!(out.state.daily_date.as_deref(), Some("2026-09-08"));
        assert_eq!(out.state.daily_remaining, 60);
        // 1000 - 30 - 90 - 40, carried across both days.
        assert_eq!(out.state.monthly_remaining, 840);
    }

    #[test]
    fn without_a_daily_setting_the_throttle_stays_dormant() {
        let out = consume(None, &settings(Some(1000), None), 50, at(2026, 9, 7));
        assert_eq!(out.state.daily_remaining, 0);
        assert_eq!(out.state.daily_date, None);
    }

    #[test]
    fn projecting_a_stale_month_rolls_over_in_memory() {
        let mut prior = LimitState::fresh(
            "t1",
            "limit:ai",
            "2026-09",
            &settings(Some(1000), Some(100)),
        );
        prior.monthly_remaining = 5;
        let (view, _history) = rolled_over(
            Some(prior),
            "t1",
            "limit:ai",
            &settings(Some(1000), Some(100)),
            at(2026, 10, 1),
        );
        assert_eq!(view.period_year_month, "2026-10");
        assert_eq!(view.monthly_remaining, 1000);
        assert_eq!(view.overuse_remaining, 100);
    }
}
