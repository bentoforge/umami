//! The booking logic — pure, no I/O, the heart of the limits domain.
//!
//! Every rule lives here: the monthly rollover (and the history row it closes), the consume cascade,
//! the overrun policy, the top-up, the gauge set — each producing the [`Outcome`] the repository
//! then commits atomically (state + optional ledger + optional history). The service runs the retry
//! loop around these functions. Keeping the arithmetic free of the store is what makes it exhaustively
//! testable — the tests below carry the weight, not an integration harness.
//!
//! Impurity is pushed to the edge: the caller supplies `now` and a pre-generated `entry_id`, so a
//! function is deterministic given its inputs and a retry recomputes the same result.

use crate::config::{LimitSettings, OverrunPolicy};
use crate::limits::{HistoryRow, LedgerEntry, LimitState, ledger_type};
use chrono::{DateTime, Datelike, SecondsFormat, Utc};

/// Optional actor/context for a ledger entry — caller-provided, never validated against umami users.
/// Three opaque ids, each length-capped at ingress; no names or free-text, so nothing
/// GDPR-sensitive lands in the ledger. `source` names the component/client that made the call and,
/// with `txn_id`, pins down exactly which operation a ledger entry belongs to.
#[derive(Debug, Clone, Default)]
pub struct Actor {
    pub user_id: Option<String>,
    pub txn_id: Option<String>,
    pub source: Option<String>,
}

/// The result of one booking operation: the state to persist, the ledger entry it produced (a gauge
/// set records no ledger, so `None`) and — when the operation crossed a month boundary — the closed
/// month's history row. `rejected` is set only by a `reject`-policy `consume` that could not be
/// covered: the service turns it into a 429 and nothing is written. `rollover` is the extra ledger
/// entry a month-end rollover produces — a `carry` (booking the previous month's overrun into this
/// one) or a `reset` marker — written atomically alongside `ledger`.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub state: LimitState,
    pub ledger: Option<LedgerEntry>,
    pub history: Option<HistoryRow>,
    pub rollover: Option<LedgerEntry>,
    pub rejected: bool,
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

/// The state as it applies to `now`'s month, plus — when a stale month was closed — its history row
/// and the rollover ledger entry that marks the boundary: a `carry` (booking the closed month's
/// overrun into the new one) under the `carry` policy, otherwise a `reset` marker.
///
/// If the stored period is stale — a real prior month — its aggregates become a [`HistoryRow`] and
/// the monthly/extra-allowance counters reset from `settings`, while the persistent custom balance
/// and the gauge value carry over. With no state yet, a fresh row and nothing to close. Pure: the
/// caller decides whether to persist (a read projects and discards, a write commits).
/// `rollover_entry_id` is used only when a rollover entry is actually produced.
pub fn rolled_over(
    existing: Option<LimitState>,
    tenant_id: &str,
    code: &str,
    settings: &LimitSettings,
    policy: OverrunPolicy,
    now: DateTime<Utc>,
    rollover_entry_id: &str,
) -> (LimitState, Option<HistoryRow>, Option<LedgerEntry>) {
    let month = year_month(now);
    let (state, history, rollover) = match existing {
        Some(state) if state.period_year_month == month => (state, None, None),
        Some(state) => {
            let history = HistoryRow {
                tenant_id: state.tenant_id.clone(),
                code: state.code.clone(),
                year_month: state.period_year_month.clone(),
                monthly_included: state.monthly_snapshot,
                monthly_used: state.monthly_snapshot - state.monthly_remaining,
                monthly_forfeited: state.monthly_remaining,
                extra_allowance_limit: state.extra_allowance_snapshot,
                extra_allowance_used: state.extra_allowance_snapshot
                    - state.extra_allowance_remaining,
                overrun: state.overrun,
                ending_custom_balance: state.custom_balance,
                gauge_value: None,
                gauge_max: None,
            };
            let carried = state.overrun;
            let monthly = settings.monthly.unwrap_or(0);
            let extra_allowance = settings.extra_allowance.unwrap_or(0);
            let mut new_state = LimitState {
                period_year_month: month,
                monthly_remaining: monthly,
                extra_allowance_remaining: extra_allowance,
                monthly_snapshot: monthly,
                extra_allowance_snapshot: extra_allowance,
                overrun: 0,
                // The persistent balance, daily throttle and gauge are not monthly and survive the
                // rollover; the daily throttle is refreshed below on its own (daily) schedule.
                ..state
            };
            // Every close writes one rollover ledger entry. Under `carry` with a debt, it is a
            // `carry`: the overrun becomes the new month's opening debt, drawn like a first usage
            // across custom → monthly → extra allowance, and whatever is left over stays as overrun
            // and rolls again next month (one pass, no recursion). Otherwise it is a `reset` marker
            // — no draw — so the ledger shows where the month turned and the new balances begin.
            let rollover = if policy == OverrunPolicy::Carry && carried > 0 {
                let mut debt = carried;
                let custom_drawn = draw_pay(&mut new_state.custom_balance, debt);
                debt -= custom_drawn;
                let monthly_drawn = draw_pay(&mut new_state.monthly_remaining, debt);
                debt -= monthly_drawn;
                let extra_drawn = draw_pay(&mut new_state.extra_allowance_remaining, debt);
                debt -= extra_drawn;
                new_state.overrun = debt;
                let mut ledger = ledger_base(
                    &new_state,
                    rollover_entry_id,
                    now,
                    ledger_type::CARRY,
                    carried,
                    &Actor::default(),
                );
                ledger.monthly_drawn = monthly_drawn;
                ledger.custom_drawn = custom_drawn;
                ledger.extra_allowance_drawn = extra_drawn;
                ledger.overrun = debt;
                ledger
            } else {
                ledger_base(
                    &new_state,
                    rollover_entry_id,
                    now,
                    ledger_type::RESET,
                    0,
                    &Actor::default(),
                )
            };
            (new_state, Some(history), Some(rollover))
        }
        None => (
            LimitState::fresh(tenant_id, code, &month, settings),
            None,
            None,
        ),
    };
    (refresh_daily(state, settings, now), history, rollover)
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
        extra_allowance_drawn: 0,
        overrun: 0,
        custom_added: 0,
        resulting_monthly: state.monthly_remaining,
        resulting_custom: state.custom_balance,
        resulting_extra_allowance: state.extra_allowance_remaining,
        resulting_overrun: state.overrun,
        actor_user_id: actor.user_id.clone(),
        txn_id: actor.txn_id.clone(),
        source: actor.source.clone(),
    }
}

/// Draws up to `*left` from `*pool`, returning what was taken.
fn draw(pool: &mut i64, left: &mut i64) -> i64 {
    let taken = (*pool).min(*left);
    *pool -= taken;
    *left -= taken;
    taken
}

/// Nets spendable allowance against the overrun debt so the two never both stand (the bookkeeping
/// invariant): any available amount pays the debt down, drawing monthly → custom → extra allowance. Called
/// after a top-up or a settings reconcile, so fresh allowance retires prior overrun.
fn settle_overrun(state: &mut LimitState) {
    let mut debt = state.overrun;
    debt -= draw_pay(&mut state.monthly_remaining, debt);
    debt -= draw_pay(&mut state.custom_balance, debt);
    debt -= draw_pay(&mut state.extra_allowance_remaining, debt);
    state.overrun = debt;
}

/// Pays up to `debt` out of `*pool`, returning what was paid.
fn draw_pay(pool: &mut i64, debt: i64) -> i64 {
    let paid = (*pool).min(debt);
    *pool -= paid;
    paid
}

/// Books `amount` against a consumable, drawing **monthly → custom → extra allowance** in that order.
///
/// `amount` is assumed non-negative (the caller validates). What cannot be covered — the overrun —
/// is handled per [`OverrunPolicy`]: `track` books to zero and sums it into the period counter (and
/// the ledger), `ignore` books to zero but does not sum it, `reject` refuses the whole booking and
/// changes nothing (`rejected` set, the service returns a 429).
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
    policy: OverrunPolicy,
) -> Outcome {
    let rollover_id = format!("{entry_id}-rollover");
    let (mut state, history, rollover) = rolled_over(
        existing,
        tenant_id,
        code,
        settings,
        policy,
        now,
        &rollover_id,
    );
    let want = amount.max(0);

    // Reject: a booking that cannot be fully covered changes nothing — the service returns a 429.
    // (`reject` never carries, so `carry` is `None` here.)
    if policy == OverrunPolicy::Reject && want > state.available() {
        let ledger = ledger_base(&state, entry_id, now, ledger_type::CONSUME, amount, actor);
        return Outcome {
            state,
            ledger: Some(ledger),
            history,
            rollover,
            rejected: true,
        };
    }

    let mut left = want;
    let monthly_drawn = draw(&mut state.monthly_remaining, &mut left);
    let custom_drawn = draw(&mut state.custom_balance, &mut left);
    let extra_allowance_drawn = draw(&mut state.extra_allowance_remaining, &mut left);

    // `left` is now the uncovered overrun. Under `track` it is summed into the period counter (and
    // always recorded on the ledger entry); `ignore` drops it from the counter.
    if policy == OverrunPolicy::Track {
        state.overrun += left;
    }

    // The daily throttle is a parallel usage counter (not a source): what was actually booked is
    // subtracted from today's allowance, floored at zero. `check` gates on it before the call.
    if settings.daily.is_some() {
        let drawn = monthly_drawn + custom_drawn + extra_allowance_drawn;
        state.daily_remaining = (state.daily_remaining - drawn).max(0);
    }

    let mut ledger = ledger_base(&state, entry_id, now, ledger_type::CONSUME, amount, actor);
    ledger.monthly_drawn = monthly_drawn;
    ledger.custom_drawn = custom_drawn;
    ledger.extra_allowance_drawn = extra_allowance_drawn;
    ledger.overrun = left;

    Outcome {
        state,
        ledger: Some(ledger),
        history,
        rollover,
        rejected: false,
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
    policy: OverrunPolicy,
) -> Outcome {
    let rollover_id = format!("{entry_id}-rollover");
    let (mut state, history, rollover) = rolled_over(
        existing,
        tenant_id,
        code,
        settings,
        policy,
        now,
        &rollover_id,
    );
    let added = amount.max(0);
    state.custom_balance += added;
    // Fresh credit retires prior overrun first (bookkeeping): the debt drops, the rest stays balance.
    settle_overrun(&mut state);

    let mut ledger = ledger_base(&state, entry_id, now, ledger_type::TOPUP, amount, actor);
    ledger.custom_added = added;

    Outcome {
        state,
        ledger: Some(ledger),
        history,
        rollover,
        rejected: false,
    }
}

/// Sets a gauge's current value for `now`'s month. A gauge is never booked — only set — so the
/// monthly/extra-allowance counters are untouched and no ledger entry is written. When the value is
/// the first one set in a new month, the value that stood at the previous gauge month's close is
/// captured into a history row (`max` is the bound in force now, a best effort — a gauge keeps no
/// per-period snapshot).
pub fn set_gauge(
    existing: Option<LimitState>,
    tenant_id: &str,
    code: &str,
    value: i64,
    max: Option<i64>,
    now: DateTime<Utc>,
) -> Outcome {
    let month = year_month(now);
    let mut state = existing
        .unwrap_or_else(|| LimitState::fresh(tenant_id, code, &month, &LimitSettings::default()));

    // A value already set in an earlier month closes that month into history before this one lands.
    let history = match (state.gauge_month.as_deref(), state.gauge_value) {
        (Some(prev_month), Some(prev_value)) if prev_month != month => Some(HistoryRow {
            tenant_id: state.tenant_id.clone(),
            code: state.code.clone(),
            year_month: prev_month.to_owned(),
            monthly_included: 0,
            monthly_used: 0,
            monthly_forfeited: 0,
            extra_allowance_limit: 0,
            extra_allowance_used: 0,
            overrun: 0,
            ending_custom_balance: 0,
            gauge_value: Some(prev_value),
            gauge_max: max,
        }),
        _ => None,
    };

    state.gauge_value = Some(value);
    state.gauge_month = Some(month);

    // A gauge set records no ledger entry — only the current value and, on a rollover, a history row.
    Outcome {
        state,
        ledger: None,
        history,
        rollover: None,
        rejected: false,
    }
}

/// Reconciles the live counters to changed per-tenant `settings`, keeping what is already used this
/// month.
///
/// For monthly and extra allowance: `remaining = max(0, new_limit - used)` where `used = snapshot -
/// remaining` — so a rise grows the remaining by the delta, a fall shrinks it, and a fall below what
/// is already used caps it at zero and warns. The persistent custom balance is never touched (it
/// moves only via top-ups); a gauge's value stays put but is flagged when it now exceeds its bound.
/// The daily throttle is not reconciled mid-day — it picks up the new setting at its next reset.
/// Records a `settings` ledger entry. Returned warnings are advisory admin messages.
#[allow(clippy::too_many_arguments)]
pub fn apply_settings_change(
    existing: Option<LimitState>,
    tenant_id: &str,
    code: &str,
    settings: &LimitSettings,
    now: DateTime<Utc>,
    entry_id: &str,
    actor: &Actor,
    policy: OverrunPolicy,
) -> (Outcome, Vec<String>) {
    let rollover_id = format!("{entry_id}-rollover");
    let (mut state, history, rollover) = rolled_over(
        existing,
        tenant_id,
        code,
        settings,
        policy,
        now,
        &rollover_id,
    );
    let mut warnings = Vec::new();

    // Monthly: what is already used stays used. A rise grows the remaining; a fall below usage caps
    // it at zero and books the shortfall as overrun (an honest debt, not a silently-dropped value).
    let used_monthly = (state.monthly_snapshot - state.monthly_remaining).max(0);
    let new_monthly = settings.monthly.unwrap_or(0);
    state.monthly_snapshot = new_monthly;
    let raw_monthly = new_monthly - used_monthly;
    if raw_monthly >= 0 {
        state.monthly_remaining = raw_monthly;
    } else {
        state.monthly_remaining = 0;
        state.overrun += -raw_monthly;
        warnings.push(format!(
            "monthly budget {new_monthly} is below the {used_monthly} already used this month; the \
             {} shortfall is booked as overrun",
            -raw_monthly
        ));
    }

    let used_extra_allowance =
        (state.extra_allowance_snapshot - state.extra_allowance_remaining).max(0);
    let new_extra_allowance = settings.extra_allowance.unwrap_or(0);
    state.extra_allowance_snapshot = new_extra_allowance;
    let raw_extra_allowance = new_extra_allowance - used_extra_allowance;
    if raw_extra_allowance >= 0 {
        state.extra_allowance_remaining = raw_extra_allowance;
    } else {
        state.extra_allowance_remaining = 0;
        state.overrun += -raw_extra_allowance;
        warnings.push(format!(
            "extra allowance {new_extra_allowance} is below the {used_extra_allowance} already used this month; the \
             {} shortfall is booked as overrun",
            -raw_extra_allowance
        ));
    }

    // A rise in budget or allowance retires prior overrun first (bookkeeping).
    settle_overrun(&mut state);

    if let (Some(max), Some(value)) = (settings.max, state.gauge_value)
        && value > max
    {
        warnings.push(format!("gauge value {value} now exceeds the max {max}"));
    }

    let ledger = ledger_base(&state, entry_id, now, ledger_type::SETTINGS, 0, actor);

    (
        Outcome {
            state,
            ledger: Some(ledger),
            history,
            rollover,
            rejected: false,
        },
        warnings,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).unwrap()
    }

    /// The ledger entry a booking produced (every test that inspects it produces one).
    fn led(out: &Outcome) -> &LedgerEntry {
        out.ledger.as_ref().expect("a ledger entry was produced")
    }

    fn settings(monthly: Option<i64>, extra_allowance: Option<i64>) -> LimitSettings {
        LimitSettings {
            monthly,
            extra_allowance,
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
            OverrunPolicy::Track,
        )
    }

    #[test]
    fn a_first_consume_creates_the_month_and_draws_from_monthly() {
        let out = consume(None, &settings(Some(1000), Some(200)), 300, at(2026, 9, 7));
        assert_eq!(out.state.period_year_month, "2026-09");
        assert_eq!(out.state.monthly_remaining, 700);
        assert_eq!(out.state.extra_allowance_remaining, 200);
        assert_eq!(led(&out).entry_type, ledger_type::CONSUME);
        assert_eq!(led(&out).monthly_drawn, 300);
        assert_eq!(led(&out).overrun, 0);
        assert_eq!(led(&out).resulting_monthly, 700);
        assert!(out.history.is_none());
    }

    #[test]
    fn the_cascade_is_monthly_then_custom_then_extra_allowance() {
        // 100 monthly + 50 custom + 200 extra allowance available; draw 320.
        let mut state =
            LimitState::fresh("t1", "limit:ai", "2026-09", &settings(Some(100), Some(200)));
        state.custom_balance = 50;
        let out = consume(
            Some(state),
            &settings(Some(100), Some(200)),
            320,
            at(2026, 9, 7),
        );
        assert_eq!(led(&out).monthly_drawn, 100);
        assert_eq!(led(&out).custom_drawn, 50);
        assert_eq!(led(&out).extra_allowance_drawn, 170);
        assert_eq!(led(&out).overrun, 0);
        assert_eq!(out.state.monthly_remaining, 0);
        assert_eq!(out.state.custom_balance, 0);
        assert_eq!(out.state.extra_allowance_remaining, 30);
    }

    #[test]
    fn an_overrun_books_to_zero_and_is_recorded() {
        let out = consume(None, &settings(Some(100), None), 250, at(2026, 9, 7));
        assert_eq!(led(&out).monthly_drawn, 100);
        assert_eq!(led(&out).overrun, 150);
        assert_eq!(out.state.available(), 0);
    }

    fn consume_p(
        existing: Option<LimitState>,
        settings: &LimitSettings,
        amount: i64,
        now: DateTime<Utc>,
        policy: OverrunPolicy,
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
            policy,
        )
    }

    #[test]
    fn track_sums_the_overrun_and_books_to_zero() {
        let cfg = settings(Some(100), None);
        let out = consume_p(None, &cfg, 250, at(2026, 9, 7), OverrunPolicy::Track);
        assert!(!out.rejected);
        assert_eq!(out.state.monthly_remaining, 0);
        assert_eq!(led(&out).overrun, 150);
        assert_eq!(out.state.overrun, 150);
        // A second overrun in the same month accumulates.
        let out = consume_p(
            Some(out.state),
            &cfg,
            30,
            at(2026, 9, 8),
            OverrunPolicy::Track,
        );
        assert_eq!(out.state.overrun, 180);
    }

    #[test]
    fn ignore_books_to_zero_without_summing() {
        let out = consume_p(
            None,
            &settings(Some(100), None),
            250,
            at(2026, 9, 7),
            OverrunPolicy::Ignore,
        );
        assert!(!out.rejected);
        assert_eq!(out.state.monthly_remaining, 0);
        // The excess is still on the ledger entry, but not summed into the period counter.
        assert_eq!(led(&out).overrun, 150);
        assert_eq!(out.state.overrun, 0);
    }

    #[test]
    fn reject_refuses_and_changes_nothing_when_over() {
        let cfg = settings(Some(100), None);
        // Fits → books normally.
        let out = consume_p(None, &cfg, 80, at(2026, 9, 7), OverrunPolicy::Reject);
        assert!(!out.rejected);
        assert_eq!(out.state.monthly_remaining, 20);
        // Over the remaining 20 → rejected, nothing drawn.
        let out = consume_p(
            Some(out.state),
            &cfg,
            50,
            at(2026, 9, 7),
            OverrunPolicy::Reject,
        );
        assert!(out.rejected);
        assert_eq!(out.state.monthly_remaining, 20);
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
        prior.extra_allowance_remaining = 100; // untouched
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
        assert_eq!(history.extra_allowance_used, 0);
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
            OverrunPolicy::Track,
        );
        assert_eq!(out.state.custom_balance, 250);
        assert_eq!(led(&out).entry_type, ledger_type::TOPUP);
        assert_eq!(led(&out).custom_added, 250);
        assert_eq!(led(&out).resulting_custom, 250);
    }

    #[test]
    fn a_topup_retires_overrun_first() {
        let owing = |debt: i64| {
            let mut state =
                LimitState::fresh("t1", "limit:ai", "2026-09", &settings(Some(0), None));
            state.overrun = debt;
            state
        };
        // A partial top-up pays the debt down and leaves no balance.
        let out = apply_topup(
            Some(owing(100)),
            "t1",
            "limit:ai",
            &settings(Some(0), None),
            60,
            at(2026, 9, 7),
            "e1",
            &Actor::default(),
            OverrunPolicy::Track,
        );
        assert_eq!(out.state.overrun, 40);
        assert_eq!(out.state.custom_balance, 0);
        assert_eq!(led(&out).resulting_overrun, 40);
        // A larger top-up clears the debt and the remainder becomes balance.
        let out = apply_topup(
            Some(owing(100)),
            "t1",
            "limit:ai",
            &settings(Some(0), None),
            250,
            at(2026, 9, 7),
            "e2",
            &Actor::default(),
            OverrunPolicy::Track,
        );
        assert_eq!(out.state.overrun, 0);
        assert_eq!(out.state.custom_balance, 150);
    }

    #[test]
    fn carry_books_a_prior_month_overrun_into_the_next() {
        // September closed 150 in overrun; October opens with 1000 monthly + 200 extra, no balance.
        let mut prior = LimitState::fresh("t1", "limit:ai", "2026-09", &settings(Some(1000), None));
        prior.monthly_remaining = 0;
        prior.overrun = 150;

        // The first October booking rolls over: the 150 is drawn (custom 0 → monthly) as a `carry`.
        let out = apply_consume(
            Some(prior),
            "t1",
            "limit:ai",
            &settings(Some(1000), Some(200)),
            50,
            at(2026, 10, 2),
            "oct-1",
            &Actor::default(),
            OverrunPolicy::Carry,
        );
        let carry = out.rollover.expect("a carry entry was produced");
        assert_eq!(carry.entry_type, ledger_type::CARRY);
        assert_eq!(carry.amount, 150);
        assert_eq!(carry.monthly_drawn, 150);
        assert_eq!(carry.overrun, 0);
        // History records September's overrun; the closed month is untouched by the carry.
        assert_eq!(out.history.expect("September closed").overrun, 150);
        // October: 1000 − 150 carry − 50 consume = 800 monthly left, extra untouched, no overrun.
        assert_eq!(out.state.monthly_remaining, 800);
        assert_eq!(out.state.extra_allowance_remaining, 200);
        assert_eq!(out.state.overrun, 0);
    }

    #[test]
    fn carry_beyond_the_new_budget_rolls_again() {
        // A 1500 overrun against only 1000 + 200 available: 300 stays as overrun and carries on.
        let mut prior = LimitState::fresh("t1", "limit:ai", "2026-09", &settings(Some(1000), None));
        prior.overrun = 1500;
        let out = apply_topup(
            Some(prior),
            "t1",
            "limit:ai",
            &settings(Some(1000), Some(200)),
            0,
            at(2026, 10, 2),
            "oct-1",
            &Actor::default(),
            OverrunPolicy::Carry,
        );
        let carry = out.rollover.expect("a carry entry was produced");
        assert_eq!(carry.monthly_drawn, 1000);
        assert_eq!(carry.extra_allowance_drawn, 200);
        assert_eq!(carry.overrun, 300);
        // Everything spendable is drawn to zero; the residual debt rides on.
        assert_eq!(out.state.monthly_remaining, 0);
        assert_eq!(out.state.extra_allowance_remaining, 0);
        assert_eq!(out.state.overrun, 300);
    }

    #[test]
    fn track_does_not_carry_the_overrun_forward() {
        // The same setup under `track`: the overrun closes into history and the new month opens
        // clean, marked by a `reset` rollover entry that draws nothing.
        let mut prior = LimitState::fresh("t1", "limit:ai", "2026-09", &settings(Some(1000), None));
        prior.overrun = 150;
        let out = apply_consume(
            Some(prior),
            "t1",
            "limit:ai",
            &settings(Some(1000), None),
            50,
            at(2026, 10, 2),
            "oct-1",
            &Actor::default(),
            OverrunPolicy::Track,
        );
        let rollover = out
            .rollover
            .as_ref()
            .expect("a reset entry marks the close");
        assert_eq!(rollover.entry_type, ledger_type::RESET);
        assert_eq!(rollover.monthly_drawn, 0);
        assert_eq!(out.history.expect("September closed").overrun, 150);
        assert_eq!(out.state.monthly_remaining, 950);
        assert_eq!(out.state.overrun, 0);
    }

    #[test]
    fn lowering_below_usage_books_overrun_and_a_rise_retires_it() {
        // 1000 budget with 800 already used (remaining 200).
        let mut state = LimitState::fresh("t1", "limit:ai", "2026-09", &settings(Some(1000), None));
        state.monthly_remaining = 200;

        // Lower to 500 (below the 800 used): remaining 0, the 300 shortfall becomes overrun.
        let (out, warnings) = apply_settings_change(
            Some(state),
            "t1",
            "limit:ai",
            &settings(Some(500), None),
            at(2026, 9, 7),
            "e1",
            &Actor::default(),
            OverrunPolicy::Track,
        );
        assert_eq!(out.state.monthly_remaining, 0);
        assert_eq!(out.state.overrun, 300);
        assert!(!warnings.is_empty());

        // Raise back to 1000: 800 is still used, so remaining settles to 200 and the debt is retired.
        let (out, _) = apply_settings_change(
            Some(out.state),
            "t1",
            "limit:ai",
            &settings(Some(1000), None),
            at(2026, 9, 7),
            "e2",
            &Actor::default(),
            OverrunPolicy::Track,
        );
        assert_eq!(out.state.overrun, 0);
        assert_eq!(out.state.monthly_remaining, 200);
    }

    #[test]
    fn a_gauge_records_a_value_without_touching_the_counters() {
        let out = set_gauge(None, "t1", "limit:seats", 42, Some(50), at(2026, 9, 7));
        assert_eq!(out.state.gauge_value, Some(42));
        assert_eq!(out.state.gauge_month, Some("2026-09".to_owned()));
        assert_eq!(out.state.monthly_remaining, 0);
        // A gauge writes no ledger entry.
        assert!(out.ledger.is_none());
        assert!(out.history.is_none());
    }

    #[test]
    fn a_gauge_set_in_a_new_month_closes_the_previous_one_into_history() {
        // A value stood in August; setting one in September closes August.
        let august = set_gauge(None, "t1", "limit:seats", 40, Some(50), at(2026, 8, 20));
        let september = set_gauge(
            Some(august.state),
            "t1",
            "limit:seats",
            45,
            Some(50),
            at(2026, 9, 3),
        );
        let history = september.history.expect("August closed into history");
        assert_eq!(history.year_month, "2026-08");
        assert_eq!(history.gauge_value, Some(40));
        assert_eq!(history.gauge_max, Some(50));
        assert_eq!(september.state.gauge_value, Some(45));
    }

    #[test]
    fn the_actor_ids_ride_along_on_the_ledger() {
        let actor = Actor {
            user_id: Some("u-42".to_owned()),
            txn_id: Some("req-999".to_owned()),
            source: Some("chat-web".to_owned()),
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
            OverrunPolicy::Track,
        );
        assert_eq!(led(&out).actor_user_id.as_deref(), Some("u-42"));
        assert_eq!(led(&out).txn_id.as_deref(), Some("req-999"));
        assert_eq!(led(&out).source.as_deref(), Some("chat-web"));
    }

    #[test]
    fn the_daily_throttle_decrements_and_resets_each_day() {
        let daily = LimitSettings {
            monthly: Some(1000),
            extra_allowance: None,
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
            OverrunPolicy::Track,
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
            OverrunPolicy::Track,
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
            OverrunPolicy::Track,
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

    /// A state with `used` of this month's budget, for the reconciliation tests.
    fn used(monthly_snapshot: i64, monthly_remaining: i64) -> LimitState {
        let mut state = LimitState::fresh(
            "t1",
            "limit:ai",
            "2026-09",
            &settings(Some(monthly_snapshot), None),
        );
        state.monthly_remaining = monthly_remaining;
        state.custom_balance = 500; // must survive every reconciliation
        state
    }

    fn reconcile(state: LimitState, new: &LimitSettings) -> (Outcome, Vec<String>) {
        apply_settings_change(
            Some(state),
            "t1",
            "limit:ai",
            new,
            at(2026, 9, 7),
            "e1",
            &Actor::default(),
            OverrunPolicy::Track,
        )
    }

    #[test]
    fn a_higher_setting_grows_the_remaining() {
        // 300 used of 1000; raise to 1500 -> 1200 remaining, custom untouched, a settings entry.
        let (out, warnings) = reconcile(used(1000, 700), &settings(Some(1500), None));
        assert_eq!(out.state.monthly_snapshot, 1500);
        assert_eq!(out.state.monthly_remaining, 1200);
        assert_eq!(out.state.custom_balance, 500);
        assert!(warnings.is_empty());
        assert_eq!(led(&out).entry_type, ledger_type::SETTINGS);
    }

    #[test]
    fn a_lower_setting_above_usage_shrinks_the_remaining() {
        // 300 used; lower to 500 (> used) -> 200 remaining, no warning.
        let (out, warnings) = reconcile(used(1000, 700), &settings(Some(500), None));
        assert_eq!(out.state.monthly_remaining, 200);
        assert!(warnings.is_empty());
    }

    #[test]
    fn a_setting_below_usage_caps_at_zero_and_warns() {
        // 300 used; lower to 200 (< used) -> 0 remaining + a warning.
        let (out, warnings) = reconcile(used(1000, 700), &settings(Some(200), None));
        assert_eq!(out.state.monthly_remaining, 0);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("monthly"), "{:?}", warnings);
    }

    #[test]
    fn lowering_a_gauge_max_below_its_value_warns() {
        let mut state =
            LimitState::fresh("t1", "limit:seats", "2026-09", &LimitSettings::default());
        state.gauge_value = Some(80);
        let new = LimitSettings {
            max: Some(50),
            ..LimitSettings::default()
        };
        let (_out, warnings) = apply_settings_change(
            Some(state),
            "t1",
            "limit:seats",
            &new,
            at(2026, 9, 7),
            "e1",
            &Actor::default(),
            OverrunPolicy::Track,
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("gauge"), "{:?}", warnings);
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
        let (view, _history, _carry) = rolled_over(
            Some(prior),
            "t1",
            "limit:ai",
            &settings(Some(1000), Some(100)),
            OverrunPolicy::Track,
            at(2026, 10, 1),
            "e-carry",
        );
        assert_eq!(view.period_year_month, "2026-10");
        assert_eq!(view.monthly_remaining, 1000);
        assert_eq!(view.extra_allowance_remaining, 100);
    }
}
