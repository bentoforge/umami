# ADR 0020 — Limits: the daily throttle is reconciled mid-day

- **Status:** accepted
- **Date:** 2026-10-21
- **Extends:** [ADR 0016](0016-limits-three-layer-model.md)

## Context

A settings change reconciles the live counters against the new values (ADR 0016). For `monthly`
and `extraAllowance` that works on `used = snapshot − remaining`, with the snapshot taken at the
start of the period.

The daily throttle had no snapshot. `dailyRemaining` was reset once a day from the tenant's
`daily` setting, and a change mid-day left it alone until the next reset. In practice:

- Raising `daily` for a tenant that had already hit today's throttle did nothing until midnight —
  the case an operator raises it for.
- Lowering `daily` did not bite until tomorrow; the tenant could still spend the old remainder.

## Decision

- The state row carries `dailySnapshot`: the value `dailyRemaining` was reset to on `dailyDate`,
  set by every daily reset.
- `apply_settings_change` reconciles the throttle within the current day like the monthly budget:
  `usedToday = dailySnapshot − dailyRemaining`, `dailyRemaining = max(0, newDaily − usedToday)`.
- A new value below today's usage caps the throttle at zero and warns. It books **no** overrun:
  the throttle is a gate in front of the buckets, not a bucket, so there is no debt to record —
  the consumption already drew from monthly / custom / extra allowance and was booked there.
- On a new day nothing is reconciled: the lazy reset (ADR 0017) already starts the day from the
  new setting.
- A row without `dailySnapshot` (written before the field existed) keeps its counter until its
  next daily reset, which fills the snapshot in.

## Alternatives considered

- **Delta against the previous tenant setting** (`remaining += newDaily − oldDaily`), with no new
  field. Rejected: it is only correct if every earlier change of the day was reconciled too, and it
  needs the old settings threaded into the pure accounting function, which today sees only the new
  ones.
- **Summing today's `consume` entries from the ledger.** Rejected: a ledger query on every settings
  change, for a value one integer on the state row answers.
- **Seeding legacy rows from the previous tenant setting.** Rejected for the same threading cost,
  to cover rows that are at most one day old at deploy time.

## Consequences

- A `daily` change takes effect immediately, in both directions, and writes a `settings` ledger
  entry like any other reconciling change.
- `dailySnapshot` is load-bearing in the same way `monthlySnapshot` is. It is serde-defaulted,
  so neither storage backend needs a migration.
- Lowering `daily` below today's usage blocks further bookings for the rest of the day without
  leaving any trace in the overrun figures. The warning in the settings response is the only
  signal.
