# ADR 0017 — Limits month rollover happens lazily on first access

- **Status:** accepted
- **Date:** 2026-09-07

## Context

Monthly and extra allowances expire at month end and are refilled from the tenant's current
settings; the custom balance persists. Each closed month must end up as a `limit-history` row for
billing. Something has to perform this month close for every tenant × limit.

## Decision

The rollover runs **on access**, not on a schedule. A shared `load_current(tenant, code)` sits in
front of *every* path (`consume`, `check`, `GET`). When it sees `periodYearMonth` differ from the
current month, it closes the previous month:

- writes the `limit-history` row (guarded by `attribute_not_exists`, so idempotent),
- lets monthly / extraAllowance expire and refills them from the current `Tenant.limits` snapshot,
- keeps `customBalance`,
- writes exactly one rollover ledger entry (`carry` under the `carry` policy, otherwise a `reset`
  marker).

The rollover is computed in the pure accounting core and committed atomically with the state
through `compare_and_swap` (state + booking + `carry` + history in one transaction).

`POST /tenants/{id}/limits/{code}/rollover` exists to force a month close from outside.

## Alternatives considered

- **A rollover sweep / cron for inactive tenants** at month change. Deliberately left out: history
  is created lazily on the first access in the new month; a tenant without any access has nothing
  to book, and an empty month record would be useless. Kept as a later option (cron backfill for
  gap-free history).

## Consequences

- Cost: **one extra write per limit per month**, carried by the first access.
- No scheduler is needed for correctness; state, ledger and history cannot drift because the month
  close goes through the same atomic write as a booking.
- **History has gaps** for limits that are never accessed in a month. This is accepted.
- A settings change that is only half-applied (L2 written, L3 not) is healed at the latest by the
  next rollover, which rebuilds from L2.
