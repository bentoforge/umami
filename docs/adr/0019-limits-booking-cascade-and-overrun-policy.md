# ADR 0019 — Limits booking cascade and overrun policies

- **Status:** accepted
- **Date:** 2026-09-09

## Context

A consumable limit has up to three buckets per tenant: the included monthly allowance, a
persistent custom balance (top-up, does not expire), and a monthly extra allowance that is the
expensive one. A booking must draw from them in a defined order, and the system must decide what
happens when the sum of all buckets is not enough.

Callers use limits differently: `check` is a mutation-free pre-gate, while `consume` books the
*actual* usage after the fact. Some callers need hard prepaid gating, others honest accounting of
usage that already happened, others only best-effort throttling.

The cascade entered the doc with the first limits design (2026-09-07); the per-limit overrun
policy (`track` / `reject` / `ignore`) and debt-like settlement followed on 2026-09-09, the
`carry` policy on 2026-09-10.

## Decision

**Cascade.** Consumption is deducted in fixed order: **monthly → custom → extraAllowance** —
first the included allowance, then the persistent custom balance, last the expensive extra
allowance.

**Overrun policy per limit** (`LimitDef.overrunPolicy`, consumable only) decides what happens to
the remainder when the buckets do not cover a booking:

- **`track`** (default): book to zero, add the remainder to the monthly `overrun` counter (and as
  `overrun` on the ledger entry). The call has happened, so it is booked honestly and billable.
  `overrun` expires at month end into the history.
- **`reject`**: reject the whole booking (**429**) and write nothing — hard prepaid gating where
  `consume` is used as reserve-then-use.
- **`ignore`**: book to zero and drop the remainder (only on the ledger entry, no counter) —
  soft best-effort throttling.
- **`carry`**: like `track`, but `overrun` does not expire. At rollover a `carry` ledger entry
  books it against the new month like a first usage (custom → monthly → extraAllowance); what
  remains stays the new month's `overrun`. One pass per rollover, no recursion.

**No negative buckets.** The remainder lives in the `overrun` counter, never as a negative balance.

**Overrun is a debt.** As soon as balance is available again (top-up or raised limit) it is first
booked against `overrun` (`settle_overrun`, order monthly → custom → extraAllowance). Invariant:
available balance and `overrun` are never positive at the same time. Lowering a limit below what
is already used moves the shortfall onto `overrun`.

**Two-phase confirmation.** Because a settings change can cause a real ledger booking,
`PATCH …/limits/{code}` without `?confirm=true` only previews: if the change moves `overrun`, it
returns `confirmationRequired` with warnings and writes nothing; the client re-sends with
`?confirm=true`.

## Consequences

- The ledger records the bucket breakdown per booking (`monthlyDrawn`, `customDrawn`,
  `extraAllowanceDrawn`, `overrun`), so billing can read extra-allowance use and overrun per month.
- Accounting is self-healing: overrun created by lowering a limit is cleared by a later top-up or
  raise, each with a `settings` / `topup` ledger entry carrying `resultingOverrun`.
- Under `carry` the overrun is a running cap rather than a monthly reset.
- A gauge has no cascade and no overrun; validation rejects a non-default policy on a gauge.
