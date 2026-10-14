# ADR 0018 — Limits: pure accounting core, thin repository, one bounded OCC loop

- **Status:** accepted
- **Date:** 2026-09-07

## Context

Limits booking carries the heavy logic: cascade, rollover, overrun handling, reconciliation on
settings changes. The state is stored in DynamoDB today, but the booking logic should not be tied
to it — a new database backend should not have to re-implement that logic. Concurrent bookers on
the same tenant × limit must not lose updates, and state and ledger must never drift apart.

## Decision

- **Pure `accounting` module**, no I/O: functions like `apply_consume`, `apply_topup`,
  `apply_settings_change`, `set_gauge` take the current state and return an `Outcome`
  (new state, ledger entry, optional history row). Cascade, rollover and reconciliation live only
  here.
- **Thin repository trait** with mechanical primitives only: `load_state`, `compare_and_swap`
  (atomic: state with version condition + ledger + optional history), `read_ledger`,
  `read_history`, `set_gauge_value`.
- **The OCC retry loop lives exactly once**, in the service: load, apply (pure), compare-and-swap.
  It is **bounded** (`LIMIT_CAS_MAX_ATTEMPTS`) with a jittered, slightly growing backoff so
  contending bookers do not collide in lockstep, and aborts with 503 instead of looping forever.
- **Fail-closed:** `check` / `consume` deny on a store error, and the contention abort is a deny
  too — cost protection over availability, as in pip.
- DynamoDB commits `compare_and_swap` as one `TransactWriteItems` (state put with
  `#version = :expected`, ledger put, history put-if-not-exists).

## Consequences

- Another backend implements the same two core methods; a Postgres backend would use
  `UPDATE … WHERE version = $n` in one transaction.
- State and ledger never drift apart.
- Testing is mostly table-driven unit tests on the pure core without a database; the OCC loop is
  tested against a `mockall` repository (k conflicts then commit; always conflict → 503; store
  error → deny); only the version condition and idempotent history put need a DynamoDB
  integration test.
- Under heavy contention on one limit, callers get 503 / deny rather than unbounded latency.
