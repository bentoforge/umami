# ADR 0016 — Limits as a three-layer model: catalogue, per-tenant values, runtime state

- **Status:** accepted
- **Date:** 2026-09-07

## Context

umami needs tenant-wide quotas of two kinds: consumable balances that get booked down (AI
credits, tokens) and absolute caps with a current value (e.g. seats).

The consumable core generalises the AI budget subsystem of `pip-core` (`src/ai/limits/`): per
`(issuer, tenant)` a monthly credit allowance with an extra allowance and an optional daily cap,
booked atomically, with the limits stamped onto the period row. On top of pip, umami adds a
persistent custom balance (top-up), gauge limits with watermarks, a transaction ledger, a monthly
history, and a backend-agnostic split between booking logic and storage.

umami already models roles, scopes and features as catalogue concepts: a global definition in the
config plus per-tenant assignment. Unlike those, limits carry real, constantly changing state.

## Decision

Limits are split into three layers:

| Layer | Where | Content | Rate of change |
|---|---|---|---|
| **L1 catalogue** | `Config.limits: Vec<LimitDef>` | *What* a limit is: kind, active facets, watermarks, labels | rare (deploy) |
| **L2 per-tenant values** | `Tenant.limits: BTreeMap<String, LimitSettings>` | *How much* per tenant: monthly, extraAllowance, daily, gauge max | rare (admin/UI) |
| **L3 runtime state** | `limits` repository (three tables) | Counters, custom balance, ledger, history | constant (every call) |

- L1 follows the `FeatureDef` pattern exactly, L2 follows `custom_fields` exactly — both are
  existing umami patterns.
- L3 is new: `limit-state` (the hot atomic row), `limit-ledger` (append-only) and
  `limit-history` (one row per closed month). It uses the atomic update pattern (OCC) already
  used by `auth/ratelimit` and `tenants`.
- L2 is the source of truth for the values. A settings change first writes `Tenant.limits`
  (`put_tenant`), then reconciles the L3 state through the regular OCC loop and
  `compare_and_swap`, writing a `settings` ledger entry.

## Alternatives considered

- **One `TransactWriteItems` across `Tenant.limits` and the L3 state** for a settings change.
  Not done: the two-step write is accepted instead (see Consequences).

## Consequences

- Limits fit into the existing catalogue concepts; definitions need no new UI (the `ConfigPage`
  edits the raw JSON), and the catalogue endpoint `GET /config/catalogue` carries the limit defs.
- A settings change is two-step, not cross-table atomic. An abort after the L2 write delays the
  effect at most until the next month (the rollover rebuilds from L2), and a retry is idempotent
  because reconciliation works on `used = snapshot − remaining`. Warnings are returned immediately.
- If no state row exists yet (limit never used), only `Tenant.limits` is written; the first call
  builds the state from the new settings.
- `monthlySnapshot` / `extraAllowanceSnapshot` on the state row are load-bearing: they keep
  `used` well-defined when settings change mid-month.
