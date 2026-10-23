# Architecture decision records

One file per decision, numbered in the order they were made: `NNNN-title.md` with status, date,
context, decision, alternatives considered and consequences. A new ADR takes the next free number
and a line in this table; a decision that replaces an earlier one says so in its header and the
earlier one's status changes to `superseded`.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-cross-tenant-token-exchange.md) | Cross-tenant token exchange for system principals | accepted |
| [0002](0002-postgres-storage.md) | PostgreSQL as a second storage backend | accepted |
| [0003](0003-api-key-auth-modes.md) | Three API-key auth modes and an honest browser threat model | accepted |
| [0004](0004-token-broker-per-api-audiences.md) | umami as a token broker with per-API audiences | accepted |
| [0005](0005-service-keys-and-personal-access-tokens.md) | Service keys and personal access tokens as one key entity | accepted |
| [0006](0006-permission-dsl-per-api-mapping.md) | Permissions projected per API from subjects via an ordered rule DSL | accepted |
| [0007](0007-roles-scopes-pat-restriction.md) | Roles for users, scopes for service keys, role restriction for PATs | accepted |
| [0008](0008-system-tenant-marker.md) | System tenant expressed via the `is:system-tenant` marker | accepted |
| [0009](0009-audience-agnostic-sessions-and-keys.md) | Audience-agnostic sessions and API keys | accepted |
| [0010](0010-hmac-signed-key-exchange.md) | HMAC signed key exchange keyed by the stored secret hash | accepted |
| [0011](0011-contacts-as-verified-list.md) | Contacts as a verified list, not an email field on the user | accepted |
| [0012](0012-mail-worker-outbound-seam.md) | umami renders mail, a worker delivers it | accepted |
| [0013](0013-password-recovery-by-mail.md) | Password recovery by mailed link | accepted |
| [0014](0014-transactional-mail-outside-notification-catalogue.md) | Transactional mail stays outside the notification catalogue | accepted |
| [0015](0015-app-owns-notification-clock.md) | The app owns the notification clock; cadences are opaque strings | accepted |
| [0016](0016-limits-three-layer-model.md) | Limits as a three-layer model: catalogue, per-tenant values, runtime state | accepted |
| [0017](0017-limits-lazy-rollover-on-access.md) | Limits month rollover happens lazily on first access | accepted |
| [0018](0018-limits-pure-accounting-core-thin-repository.md) | Limits: pure accounting core, thin repository, one bounded OCC loop | accepted |
| [0019](0019-limits-booking-cascade-and-overrun-policy.md) | Limits booking cascade and overrun policies | accepted |
| [0020](0020-limits-daily-throttle-reconciled-mid-day.md) | Limits: the daily throttle is reconciled mid-day | accepted |
| [0021](0021-external-recipients-without-identity.md) | External recipients: a notification address without an identity | accepted, amended by 0022 |
| [0022](0022-recipients-get-their-own-gate.md) | External recipients get their own gate: `recipientsIf` | accepted |

The topic docs under `docs/` link the decisions behind them at their top, so a reader of
[NOTIFICATIONS.md](../NOTIFICATIONS.md) or [LIMITS.md](../LIMITS.md) finds the relevant ones
without this table.
