# ADR 0001 — Cross-tenant token exchange for system principals

- **Status:** accepted
- **Date:** 2026-10-05

## Context

umami issues the tokens for a fleet of product services (e.g. dbx, which stores data under the
token's `tenant` claim). Some work is deployment-wide but has to happen *inside* a customer tenant:
an operator importing a manufacturer's catalog into that manufacturer's tenant, a sync job writing
into many tenants.

Until now there were two ways, neither good:

- **One credential per customer tenant.** A service key or PAT has to be created and stored for
  every tenant someone wants to write into — tedious, and it multiplies secrets.
- **`POST /auth/switch-tenant`.** Exists for system-tenant users, but is bound to a browser session
  (it needs the refresh cookie), so a CLI or job cannot use it.

The previous token source for these jobs, a Lambda signing HS256 tokens with a shared secret, has
been removed.

## Decision

`POST /auth/token` takes an optional `tenantId`. When it names another tenant than the principal's
own, the minted token acts in that tenant: `tenant` is the target, permissions are resolved against
the target's features, `is:system-tenant-member` is kept and `is:system-tenant` is not — the same
shape as a switched session token. Every such exchange is audited in the target tenant. Only
principals whose home is the system tenant may do this, and which ones is decided by the
configurable permission rules of the umami API, not by code:

1. **Personal access tokens** need `switch:tenant`. A PAT may act in exactly the tenants its user
   could switch into from a session, so it adds no power the user did not already have. This is
   the path for a person running a job.
2. **Service keys** need the new permission `exchange:any-tenant`, which the default config grants
   to nobody. A deployment opts a key in with an explicit rule
   (`scope:importer + is:system-tenant-member → exchange:any-tenant`). This is the path for
   unattended jobs.

Two new synthetic markers let the rules tell a PAT apart from a session:

- `is:pat` — the token was exchanged from a PAT.
- `is:hmac-pat` — that PAT used the signed (HMAC) exchange, so its secret never crossed the wire.

A PAT never carries `is:2fa`. A rule like
`is:system-tenant-member + is:2fa, is:system-tenant-member + is:hmac-pat → switch:tenant` therefore
requires a second factor for sessions and the signed exchange for PATs.

## Alternatives considered

- **Reuse `switch:tenant` for service keys.** Rejected: `switch:tenant` follows system-tenant
  *membership*, and in the default config every system-tenant principal holds it. Machine keys
  would have reached every tenant without anyone deciding so.
- **An "act as" (`act`) claim and let the services interpret it.** Rejected for now: every product
  service would have to understand delegation, while a token scoped to the target tenant works
  with the existing `tenant` check unchanged.
- **Per-tenant credentials only.** Works without code changes, but scales with the number of
  tenants and is exactly the secret sprawl this removes.

## Consequences

- A system-tenant PAT or opted-in service key becomes a **master key** for all tenants. Mitigations:
  short token lifetimes, revocation (delete the key, deactivate or `tokenVersion`-bump the user),
  the audit trail in every target tenant, and hardening the rule with `is:hmac-pat` / `is:2fa`.
- **The default config is unchanged:** a system-tenant member's PAT can switch tenants right away.
  Deployments that want the stricter rule above have to write it.
- **Product services need no change**, beyond trusting umami as issuer and having an API (audience)
  entry with the permissions they check (for dbx: `write:blocks`, `write:assets`).
- **Tenant IDs matter:** the token's `tenant` is the umami tenant id. A service that already holds
  data under some tenant key needs the umami tenant to carry the same id.
