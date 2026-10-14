# ADR 0008 — System tenant expressed via the `is:system-tenant` marker

- **Status:** accepted
- **Date:** 2026-08-09

## Context

Some umami routes act across tenants (`GET/POST /tenants`, `DELETE /tenants/{id}`) and must only be
reachable from the system tenant, configured as `UMAMI_SYSTEM_TENANT_ID`. Until this decision they
were protected by an interim, env-based guard in the route handlers (`enforce_system_tenant`),
outside the permission model. This decision folds in what was tracked as "Schritt 2".

## Decision

- The mint layer adds the synthetic marker **`is:system-tenant`** to the subject set when the
  token's tenant is `UMAMI_SYSTEM_TENANT_ID`. Like all `is:*` markers it is computed at token-issue
  time, never stored, and not grantable or revocable.
- The `umami` API's permission rules map the marker to cross-tenant permissions (initially
  `admin:system`; today `manage:tenants` and `switch:tenant`).
- The cross-tenant routes check **those permissions**. The env-based `enforce_system_tenant` guard
  is removed; there is no tenant guard in the route handlers.

## Consequences

- The system-tenant rule is config-expressed and travels in the token, like every other
  authorization decision.
- The marker can be combined with other subjects in rules and assignability conditions, e.g.
  `scope:messaging-linker + is:system-tenant → messaging:link`, or a scope that is only
  `assignableIf: "is:system-tenant"`.
- Which permissions the system tenant gets is a deployment's config choice, not code.
- Cross-tenant tokens for system principals build on this marker; see
  [ADR 0001](0001-cross-tenant-token-exchange.md).
