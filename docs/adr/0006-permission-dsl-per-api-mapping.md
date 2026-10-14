# ADR 0006 — Permissions projected per API from subjects via an ordered rule DSL

- **Status:** accepted
- **Date:** 2026-08-09

## Context

umami mints JWTs for several APIs (audiences). Product code needs a stable thing to check, while
the policy of who may do what keeps changing. In the previous model, roles carried a `permissions`
list and tenant features were derived from billing packages, so authorization was spread over role
definitions and the billing axis.

This refines the per-API permission projection introduced with the token broker
(see [ADR 0004](0004-token-broker-per-api-audiences.md)).

## Decision

Authorization is a small ACL in which **code only ever checks permissions**:

- **Subjects** are labels with a prefix: `role:*` (users), `scope:*` (API service keys),
  `feature:*` (tenants) and computed `is:*` markers. They carry no meaning by themselves.
- **Permissions** are bare strings (`write:blocks`, `manage:config`). They exist only in the JWT
  `permissions` claim — never stored, never assigned directly.
- **The mapping lives only in config, per API**: each `apis` entry has an **ordered list** of
  `{ when, grant }` rules. Role, scope and feature definitions are labels only (`code`, `name`,
  `description?`, `assignableIf?`).
- **One condition grammar** everywhere: `,` = OR, `+` = AND, `!` = NOT; a term is a subject or a
  bare permission, evaluated by set membership.
- **Rules accumulate in order**: a rule's `when` is checked against subjects plus the permissions
  granted so far, so a later rule can reference a permission an earlier one granted
  (`role:admin → write:blocks`, then `write:blocks → read:blocks`).
- **Eligibility** per API is a condition over the final set; false means no token (403).
- **No `features` claim** in the token: everything the product needs is cooked into `permissions`.
- **`assignableIf` is the single source of dependency** for roles, scopes and features; there is no
  separate `requires` list.
- Tenant `features` are a flat, directly granted set. The billing axis no longer feeds the
  permission game; package→feature derivation for authorization is dropped.

## Alternatives considered

- **Rules as a map instead of an ordered list.** Not chosen: ordering is what makes chaining
  well-defined and author-controlled.
- **Roles carrying their own `permissions` list, features derived from packages** (the previous
  model). Superseded by this decision.

## Consequences

- Product code stays stable; the role/feature→permission policy evolves in config.
- "Which permissions land in the JWT for audience X" is explicit and per audience.
- Rule order matters: a rule can only reference permissions granted by rules above it.
- Products cannot read tenant features from the token; they must be mapped to permissions.
- Existing dev tables predating the namespaced labels had to be recreated.
