# ADR 0007 — Roles for users, scopes for service keys, role restriction for PATs

- **Status:** accepted
- **Date:** 2026-08-09

## Context

Three kinds of principal obtain tokens from umami: users (interactive sessions), API service keys
(machine-to-machine, no user) and personal access tokens (PATs), which belong to a user. All of
them need a set of subject labels that the per-API permission rules
(see [ADR 0006](0006-permission-dsl-per-api-mapping.md)) map to permissions.
The split into service keys and PATs itself is recorded in
[ADR 0005](0005-service-keys-and-personal-access-tokens.md); this ADR fixes which subject labels
each kind carries.

## Decision

- **Users carry `role:*`, service keys carry `scope:*`.** Both have identical mechanics (a label
  mapped to permissions) but are **kept separate on purpose**, so that M2M tokens can be granted
  capabilities no user role ever maps to — e.g. a bot-backend service key getting
  `messaging:link` / `messaging:resolve`, which no `role:*` grants, so no human can hold them.
- **PATs act as their user**, so they carry `role:*`, not scopes, and take no scopes.
- **A PAT keeps an optional role-level restriction**: a `role:*` list; its effective roles are
  `user.roles ∩ pat.roles`, and an empty list means the user's full roles. This is a subject-level
  down-scope, distinct from M2M scopes.
- Scopes are assignable to a key exactly like roles to a user: via `assignableIf` against the
  tenant's feature set.

## Consequences

- Storage differs by key kind: a service key (`user_id = None`) stores `scopes`, a PAT
  (`user_id = Some`) stores a `roles` restriction.
- A PAT can never exceed its user's roles; it can only narrow them.
- Machine-only permissions can be expressed in config by mapping only `scope:*` subjects to them.
