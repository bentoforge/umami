# ADR 0004 — umami as a token broker with per-API audiences

- **Status:** accepted
- **Date:** 2026-08-04

## Context

umami issued tokens for itself only. The audience was a single deployment-wide value
(`UMAMI_DEFAULT_AUDIENCE`), and the extra claims came from one top-level `tokenClaims` mapping that
applied to every token.

The product services in the fleet each need tokens with their own `aud`, their own permissions and
their own claims — which one deployment-wide audience and claim mapping cannot express.

## Decision

umami becomes a **token broker**: it mints tokens not only for itself but for any target API in the
fleet. Every target API is declared in the config `apis` catalog as an `ApiDef` with:

- a `code` (the internal id callers name) and an `audience` (the token's `aud`);
- an optional **eligibility** gate — a boolean expression over the requester's permissions and
  features; when it does not hold, minting is `403`;
- a **permission projection** — rules that map the requester's permissions and features to the
  permissions that API understands;
- a **claim mapping** — `claimName → source`, where a source is a literal or a reference into the
  user or tenant.

Expressions use one small DSL (`,` = OR, `+` = AND) evaluated against the requester's set of
permissions and features.

**One token = one audience** — a JWT has one `aud`. A caller that talks to several APIs holds one
token per API. Every minting path resolves the target `ApiDef`, checks eligibility, projects the
permissions, applies the claim mapping and mints with `aud = api.audience`.

umami's own admin API is just one entry in the catalog (`code: "umami"`), and the default target
when a caller names none.

## Consequences

- **Config:** `apis: [ApiDef]` is added; the default config ships the `umami` API, with the old
  `tokenClaims` behaviour folded into its `claims`. The top-level `tokenClaims` is superseded by
  per-API `claims`, and `UMAMI_DEFAULT_AUDIENCE` by the `umami` API's `audience`.
- **Token issuance:** `aud` is per call, taken from the resolved API, instead of fixed.
- The shape of the permission projection (rule format, grammar, subjects) was reworked afterwards;
  see [ADR 0006 — permission DSL](0006-permission-dsl-per-api-mapping.md).
- **Deferred:** `perm:`/`feat:` namespacing in the DSL to disambiguate name collisions, per-API rate
  limits, and audience-scoped restrictions on API-key creation.
