# ADR 0005 — Service keys and personal access tokens as one key entity

- **Status:** accepted
- **Date:** 2026-08-06

## Context

API keys originally always acted as themselves: the exchanged token had `sub = keyId` and the
key's own permissions. Three real use-cases need a credential that is exchanged for a short-lived
JWT:

1. A per-tenant service in the browser (an embedded app).
2. A CLI where a user drops in a key and expects it to act as *them*.
3. A real service authenticating as an app to umami itself — the client-credentials /
   service-account case.

The second one does not fit a key that acts as itself: it should carry the user's permissions and
die when the user is deactivated.

## Decision

A key has a **subject** — whose identity and permissions the exchanged token carries. This is
orthogonal to the auth modes (which are about *where the secret lives*). The `user_id` field on the
key discriminates two kinds:

- **Service key** (`user_id = None`) — acts as itself: `sub = keyId`, permissions from the key's
  `scopes`. Managed per tenant; revoked by deleting the key.
- **Personal access token (PAT)** (`user_id = Some(userId)`) — acts as the user: `sub = userId`,
  permissions from the **user**, intersected with the key's optional restriction, never an
  escalation. It carries `user.tokenVersion`, so deactivating the user or bumping `tokenVersion`
  also kills the PAT. Managed self-service by the user.

The three use-cases collapse to these two kinds:

1. Per-tenant browser service → service key with minimal scopes.
2. CLI → PAT, optionally down-scoped.
3. Service-to-umami → a **service key owned by the system tenant**, server-side secret, with the
   elevated scopes it needs. No separate service-account entity type.

Both kinds share the key format, the `api-keys` table and the single exchange endpoint
`POST /auth/token`; only `sub` and permission resolution differ. A PAT is still exchanged for a
short-lived JWT, so product services never see it.

## Alternatives considered

- **A separate entity type for service accounts.** Not introduced: a system-tenant service key
  already covers the client-credentials case. Promoting keys to full service-account users
  (profile, richer identity) is deferred.

## Consequences

- One code path for storage and exchange; the exchange branches on the subject. A PAT loads the
  user fresh, so user deactivation bites at the next exchange.
- PATs can never exceed their user's permissions; down-scoping is the only adjustment.
- Per-key settings that are tenant decisions (e.g. a per-key rate-limit override, a per-key token
  lifetime) apply to service keys only; PATs, created self-service, use the global values.
- Acting in another tenant builds on this split, with different rules per subject kind — see
  [ADR 0001](0001-cross-tenant-token-exchange.md).
