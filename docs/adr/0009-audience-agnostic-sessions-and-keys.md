# ADR 0009 — Audience-agnostic sessions and API keys

- **Status:** accepted
- **Date:** 2026-08-20

## Context

With umami minting tokens per target API (see
[ADR 0004 — token broker](0004-token-broker-per-api-audiences.md)), the first design pinned the
audience in several places and offered three minting paths:

1. **Login** took an optional `api`, and the **session recorded it** (`api_code`), so every
   `POST /auth/refresh` re-minted for that same audience.
2. **API-key exchange** (`POST /auth/token`): each key carried an allow-list `apis: [code,…]`
   (default `["umami"]`); `api` had to name one of them.
3. **User → downstream exchange** (`POST /auth/exchange { api }`): an RFC-8693-style exchange,
   authenticated by a held umami access token, to obtain a token for *another* API without a fresh
   login.

A login session, however, identifies a user and a device, not an API.

## Decision

Neither the session nor a key pins an audience; the caller names the target on each mint.

- **One operation for users:** `POST /auth/refresh?api=<code>` trades the refresh cookie for an
  access token for any API the user is eligible for (default `umami`) — for the first token and for
  every renewal alike. Login's `api` remains a convenience that returns the first access token in
  the same round-trip; the session does not remember it. A SPA holding tokens for several APIs calls
  `/auth/refresh?api=` once per API; concurrent calls are safe through the refresh grace window.
- **`POST /auth/exchange` is removed.** Path 1 covers what it did.
- **API keys lose their `apis` allow-list** (2026-08-22). `POST /auth/token { apiKey, api? }` picks
  the target from `api` (default `umami`), bounded only by the key's scopes and the API's
  eligibility.
- **Cross-site SPAs** (a different registrable domain, where `SameSite=Lax` withholds the cookie on
  a background `fetch`) are not served by a bearer-based exchange; they use the OIDC redirect flow,
  a top-level navigation that `Lax` does carry. Same-site subdomains use `/auth/refresh` directly
  with `credentials: "include"` and CORS.

## Alternatives considered

- **Session pins the audience at login** — the original design. Replaced: it ties a session to one
  API, and needed a second mechanism for every other API.
- **A separate user → downstream token exchange** (`/auth/exchange`, RFC-8693 style). Replaced by
  `?api=` on refresh, which does the same with the cookie the user already holds.
- **Per-key `apis` allow-list.** Dropped to mirror the audience-agnostic session; a key's reach is
  already bounded by its scopes and each API's eligibility.

## Consequences

- The user paths differ only in how the caller authenticates: refresh cookie vs. API key.
- Old session rows with `api_code` and old key rows with `apis` keep deserializing; the field is
  ignored.
- An API that must not be reachable by some key or user has to say so in its `eligibility`, not in
  the key.
- A deployment that puts umami on a different registrable domain than its apps relies on the
  redirect flow (see the deferred authorization code in `AUDIENCES.md`).
