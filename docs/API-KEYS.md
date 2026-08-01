# umami — API Keys (machine-to-machine) — design (authoritative)

Machine-to-machine authentication: an **API key** is a long-lived credential for a **confidential
(server-side) client** that exchanges it for a short-lived access token (JWT). In spirit this is
OAuth2 `client_credentials`.

## Golden rule: API keys are server-side only

- **Never put an API key in a browser/SPA/mobile-JS.** A public client cannot keep a secret; a key
  in JS is readable by anyone (view-source, devtools, network tab).
- **Client-side hashing does NOT help.** Computing `hash(key + timestamp)` in JS still requires the
  key to be *in* the JS — an attacker who reads the page has the key and can mint their own hashes.
  Hashing hides the key from network logs, not from whoever loaded the page.

## A browser needs to call product services? Two correct options

1. **Authenticate as a user** — the SPA uses umami's normal login (password/MFA → in-memory access
   token + `HttpOnly` refresh cookie). This is the default for browser apps; no API key involved.
2. **Backend-for-Frontend (BFF)** — the key lives **only** on a backend; the backend exchanges it
   for a JWT server-side and hands the **short-lived JWT** (never the key) to the JS. Leaking a
   ~10-minute scoped JWT is far less damaging than leaking a long-lived key. The BFF is *less* work
   than client-side crypto: hold the key in env → POST it to umami over TLS → return the JWT. No
   hashing on that server — umami does it.

## The exchange (token endpoint)

- `POST /auth/token` body `{ "apiKey": "umk_<keyId>_<secret>" }` → `{ accessToken, expiresIn }`.
- The **raw key over TLS** is fine — the caller is a trusted backend, the exchange is infrequent
  (once per JWT lifetime), and it goes to a single endpoint. umami stores only `sha256(secret)`,
  splits out `keyId` → `GetItem` → constant-time compares.
- Issues **only an access token** — no refresh cookie, no `sessions` row. The API key *is* the
  long-lived credential; the client re-exchanges when the JWT expires.
- JWT claims identical to a user token: `iss`, `aud`, `tenant`, `permissions`, `iat`, `exp`, with
  `sub = keyId` (a valid 32-char id) and `kind: "api_key"` to distinguish it. Permissions resolve
  from the key's `roles` via the **config catalog** — same machinery as users.

Product services see no difference between a human and a machine token; they check `tenant` +
`permissions` only.

## Key format & storage

- Format `umk_<keyId>_<secret>`:
  - `umk_` prefix → secret-scanning tools (GitHub/GitLab) detect leaks automatically.
  - `keyId` → O(1) lookup (table PK); no hash-scan across all keys.
  - `secret` → high-entropy (≥32 bytes), shown **once** at creation.
- Stored: only `sha256(secret)` (base64), constant-time compared. High-entropy random secrets don't
  need argon2 (that's for low-entropy human passwords).

## Entity — table `api-keys` (+ GSI `ByTenantIndex`)

- **PK** `keyId` (32-char generated id)
- `tenantId` → **GSI `ByTenantIndex`** (list a tenant's keys)
- `secretHash` (sha256, base64)
- `roles: [code]` → permissions resolved via config
- `name` (label), `status` (`Active` | `Revoked`)
- `expiresAt?` (optional), `lastUsedAt?`, `created`

## Endpoints

- `POST /auth/token` — the exchange (rate-limited; see below)
- `POST /tenants/{id}/api-keys` (`write:members`/`admin:tenant`) — create; returns the full
  `umk_…` string **once** (never retrievable again)
- `GET /tenants/{id}/api-keys` — list (metadata only, never the secret)
- `DELETE /tenants/{id}/api-keys/{keyId}` — revoke (delete the row)

## Security

- **Revocation** = delete the key row → bites at the next exchange (same 5–15 min offline-verify
  latency as everything; already-issued JWTs remain valid until `exp`, by design).
- **Rate-limit** `/auth/token` per-key + per-IP (brute force).
- Track `lastUsedAt` for hygiene; support optional `expiresAt` + rotation (create new, revoke old).
- **Never log** the key or the secret.

## Deferred / not v1

- **Proof-of-Possession** variant (`keyId + HMAC-SHA256(key, timestamp+nonce)` with freshness +
  nonce replay protection) — only worthwhile if a *backend* client must never transmit the secret
  even over TLS. Use real HMAC (not `sha256(key‖ts)`, which is length-extension-prone). Not needed
  for v1.
- Promoting keys to full **service-account users** (profile, richer identity) — v1 keeps keys
  lightweight (tenantId + roles directly on the key).
