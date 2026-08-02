# umami — API keys (machine-to-machine & frontend) — design (authoritative)

An **API key** is a credential a client exchanges for a short-lived access token (JWT) —
OAuth2 `client_credentials` in spirit. umami offers **three auth modes**; a customer picks per
integration based on what they can run and how much protection they need.

## Honest framing

A secret that reaches a **browser** is not secret — anyone who opens the page can read it. So the
question is never "how do I hide a frontend key" (impossible) but "how much do I cap the damage".
The three modes trade off *where the secret lives* against *client complexity*:

| Mode | Secret lives | Stops | Does **not** stop | Use when |
|------|--------------|-------|-------------------|----------|
| **1. Key + Origin** | in the browser (semi-public) | casual browser reuse ("embed in another site") | key extraction + replay from a script | no backend; **quota-bounded / low-value** |
| **2. Signed (HMAC)** | client-side, **never transmitted** | secret on the wire; request replay (with nonce) | someone reading the secret *out of frontend JS* | client can compute HMAC; **backend/native** client, or keep secret off the wire |
| **3. BFF** | **server-side only** | essentially everything (key never in browser) | — | any backend exists; **high value** |

**Rule of thumb:** backend available → **Mode 3**. No backend but a real (non-browser) client that
can HMAC → **Mode 2**. Plain static frontend with quota-bounded cost → **Mode 1** (+ hard quota).

## Common core (all modes)

- Key format `umk_<keyId>_<secret>`: `umk_` prefix (secret-scanner detection), `keyId` (O(1)
  lookup / table PK), high-entropy `secret` (≥32 bytes), shown **once** at creation.
- Stored: only `sha256(secret)` (base64), constant-time compared.
- A successful exchange issues a **short-lived access token** (JWT): `sub = keyId`,
  `kind: "api_key"`, `tenant` + `permissions` resolved from the key's `roles` via the config
  catalog — same claims as a user token. **No session / no cookie**; the client re-exchanges when
  the JWT expires.
- Table `api-keys` (PK `keyId`, GSI `ByTenantIndex`), CRUD returns the secret once.
- **Revocation** = delete the key row → bites at the next exchange (already-issued JWTs live until
  `exp`, by design). **Rate-limit** the exchange; track `lastUsedAt`.
- **The real cost cap is the tenant/key quota** (the entitlements/limits layer): even a leaked key
  can only burn up to the quota. Modes 1 and 2 *depend* on this; Mode 3 benefits from it too.

## Mode 1 — API key + Origin allowlist (frontend-pragmatic)

The key sits in frontend JS (e.g. an app embedded in a shop `iframe`). Accepted as a
**semi-public, quota-bounded** credential — the Google Maps / Firebase web-key profile.

- `POST /auth/token { apiKey }`; the browser attaches an unspoofable `Origin` header.
- The key carries `allowedOrigins: [..]`; umami rejects an exchange whose `Origin` isn't listed →
  stops "someone embeds my key in *their* site" (browser attackers can't forge `Origin`).
- ❗ **Not a boundary:** an extracted key replays from curl with a forged `Origin`. Therefore Mode 1
  **requires** a hard tenant/key **quota + rate-limit** — that is what actually caps the cost.
- Use **`Origin`, not `Referer`** (Referer is suppressible by `Referrer-Policy`/privacy tools and
  leaks the path). Note the iframe subtlety: the fetch's `Origin` is the *app's* origin, not the
  embedding shop's. Restricting *which shop may embed the app* is a separate mechanism — CSP
  `frame-ancestors` on the app, not the key.

## Mode 2 — Signed request (HMAC proof-of-possession)

The secret is used to **sign**, never sent. Request carries `keyId`, `timestamp`, `nonce`, and
`mac = HMAC-SHA256(secret, "<keyId>.<timestamp>.<nonce>")`.

- umami: look up `keyId` → `secret` → recompute the HMAC and constant-time compare; require
  `|now − timestamp| ≤ ~120s`; reject a reused `nonce` (short-TTL nonce cache — a `nonces` table
  with a DynamoDB TTL). On success, issue the JWT as usual.
- Prefer **HMAC-SHA256**. HMAC-SHA1 is still sound *as a MAC* (SHA-1's collision weakness doesn't
  break HMAC), so it's acceptable, but SHA-256 is the modern default — pick it unless a client is
  constrained.
- **Where it shines:** backend / native clients — the secret never transits (safe against proxy/log
  capture) and requests can't be replayed. **Caveat for frontends:** if the secret is in browser
  JS, Mode 2 still doesn't hide it from someone reading the source — it only protects the
  *transport*. In a browser, Mode 2 ≈ Mode 1 in real security; the quota remains the backstop.

## Mode 3 — BFF (recommended default when a backend exists)

The key lives **only** on a backend. The backend does the exchange (Mode 1 or 2) server-side and
hands the iframe a **short-lived scoped JWT** — never the key. A leak is then minutes-long and
quota-capped. Least code on the "dumb server" (hold key → POST over TLS → return JWT; umami hashes).

## Entity / endpoint additions

- `api-keys` gains optional `allowedOrigins: [String]` (Modes 1/2).
- Mode 2 adds a `nonces` table (PK `nonce`, DynamoDB TTL ~5 min) for replay protection, and the
  exchange accepts the signed form (`keyId`/`timestamp`/`nonce`/`mac`) in addition to the raw
  `apiKey`.
- Exchange enforces `allowedOrigins` (when set) and, for Mode 2, freshness + nonce.

## Endpoints

- `POST /auth/token` — exchange (raw key **or** signed form), rate-limited
- `POST /tenants/{id}/api-keys` (`write:members`/`admin:tenant`) — create; returns `umk_…` once,
  optionally with `allowedOrigins`, `roles`, `expiresAt`
- `GET /tenants/{id}/api-keys` — list (metadata only)
- `DELETE /tenants/{id}/api-keys/{keyId}` — revoke

## Deferred / not v1

- Promoting keys to full **service-account users** (profile, richer identity) — v1 keeps keys
  lightweight (tenantId + roles on the key).
- Per-key (not just per-tenant) quotas, if needed later.
