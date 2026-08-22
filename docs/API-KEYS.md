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
| **1. Key + Origin** | in the browser (semi-public) | casual browser reuse ("embed in another site") | key extraction + replay from a script | no backend; **rate-limited / low-value** |
| **2. Signed (HMAC)** | client-side, **never transmitted** | secret on the wire (proxy/log capture) | someone reading the secret *out of frontend JS*; replay within the ~±1 h window | client can compute HMAC; **backend/native** client, or keep secret off the wire |
| **3. BFF** | **server-side only** | essentially everything (key never in browser) | — | any backend exists; **high value** |

**Rule of thumb:** backend available → **Mode 3**. No backend but a real (non-browser) client that
can HMAC → **Mode 2**. Plain static frontend with low-value cost → **Mode 1** (+ strict rate-limit).

## Two subject kinds (who the token acts as)

Orthogonal to the modes above (which are about *where the secret lives*), a key has a **subject** —
whose identity/permissions the exchanged token carries. The `user_id` field on the key discriminates:

| Kind | `user_id` | Token `sub` | Permissions from | Managed at | Revocation |
|------|-----------|-------------|------------------|-----------|------------|
| **Service key** | `None` | `keyId` | the key's `scopes` | `/tenants/{id}/api-keys` (`manage:service-keys`) | delete the key |
| **Personal access token (PAT)** | `Some(userId)` | `userId` | the **user** (∩ the key's optional `roles` restriction, never an escalation), carries `user.tokenVersion` | `/auth/me/api-keys` (`manage:pat`, self-service) | delete the key **or** deactivate / `tokenVersion`-bump the user |

Mapping the real use-cases:

1. **Per-tenant service in the browser** → *service key*, Mode 1 (origins + rate-limit). The key is a
   tenant machine principal with minimal `scopes`.
2. **CLI where a user drops in a key** → *PAT*. Acts as that user, optionally down-scoped; dies when
   the user is deactivated. The CLI exchanges it for a short-lived JWT like everything else.
3. **A real service authenticating as an app to umami itself** → *service key owned by the system
   tenant*, Mode 3 (server-side secret, no origins), with the elevated `scopes` it needs. That is the
   client-credentials / service-account case — no separate entity type.

Both kinds share the key format, the `api-keys` table, and the single exchange endpoint below; only
`sub` + permission resolution differ.

## Common core (all modes)

- Key format `umk_<keyId>_<secret>`: `umk_` prefix (secret-scanner detection), `keyId` (O(1)
  lookup / table PK), high-entropy `secret` (≥32 bytes), shown **once** at creation.
- Stored: only `sha256(secret)` (base64), constant-time compared.
- A successful exchange issues a **short-lived access token** (JWT), `kind: "api_key"`, `tenant` +
  `permissions` via the config catalog — same claims as a user token. The target audience is chosen
  by the optional `api` parameter on the exchange (default `umami`). `sub` and the permission
  source depend on the subject kind (see above): service key → `sub = keyId`, perms from the key's
  `scopes`; PAT → `sub = userId`, perms from the user (∩ the key's `roles` restriction). **No session
  / no cookie**; the client re-exchanges when the JWT expires.
- Table `api-keys` (PK `keyId`, GSI `ByTenantIndex`), CRUD returns the secret once.
- **Revocation** = delete the key row → bites at the next exchange (already-issued JWTs live until
  `exp`, by design). **Rate-limit** the exchange; track `lastUsedAt`.
- **The real cost cap is rate-limiting** the exchange and the downstream API: even a leaked key can
  only burn what the rate limits allow. Modes 1 and 2 *depend* on this; Mode 3 benefits from it too.

## Mode 1 — API key + Origin allowlist (frontend-pragmatic)

The key sits in frontend JS (e.g. an app embedded in a shop `iframe`). Accepted as a
**semi-public, rate-limited** credential — the Google Maps / Firebase web-key profile.

- `POST /auth/token { apiKey }`; the browser attaches an unspoofable `Origin` header.
- The key carries `allowedOrigins: [..]`; umami rejects an exchange whose `Origin` isn't listed →
  stops "someone embeds my key in *their* site" (browser attackers can't forge `Origin`).
- ❗ **Not a boundary:** an extracted key replays from curl with a forged `Origin`. Therefore Mode 1
  **requires** a strict **rate-limit** — that is what actually caps the cost.
- Use **`Origin`, not `Referer`** (Referer is suppressible by `Referrer-Policy`/privacy tools and
  leaks the path). Note the iframe subtlety: the fetch's `Origin` is the *app's* origin, not the
  embedding shop's. Restricting *which shop may embed the app* is a separate mechanism — CSP
  `frame-ancestors` on the app, not the key.

## Mode 2 — Signed request (HMAC proof-of-possession)

The secret is used to **sign**, never sent. Request carries `keyId` + `mac`:

```
mac = base64url( HMAC-SHA256( key = SHA-256(secret), "umami:apikey:<keyId>:<hourBucket>" ) )
hourBucket = floor(unixSeconds / 3600)
```

- **The HMAC key is `SHA-256(secret)` — exactly the digest umami already stores.** So the client
  derives it from its secret, and the server verifies with the stored hash: no raw secret on the
  wire *and* none kept at rest. (`verify_key_hmac` in `auth/apikeys`.)
- umami recomputes the MAC for the current hour and **±1 hour** (clock-skew / boundary tolerance),
  constant-time compares, and on a match issues the JWT as usual. The message binds the `keyId`, so
  a MAC for one key can't be replayed against another.
- Prefer **HMAC-SHA256** (the modern default).
- **Where it shines:** backend / native clients — the secret never transits (safe against proxy/log
  capture). **Tradeoff:** a captured MAC is **replayable within its ~±1 h window**; TLS plus the
  narrow window bound the exposure. **Caveat for frontends:** if the secret lives in browser JS,
  Mode 2 still doesn't hide it from someone reading the source — it only protects the *transport*;
  rate-limiting remains the backstop.

## Mode 3 — BFF (recommended default when a backend exists)

The key lives **only** on a backend. The backend does the exchange (Mode 1 or 2) server-side and
hands the iframe a **short-lived scoped JWT** — never the key. A leak is then minutes-long and
rate-limited. Least code on the "dumb server" (hold key → POST over TLS → return JWT; umami hashes).

## Entity / endpoint additions

- `api-keys` carries optional `allowedOrigins: [String]` (Modes 1/2) and `allowSecretLogin: bool`
  (default **false**): whether the raw-secret exchange (Mode 1) is accepted at all. When off, the
  key is **HMAC-only** (Mode 2) — a raw-secret exchange is refused even with the correct secret.
- The exchange accepts either the raw `apiKey` (Mode 1, only if `allowSecretLogin`) **or** the
  signed form `keyId` + `mac` (Mode 2) — see above.
- Exchange enforces `allowedOrigins` (when set) and `allowSecretLogin`.

## Endpoints

- `POST /auth/token` — exchange (raw key **or** signed form), rate-limited
- `POST /tenants/{id}/api-keys` (`manage:service-keys`) — create; returns `umk_…` once,
  optionally with `allowedOrigins`, `scopes`, `expiresAt`
- `GET /tenants/{id}/api-keys` — list (metadata only)
- `DELETE /tenants/{id}/api-keys/{keyId}` — revoke

## Deferred / not v1

- Promoting keys to full **service-account users** (profile, richer identity) — v1 keeps keys
  lightweight (tenantId + scopes on the key).
- Per-key (not just per-tenant) rate limits, if needed later.
