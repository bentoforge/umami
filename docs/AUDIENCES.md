# umami — Audiences & token projection (authoritative)

umami is a **token broker**: it mints tokens not only for itself but for any target API in the
fleet, each with its own `aud`, eligibility gate, permission projection and claim mapping — all
defined in the config `apis` catalog.

## The `apis` catalog (config)

```jsonc
apis: [
  { "code": "umami", "audience": "umami", "passthrough": true,
    "claims": { "features": "features" } },        // the umami admin API (current behaviour)

  {
    "code": "dbx-core",
    "audience": "dbx-core",                          // → the token's `aud`
    "eligibility": "member,admin",                   // must be true, else 403
    "permissions": {                                 // rule map: expression → injected permissions
      "admin:tenant":               ["admin:blocks", "admin:assets", "write:blocks"],
      "write:members+admin:tenant": ["manage:team"],
      "write:blocks":               ["write:blocks"],
      "ai":                         ["use:ai"]       // feature-based
    },
    "claims": {                                      // claim mapping for this audience
      "svc":      "dbx-core",                        // static literal
      "features": "features",                        // effective feature codes (array)
      "dept":     "customUser:department"            // project a custom user field
    }
  }
]
```

Each `ApiDef`:
- **`code`** — internal id (referenced by API keys and the exchange call).
- **`audience`** — the `aud` claim written into tokens minted for this API.
- **`passthrough`** *(optional, default false)* — if true, the token carries the requester's own
  role-derived permissions verbatim (the `permissions` map is ignored). Used for the `umami` API.
- **`eligibility`** *(optional)* — a boolean expression that must hold, else the exchange is `403`.
- **`permissions`** — rule map, `expression → [permission,…]`; the token's permissions are the
  **union** of the outputs of all rules whose expression matches.
- **`claims`** *(optional)* — `claimName → source` (see below).

## The mini-DSL

- `,` = **OR** (low precedence), `+` = **AND** (high). So `"a,b+c"` = `a OR (b AND c)`.
- Terms are matched against the requester's set **S = permissions ∪ features** (bare names).
  *(Optional future `perm:`/`feat:` prefixes to disambiguate collisions.)*
- Evaluation: `expr.split(',').any(clause => clause.split('+').all(term => S.has(term)))`.

## Claim sources

| Source string | Value written |
|---|---|
| `"features"` | array of the tenant's effective feature codes |
| `"customUser:<key>"` | the user's custom field `<key>` (if present) |
| `"customTenant:<key>"` | the tenant's custom field `<key>` (if present) |
| anything else | the literal string |

Machine tokens (API-key exchange) additionally carry `kind: "api_key"`.

## The exchange paths

All resolve the target `ApiDef`, evaluate eligibility against the requester's S, project the
permissions, apply the claim mapping, and mint a token with `aud = api.audience`. **One token = one
audience** (a JWT has one `aud`).

1. **Login, minting directly** — `POST /auth/login { …, api? }` (and passkey login
   `POST /auth/webauthn/login/finish { …, api? }`). When a user works mostly against one product
   API, `api` mints the access token for it right away — no follow-up `/auth/exchange` round-trip.
   The **session records `api_code`**, so `POST /auth/refresh` keeps re-minting for the same
   audience. `api` defaults to `"umami"` (the admin API). Ineligibility fails the login (403) before
   a session is created.

2. **API-key exchange** — `POST /auth/token { apiKey, api? }`. A key carries `apis: [code,…]` (the
   set it may mint for; default `["umami"]`). `api` selects one of them (required when the key
   allows more than one; a not-allowed `api` is 403). The requester's S comes from the key's roles
   (+ its tenant's effective features). Machine tokens also carry `kind: "api_key"`.

3. **User → downstream exchange** — `POST /auth/exchange { api }`, authenticated by the caller's
   umami access token. Lets an already-logged-in user/SPA obtain a token for *another* product API
   without a fresh login. Does **not** touch the session or the stored umami token. The requester's
   S comes from the user's roles (+ tenant features). (RFC-8693-style token exchange.)

Use path 1 when the SPA targets one API; path 3 when a umami-admin session occasionally needs a
downstream token too.

## Worked example

Key targets `dbx-core`; its roles resolve to `{member, write:blocks}`; its tenant has feature
`{ai}` → **S = {member, write:blocks, ai}**.

- Eligibility `member,admin`: `member ∈ S` → **eligible**.
- Projection: `write:blocks → [write:blocks]` ✓, `ai → [use:ai]` ✓ (others don't match)
  → **permissions = {write:blocks, use:ai}**.
- Token: `aud=dbx-core`, `permissions=[write:blocks,use:ai]`, `svc=dbx-core`, `features=[ai]`,
  `dept=<user.customFields.department>`.

## What changes

- **config**: add `apis: [ApiDef]`; the default config ships the `umami` API (`passthrough`, with
  the old `tokenClaims` behaviour folded into its `claims`). The top-level `tokenClaims` is
  superseded by per-API `claims`.
- **api-keys**: add `apis: [code]` (allowed targets; default `["umami"]`).
- **token issuance**: `aud` is now per-call (from the resolved API). `login`/`refresh` mint for the
  `umami` API. API-key exchange mints for the key's chosen API. New `POST /auth/exchange` mints a
  downstream token for the authenticated user.
- **`UMAMI_DEFAULT_AUDIENCE`** env is superseded by the `umami` API's `audience` in config.

## Deferred

- `perm:`/`feat:` namespacing in the DSL; per-API rate limits; audience-scoped API-key creation
  restrictions.
