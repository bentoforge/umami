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

## The minting paths

All resolve the target `ApiDef`, evaluate eligibility against the requester's S, project the
permissions, apply the claim mapping, and mint a token with `aud = api.audience`. **One token = one
audience** (a JWT has one `aud`). The two user paths differ only in *how the caller authenticates* —
by refresh cookie vs. by API key.

1. **Cookie → access token** — `POST /auth/refresh?api=<code>`, authenticated by the `HttpOnly`
   refresh cookie. This is the one operation a logged-in user (or their same-site SPA) uses to obtain
   an access token, whether it's the *first* one for an API or a *renewal* of an expired one — the
   session is **audience-agnostic**, so the same cookie mints for any API the user is eligible for.
   `api` defaults to `"umami"` (the admin API); an ineligible `api` is `403`. `POST /auth/login
   { …, api? }` (and passkey `POST /auth/webauthn/login/finish { …, api? }`) is just the convenience
   of setting the cookie *and* handing back that first access token in one round-trip; the session
   does **not** remember `api`. To hold tokens for several APIs at once, a SPA simply calls
   `/auth/refresh?api=` once per API — concurrent calls are safe (see the refresh grace window).

2. **API-key exchange** — `POST /auth/token { apiKey, api? }`. `api` picks the target audience
   (default `umami`); a key is not pinned to an audience, so the requested one is bounded only by
   the key's scopes + the API's eligibility (an ineligible `api` is 403). The requester's S comes
   from the key's roles (+ its tenant's effective features). Machine tokens also carry
   `kind: "api_key"`. No cookie, no session — this is the machine/BFF path.

> **Cross-*site* SPAs** (a product SPA on a genuinely different registrable domain, where
> `SameSite=Lax` withholds the umami cookie on background `fetch`) are **not** served by a
> bearer-based token exchange in v1; they use the enterprise **OIDC redirect** flow (a top-level
> navigation, which `Lax` does carry). Same-*site* subdomains (`spa.myapp.com` → `iam.myapp.com`)
> use path 1 directly with `fetch(..., { credentials: "include" })` + CORS.

## Worked example

A key requests `api=dbx-core`; its roles resolve to `{member, write:blocks}`; its tenant has feature
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
- **token issuance**: `aud` is now per-call (from the resolved API). `login`, `refresh`, and
  API-key exchange all mint for the requested `api` (default `umami`); neither the session nor a
  key pins an audience.
- **`UMAMI_DEFAULT_AUDIENCE`** env is superseded by the `umami` API's `audience` in config.

## Deferred

- `perm:`/`feat:` namespacing in the DSL; per-API rate limits; audience-scoped API-key creation
  restrictions.
