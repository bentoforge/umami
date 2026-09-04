# umami — Audiences & token projection (authoritative)

umami is a **token broker**: it mints tokens not only for itself but for any target API in the
fleet, each with its own `aud`, eligibility gate, permission projection and claim mapping — all
defined in the config `apis` catalog.

## The `apis` catalog (config)

```jsonc
apis: [
  { "code": "umami", "audience": "umami",
    "claims": { "features": "$tenant.features" } },  // the umami admin API

  {
    "code": "dbx-core",
    "audience": "dbx-core",                          // → the token's `aud`
    "eligibility": "role:member,role:admin",         // must hold, else 403
    "permissions": [                                 // ORDERED list; later rules see earlier grants
      { "when": "admin:tenant", "grant": ["admin:blocks", "admin:assets", "write:blocks"] },
      { "when": "write:members+admin:tenant", "grant": ["manage:team"] },
      { "when": "feature:ai", "grant": ["use:ai"] }
    ],
    "claims": {                                      // claim mapping for this audience
      "svc":      "dbx-core",                        // static literal (no `$`)
      "features": "$tenant.features",                // effective feature codes (array)
      "dept":     "$user.custom.department"          // project a custom user field
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

A source is either a **literal string** or a **`$` reference**. The `$` is what makes the
difference, and forgetting it used to fail silently — `"tenant.features"` wrote those very words into
the token instead of the array. `PUT /config` now refuses both that and an unknown `$…` reference.

| Source string | Value written |
|---|---|
| `"$user.id"` / `.username` / `.title` / `.salutation` / `.firstname` / `.lastname` | that field, omitted when absent |
| `"$user.email"` | the preferred **confirmed** address, omitted when there is none. Costs one read, and only for an API that asks |
| `"$user.name"` / `.fullName` / `.addressableName` | the server-composed display names |
| `"$user.locale"` | the resolved language (BCP-47) |
| `"$user.roles"` | the user's role codes (array) |
| `"$tenant.id"` / `.name` / `.slug` | that field |
| `"$tenant.features"` | the tenant's effective feature codes (array) |
| `"$user.custom.<code>"` / `"$tenant.custom.<code>"` | that custom field, omitted when absent |
| anything without a leading `$` | the **literal string** |

A user record carries no address of its own — `$user.email` resolves through the contacts list (see
[CONTACTS.md](CONTACTS.md) §6).

### What is always in a token, mapping or not

`iss`, `sub`, `aud`, `tenant`, `permissions`, `iat`, `exp` and `ver` (the `tokenVersion` snapshot) are
hardcoded. Three more appear conditionally: `kind` (`"api_key"` on a key exchange, `"messaging"` on a
chat resolve), `amr` (the second factors a session used — `["passkey"]`, `["totp"]`, or both), and
`locale` — see below.

**Everything else comes from the mapping**, so a deployment that maps nothing gets exactly that list.
In particular umami puts no personal data in a token by default.

### `locale` — the one profile field that self-emits

`locale` is the exception to "personal data only via the mapping". A user who has **chosen** a
language (an explicit profile `locale`, not "automatic") gets it as the standard OIDC `locale` claim
in every token, whether or not the API maps `$user.locale` — their stated preference is meant to
travel, honoured by downstream services and by umami's own re-reads without a second lookup.

A user on **automatic** (no profile language) is deliberately left claim-less. wasabi's authenticator
then negotiates the language from each request's `Accept-Language` against the deployment's supported
set — so it tracks the browser instead of freezing a login-time guess into the token. An API that
maps `locale` itself (via `$user.locale` or a literal) still wins; the self-emit only fills the gap.

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
> the default `SameSite=Lax` withholds the umami cookie on background `fetch`; `UMAMI_COOKIE_SAMESITE=none`
> makes it third-party, which Safari blocks outright) are **not** served by a
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
- An **authorization code** for `GET /auth/authorize`. The redirect itself exists (hosted login,
  `security.redirectUris`), but it hands back only control, not a credential: umami is deployed
  next to the apps it serves, so the browser carries the refresh cookie across the redirect and the
  app refreshes normally. A code (plus its table, TTL, single-use enforcement, reuse detection and
  PKCE) becomes necessary only for a deployment that puts umami on a *different registrable domain*
  than the app.
