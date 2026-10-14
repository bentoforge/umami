# umami — Audiences & token projection (authoritative)

umami is a **token broker**: it mints tokens not only for itself but for any target API in the
fleet, each with its own `aud`, eligibility gate, permission projection and claim mapping — all
defined in the config `apis` catalog.

Related decisions:
- [ADR 0004 — umami as a token broker with per-API audiences](adr/0004-token-broker-per-api-audiences.md)
- [ADR 0009 — Audience-agnostic sessions and API keys](adr/0009-audience-agnostic-sessions-and-keys.md)

## The `apis` catalog (config)

```jsonc
apis: [
  { "code": "umami", "audience": "umami",
    "claims": { "features": "$tenant.features" } },  // the umami admin API

  {
    "code": "catalog",
    "audience": "catalog",                          // → the token's `aud`
    "eligibility": "role:member,role:admin,role:owner", // must hold, else 403
    "permissions": [                                 // ORDERED list; later rules see earlier grants
      { "when": "role:admin,role:owner", "grant": ["write:blocks", "read:blocks"] },
      { "when": "role:member", "grant": ["read:blocks"] },
      { "when": "feature:ai + role:member", "grant": ["use:ai"] },
      { "when": "write:blocks + feature:ai", "grant": ["generate:blocks"] }  // sees rule 1's grant
    ],
    "claims": {                                      // claim mapping for this audience
      "svc":      "catalog",                        // static literal (no `$`)
      "features": "$tenant.features",                // effective feature codes (array)
      "dept":     "$user.custom.department"          // project a custom user field
    }
  }
]
```

Each `ApiDef`:
- **`code`** — internal id, named by the `api` parameter at login, refresh and key exchange.
- **`audience`** — the `aud` claim written into tokens minted for this API.
- **`eligibility`** *(optional)* — an expression that must hold, else the mint is `403`. It is
  evaluated **after** the projection, against the subjects plus the permissions just granted.
- **`permissions`** — an **ordered** list of `{ when, grant }` rules. They fire top to bottom: each
  `when` is evaluated against the subjects plus everything granted so far, and a match adds its
  `grant`. The token's permissions are all grants collected that way. The `umami` API itself is
  configured like any other entry; there is no pass-through mode.
- **`claims`** *(optional)* — `claimName → source` (see below).

## The mini-DSL

`when` and `eligibility` use the permission-string DSL from [PERMISSIONS.md](PERMISSIONS.md) §2:

- `,` = **OR** (lowest precedence), `+` = **AND**, `!term` = **NOT**. So `"a,b+!c"` =
  `a OR (b AND NOT c)`. An empty expression holds.
- Terms are matched by set membership against the subject set **S** (namespaced `role:*` or
  `scope:*`, `feature:*`, `is:*` — see PERMISSIONS.md §1) plus the bare permissions granted by
  earlier rules.

## Claim sources

A source is either a **literal string** or a **`$` reference**. The `$` is what makes the
difference: `PUT /config` refuses a reference that lacks it (`"tenant.features"` would otherwise be
written as those very words instead of the array) as well as an unknown `$…` reference.

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
   Why the session pins no audience: [ADR 0009](adr/0009-audience-agnostic-sessions-and-keys.md).

2. **API-key exchange** — `POST /auth/token { apiKey, api? }`. `api` picks the target audience
   (default `umami`); a key is not pinned to an audience, so the requested one is bounded only by
   the API's eligibility (an ineligible `api` is 403). The requester's S comes from the key:
   a service key contributes its `scope:*`, a personal access token its user's `role:*` (narrowed
   by the PAT's role restriction), plus the tenant's `feature:*` and computed `is:*` markers. Machine tokens also carry
   `kind: "api_key"`. No cookie, no session — this is the machine/BFF path.

> **Cross-*site* SPAs** (a product SPA on a genuinely different registrable domain, where
> the default `SameSite=Lax` withholds the umami cookie on background `fetch`; `UMAMI_COOKIE_SAMESITE=none`
> makes it third-party, which Safari blocks outright) are **not** served by a
> bearer-based token exchange in v1; they use the enterprise **OIDC redirect** flow (a top-level
> navigation, which `Lax` does carry). Same-*site* subdomains (`spa.myapp.com` → `iam.myapp.com`)
> use path 1 directly with `fetch(..., { credentials: "include" })` + CORS.

## Worked example

A user with role `admin` refreshes for `api=catalog`; their tenant has feature `ai`
→ **S = {role:admin, feature:ai}**.

- Projection, top to bottom: `role:admin,role:owner` ✓ → grants `write:blocks`, `read:blocks`;
  `role:member` ✗; `feature:ai + role:member` ✗; `write:blocks + feature:ai` ✓ (it sees rule 1's
  grant) → grants `generate:blocks`.
- Eligibility `role:member,role:admin,role:owner`: `role:admin` holds → **eligible**.
- Token: `aud=catalog`, `permissions=[generate:blocks,read:blocks,write:blocks]`, `svc=catalog`,
  `features=[ai]`, `dept=<user.custom.department>` (omitted when the user has no such field).

## Deferred

- Per-API rate limits; audience-scoped API-key creation restrictions.
- An **authorization code** for `GET /auth/authorize`. The redirect itself exists (hosted login,
  `security.redirectUris`), but it hands back only control, not a credential: umami is deployed
  next to the apps it serves, so the browser carries the refresh cookie across the redirect and the
  app refreshes normally. A code (plus its table, TTL, single-use enforcement, reuse detection and
  PKCE) becomes necessary only for a deployment that puts umami on a *different registrable domain*
  than the app.
