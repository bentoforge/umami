# umami configuration reference

umami's behaviour is driven by **one JSON document** — the *config*. It holds the catalogs (roles,
scopes, features, custom fields), the security settings, the messaging integration
and, crucially, the **per-API permission mapping**. This file documents the whole document, the full
permission catalog, and a copy-pasteable **standard config**.

For the permission-string DSL and the mint algorithm in depth, see [PERMISSIONS.md](PERMISSIONS.md).

---

## 1. Where the config lives

- **S3-backed** when an S3 client is available the wasabi way (`S3_BUCKET_SUFFIX` set): the whole
  document is stored as one object in the fixed bucket `config.<S3_BUCKET_SUFFIX>` (auto-created on
  first boot, like a DynamoDB table) and cached in memory. Edit it via `PUT /config` (load → edit →
  write back; optimistic `version`).
- **In-memory default** otherwise (dev/tests): [`Config::default()`](../src/config/mod.rs) — **not
  persisted**, so edits are lost on restart. This is the config described under
  [§5](#5-the-built-in-default).

New fields are added with `#[serde(default)]`, so an older stored document keeps loading after an
upgrade (missing keys fall back to defaults).

Relevant environment variables:

| Env | Effect |
|-----|--------|
| `S3_BUCKET_SUFFIX` | When set, persist config in S3 (bucket `config.<suffix>`); unset ⇒ in-memory default (non-persistent). |
| `UMAMI_CONFIG_KEY` | Optional object key for the config document (default `umami/config.json`). |
| `UMAMI_SYSTEM_TENANT_ID` | Tenant whose members get the `is:system-tenant` marker (⇒ `manage:tenants` + `switch:tenant`). |
| `UMAMI_AUTO_INIT=true` | Bootstrap a first tenant + owner when zero tenants exist. |
| `UMAMI_UI_DIR` | Directory of the built management SPA to serve under `/app` (default `clients/ui/dist`; absent index.html ⇒ API-only). |

---

## 2. Document shape

```jsonc
{
  "version": 1,                       // optimistic-concurrency counter, bumped on every PUT
  "roles":   [ RoleDef, … ],          // assignable to users        (role:*)
  "scopes":  [ ScopeDef, … ],         // assignable to service keys (scope:*)
  "features":[ FeatureDef, … ],       // granted to tenants         (feature:*)
  "customTenantFields": [ CustomFieldDef, … ],
  "customUserFields":   [ CustomFieldDef, … ],
  "security":  SecuritySettings,
  "messaging": MessagingConfig,
  "branding":  BrandingConfig,        // white-labeling the management UI
  "apis":      [ ApiDef, … ]          // audiences + permission mapping
}
```

### Building blocks

```jsonc
// RoleDef / ScopeDef / FeatureDef — same shape:
{ "code": "role:admin", "name": "Administrator", "assignableIf": "feature:pro" }
//   assignableIf (optional): a DSL expression over the tenant's feature set (incl. synthetic
//   is:* markers). Role/scope: gates whether it may be assigned. Feature: gates whether it may be
//   granted (prerequisites). Omitted = always assignable/grantable.

// CustomFieldDef:
{ "code": "customerNo", "label": "Kundennummer", "type": "string",
  "options": [],          // allowed values, for type "select"
  "required": true,
  "showInTable": true }   // surface as a column in the admin list tables
//   type ∈ { "string", "number", "bool"/"boolean", "select" }

// SecuritySettings:
{ "minPasswordLength": 8, "accessTtlSecs": 600, "refreshTtlSecs": 2592000,
  "messagingCodeTtlSecs": 600,    // link-code validity window (single-use OTP)
  "rateLimits": RateLimitsConfig,  // auth-endpoint rate limits (see §8)
  "redirectUris": [                // exact URLs GET /auth/authorize may return to
    "https://app.example.com/auth/callback" ] }
//   redirectUris is top-level, not per-API: logging in is not an API-scoped act — the session it
//   creates is audience-agnostic, and which APIs the user may then call follows from their roles.
//   Matched EXACTLY: no prefixes, no wildcards (`https://app.example.com.evil.test` would
//   prefix-match). Empty list ⇒ the hosted-login redirect is disabled.

// RateLimitsConfig — all three policies optional (older configs keep loading); a policy's
//   max (maxFailures / maxPerWindow) of 0 disables it (e.g. run per-IP only):
{ "login":         { "maxFailures": 5,   "windowSecs": 300, "blockSecs": 900 },
  "tokenExchange": { "maxPerWindow": 60,  "windowSecs": 60,  "blockSecs": 300 },
  "perIp":         { "maxPerWindow": 300, "windowSecs": 60,  "blockSecs": 300 } }

// MessagingConfig — either/both optional; when set, /auth/me/messaging-code returns deep links
//   and every token gets the is:messaging-configured marker:
{ "whatsappNumber": "4915112345678", "telegramBot": "my_link_bot" }

// BrandingConfig — white-label the UI at runtime (all optional; empty → built-in defaults). umami
//   serves these at /app/branding.css, /app/logo, /app/favicon. logo/favicon may be a data: URI
//   (self-contained) or an http(s) URL. Swap the accent via customCss:
{ "customCss": ":root{--brand: 225 29 72; --brand-dark: 190 18 60}",  // space-separated RGB
  "logoLight": "data:image/svg+xml;base64,…",  // or "https://cdn.example.com/logo-light.svg"
  "logoDark":  "data:image/svg+xml;base64,…",  // shown in dark mode; each falls back to the other
  "favicon":   "data:image/png;base64,…" }
//   served at /app/logo/light, /app/logo/dark, /app/favicon; the UI picks the logo by theme.
//
//   The top bar has four tokens of its own, for a logo that needs its own background:
//     --header-bg      the bar
//     --header-fg      nav text and icons; inactive items are this at 70% opacity
//     --header-accent  the active nav item
//     --header-border  the rule below the bar
//   Set them in :root and they apply in BOTH light and dark mode — usually what you
//   want when the bar carries a logo. Set them under .dark as well to differ.
//
//   Why tokens and not plain CSS: every element in the bar declares its own colour,
//   so `header { color: … }` is never inherited and never applies, however important
//   you make it. Width and other non-colour properties are still plain CSS —
//   `header { border-bottom-width: 4px }` works, because nothing else sets it.
//
//   Example, a dark blue bar with a cyan rule and cyan highlights:
{ "customCss": ":root{--header-bg: 30 58 113; --header-fg: 255 255 255; --header-accent: 45 203 166; --header-border: 45 203 166} header{border-bottom-width:4px}" }

// ApiDef — a target audience + its permission projection:
{ "code": "dbx-core", "audience": "dbx-core",
  "eligibility": "role:member,role:admin",      // optional gate; no token minted if it fails
  "permissions": [ { "when": "role:admin", "grant": ["write:blocks"] }, … ],  // ordered
  "claims": { "svc": "dbx-core", "org": "customTenant:customerNo" } }
```

---

## 3. The subject model

At mint time umami builds a **subject set** and runs it through the target API's ordered
`permissions` rules (see [PERMISSIONS.md](PERMISSIONS.md)). Subjects are namespaced:

| Namespace | Source | Example |
|-----------|--------|---------|
| `role:*`  | the user's `roles` (a PAT intersects with its restriction) | `role:owner` |
| `scope:*` | a service key's `scopes` | `scope:messaging-linker` |
| `feature:*` | the tenant's granted `features` | `feature:pro` |
| `is:*` | **synthetic** — computed at mint, never stored | `is:system-tenant` |

**Synthetic markers:**

| Marker | Added when |
|--------|-----------|
| `is:system-tenant` | the token's tenant equals `UMAMI_SYSTEM_TENANT_ID` |
| `is:messaging-configured` | the config has `messaging.telegramBot` and/or `messaging.whatsappNumber` |

Synthetic markers also participate in **assignability** (`assignableIf`) via
`Config::eval_feature_set`, so a scope/role can be gated on e.g. `is:system-tenant` and will only
appear in that tenant's pickers.

Code only ever checks **permissions** (bare strings like `manage:users`). Roles/scopes/features/
markers are turned into permissions solely by the `apis` mapping — there are no ad-hoc tenant/marker
checks in the route handlers.

---

## 4. Permission catalog

These are all the permission strings umami's own API (`code: "umami"`) recognises. Product APIs
define their own.

| Permission | Gates (umami routes) |
|------------|----------------------|
| `manage:tenants` | `GET/POST /tenants`, `DELETE /tenants/{id}`, `GET /tenants/{id}/assignable-features`, `POST`/`DELETE /tenants/{id}/features/{code}` (cross-tenant) |
| `switch:tenant` | `POST /auth/switch-tenant` |
| `admin:tenant` | `GET`/`PATCH /tenants/{id}` (name + custom fields), `GET /tenants/{id}/audit` (own tenant) |
| `manage:users` | users CRUD + admin password reset, `GET /users/{id}/assignable-roles` |
| `manage:service-keys` | service-key create/list/revoke, `GET /tenants/{id}/assignable-scopes` |
| `manage:config` | `GET`/`PUT /config` |
| `manage:profile` | edit own profile — `PATCH /auth/me` (name parts + self-editable custom fields) |
| `manage:passwords` | own security settings — `POST /auth/me/password`, TOTP setup/verify/disable, passkey registration |
| `manage:personal-tokens` | own personal access tokens under `/auth/me/api-keys` |
| `manage:sessions` | see/revoke own sessions — `GET /auth/sessions`, `DELETE /auth/sessions/{id}`, `POST /auth/logout-all` |
| `manage:messaging` | `/auth/me/messaging-code` (+regenerate), `/auth/me/messaging-links` (+unlink) |
| `messaging:link` | `POST /messaging/links` (bot backend claims a mapping) |
| `messaging:resolve` | `GET /messaging/resolve` (identity → user info / token) |

The five `manage:profile`/`passwords`/`personal-tokens`/`sessions`/`messaging` permissions are the
**granular self-service** set. There is no `self:readonly` deny marker: a read-only user is one whose
role simply isn't granted these; a deployment that doesn't use a given surface (e.g. no PATs) just
doesn't grant that permission, and the corresponding UI hides itself.

**Authenticated but permission-free** (any valid token): `GET /auth/me`, `GET /config/custom-fields`,
plus login/refresh/logout, JWKS and the passkey-login ceremonies.

---

## 5. The built-in default

The built-in default is **deliberately minimal** — a bootstrap-only mapping so the auto-init
system-tenant owner can log in and administer (and then write the real config). It is *not* a full
role matrix; see [§6](#6-proposed-standard-config) for that. The default `apis[0]` (`umami`) ships
(ordered):

| `when` | `grant` |
|--------|---------|
| *(empty — always)* | `manage:profile`, `manage:passwords`, `manage:personal-tokens`, `manage:sessions` |
| `role:owner` | `admin:tenant`, `manage:users`, `manage:service-keys`, `manage:config` |
| `is:system-tenant` | `manage:tenants`, `switch:tenant` |
| `is:messaging-configured` | `manage:messaging` |
| `scope:messaging-linker + is:system-tenant` | `messaging:link` |
| `scope:messaging-resolver + is:system-tenant` | `messaging:resolve` |

Default **roles**: `role:owner`, `role:admin`, `role:member`, `role:viewer`, `role:readonly`
(all `assignableIf` omitted). Default **scopes**: `scope:messaging-linker`,
`scope:messaging-resolver` (both `assignableIf: "is:system-tenant"`). No default
features/custom fields.

> ⚠ In the minimal default, **only `role:owner` is mapped** — `role:admin` / `role:member` /
> `role:viewer` grant nothing until you map them in your config. This is intentional: real
> deployments define the matrix (see §6). `role:readonly` maps to the deny marker; assign it to a
> user to block their self-service profile/password edits.

---

## 6. Proposed standard config

A fuller starting point — the full role matrix the minimal default omits, plus a licensed
feature/scope and a product-API entry with eligibility + claims. Copy, adjust, `PUT /config`.

```jsonc
{
  "version": 1,
  "roles": [
    { "code": "role:owner",    "name": "Owner" },
    { "code": "role:admin",    "name": "Administrator" },
    { "code": "role:member",   "name": "Member" },
    { "code": "role:viewer",   "name": "Viewer" },
    { "code": "role:readonly", "name": "Read-only" }
  ],
  "scopes": [
    { "code": "scope:messaging-linker",   "name": "Messaging linker",   "assignableIf": "is:system-tenant" },
    { "code": "scope:messaging-resolver", "name": "Messaging resolver", "assignableIf": "is:system-tenant" },
    { "code": "scope:ingest",             "name": "Telemetry ingest" }
  ],
  "features": [
    { "code": "feature:pro", "name": "Pro plan" },
    { "code": "feature:ai",  "name": "AI add-on", "assignableIf": "feature:pro" }
  ],
  "customTenantFields": [
    { "code": "customerNo", "label": "Customer no.", "type": "string", "required": false, "showInTable": true }
  ],
  "customUserFields": [],
  "security": {
    "minPasswordLength": 8,
    "accessTtlSecs": 600,
    "refreshTtlSecs": 2592000,
    "messagingCodeTtlSecs": 600,
    "rateLimits": {
      "login":         { "maxFailures": 5,   "windowSecs": 300, "blockSecs": 900 },
      "tokenExchange": { "maxPerWindow": 60,  "windowSecs": 60,  "blockSecs": 300 },
      "perIp":         { "maxPerWindow": 300, "windowSecs": 60,  "blockSecs": 300 }
    }
  },
  "messaging": { "telegramBot": "my_link_bot", "whatsappNumber": "4915112345678" },
  "apis": [
    {
      "code": "umami", "audience": "umami",
      "permissions": [
        { "when": "role:owner",  "grant": ["admin:tenant","manage:users","manage:service-keys","manage:config"] },
        { "when": "role:admin",  "grant": ["manage:users","manage:service-keys"] },
        { "when": "is:system-tenant", "grant": ["manage:tenants","switch:tenant"] },
        // Granular self-service for every non-read-only user (a read-only role is simply excluded —
        // there is no separate deny marker).
        { "when": "!role:readonly", "grant": ["manage:profile","manage:passwords","manage:personal-tokens","manage:sessions"] },
        { "when": "is:messaging-configured + !role:readonly", "grant": ["manage:messaging"] },
        { "when": "scope:messaging-linker + is:system-tenant",   "grant": ["messaging:link"] },
        { "when": "scope:messaging-resolver + is:system-tenant", "grant": ["messaging:resolve"] }
      ]
    },
    {
      "code": "dbx-core", "audience": "dbx-core",
      "eligibility": "role:member,role:admin,role:owner",
      "permissions": [
        { "when": "role:admin,role:owner", "grant": ["write:blocks","read:blocks"] },
        { "when": "role:member",           "grant": ["read:blocks"] },
        { "when": "feature:ai + role:member", "grant": ["use:ai"] },
        { "when": "scope:ingest",          "grant": ["write:telemetry"] }
      ],
      "claims": { "org": "customTenant:customerNo" }
    }
  ]
}
```

> Note: `role:viewer` is intentionally left unmapped here — the umami list routes require
> `manage:users` / `manage:service-keys`, and there is no read-only variant in code. To give
> viewers read access you would add a `read:*` permission **and** gate the relevant routes on it in
> the handler; the config can only mint permissions, not decide which a route requires.

---

## 7. Messaging specifics

- The per-user **link code** is a short-lived, single-use OTP (`security.messagingCodeTtlSecs`).
  `GET /auth/me/messaging-code` returns the current code, rotating it if expired, and — when
  `messaging` is configured — ready-made deep links (`t.me/<bot>?start=<code>`,
  `wa.me/<number>?text=<code>`).
- The bot backend is a **system-tenant service key** carrying `scope:messaging-linker`
  (→ `messaging:link`) and/or `scope:messaging-resolver` (→ `messaging:resolve`). Because the
  mapping requires `+ is:system-tenant`, such a key only works in the system tenant.
- Code generation and link attempts are written to the audit log.

See [PERMISSIONS.md](PERMISSIONS.md) for the DSL and mint flow, and the module docs in
[`src/messaging`](../src/messaging) for the link/resolve endpoints.

---

## 8. Rate limiting

`security.rateLimits` bounds the unauthenticated auth endpoints. It is a **layered** design (all
policies configurable; set a policy's `max` to `0` to disable it and run, say, per-IP only):

| Policy | Subject | Endpoint(s) | Counts | Reset on success | Purpose |
|--------|---------|-------------|--------|------------------|---------|
| `perIp` | client IP, **per endpoint** | `/auth/login`, `/auth/token` (+ webauthn login-finish) | all requests | no | the primary blunt instrument — caps a dumb loop / flood from one IP |
| `tokenExchange` | API key id | `/auth/token` | all exchanges (incl. successful) | no | a **volume/quota** cap catching one key hammering across many IPs |
| `login` | resolved **user id** | `/auth/login` | **failed** attempts only | **yes** | brute-force protection |

Why layered rather than per-IP alone: per-IP is generous by necessity (NAT/CGNAT puts many real
users behind one address), so it can't catch a single key spread across many IPs (→ `tokenExchange`)
or a distributed brute-force with few tries per IP (→ `login`).

The `login` cap keys on the **resolved user id**, not the submitted username, so it tracks a real
account regardless of how the username was typed. Login resolves the account first, then applies the
cap; the per-IP cap (checked before the lookup) is what bounds the cost of that resolve, so an
attacker cannot turn the lookup into a DoS. Attempts against unknown/inactive usernames get no
per-account counter (there is nothing to key on) and are covered by the per-IP cap alone.

Fields: `login` uses `maxFailures`; `tokenExchange`/`perIp` use `maxPerWindow`. All take
`windowSecs` (the counting window) and `blockSecs` (how long a tripped subject is blocked — may
exceed the window). Defaults are tuned so a well-behaved client that **caches** the short-lived
access token (~`accessTtlSecs`) sits far below the limits, while a client that re-exchanges on every
call trips almost immediately.

Mechanics & guarantees:

- **Storage:** DynamoDB (`<DYNAMO_TABLE_PREFIX>-rate-limits`), behind a `RateLimitRepository` trait
  so the backend is swappable. Counters use an atomic `ADD` (fixed window); each row carries a
  numeric `ttl` so DynamoDB self-cleans; the TTL is enabled by umami on boot (see the README).
- **Response:** a uniform `429 Too Many Requests` + `Retry-After`, with a generic body (no
  account-existence leak).
- **Fail-open:** if the store is unavailable, umami **allows** auth (it never DoSes itself) and logs
  loudly; a per-node bounded LRU still short-circuits already-known blocks with zero store traffic.
- **Per-key override:** a service key may carry a `rateLimit` overriding `tokenExchange` — to raise
  the cap for a legit high-fanout backend, or disable the per-key cap for a controlled public-token
  flow (the per-IP cap still applies). See [API-KEYS.md](API-KEYS.md).
- **Env:** only the LRU cache size is env (`UMAMI_RATELIMIT_CACHE_CAP`, default 50000); thresholds
  live here in the config.
