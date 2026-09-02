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
| `UMAMI_CONFIG_S3_KEY` | Optional object key for the config document (default `umami/config.json`). |
| `UMAMI_SYSTEM_TENANT_ID` | Tenant whose members get the `is:system-tenant` marker (⇒ `manage:tenants` + `switch:tenant`). |
| `UMAMI_AUTO_INIT=true` | Bootstrap a first tenant + owner when zero tenants exist. |
| `UMAMI_UI_DIR` | Directory of the built management SPA to serve under `/app` (default `clients/ui/dist`; absent index.html ⇒ API-only). |
| `UMAMI_MAIL_SQS_QUEUE_URL` | SQS queue umami hands outbound transactional mail to. Unset ⇒ mail disabled, and confirming an address is refused up front. Links in those mails are built from `UMAMI_ISSUER`. |

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
  "notificationTypes": [ NotificationTypeDef, … ],  // what users can subscribe to
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
  "contactChallengeTtlSecs": 86400,  // address-confirmation link validity (single-use)
  "passwordResetTtlSecs": 3600,      // recovery link validity — shorter: it IS account takeover
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
  "perIp":         { "maxPerWindow": 300, "windowSecs": 60,  "blockSecs": 300 },
  "mailSend":      { "maxPerWindow": 5,   "windowSecs": 3600, "blockSecs": 3600 } }
//   mailSend is keyed on the USER, not the IP: the address being mailed sits on somebody's own
//   contact list, so the account is the party to hold accountable. Without the cap, anyone with an
//   account can add a stranger's address and have umami mail that stranger on repeat.

// MessagingConfig — either/both optional; when set, /auth/me/messaging-code returns deep links
//   and every token gets the is:messaging-configured marker:
{ "whatsappNumber": "4915112345678", "telegramBot": "my_link_bot" }

// NotificationTypeDef — one subscribable thing. See NOTIFICATIONS.md for the model.
//   A cadence code is a plain STRING, not a fixed enum: umami never interprets one (no arithmetic,
//   no ordering, no scheduling — the rule is equality), so the vocabulary is the deployment's.
//   `on-publish` and `quarterly` are as valid as `weekly`, and each carries its own label the way a
//   role or a feature does. PUT /config rejects a duplicate code, a type with no cadences, a
//   non-lowercase or unlabelled cadence, and a `default` the type is never fired at.
{ "code": "wsc-new-content",        // stable: keys every user's stored choice
  "name": "New content",
  "description": "Pages published since the last message.",
  "cadences": [                     // what the app actually fires — code plus the words a user reads
    { "code": "daily",   "name": "Täglich" },
    { "code": "weekly",  "name": "Wöchentlich" },
    { "code": "monthly", "name": "Monatlich" }
  ],
  "default": "weekly",              // "on", a cadence code, or omitted for off
  "eligibleIf": "role:wsc-editor" } // DSL over role:*/feature:*/is:system-tenant{,-member}
//   Omit `cadences` entirely for a type with no rhythm of its own: the choice is then "on"/"off".
//   `off` and `on` are reserved and cannot be cadence codes. A user can always choose `off`,
//   whether or not the type has a rhythm.
//   eligibleIf is the INPUT vocabulary, not permissions. Session markers (is:2fa, is:passkey,
//   is:totp) describe how a session authenticated and a notification has no session — naming one
//   would simply never match, with nothing to explain why.

// BrandingConfig — white-label the UI at runtime (all optional; empty → built-in defaults). umami
//   serves these at /app/branding.css, /app/logo, /app/favicon. logo/favicon may be a data: URI
//   (self-contained) or an http(s) URL. Swap the accent via customCss:
{ "customCss": ":root{--brand: 225 29 72; --brand-dark: 190 18 60}",  // space-separated RGB
  "logoLight": "data:image/svg+xml;base64,…",  // or "https://cdn.example.com/logo-light.svg"
  "logoDark":  "data:image/svg+xml;base64,…",  // shown in dark mode; each falls back to the other
  "favicon":   "data:image/png;base64,…",
  "title":     "noonu" }                       // browser tab AND the logo's alt text
//   served at /app/logo/light, /app/logo/dark, /app/favicon; the UI picks the logo by theme.
//
//   The top bar has six tokens of its own, for a logo that needs its own background:
//     --header-bg          the bar
//     --header-text        nav text and icons, hovered
//     --header-text-muted  inactive nav items
//     --header-hover       background of a hovered item
//     --header-accent      the active nav item; follows --brand unless set
//     --header-border      the rule below the bar
//   `fg-muted` and `hover` are colours, not opacities, and they are the two to get
//   wrong: 70% of a dark grey on white reads as restrained, 70% of white on a dark
//   bar reads as washed out, and the same goes for the hover wash. Recolour the
//   bar, set all four foreground tokens.
//   Set them in :root and they apply in BOTH light and dark mode — usually what you
//   want when the bar carries a logo. Set them under .dark as well to differ.
//
//   Why tokens and not plain CSS: every element in the bar declares its own colour,
//   so `header { color: … }` is never inherited and never applies, however important
//   you make it. Width and other non-colour properties are still plain CSS —
//   `header { border-bottom-width: 4px }` works, because nothing else sets it.
//
//   The sign-in screen has seven of its own — it is the first thing anyone sees,
//   and for a customer's users often the only umami page they ever look at:
//     --login-bg            the page behind the box
//     --login-card          the box itself
//     --login-text          heading and labels
//     --login-primary       the submit button, with --login-primary-text its label
//     --login-secondary     the outline button's border, --login-secondary-text its label
//   Button hovers are element-level opacity, not tokens: unlike a colour wash that
//   lands the same way whatever is behind. The input boxes stay neutral on purpose —
//   a form field reads as a light box even on a coloured card.
//
//   Example, a dark blue bar with a cyan rule and cyan highlights:
{ "customCss": ":root{--header-bg: 30 58 113; --header-text: 255 255 255; --header-text-muted: 203 213 225; --header-hover: 42 74 139; --header-accent: 45 203 166; --header-border: 45 203 166} header{border-bottom-width:4px}" }

// ApiDef — a target audience + its permission projection:
{ "code": "dbx-core", "audience": "dbx-core",
  "eligibility": "role:member,role:admin",      // optional gate; no token minted if it fails
  "permissions": [ { "when": "role:admin", "grant": ["write:blocks"] }, … ],  // ordered
  "claims": { "svc": "dbx-core", "org": "$tenant.custom.customerNo" } }
//   A claim source is either a LITERAL string or a `$` reference. Without the `$` it is a literal —
//   `"tenant.features"` puts those words in the token, not the array. PUT /config now refuses a
//   value that looks like a reference but is missing its `$`, and an unknown `$…` reference too:
//   both used to fail silently, as a claim that is simply absent or carries the wrong words.
//   References: $user.{id,username,title,salutation,firstname,lastname,name,fullName,
//   addressableName,locale,roles}, $tenant.{id,name,slug,features},
//   $user.custom.<code>, $tenant.custom.<code>
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
| `view:ratelimits` | `GET /rate-limits/blocks` — the deployment-wide rate-limit overview (§8) |
| `manage:profile` | edit own profile — `PATCH /auth/me` (name parts + self-editable custom fields) |
| `manage:passwords` | own security settings — `POST /auth/me/password`, TOTP setup/verify/disable, passkey registration |
| `manage:personal-tokens` | own personal access tokens under `/auth/me/api-keys` |
| `manage:sessions` | see/revoke own sessions — `GET /auth/sessions`, `DELETE /auth/sessions/{id}`, `POST /auth/logout-all` |
| `manage:contacts` | own email addresses — `GET`/`POST /auth/me/contacts`, `DELETE /auth/me/contacts/{address}`, `PUT /auth/me/preferred-contact` — and own notification choices under `/auth/me/notifications` |
| `notifications:audience` | `POST /notifications/audience` (who hears about one firing) |
| `notifications:send` | `POST /notifications/send` (hand finished messages over) |
| `notifications:report` | `POST /notifications/undeliverable` (the mail worker reports a hard bounce) |
| `manage:messaging` | `/auth/me/messaging-code` (+regenerate), `/auth/me/messaging-links` (+unlink) |
| `messaging:link` | `POST /messaging/links` (bot backend claims a mapping) |
| `messaging:resolve` | `GET /messaging/resolve` (identity → user info / token) |

`manage:contacts` sits in the **baseline** rule (below) rather than behind a marker: keeping your own
addresses current is profile data, not a deployment capability. What does depend on infrastructure is
verification and password recovery, and neither exists yet — see [CONTACTS.md](CONTACTS.md).

The five `manage:profile`/`passwords`/`personal-tokens`/`sessions`/`messaging` permissions are the
**granular self-service** set. There is no `self:readonly` deny marker: a read-only user is one whose
role simply isn't granted these; a deployment that doesn't use a given surface (e.g. no PATs) just
doesn't grant that permission, and the corresponding UI hides itself.

**Authenticated but permission-free** (any valid token): `GET /auth/me`, `GET /config/custom-fields`,
plus login/refresh/logout, JWKS and the passkey-login ceremonies.

**Unauthenticated** (no token at all): `GET /auth/capabilities` — what the sign-in screen may offer,
currently `{ "passwordRecovery": bool }` — plus the three ceremonies whose proof *is* the mailed
secret: `POST /auth/contacts/verify`, `POST /auth/forgot-password`, `POST /auth/reset-password`. See
[CONTACTS.md](CONTACTS.md) for why those cannot require a session.

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
| `is:system-tenant-member` | `manage:tenants`, `switch:tenant`, `view:ratelimits` |
| `is:messaging-configured` | `manage:messaging` |
| `scope:messaging-linker + is:system-tenant` | `messaging:link` |
| `scope:messaging-resolver + is:system-tenant` | `messaging:resolve` |
| `scope:notifier + is:system-tenant` | `notifications:audience`, `notifications:send` |
| `scope:mail-worker + is:system-tenant` | `notifications:report` |

Default **roles**: `role:owner`, `role:admin`, `role:member`, `role:viewer`, `role:readonly`
(all `assignableIf` omitted). Default **scopes**: `scope:messaging-linker`,
`scope:messaging-resolver`, `scope:notifier`, `scope:mail-worker` (all
`assignableIf: "is:system-tenant"`). No default
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
    { "code": "scope:notifier",           "name": "Notifier",           "assignableIf": "is:system-tenant" },
    { "code": "scope:mail-worker",        "name": "Mail worker",        "assignableIf": "is:system-tenant" },
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
    "contactChallengeTtlSecs": 86400,
    "passwordResetTtlSecs": 3600,
    "rateLimits": {
      "login":         { "maxFailures": 5,   "windowSecs": 300, "blockSecs": 900 },
      "tokenExchange": { "maxPerWindow": 60,  "windowSecs": 60,  "blockSecs": 300 },
      "perIp":         { "maxPerWindow": 300, "windowSecs": 60,  "blockSecs": 300 },
      "mailSend":      { "maxPerWindow": 5,   "windowSecs": 3600, "blockSecs": 3600 }
    }
  },
  "messaging": { "telegramBot": "my_link_bot", "whatsappNumber": "4915112345678" },
  "apis": [
    {
      "code": "umami", "audience": "umami",
      "permissions": [
        { "when": "role:owner",  "grant": ["admin:tenant","manage:users","manage:service-keys","manage:config"] },
        { "when": "role:admin",  "grant": ["manage:users","manage:service-keys"] },
        { "when": "is:system-tenant", "grant": ["manage:tenants","switch:tenant","view:ratelimits"] },
        // Granular self-service for every non-read-only user (a read-only role is simply excluded —
        // there is no separate deny marker).
        { "when": "!role:readonly", "grant": ["manage:profile","manage:passwords","manage:personal-tokens","manage:sessions"] },
        { "when": "!role:readonly", "grant": ["manage:contacts"] },
        { "when": "is:messaging-configured + !role:readonly", "grant": ["manage:messaging"] },
        { "when": "scope:messaging-linker + is:system-tenant",   "grant": ["messaging:link"] },
        { "when": "scope:messaging-resolver + is:system-tenant", "grant": ["messaging:resolve"] },
        { "when": "scope:notifier + is:system-tenant", "grant": ["notifications:audience","notifications:send"] },
        { "when": "scope:mail-worker + is:system-tenant", "grant": ["notifications:report"] }
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
      "claims": { "org": "$tenant.custom.customerNo" }
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
| `mailSend` | **user id** | address confirmation **and** password recovery | every queued mail | no | stops an account from using umami to mail a stranger on repeat |
| `perIp:recover` | client IP | `POST /auth/forgot-password` | all requests | no | its own counter, so a recovery flood cannot consume the login budget |
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

Fields: `login` uses `maxFailures`; `tokenExchange`/`perIp`/`mailSend` use `maxPerWindow`. All take
`windowSecs` (the counting window) and `blockSecs` (how long a tripped subject is blocked — may
exceed the window). Defaults are tuned so a well-behaved client that **caches** the short-lived
access token (~`accessTtlSecs`) sits far below the limits, while a client that re-exchanges on every
call trips almost immediately.

Mechanics & guarantees:

- **Storage:** DynamoDB (`<DYNAMO_TABLE_PREFIX>-rate-limits`), behind a `RateLimitRepository` trait
  so the backend is swappable. Counters use an atomic `ADD` (fixed window); each row carries a
  numeric `ttl` so DynamoDB self-cleans; the TTL is enabled by umami on boot (see the README). One
  sparse GSI, `BlocksByPolicyIndex`, indexes **blocks only** — see [§8.1](#81-reading-the-limiter-management-ui).
- **Response:** a uniform `429 Too Many Requests` + `Retry-After`, with a generic body (no
  account-existence leak).
- **Fail-open:** if the store is unavailable, umami **allows** auth (it never DoSes itself) and logs
  loudly; a per-node bounded LRU still short-circuits already-known blocks with zero store traffic.
- **Per-key override:** a service key may carry a `rateLimit` overriding `tokenExchange` — to raise
  the cap for a legit high-fanout backend, or disable the per-key cap for a controlled public-token
  flow (the per-IP cap still applies). See [API-KEYS.md](API-KEYS.md).
- **Env:** only the LRU cache size is env (`UMAMI_RATELIMIT_CACHE_CAP`, default 50000); thresholds
  live here in the config.

### 8.1 Reading the limiter (management UI)

Everything the limiter knows is readable, read-only, through five routes. None of them counts the
request it is reporting on — inspection goes straight to the stored items rather than through the
enforcement path, which would both increment the counter and consult the node-local LRU (an answer
that would differ from node to node).

| Route | Permission | Shows |
|-------|-----------|-------|
| `GET /auth/me/rate-limit` | any valid token | your own `login` failure count and block |
| `GET /users/{id}/rate-limit` | `manage:users` (own tenant) | that account's `login` state |
| `GET /tenants/{id}/api-keys/{keyId}/rate-limit` | `manage:service-keys` (own tenant) | that service key's `tokenExchange` state, under the policy the key actually runs on (its override, or the global one) |
| `GET /auth/me/api-keys/{keyId}/rate-limit` | `manage:personal-tokens` | the same, for one of your own PATs |
| `GET /users/{id}/pats/{keyId}/rate-limit` | `manage:users` (own tenant) | the same, for a tenant user's PAT |
| `GET /rate-limits/blocks` | `view:ratelimits` | blocks that tripped recently, across every policy, newest first |

**Cost.** The first five name their subject, so each is two `GetItem`s (the counter and the block)
on the table's hash key — no index involved. The overview cannot name its subjects (*which* IPs
tripped is the question), so it queries a GSI, `BlocksByPolicyIndex` (hash `policy`, range
`blockedAt`), for one bounded page per policy — the last hour, at most 100 blocks. It never scans.

Those two bounds take no query parameter: they are exactly what limits the read, so a caller able
to widen them could turn one screen into an arbitrarily expensive query. The response carries
`since` and `policies`, so a client labels the view from what it actually got rather than from an
assumption.

**Only blocks are indexed.** The index attributes are written solely by `set_block`, which runs when
a subject actually trips a threshold — rare by construction. Writing them on every `increment`
instead would add an indexed write to every login and token exchange and funnel all of them into one
partition per policy name: the hot partition the rate limiter exists to prevent. The consequence is
worth stating plainly — **a counter that never trips leaves no trace in the overview.** It answers
"who got blocked", not "who is close to the cap"; for the latter, look at a named subject.

**Upgrading an existing deployment.** `BlocksByPolicyIndex` is created with the table, and umami
also *converges* it on every boot — `CreateTable` is a no-op on a table that already exists, so a
deployment that predates the overview would otherwise never get the index. Convergence needs
`dynamodb:UpdateTable` on the table prefix; without it umami logs a warning and carries on (auth is
unaffected, the overview just stays empty). The manual equivalent:

```bash
aws dynamodb update-table --table-name <DYNAMO_TABLE_PREFIX>-rate-limits \
  --attribute-definitions AttributeName=policy,AttributeType=S AttributeName=blockedAt,AttributeType=N \
  --global-secondary-index-updates '[{"Create":{"IndexName":"BlocksByPolicyIndex","KeySchema":[{"AttributeName":"policy","KeyType":"HASH"},{"AttributeName":"blockedAt","KeyType":"RANGE"}],"Projection":{"ProjectionType":"ALL"}}}]'
```

Either way the overview only shows blocks written *after* the index exists: older block rows carry
no `policy`/`blockedAt` attributes, and DynamoDB's backfill can only index what an item holds.

`view:ratelimits` is deliberately separate from `view:audit`. The audit log is tenant-scoped;
client IPs belong to no tenant at all, so the overview is a deployment-wide operator's view. The
built-in bootstrap config grants it alongside the cross-tenant admin permissions
(`is:system-tenant-member`).
