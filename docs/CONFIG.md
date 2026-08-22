# umami configuration reference

umami's behaviour is driven by **one JSON document** — the *config*. It holds the catalogs (roles,
scopes, features, limits, packages, custom fields), the security settings, the messaging integration
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
  "limits":  [ LimitDef, … ],         // metered quotas (accounting)
  "packages":[ PackageDef, … ],       // sellable bundles of features+limits (accounting)
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
  "messagingCodeTtlSecs": 600 }   // link-code validity window (single-use OTP)

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
| `admin:tenant` | `GET`/`PATCH /tenants/{id}`, `PATCH …/status`, `PATCH …/license`, packages + entitlements, `GET /tenants/{id}/audit` (own tenant) |
| `manage:users` | users CRUD + admin password reset, `GET /users/{id}/assignable-roles` |
| `manage:service-keys` | service-key create/list/revoke, `GET /tenants/{id}/assignable-scopes` |
| `manage:pat` | own personal access tokens under `/auth/me/api-keys` |
| `manage:config` | `GET`/`PUT /config` |
| `write:usage` | `GET`/`POST /tenants/{id}/usage` (metering) |
| `self:readonly` | **deny marker** — its presence *blocks* `POST /auth/me/password` and `PATCH /auth/me` (guarded via `!self:readonly`) |
| `messaging:self` | `/auth/me/messaging-code` (+regenerate), `/auth/me/messaging-links` (+unlink) |
| `messaging:link` | `POST /messaging/links` (bot backend claims a mapping) |
| `messaging:resolve` | `GET /messaging/resolve` (identity → user info / token) |

**Authenticated but permission-free** (any valid token): `GET /auth/me`, `POST /auth/logout-all`,
`GET /config/custom-fields`, plus login/refresh/logout, JWKS and the MFA ceremonies. (`POST /auth/me/password` and `PATCH /auth/me` are authenticated too, but blocked when
`self:readonly` is present.)

---

## 5. The built-in default

The built-in default is **deliberately minimal** — a bootstrap-only mapping so the auto-init
system-tenant owner can log in and administer (and then write the real config). It is *not* a full
role matrix; see [§6](#6-proposed-standard-config) for that. The default `apis[0]` (`umami`) ships
(ordered):

| `when` | `grant` |
|--------|---------|
| `role:owner` | `admin:tenant`, `manage:users`, `manage:service-keys`, `manage:pat`, `manage:config`, `write:usage` |
| `is:system-tenant` | `manage:tenants`, `switch:tenant` |
| `role:readonly` | `self:readonly` (deny marker) |
| `is:messaging-configured` | `messaging:self` |
| `scope:messaging-linker + is:system-tenant` | `messaging:link` |
| `scope:messaging-resolver + is:system-tenant` | `messaging:resolve` |

Default **roles**: `role:owner`, `role:admin`, `role:member`, `role:viewer`, `role:readonly`
(all `assignableIf` omitted). Default **scopes**: `scope:messaging-linker`,
`scope:messaging-resolver` (both `assignableIf: "is:system-tenant"`). No default
features/limits/packages/custom fields.

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
  "limits":   [ { "code": "seats", "name": "Seats", "default": "5" } ],
  "packages": [],
  "customTenantFields": [
    { "code": "customerNo", "label": "Customer no.", "type": "string", "required": false, "showInTable": true }
  ],
  "customUserFields": [],
  "security": {
    "minPasswordLength": 8,
    "accessTtlSecs": 600,
    "refreshTtlSecs": 2592000,
    "messagingCodeTtlSecs": 600
  },
  "messaging": { "telegramBot": "my_link_bot", "whatsappNumber": "4915112345678" },
  "apis": [
    {
      "code": "umami", "audience": "umami",
      "permissions": [
        { "when": "role:owner",  "grant": ["admin:tenant","manage:users","manage:service-keys","manage:pat","manage:config","write:usage"] },
        { "when": "role:admin",  "grant": ["manage:users","manage:service-keys","manage:pat","write:usage"] },
        { "when": "role:member", "grant": ["manage:pat","write:usage"] },
        { "when": "is:system-tenant", "grant": ["manage:tenants","switch:tenant"] },
        { "when": "role:readonly", "grant": ["self:readonly"] },
        { "when": "is:messaging-configured", "grant": ["messaging:self"] },
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
