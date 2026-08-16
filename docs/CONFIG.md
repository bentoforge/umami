# umami configuration reference

umami's behaviour is driven by **one JSON document** — the *config*. It holds the catalogs (roles,
scopes, features, limits, packages, custom fields), the security settings, the messaging integration
and, crucially, the **per-API permission mapping**. This file documents the whole document, the full
permission catalog, and a copy-pasteable **standard config**.

For the permission-string DSL and the mint algorithm in depth, see [PERMISSIONS.md](PERMISSIONS.md).

---

## 1. Where the config lives

- **S3-backed** when `UMAMI_CONFIG_BUCKET` is set: the whole document is stored as one object and
  cached in memory. Edit it via `PUT /config` (load → edit → write back; optimistic `version`).
- **Built-in default** otherwise (dev/tests): [`Config::default()`](../src/config/mod.rs). This is the
  config described under [§7](#7-the-built-in-default).

New fields are added with `#[serde(default)]`, so an older stored document keeps loading after an
upgrade (missing keys fall back to defaults).

Relevant environment variables:

| Env | Effect |
|-----|--------|
| `UMAMI_CONFIG_BUCKET` | Use S3 config instead of the built-in default. |
| `UMAMI_SYSTEM_TENANT_ID` | Tenant whose members get the `is:system-tenant` marker (⇒ `admin:system`). |
| `UMAMI_AUTO_INIT=true` | Bootstrap a first tenant + owner when zero tenants exist. |

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
{ "key": "customerNo", "label": "Kundennummer", "type": "string",
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

Code only ever checks **permissions** (bare strings like `write:members`). Roles/scopes/features/
markers are turned into permissions solely by the `apis` mapping — there are no ad-hoc tenant/marker
checks in the route handlers.

---

## 4. Permission catalog

These are all the permission strings umami's own API (`code: "umami"`) recognises. Product APIs
define their own.

| Permission | Gates (umami routes) |
|------------|----------------------|
| `admin:system` | `GET/POST /tenants`, `DELETE /tenants/{id}`, `POST /auth/switch-tenant`, `GET /tenants/{id}/assignable-features`, `POST`/`DELETE /tenants/{id}/features/{code}` |
| `admin:tenant` | `GET`/`PATCH /tenants/{id}`, `PATCH …/status`, `PATCH …/license`, packages + entitlements, `GET /tenants/{id}/audit` |
| `write:members` | users CRUD + admin password reset, service-key create/list/delete, `GET /users/{id}/assignable-roles`, `GET /tenants/{id}/assignable-scopes` |
| `manage:config` | `GET`/`PUT /config` |
| `write:usage` | `GET`/`POST /tenants/{id}/usage` (metering) |
| `messaging:self` | `/auth/me/messaging-code` (+regenerate), `/auth/me/messaging-links` (+unlink) |
| `messaging:link` | `POST /messaging/links` (bot backend claims a mapping) |
| `messaging:resolve` | `GET /messaging/resolve` (identity → user info / token) |

**Authenticated but permission-free** (any valid token): `GET /auth/me`, `POST /auth/logout-all`,
`POST /auth/me/password`, PAT management under `/auth/me/api-keys`, `POST /auth/exchange`,
`GET /config/custom-fields`, plus login/refresh/logout, JWKS and the MFA ceremonies.

---

## 5. The built-in default

The default `apis[0]` (`umami`) ships this mapping (ordered):

| `when` | `grant` |
|--------|---------|
| `role:owner` | `admin:tenant`, `write:members`, `manage:config`, `write:usage` |
| `role:admin` | `write:members`, `write:usage` |
| `role:member` | `write:usage` |
| `is:system-tenant` | `admin:system` |
| `is:messaging-configured` | `messaging:self` |
| `scope:messaging-linker + is:system-tenant` | `messaging:link` |
| `scope:messaging-resolver + is:system-tenant` | `messaging:resolve` |

Default **roles**: `role:owner`, `role:admin`, `role:member`, `role:viewer` (all `assignableIf`
omitted). Default **scopes**: `scope:messaging-linker`, `scope:messaging-resolver` (both
`assignableIf: "is:system-tenant"`). No default features/limits/packages/custom fields.

> ⚠ **`role:viewer` has no mapping** in the default — a viewer gets zero permissions, and there is
> no read-only permission in the umami API (listing users needs `write:members`). If you want
> viewers to read, add a permission and map it (see the standard config below).

---

## 6. Proposed standard config

A fuller starting point. It keeps the built-in umami mapping, **adds a read permission for
viewers**, shows a licensed feature/scope, and adds a product-API entry with eligibility + claims.

```jsonc
{
  "version": 1,
  "roles": [
    { "code": "role:owner",  "name": "Owner" },
    { "code": "role:admin",  "name": "Administrator" },
    { "code": "role:member", "name": "Member" },
    { "code": "role:viewer", "name": "Viewer" }
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
    { "key": "customerNo", "label": "Customer no.", "type": "string", "required": false, "showInTable": true }
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
        { "when": "role:owner",  "grant": ["admin:tenant","write:members","manage:config","write:usage"] },
        { "when": "role:admin",  "grant": ["write:members","write:usage"] },
        { "when": "role:member", "grant": ["write:usage"] },
        { "when": "role:viewer", "grant": ["read:members"] },
        { "when": "is:system-tenant", "grant": ["admin:system"] },
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

> Note: `read:members` above is *illustrative* — if you add it, also gate the umami list routes on
> it in code (they currently require `write:members`). The config can only mint permissions; which
> permission a route requires is decided in the handler.

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
