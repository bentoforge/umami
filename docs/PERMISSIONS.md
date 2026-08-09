# umami — Permission model (authoritative)

The authorization model is a small **ACL**: users get **roles**, tenants get **features**, and
application code **only ever checks permissions**. Roles and features carry no meaning by
themselves — a per-API **mapping** turns the subject's roles/features into the permissions baked
into a JWT. This keeps product code stable (it checks permissions) while the role/feature→permission
policy evolves in config.

> Supersedes the earlier model where roles carried a `permissions` list and features were derived
> from packages. See `docs/AUDIENCES.md` for the per-API token-broker mechanics this builds on.

## 1. The four subject kinds

| Kind | Prefix | Assigned to | Stored | Example |
|------|--------|-------------|--------|---------|
| **Role** | `role:` | a **user** | `user.roles` | `role:admin` |
| **Scope** | `scope:` | an **API service key** (M2M) | `apiKey.scopes` | `scope:limits-admin` |
| **Feature** | `feature:` | a **tenant** | `tenant.features` | `feature:premium` |
| **Synthetic** | `is:` | — (computed) | never stored | `is:system-tenant` |

- **Roles vs. scopes:** identical mechanics (a label mapped to permissions), but roles are for
  **users** and scopes for **machine (M2M) tokens**. Kept separate on purpose so M2M tokens can be
  granted capabilities **no user role ever maps to** — e.g. a service key of the main app getting
  `read:limits` / `write:limits` in umami, which no `role:*` grants, so no human can hold them.
- **Personal access tokens (PATs)** act as their user, so they carry `role:*`, not scopes. A PAT may
  carry an optional **role restriction** (`role:*` list); its effective roles are then
  `user.roles ∩ pat.roles` (empty list = the user's full roles) — a subject-level down-scope,
  distinct from M2M scopes.
- **Permissions** are the only thing code checks. Bare strings (no prefix): `write:blocks`,
  `admin:tenant`, `manage:config`. They exist **only** in the JWT `permissions` claim — never stored
  on a user/tenant/key, never assigned directly.
- **Synthetic markers** (`is:*`) are computed by the mint layer at token-issue time and are
  **not grantable/revocable**. Today the only one is `is:system-tenant`, added when the token's
  tenant equals `UMAMI_SYSTEM_TENANT_ID`. (Room for more later, e.g. `is:trial`.)

### Subject set `S`
At token-issue time the mint layer builds `S` from the principal + tenant + computed markers:

```
S = { subject labels of the principal }   // a user (or user-acting PAT): its role:*
                                           // an M2M service key:          its scope:*
  ∪ { the tenant's feature:* }             // tenant.features
  ∪ { computed is:* }                      // e.g. is:system-tenant
```

So a **user/PAT** token carries `role:*`, a **service-key** token carries `scope:*`; both add the
tenant's `feature:*` and any synthetic `is:*`. Everything downstream (eligibility, permission
mapping) is pure set-membership against `S`.

## 2. The permission-string DSL

One grammar, used everywhere a condition is expressed:

```
expression := clause ("," clause)*     // "," = OR   (lowest precedence)
clause     := term ("+" term)*         // "+" = AND
term       := ["!"] name               // "!" = NOT (negation)
name       := a subject token, e.g. role:admin | feature:premium | is:system-tenant
```

Evaluation against `S`:
- `expression` holds iff **any** clause holds.
- `clause` holds iff **all** its terms hold.
- `term x` holds iff `x ∈ S`; `!x` holds iff `x ∉ S`.
- Whitespace around terms is trimmed. An **empty** expression holds (no restriction); an empty
  clause (e.g. a stray `,`) is dropped.

Example: `role:admin, feature:premium + !is:trial` = *(admin)* OR *(premium AND not trial)*.

A `name` is either a **subject** (prefixed: `role:` / `scope:` / `feature:` / `is:`) or a **bare
permission** (no prefix, e.g. `write:blocks`). Permission rules are evaluated **in order** and
accumulate: a later rule's condition can therefore reference a permission a **previous** rule already
granted — enabling chaining like `role:admin → write:blocks`, then `write:blocks → read:blocks`
(see §4).

## 3. Config — mapping lives only in `apis`

```jsonc
{
  "roles": [
    { "code": "role:owner", "name": "Owner" },
    { "code": "role:admin", "name": "Administrator" },
    { "code": "role:ai",    "name": "AI user", "assignableIf": "feature:ai" }
  ],
  "scopes": [
    { "code": "scope:limits-admin", "name": "Read/write limits (M2M)" }
  ],
  "features": [
    { "code": "feature:base",    "name": "Base package" },
    { "code": "feature:premium", "name": "Premium", "assignableIf": "feature:base" },
    { "code": "feature:ai",      "name": "AI add-on", "assignableIf": "feature:premium" }
  ],
  "apis": [
    {
      "code": "umami", "audience": "umami",
      "permissions": [                                  // ordered; later rules see earlier grants
        { "when": "role:owner",         "grant": ["admin:tenant","write:members","manage:config","write:usage"] },
        { "when": "role:admin",         "grant": ["write:members","write:usage"] },
        { "when": "role:member",        "grant": ["write:usage"] },
        { "when": "is:system-tenant",   "grant": ["admin:system"] },        // cross-tenant admin (§6)
        { "when": "scope:limits-admin", "grant": ["read:limits","write:limits"] }  // M2M-only
      ]
    },
    {
      "code": "dbx-core", "audience": "dbx-core",
      "eligibility": "role:member, role:admin, is:system-tenant",   // false ⇒ no JWT (403)
      "permissions": [
        { "when": "role:admin",           "grant": ["admin:blocks","write:blocks"] },
        { "when": "feature:ai + role:ai", "grant": ["use:ai"] },
        { "when": "write:blocks",         "grant": ["read:blocks"] }   // chains off an earlier grant
      ],
      "claims": { "svc": "dbx-core" }
    }
  ]
}
```

- **Roles no longer declare permissions.** `RoleDef = { code, name, assignableIf? }`.
- **Scopes** mirror roles for M2M keys. `ScopeDef = { code, name, assignableIf? }`.
- **Features no longer derive from packages.** `FeatureDef = { code, name, assignableIf? }`.
- The **only** place role/scope/feature → permission is mapped is each API's `permissions` — an
  **ordered list** of `{ when, grant }` rules. Rules run top-to-bottom, accumulating: a rule fires
  when its `when` holds against the current set (subjects + permissions granted so far), adding its
  `grant`. The token's permissions are the accumulated set. Ordered (not a map) so chaining is
  well-defined and author-controlled. This makes "which permissions land in the JWT for audience X"
  explicit and per-audience.
- `eligibility` (optional): if present and false against the final accumulated set (subjects +
  granted permissions), **no token is issued for that API** (403). Omitted = always eligible.
- **Retired:** per-role `permissions`, `passthrough`, top-level `tokenClaims`, `permissions_for_roles`.

## 4. Mint flow (per token)

*("mint" = issue + sign a JWT — the `mint_for_api` broker step every login / refresh / API-key
exchange / downstream exchange runs through.)*

1. Build the subject set `subjects`:
   - user / PAT → the user's `role:*` (a PAT with a non-empty `roles` restriction uses
     `user.roles ∩ pat.roles`); service key → the key's `scope:*`;
   - ∪ the tenant's `feature:*`; ∪ computed `is:*` (e.g. `is:system-tenant`).
2. Resolve the target `ApiDef` (login/refresh → `umami` or the session's `api_code`; api-key/PAT →
   the key's chosen api; downstream → the requested api).
3. **Permissions (ordered accumulate):** `granted = {}`; for each rule in `api.permissions` in order,
   if `rule.when` holds against `subjects ∪ granted`, add `rule.grant` to `granted`. Result = `granted`
   (deduped, sorted).
4. **Eligibility:** if `api.eligibility` is set and doesn't hold against `subjects ∪ granted` → 403.
5. **Claims:** `api.claims` (`customUser:*` / `customTenant:*`; literals) — as in AUDIENCES.md, plus
   `kind: "api_key"` for machine tokens. **No `features` claim** by default — everything the product
   needs is cooked into `permissions`.

## 5. Assignability + management

### Roles → users
A role is **assignable to a user** iff its `assignableIf` holds against the **tenant's** feature set
(`feature:*` ∪ `is:*`) — only tenant features are checkable here, never the user's other roles. A
missing `assignableIf` means "always assignable".

- `GET /users/{id}/assignable-roles` → the role codes assignable in that user's tenant (for edit UIs).
- Creating/patching a user validates every assigned role exists **and** is assignable; otherwise 4xx.

### Scopes → API service keys
Scopes work exactly like roles, for M2M service keys: a scope is **assignable to a key** iff its
`assignableIf` holds against the tenant's feature set. `GET /tenants/{id}/assignable-scopes` lists
them (for the key-create UI); creating a service key validates each `scope:*` exists and is
assignable. *(PATs act as their user via `role:*`, so they don't take scopes.)*

### Features → tenants
A feature is **grantable to a tenant** iff its `assignableIf` holds against the tenant's **current**
feature set (this encodes prerequisites, e.g. `feature:premium` requires `feature:base`).

- `GET /tenants/{id}/assignable-features` → grantable, not-yet-granted, non-synthetic feature codes.
- `POST /tenants/{id}/features/{code}` — **grant**; validates `assignableIf` + not synthetic; returns
  the updated `{ features, assignable }`.
- `DELETE /tenants/{id}/features/{code}` — **revoke**; returns the updated `{ features, assignable }`.
  **Rejected** when:
  - `code` is synthetic (`is:*`), or
  - removing it would make another granted feature no longer assignable (i.e. some granted `f`'s
    `assignableIf` no longer holds against `features − code`) — a prerequisite is in use.

`assignableIf` is the single source of dependency; there is no separate `requires` list.

## 6. System tenant via `is:system-tenant` (folds in "Schritt 2")

The mint layer adds `is:system-tenant` to `S` when the token's tenant is the configured
`UMAMI_SYSTEM_TENANT_ID`. The `umami` API maps it to a cross-tenant permission (e.g. `admin:system`),
and the cross-tenant routes (`GET/POST /tenants`, `DELETE /tenants/{id}`) check **that permission**
instead of the env-based `enforce_system_tenant` guard. The interim guard is **removed**; the rule is
now config-expressed and travels in the token.

## 7. Storage & migration

- **User:** `roles: Vec<String>` — now namespaced (`role:owner`, …).
- **API key:** service key (`user_id = None`) → `scopes: Vec<String>` (`scope:*`); PAT
  (`user_id = Some`) → `roles: Vec<String>` (`role:*` restriction, intersected with the user's roles;
  empty = full user roles).
- **Tenant:** gains `features: Vec<String>` — the flat, directly-granted authorization set. The
  billing axis (`packages`, `limitOverrides`, pricing, entitlements, usage metering) is **unchanged**
  and no longer feeds the permission game; package→feature derivation for authorization is dropped.
- **Config default** ships `role:owner|admin|member|viewer`, a couple of demo features, and the
  `apis` mapping that reproduces today's umami admin permissions.
- GSI/schema note: existing dev tables predate the namespacing — recreate with a fresh
  `DYNAMO_TABLE_PREFIX` (or wipe), as before.

## 8. Decisions (resolved)

1. **Permissions are referenceable in the DSL** via ordered, accumulating rules — a later rule can
   match a permission an earlier rule granted (§2/§4).
2. **No `features` claim** — everything the product needs is cooked into `permissions`.
3. **PATs keep a role-level restriction** (`user.roles ∩ pat.roles`), separate from M2M scopes (§1).

## 9. Build phases (each green-gated: fmt / clippy -D warnings / test)

1. **Config + DSL:** new `RoleDef`/`ScopeDef`/`FeatureDef`, `apis` ordered `{when,grant}` rules, DSL
   with `!` + bare-permission terms; default config; unit tests for the DSL and the ordered
   accumulate (incl. chaining + negation).
2. **Mint:** build subjects (principal's `role:*` with PAT `∩`, **or** the key's `scope:*`, plus
   `feature:*` and `is:system-tenant`), ordered permission accumulate + eligibility in the broker;
   retire `permissions_for_roles`/`passthrough`; service keys carry `scopes`, PATs carry a `roles`
   restriction.
3. **Tenant `features` set** + grant/revoke/assignable services (with the revoke-dependency check);
   retire `enforce_system_tenant` in favour of `admin:system`.
4. **Role & scope assignability** + `assignable-roles` / `assignable-scopes`; validate on user
   create/patch and service-key create.
5. **SDK + UI:** assignable-role picker (user editor), assignable-scope picker (key editor), feature
   grant/revoke UI; config editor stays the raw-JSON editor.
