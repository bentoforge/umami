# umami — Configuration Model (authoritative)

The **config** is the catalog + system settings that define the *shape* of the system (which roles,
features, packages, limits, custom fields exist; security settings; token composition). It is read
often, written rarely, and small — so it is loaded and saved as **one whole document**, cached in
memory, and edited by the client (load → edit → write the whole thing back).

## The split (catalog vs assignments)

| Layer | What | Where |
|-------|------|-------|
| **Config** (this doc) | role/feature/limit/package **definitions**, custom-field **schemas**, security settings, token-claim composition | `ConfigRepository` (one document) |
| **Assignments + values** | `user.roles`, `tenant.packages` (accounting records), per-tenant feature overrides, custom-field **values** | on the entities (DynamoDB; accounting is optimistic-locked) |

"Which roles exist" = config. "A user has roles" = assignment. "Which features exist" = config.
"Per tenant on/off/standard" = override.

## `ConfigRepository` (trait — like `KeyRepository`)

- `current() -> Arc<Config>` — cached, periodically refreshed (no per-request I/O; umami only reads
  config at login/refresh, not on the product-service hot path).
- `save(&Config) -> Result<()>` — writes the whole document (optimistic concurrency via `version`).
- Impls:
  - **`S3ConfigRepository`** (production): whole `config.json` in S3 — `cached_object(bucket, key,
    ttl)` for reads, `put_object` for writes. Falls back to `Config::default()` if the object is
    absent (clean first-boot). S3 versioning gives free history/audit.
  - **`StaticConfigRepository`** (dev/tests/no-S3): serves a built-in `Config::default()`.
  - Selection: S3 when `UMAMI_CONFIG_BUCKET` is set, else Static.
- **Live editing** is client-driven: `GET /config` → edit → `PUT /config` (whole doc, admin-gated).

## `Config` entity (JSON; money/limits as `rust_decimal::Decimal`)

```jsonc
Config {
  version: u64,                 // optimistic-concurrency counter for save()
  roles:    [ { code, name, permissions: ["manage-users","delete-user", …] } ],
  features: [ { code, name } ],
  limits:   [ { code, name, unit?: string, default?: Decimal } ],
  packages: [ { code, name,
                features: ["ai","export"],                 // feature codes turned on
                limits:   [ { code: "ai-tokens", value: Decimal } ],  // limits raised
                prices:   [ { validFrom: Date, price: Decimal } ] } ],
  customTenantFields: [ { key, label, type, … } ],
  customUserFields:   [ { key, label, type, … } ],
  security: { minPasswordLength: u32, accessTtlSecs: u64, refreshTtlSecs: u64 },
  tokenClaims: [ … which optional claims to include … ]
}
```

**Numerics:** all money/limit values use `rust_decimal::Decimal` — exact decimal, **never `f64`**;
serialized as a precise decimal (and stored as DynamoDB `N`, which is exact).

## Roles → permissions (replaces the Phase-3 provisional map)

- `User.role` → **`User.roles: [code]`** (a list).
- The token's `permissions` claim = **union** of `config.roles[code].permissions` over the user's
  roles.
- umami's own admin routes still require specific permission strings (e.g. `admin:tenant`,
  `write:members`); the **default config** grants those to `owner`/`admin`. Redefining roles so
  they no longer grant them is the admin's responsibility (umami may reserve a few strings later).

## Features & limits resolution (pure function of config + tenant)

- **Effective features** = union of the active packages' features, then per-tenant override
  (`standard` = inherit / `on` = force on / `off` = force off).
- **Effective limits** = raised by the active packages, then per-tenant override (explicit value,
  or empty → computed from packages).

## Accounting & consistency

- `tenant.packages`: `[{ code, assignedAt, accountedUntil, monthlyPrice?, priceFixedUntil, active }]`
  on the tenant entity (same package `code` may appear multiple times). This already covers most of
  licensing + accounting.
- **No stale reads for accounting.** Consistency-critical writes use **optimistic locking**: a
  `version` field + a conditional write (`condition: version = :expected`, `SET version = :expected
  + 1`); on `ConditionalCheckFailedException`, re-read and retry. Read-modify-write reads the base
  table **strongly consistent** (`get_item(...).consistent_read(true)`). **Never** read accounting
  state from a GSI (GSIs are always eventually consistent). Pure counters (usage metering) use the
  atomic `ADD` update expression (no read).
- **Uniqueness reminder** (confirmed against dbx-core's `AssetRepository`): a conditional write
  enforces uniqueness only on an item's **own primary key**; a GSI never does. `AssetRepository`
  guards only its PK (random `assetId`) and deliberately allows duplicate `assetName`s. So config
  codes are the **PK** of their item (uniqueness free); a unique secondary attribute needs a guard
  item (as `user-emails` does).

## Build order (sub-steps)

1. **Foundation** — `config` module + `ConfigRepository` trait + S3/Static impls + `Config`
   entity + `Config::default()`; `User.role` → `roles: [code]`; config-driven permission
   resolution in login/refresh; `GET`/`PUT /config` (admin-gated).
2. **Security settings** — enforce `minPasswordLength` on user/owner creation; take access/refresh
   TTLs from config.
3. **Packages + accounting** — `tenant.packages`, optimistic locking (`version`), price schedule,
   effective-limits resolver.
4. **Features + custom fields + configurable claims**.
