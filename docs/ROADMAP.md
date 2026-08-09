# umami — Implementation Roadmap

Step-by-step plan derived from [PLAN.md](../PLAN.md). We implement **one step at a time**; each
step ends with a **green gate**: `cargo fmt --check && cargo clippy -- -D warnings && cargo build
&& cargo test`. Check items off as we go.

**Legend:** `[ ]` todo · `[~]` in progress · `[x]` done · 🟢 = green gate required here.

---

## Phase 0 — Repo & scaffolding  ✅ DONE

- [x] `git init`, directory layout (`src/`, `http/`, `docs/`, `clients/typescript/`)
- [x] `.gitignore`, `.env.example`
- [x] `README.md`, `CLAUDE.md`, this `ROADMAP.md`
- [x] `Cargo.toml` — binary crate `umami`, wasabi `2.6.0` (`aws_dynamodb`); AWS SDK + crypto
      features reconciled against wasabi's lockfile. Auth crates are added per-phase (kept lean).
- [x] `src/main.rs` — strict-lint block from dbx-core, `app()` boots `run_webserver` with only
      `get_info_route()`
- [x] 🟢 `cargo fmt/clippy/build/test` green; `cargo run` boots and `GET /info/v1` responds
      (verified 200 with `{app,version,clusterId,taskId}`; unknown route → 404)

> **Note — `constants.rs` moved to Phase 1.** Under the strict `#![deny(warnings)]` lints, an
> unused `pub const` in a *binary* crate triggers `dead_code` and fails the build. So constants
> land together with their first consumer (matching how dbx-core keeps every constant used), not
> as an orphan module. Prepared content: `MAX_TEXT_BODY_SIZE`, permission strings
> (`admin:tenant`, `write:members`, `write:teams`), `REFRESH_COOKIE_NAME`, access/refresh TTL
> defaults.

## Phase 1 — Skeleton service  ✅ DONE

- [x] Wire `Authenticator::from_env()` into `app()`; expose wasabi's `get_user_info_route`
      (consumes the authenticator, so the wiring is exercised)
- [x] Stub `GET /.well-known/jwks.json` returning an empty key set (`auth/tokens.rs`)
- [x] `auth/mod.rs` module skeleton
- [x] 🟢 boots with auth wired; JWKS stub → `{"keys":[]}`, `/user-info/v1` without token → 401,
      `/info/v1` → 200

> **Deferred to Phase 2 (dead-code discipline):**
> - **`DynamoClient::from_env()`** — has no consumer until the first repository, so wiring it now
>   would be an unused binding. It lands with the `users` repository in Phase 2, which is also the
>   first real AWS boot test (needs `aws sso login --profile dbx-dev`).
> - **`constants.rs`** — no consumer in Phase 1 (the JWKS stub needs none); lands with login.
> - **Claim-assembly helper** — needs a real user/tenant to assemble from; lands with token issuance.

## Phase 2 — Users + password login + token issuance  ✅ DONE  *(the crux)*

- [x] `constants.rs` + `DynamoClient::from_env()` wiring (deferred from Phase 1)
- [x] `users/` — `User` entity (`userId`, `email`, `name`, `locale`, `passwordHash`, `status`,
      `tokenVersion`, timestamps); `DynamoUserRepository`. **Email uniqueness + lookup via a
      dedicated `user-emails` table** (conditional put) instead of an `EmailIndex` GSI — strongly
      consistent for both login and uniqueness (the PLAN allowed this alternative).
- [x] `auth/password.rs` — argon2id hash/verify (default params; tuning is a Phase-8 concern)
- [x] `auth/tokens.rs` — **ES256** signing via `jsonwebtoken` + `EncodingKey::from_ec_pem`;
      wasabi-compatible claims; real `GET /.well-known/jwks.json` (P-256 JWK with `kid`, derived
      via `p256`). **Keys behind a `KeyRepository` trait** (`EnvKeyRepository` now; AWS+refresh
      later) — see [[umami-key-repository]].
- [x] `auth/session.rs` — `Session` entity + `sessions` table (PK `sessionId`); create/get/
      rotate/delete; stores only `hash(refreshSecret)`; numeric `ttl` attribute written so a
      DynamoDB TTL can self-clean once enabled out-of-band (`ByUserIndex` GSI deferred to Phase 3
      with logout-all/device-list; TTL enablement deferred to Phase 8/ops).
- [x] `auth/cookies.rs` — build/parse `HttpOnly; Secure; SameSite=Lax; Path=/auth` refresh cookie
- [x] `auth/login.rs` — `POST /auth/login`, `POST /auth/refresh` (rotation + reuse detection,
      PLAN §5.5), `POST /auth/logout`. Dev-bootstrap `POST /users` gated by
      `UMAMI_ALLOW_OPEN_SIGNUP` (Phase 3 replaces with permission gating).
- [x] 11 unit tests (password, cookie build/parse, refresh-secret, JWK export, ES256 sign→verify)
- [x] 🟢 **Interop verified** end-to-end against real DynamoDB (`dbx-dev`): umami's own wasabi
      `Authenticator` (identical JWKS+ES256 path a product service uses) accepts an umami-issued
      token on `/user-info/v1` → **200**; login/refresh-rotation/reuse-detection/logout all pass.
      *(Pointing dbx-core at umami is the same config; a live dbx-core run wasn't needed to prove
      the path. EdDSA remains unexplored — ES256 confirmed working.)*

> **Model note (see [SCHEMA.md](SCHEMA.md), which supersedes PLAN.md §3):** tenant **owns** user
> (no memberships table); global email identity; **no** parent-tenant and **no** switch-tenant in
> v1 (one tenant per user → the `tenant` claim is always the home tenant). Cross-tenant is a
> *later* feature built on user-invites. Teams are deferred (a separate authz axis).

## Phase 3 — Tenants + tenant-owned users + role→permissions + /auth/me  ✅ DONE

- [x] `tenants/` — `Tenant` entity (id/name/slug + status/plan/usage), `DynamoTenantRepository`,
      `POST /tenants`, `GET /tenants/{id}`, `PATCH /tenants/{id}` (name/plan)
- [x] Extend `User` — `tenantId` (owning tenant) + `role` (`owner`/`admin`/`member`/`viewer`) +
      `ByTenantIndex` GSI (list a tenant's users)
- [x] `POST /tenants` creates the tenant **and its first `owner` user** — self-serve bootstrap
      gated by `UMAMI_ALLOW_SIGNUP`, **replacing** the `UMAMI_ALLOW_OPEN_SIGNUP` hack
- [x] `POST /users` gated behind `write:members`, scoped to the caller's tenant; `GET /users`
      (list), `PATCH /users/{id}` (role/status)
- [x] Role→permission resolver (provisional map); login/refresh bake **real** `permissions` (from
      role) and `tenant` (= home tenant) into the token
- [x] `auth/me.rs` — `GET /auth/me` (user + tenant, fresh from the store)
- [x] `POST /auth/logout-all` — atomic `tokenVersion` bump
- [x] 🟢 Verified live (DynamoDB): signup → owner token carries `admin:tenant`+`write:members` and
      the tenant claim; owner creates member+viewer; **viewer (perms `[]`) is 401 on `POST /users`**;
      GET/PATCH tenant work; logout-all → owner refresh 401; interop `/user-info/v1` still 200.

> `sessions` `ByUserIndex` GSI deferred to the device-list/per-device-logout feature (logout-all
> works via the `tokenVersion` bump alone). Sequential tenant→owner and email-guard→user writes
> carry a small orphan risk pending `TransactWriteItems` (hardening).

## Phase 4 — Config (catalog + settings)  ✅ DONE  *(see [CONFIG.md](CONFIG.md))*

Replaces the struck "user invites" phase: the permission model is now **config-driven**. A
`ConfigRepository` (trait, cached, like `KeyRepository`) serves one whole `Config` document
(roles/features/limits/packages/custom-fields/security/claims). Sub-steps:

- [x] **Foundation** — `config/` module + `ConfigRepository` trait + `S3ConfigRepository` +
      `StaticConfigRepository` (`Config::default()`); selection via `UMAMI_CONFIG_BUCKET`
- [x] `User.role` → **`roles: [code]`**; permissions = union of `config.roles[code].permissions`
      (replaced the Phase-3 provisional hardcoded map)
- [x] `GET`/`PUT /config` (gated by `manage:config`; PUT uses optimistic `version` concurrency →
      409 on mismatch; client loads → edits → writes the whole doc)
- [x] 🟢 Verified live: default config boots; owner token carries config-resolved permissions;
      `/config` GET/PUT round-trips with a version bump; stale PUT → 409; viewer (perms `[]`) → 401
- [x] Security settings: `minPasswordLength` enforced on user/owner creation; access/refresh TTLs
      taken from `config.security` (no longer env)
- [x] Packages + accounting: `tenant.packages` (assignment records) + `POST`/`DELETE
      /tenants/{id}/packages`; **optimistic locking** (`version` + conditional write, 409 on
      conflict) + strongly-consistent tenant reads; effective-limits + monthly-price resolvers;
      `GET /tenants/{id}/entitlements`. Verified live: entitlements resolve (limit 1000, total 79);
      **10 concurrent assigns → 2×200 + 8×409** (lock holds)
- [x] Features + custom fields + configurable token claims: per-tenant `FeatureToggle`
      (standard/on/off) + `effective_features`; `PUT /tenants/{id}/features/{code}`; `features` in
      entitlements; config-defined custom tenant/user fields, schema-validated on write;
      `config.tokenClaims` drives extra JWT claims (`features` + selected custom user fields).
      Verified live: feature inherit/off propagates to entitlements and the token; custom-field
      validation (unknown/wrong-type → 400)

*(Teams and cross-tenant switching remain post-v1 — see SCHEMA.md.)*

## Phase 5 — MFA  ✅ DONE

- [x] `auth/totp.rs` — `POST /auth/mfa/totp/setup` (secret + otpauth URL) + `/verify` + `/disable`;
      secret **encrypted at rest** (AES-256-GCM, `auth/secretbox.rs`, key from `UMAMI_MFA_KEY`);
      pending→active on verify
- [x] MFA challenge folded into `/auth/login`: `totpCode` optional; enabled + no code →
      `{mfaRequired:true}` (no token/cookie); wrong code → 401; correct code → token
- [x] 🟢 TOTP verified live: setup → verify(wrong 401 / right enabled) → login challenge → wrong
      401 → right token → disable → login without code succeeds
- [x] `auth/webauthn.rs` — `webauthn-rs` register (`start`/`finish`) + passwordless login
      (`start`/`finish`); `WebauthnService` + `webauthn-credentials` (PK `userId`, SK
      `credentialId`) and `webauthn-ceremonies` (PK `ceremonyId`, TTL) tables; ceremony state
      persisted between start/finish and consumed once (delete-and-return); login reuses the shared
      `issue_session`. RP config from `UMAMI_WEBAUTHN_RP_ID`/`UMAMI_WEBAUTHN_ORIGIN`.
      *(`CredentialIndex` GSI deferred — email-first flow queries by `userId`; add it for
      discoverable/usernameless login.)*
- [x] 🟢 WebAuthn register + authenticate ceremony passes headless (soft-authenticator integration
      test, state round-tripped through JSON); HTTP wiring smoke-tested live (register/start →
      options; no-token 401; no-passkey 401; bad ceremony 400)

## Phase 6 — CRM / licensing  ✅ DONE

- [x] `PATCH /tenants/{id}/status` (CRM status `Lead`…`Churned`), `PATCH /tenants/{id}/license`
      (`plan`/`billedUntil`/`seatsLimit`), both `admin:tenant`, optimistic-locked
- [x] Usage metering — **generic per-metric** `POST /tenants/{id}/usage/{metric}` (atomic `ADD`)
      + `GET /tenants/{id}/usage`, gated by `write:usage`. Counters live in a `usage` table keyed
      by `{period}#{metric}` (period = calendar month → **rollover is automatic**, no reset logic).
      **Quotas resolved from the config limits/entitlements**, not stored inline — so the inline
      `aiTokensUsed`/`aiTokensQuota`/`usagePeriodStart` fields were dropped from `Tenant`.
- [x] 🟢 Verified live: status→Onboarding; license→pro/billedUntil/seats; meter ai-tokens 300 then
      800 → used 1100 vs entitlement limit 1000 → `overQuota` flips true; GET usage lists the
      period's metrics; negative amount → 400

## Phase 6b — API keys (machine-to-machine & frontend)  ✅ DONE  *(see [API-KEYS.md](API-KEYS.md))*

Modes shipped: **1) key + Origin allowlist** (frontend) and **3) BFF** (raw exchange server-side).
**Mode 2 (signed HMAC)** deferred.

- [x] `api-keys` table (PK `keyId`, `tenantId` + `ByTenantIndex`, `secretHash`, `roles`, `name`,
      `status`, `allowedOrigins`, `expiresAt?`, `lastUsedAt?`) + repo
- [x] `POST /auth/token` — raw `umk_<keyId>_<secret>`, `sha256` constant-time compare; issues an
      access token (no session/cookie), `sub = keyId`, `kind: "api_key"`, `tenant` + permissions
      from the key's roles via config; best-effort `lastUsedAt`
- [x] Mode 1: `allowedOrigins` enforced against the browser `Origin` header (missing/foreign → 403).
      The tenant quota (usage/entitlements from Phase 6) is the real cost cap.
- [x] `POST`/`GET`/`DELETE /tenants/{id}/api-keys` (`write:members`; create returns the secret
      once; list omits the secret; delete revokes)
- [x] 🟢 Verified live: create → exchange → machine token accepted on a protected route (interop
      200); wrong/revoked key → 401; Origin allow-list (403 / 403 / 200); permissions from role
- [ ] *Deferred:* Mode 2 signed HMAC (`nonces` table + freshness); rate-limit on `/auth/token`
      (Phase 8)

> A browser-exposed key is treated as semi-public (Mode 1) and capped by quota; Modes 2/3 keep the
> secret off the browser/wire. Framing (which shop may embed) = CSP `frame-ancestors`, not the key.

## Phase 7 — TypeScript SDK + admin UI  ✅ DONE

**SDK** (`clients/typescript/`, `umami-client`):
- [x] `UmamiClient`: `login`/`refresh`/`logout`/`logoutAll`/`getMe`, in-memory access token +
      **auto-refresh-on-401** fetch wrapper (`credentials:'include'`), `getClaims`/`hasPermission`
- [x] WebAuthn wrappers (`registerPasskey`/`loginWithPasskey` over `navigator.credentials`, with
      base64url↔buffer helpers), TOTP, API-key `exchangeApiKey`, and tenant/user/config/api-key CRUD
- [x] Full request/response **types** hand-mirrored from the Rust contract (`src/types.ts`);
      `UmamiError` carries status + body. *(OpenAPI/codegen is a future anti-drift option.)*

**UI** (`clients/ui/`, `umami-ui`) — React 18 + Vite + Tailwind + i18next, TSX, analogous to
`dpp-ui`, consuming the SDK via `file:../typescript`:
- [x] Login-starter: login screen (+ MFA challenge field + passkey button), authenticated shell
      reading `/auth/me`, permission chips from the token, i18n (en/de), dev proxy to umami
- [x] 🟢 Verified: both packages typecheck + build; **live browser E2E** — SPA → SDK → umami login
      → dashboard shows the owner + tenant + decoded permissions

- [ ] *Deferred:* npm publish via CI (Phase 8); fuller admin screens (users/keys/config editor);
      optional `@durablox/ui` component lib; serving the built UI from S3 via umami (like dbx-core)

## Phase 7b — Audiences & token projection  ✅ DONE  *(see [AUDIENCES.md](AUDIENCES.md))*

umami is now a **token broker**: it mints tokens for any target API in the config `apis` catalog,
each with its own `aud`, eligibility gate, permission projection and claim mapping.

- [x] `config.apis: [ApiDef]` — `code`, `audience`, `passthrough`, `eligibility` (bool expr),
      `permissions` (rule map `expr → [perm]`), `claims` (`name → source`). Mini-DSL: `,`=OR,
      `+`=AND over **S = permissions ∪ features**. Default config ships the `umami` API
      (`passthrough`, `claims:{features}`); top-level `tokenClaims` superseded (kept for back-compat).
- [x] `auth/broker.rs` — shared `mint_for_api(MintParams)`: resolve API → eligibility (403) →
      `project_permissions` → `build_claims` (+ `kind` for machine tokens) → sign with `aud`.
- [x] **Three mint paths**, all through the broker:
      login `POST /auth/login {api?}` **and passkey `…/webauthn/login/finish {api?}`** (session
      records `api_code`; refresh reuses it),
      API-key `POST /auth/token {apiKey, api?}` (key carries `apis:[code]`, default `["umami"]`),
      user downstream `POST /auth/exchange {api}` (authenticated, no session).
- [x] `AccessTokenClaims.audience`, `Session.api_code`, `ApiKey.apis` (+ create/view/DSL).
- [x] SDK: `Config.apis`/`ApiDef`, `ApiKey.apis`, `login(…, api?)`, `exchangeApiKey(key, api?)`,
      new `exchange(api)`. Rust 30 tests green (4 new config tests); live-verified: login-with-api,
      refresh keeps `aud`, unknown-API 400, key multi-API selection (400/403 guards), api-key `kind`.
- [ ] *Deferred:* `perm:`/`feat:` DSL namespacing; per-API rate limits; audience-scoped key-creation
      restrictions.
- [x] 🟢 Full non-`umami` projection verified **live** against a real S3-backed config (added a
      `dbx-core` API via `PUT /config`): `login {api:"dbx-core"}` → `aud=dbx-core`, permissions =
      union of matching DSL rules, claims mapped, base perms filtered; eligibility-403 confirmed.

## Phase 7c — S3 config store: auto-provision + versioning  ✅ DONE

- [x] `S3ConfigRepository` now **auto-creates** its bucket on boot (like each repo's DynamoDB table)
      and uses wasabi's naming schema: `UMAMI_CONFIG_BUCKET` is the **prefix**, effective bucket
      `<prefix>.<S3_BUCKET_SUFFIX>` (no more `FullyQualifiedName`).
- [x] **Bucket versioning** enabled on boot for config rollback, via a new wasabi primitive
      `S3Client::enable_versioning(bucket, Option<VersionRetention>)` (**wasabi 2.7.0**). Optional
      noncurrent-version retention from env: `UMAMI_CONFIG_VERSIONS_KEEP` (keep newest N) /
      `UMAMI_CONFIG_VERSIONS_EXPIRE_DAYS` (expire after N days) → S3 lifecycle rule.
- [x] Best-effort: a missing `s3:PutBucketVersioning`/`s3:PutLifecycleConfiguration` grant logs a
      WARN instead of crashing the service (versioning is a durability nicety, not a boot gate).
- [x] Live-verified against dbx-dev: bucket auto-created as `<prefix>.<suffix>` + config.json seeded
      + service boots. Versioning/retention calls fire but need the two S3 grants on the deploy role
      to take effect (dev SSO role lacks them). wasabi bumped 2.6.0 → **2.7.0**.

## Phase 7d — Management UI + cross-tenant admin + username identity  ✅ DONE

- [x] **Username identity** (see [SCHEMA.md](SCHEMA.md)): login id is now `username` (required,
      unique case-insensitively, `user-usernames` guard); `email` optional + non-unique; missing
      username defaults to email. Login/passkey/exchange by username; bootstrap login `UMAMI`/`UMAMI`.
- [x] **Cross-tenant admin** (system-tenant only via `UMAMI_SYSTEM_TENANT_ID`, guard
      `enforce_system_tenant`; interim until an `is:system-tenant` feature→permission lands):
      `GET /tenants` (list all, GSI-sorted newest-first), `POST /tenants` (repurposed from
      self-serve — `UMAMI_ALLOW_SIGNUP` removed), `DELETE /tenants/{id}` (only if 0 users; system
      tenant protected). `DELETE /users/{id}` (own-tenant, self-delete blocked).
- [x] **`UMAMI_AUTO_INIT`**: bootstrap system tenant + owner on an empty deployment.
- [x] **GSIs**: tenants `ByLastUpdatedIndex` (constant-partition, injected at write); users
      `ByTenantIndex` now composite (`tenantId` + `lastSeen`, bumped on login+refresh).
      ⚠️ existing dev tables must be recreated (DynamoDB won't alter GSIs in place).
- [x] Repos: Tenant `list_all`/`create_tenant_with_id`/`delete_tenant`; User `delete_user`/`touch_last_seen`.
- [x] **UI** on **react-router-dom**: `AdminLayout` + permission-gated tabs; Tenants
      (list/create/edit/delete), Users (list/create/edit/suspend/delete), Config (crude whole-JSON
      editor, version-checked). Login by username. SDK updated to match.
- [x] 🟢 Verified live (dbx-dev): backend E2E (auto-init, username login, fallback, uniqueness,
      cross-tenant 403 guard, delete guards) + **browser click-through of all four screens**.
- [ ] *Deferred (Schritt 2):* replace the env-based cross-tenant guard with an `is:system-tenant`
      feature → permission projected into the token; cross-tenant user management.

## Phase 8 — Hardening

- [ ] Rate limiting (`/auth/login`, MFA verify — per-IP + per-account backoff)
- [ ] Key rotation (multi-key JWKS with `kid`; `UMAMI_PREVIOUS_KEYS`)
- [ ] Session TTL sweep verification; audit logging
- [ ] CI (`.github`) mirroring dbx-core: fmt, clippy `-D warnings`, build, test (+ `cargo audit`)
- [ ] `http/` request samples; docs polish
- [ ] 🟢 full green + CI green

---

## Non-goals for v1 (do not build)

SAML, SCIM, social login beyond generic OIDC · hosted/branded login UI · single-table DynamoDB
design · an embeddable `umami-core` library crate · instant (sub-token-TTL) revocation at product
services · **M:N user↔tenant memberships · parent-tenant hierarchy · cross-tenant switching ·
teams** (see [SCHEMA.md](SCHEMA.md) — tenant owns user; multi-tenant is a later invite-based
feature).

## Phase 7e — Audit log + self-service password change / admin reset  ✅ DONE

- [x] **Audit log** (`mod audit`, repository pattern): `audit-log` table (PK `id`, GSIs
      `ByUserIndex` + `ByTenantIndex`, both range `timestamp`), fields `id/timestamp/tenant/user/
      severity(good|neutral|bad)/message` + numeric `ttl` (DynamoDB TTL enabled out-of-band via
      Terraform, `UMAMI_AUDIT_RETENTION_DAYS`, default 365). `record_best_effort` never fails the
      request it describes.
- [x] Recorded events: login **good**/**bad**, refresh reuse-detection **bad**, API-key/PAT
      exchange **good**, downstream `/auth/exchange` → no row on success (just `lastSeen` bump; a
      routine "fresher token" would flood the log), **bad** on denial. Read: `GET /auth/me/audit`,
      `GET /tenants/{id}/audit` (admin, own tenant), newest-first, `?limit` capped at 250.
- [x] **Password change/reset** (there was previously no way to change a password): self-service
      `POST /auth/me/password {currentPassword,newPassword}` (verifies current, bumps `tokenVersion`
      → logs out other sessions); admin `POST /users/{id}/password {newPassword?}` (own tenant,
      `write:members`; generates a one-time temp password when omitted, also bumps `tokenVersion`).
- [x] SDK: `changePassword`, `resetPassword`, `myAudit`, `tenantAudit` + `AuditEntry`/`AuditSeverity`.
      UI: change-password panel on Profile, "Reset pw" on Users (temp shown once), an **Audit** tab
      (admin, coloured severity badges).
- [x] 🟢 Verified live (dbx-dev) + browser: wrong password now rejected, self-change invalidates the
      old password, admin reset temp works, audit trail populated & readable per tenant/user.

## Working agreement

- One step at a time; do not start the next step before the current green gate passes.
- Grep the reference repos before inventing a pattern.
- Curly braces on every `if`. Never log secrets/tokens/hashes.
