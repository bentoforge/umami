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

## Phase 4 — Config (catalog + settings)  *(see [CONFIG.md](CONFIG.md))*

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
- [ ] Features + custom fields + configurable token claims

*(Teams and cross-tenant switching remain post-v1 — see SCHEMA.md.)*

## Phase 5 — MFA

- [ ] `auth/totp.rs` — `POST /auth/mfa/totp/setup` (provisioning secret/QR) + `/verify`; encrypt
      `totpSecret` at rest
- [ ] Fold MFA challenge into `/auth/login` (return challenge instead of token when MFA enabled)
- [ ] `auth/webauthn.rs` — `webauthn-rs` register (`start`/`finish`) + login (`start`/`finish`);
      `webauthn-credentials` table (PK `userId`, SK `credentialId`) + `CredentialIndex` GSI
- [ ] 🟢 TOTP + WebAuthn ceremonies pass; login MFA branch tested

## Phase 6 — CRM / licensing

- [ ] Tenant `status` transitions (`Lead`…`Churned`), `plan`/`billedUntil`/`seatsLimit`;
      `PATCH /tenants/{id}/status`, `PATCH /tenants/{id}/license`
- [ ] Usage metering: `POST /tenants/{id}/usage/ai-tokens` (increment + period rollover),
      `GET /tenants/{id}/usage`
- [ ] 🟢 status/license/usage routes with rollover tested

## Phase 7 — TypeScript SDK (`clients/typescript/`)

- [ ] `login`/`logout`/`getMe`; in-memory access token; auto-refresh-on-401 fetch
      wrapper; `credentials: 'include'`
- [ ] WebAuthn wrappers (`registerPasskey`/`loginWithPasskey`)
- [ ] Type generation from the Rust contract (OpenAPI or emitted TS types) so SDK can't drift
- [ ] npm publish from subdirectory via CI
- [ ] 🟢 SDK builds; typecheck green against server contract

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

## Working agreement

- One step at a time; do not start the next step before the current green gate passes.
- Grep the reference repos before inventing a pattern.
- Curly braces on every `if`. Never log secrets/tokens/hashes.
