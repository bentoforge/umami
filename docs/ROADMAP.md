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

## Phase 3 — Tenants + memberships + role→permission resolution

- [ ] `tenants/` — `Tenant` entity (incl. status/plan/usage fields), `DynamoTenantRepository`,
      CRUD routes `POST /tenants`, `GET/PATCH /tenants/{id}`
- [ ] `memberships/` — `Membership` entity (PK `tenantId`, SK `userId`, `role`, `teamIds`,
      `status`), `ByUserIndex` GSI; `PUT/DELETE /tenants/{id}/members/{userId}`
- [ ] Role→permission map (`owner`/`admin`/`member`/`viewer` → wasabi permission strings); resolve
      **effective permissions for the active tenant** at token-issue time and bake into claim
- [ ] `auth/me.rs` — `GET /auth/me` (profile + memberships), `POST /auth/switch-tenant`
      (validate membership → re-issue token scoped to new tenant, update `session.activeTenantId`)
- [ ] `POST /auth/logout-all` — bump `user.tokenVersion`
- [ ] 🟢 login → switch-tenant re-issues token with new `tenant` + permissions; logout-all
      invalidates at next refresh

## Phase 4 — Teams

- [ ] `teams/` — `Team` entity (PK `tenantId`, SK `teamId`), `DynamoTeamRepository`, CRUD
      `POST /tenants/{id}/teams`, list, `PATCH`, `DELETE`
- [ ] Team assignment on memberships (`teamIds` maintenance)
- [ ] 🟢 team CRUD + membership team-assignment covered by tests

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

- [ ] `login`/`logout`/`switchTenant`/`getMe`; in-memory access token; auto-refresh-on-401 fetch
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
services.

## Working agreement

- One step at a time; do not start the next step before the current green gate passes.
- Grep the reference repos before inventing a pattern.
- Curly braces on every `if`. Never log secrets/tokens/hashes.
