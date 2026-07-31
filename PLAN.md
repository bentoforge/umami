# umami — Build Specification

> **umami** = **u**IAM = **micro IAM**. A small, B2B-focused identity & tenant service in
> Rust, built on the in-house **wasabi** framework, hosted natively on AWS (DynamoDB), and
> intended to be published as open source.
>
> This document is the build guide for Claude Code. It is written to be handed to an agent
> that has the `wasabi` and `dbx-core` repositories available for reference. **Follow the
> conventions of those two repos exactly** — this spec describes *what* to build and the
> *design decisions*; wasabi/dbx-core show *how* we write code.
>
> Project language (code, commits, docs): **English**.

---

## 0. Reference repositories (read these first)

| Repo | Path | Use as reference for |
|------|------|----------------------|
| `wasabi` | `../wasabi` (or git `https://github.com/0711sw/wasabi`, tag) | Framework: warp filters, `Authenticator`/`User`, `DynamoClient`, schema helpers, error handling, logging |
| `dbx-core` | `../durablox/dbx-core` | Reference *service* built on wasabi: repository pattern, module layout, `main.rs` wiring, route functions, strict lints, CI |

Concrete files worth copying patterns from:

- `dbx-core/src/main.rs` — service bootstrap, `run_webserver(routes![...])`, dependency wiring via `Arc`.
- `dbx-core/src/blox/repository.rs` — the canonical repository: `#[async_trait]` trait + `#[cfg_attr(test, mockall::automock)]`, `DynamoXRepository { client: DynamoClient }`, `with_client(&DynamoClient)` that calls `create_table`, field-name `const`s, camelCase entities.
- `dbx-core/src/metamodel/service.rs` — the canonical warp route: `pub fn x_api_route(deps) -> BoxedFilter<(impl warp::Reply,)>`, `into_response` / `into_response_with_status`, `with_body_as_string`, `with_cloneable`, `enforce_user_with_any_permission`.
- `wasabi/wasabi-core/src/web/auth/{mod.rs,user.rs,authenticator.rs}` — JWT validation, claim constants, `User` accessors.
- `wasabi/wasabi-core/src/aws/dynamodb/{mod.rs,schema.rs,client.rs}` — `DynamoClient`, `stream_all`, `find_first`, `generate_id()`, `str()`, `ItemBuilder`, `str_attribute`, `with_range_index`, `with_hash_index`, `replicated_range_index`.

---

## 1. What umami is (and is not)

umami is the **identity provider and tenant/membership authority** for a fleet of wasabi-based
B2B SaaS services (e.g. dbx-core / "Produkt-Profi"). It owns:

1. **Authentication** — password login (argon2), MFA via TOTP and WebAuthn/FIDO2 (passkeys +
   hardware keys like YubiKey), account lifecycle.
2. **B2B tenant model** — tenants/workspaces, teams, users, and the many-to-many memberships
   between them, with roles → permissions.
3. **Token issuance** — umami is the **JWT issuer**. It signs short-lived access tokens and
   publishes its public keys via a **JWKS endpoint**. Every wasabi service already knows how to
   trust a JWKS issuer (see §6), so integration is pure configuration — no code change in the
   product services.
4. **A "micro-CRM" + light licensing layer** — per-tenant customer status (lead / testing /
   onboarding / active / …), plan/package, billing period, and usage metering (e.g. AI tokens
   consumed this month). This is **our domain data**, not something off-the-shelf IAM provides.

umami is **NOT**:

- A B2C user-management console or a Keycloak/Auth0 clone.
- A SAML IdP. **Enterprise SSO is OIDC-only.** Customers who need SAML put a broker in front
  that bridges SAML→OIDC. This is a deliberate scope cut to stay "micro". (SCIM provisioning is
  a plausible *later* addition — it's plain REST and does not touch the core.)
- A hosted login UI. umami ships a **headless API + a thin TypeScript client SDK** (see §8). The
  integrating app builds its own UI and calls the SDK. The only server-owned UI-ish surface is
  the OIDC redirect callback for enterprise login (the code↔token exchange must stay
  server-side).

### Design boundary (the one to internalize)

We separate two layers cleanly:

- **Authentication core** (credential storage, token crypto, session invalidation, MFA, OIDC
  flows) — security-critical, built on proven crates, never hand-rolled.
- **Authorization + tenant + CRM/licensing layer** — our own domain model in DynamoDB. This is
  the actual value of umami and where off-the-shelf IAM is too generic.

---

## 2. Crate & repository layout

Follow the `dbx-core` shape: a **single binary crate** depending on `wasabi`, modular
internally. (A future extraction of the domain logic into a reusable `umami-core` library is
possible but explicitly out of scope for v1 — keep it micro.)

```
umami/
├── Cargo.toml                 # binary crate `umami`, depends on wasabi (aws_dynamodb)
├── CLAUDE.md                  # copy dbx-core/CLAUDE.md structure, adapt
├── README.md
├── .env.example
├── http/                      # .http request samples (mirror dbx-core/http)
├── src/
│   ├── main.rs                # bootstrap + route wiring (mirror dbx-core/main.rs, incl. strict lints)
│   ├── constants.rs           # sizes, permission strings, cookie names, TTLs
│   ├── auth/
│   │   ├── mod.rs             # shared auth types, claim assembly
│   │   ├── login.rs           # POST /auth/login (password), route + handler
│   │   ├── session.rs         # session repository (DynamoDB), refresh + rotation + reuse detection
│   │   ├── tokens.rs          # JWT signing (EdDSA), JWKS endpoint, key management/rotation
│   │   ├── password.rs        # argon2 hash/verify
│   │   ├── totp.rs            # TOTP enrol/verify
│   │   ├── webauthn.rs        # WebAuthn register/login ceremonies (webauthn-rs)
│   │   ├── cookies.rs         # HttpOnly refresh-cookie build/parse helpers
│   │   └── me.rs             # GET /auth/me, POST /auth/switch-tenant
│   ├── tenants/
│   │   ├── mod.rs            # Tenant entity (incl. status/plan/usage), enums
│   │   ├── repository.rs     # DynamoTenantRepository
│   │   └── service.rs        # CRUD + status/license/usage routes
│   ├── teams/
│   │   ├── mod.rs
│   │   ├── repository.rs
│   │   └── service.rs
│   ├── users/
│   │   ├── mod.rs            # User entity (identity, mfa, status, token_version)
│   │   ├── repository.rs     # DynamoUserRepository (+ EmailIndex GSI, WebAuthn creds)
│   │   └── service.rs        # invite/create/list/deactivate
│   └── memberships/
│       ├── mod.rs            # Membership entity (tenant↔user, role), team membership
│       ├── repository.rs
│       └── service.rs
└── clients/
    └── typescript/           # thin client SDK (see §8) — SAME REPO (monorepo). See decision below.
```

### Decision: TypeScript client in the same repo (recommended)

Keep the TS SDK in `clients/typescript/` **in the umami repo** for v1:

- Single source of truth for the wire contract; the SDK and server version in lockstep.
- The SDK types can be generated from the Rust side (see §8), so co-location avoids drift.
- CI publishes the npm package from the subdirectory.

Split into a dedicated repo **only if/when**: the SDK gains an independent release cadence, or
you add multiple language SDKs. Until then a separate repo is pure overhead. This is the one
layout decision worth revisiting later; everything else should just follow dbx-core.

---

## 3. Data model

> ⚠️ **Superseded by [docs/SCHEMA.md](docs/SCHEMA.md).** The M:N sketch below was the original
> exploration. The **decided** model is *tenant owns user* (no memberships table), global email
> identity, no parent-tenant and no cross-tenant switching in v1; teams and multi-tenant (via
> invites) are deferred. Read SCHEMA.md for the authoritative entities and endpoints; the section
> below is kept for historical context only.

Interpretation of the requested chain `tenant 1─N team, team M─N user, user 1─N session`:

- A **Tenant** (workspace) has many **Teams**.
- **Users** are **global identities** (one identity, reusable across tenants). Users relate to
  tenants and teams **many-to-many** via **Membership** records.
- A **User** has many **Sessions** (one per device/browser).

Persistence style: **one DynamoDB table per aggregate with GSIs**, exactly like dbx-core (which
uses `blocks` + `entity-locales` tables, not single-table design). All table names get the
`DYNAMO_TABLE_PREFIX`. Entities are serde `camelCase`; every persisted field has a
`const FIELD_*` string, mirroring `dbx-core/src/blox/repository.rs`.

### 3.1 Tenant — table `tenants`

Carries the micro-CRM + licensing fields.

- **PK** `tenantId` (hash only)
- `name`, `slug`
- `status`: enum `Lead | Testing | Onboarding | Active | Suspended | Churned`
- `plan`: string package id (e.g. `free`, `pro`, `enterprise`)
- `billedUntil`: `Date` (ISO `YYYY-MM-DD`), optional
- `seatsLimit`: `u32`, optional
- Usage (current period):
  - `usagePeriodStart`: `Date`
  - `aiTokensUsed`: `u64`
  - `aiTokensQuota`: `u64`, optional
- `created`, `lastUpdated`: `DateTime<Utc>` (RFC3339)

### 3.2 User — table `users` (+ GSI `EmailIndex`)

Global identity + credentials.

- **PK** `userId` (hash only)
- `email` (login identifier) → **GSI `EmailIndex`** (hash on `email`) for login lookup. Enforce
  uniqueness on write via a conditional put keyed on a normalized email (or a dedicated
  `user-emails` lookup table if you prefer strict uniqueness guarantees).
- `name`, `locale` (BCP-47, default `en-US`)
- `passwordHash`: argon2id string (nullable — SSO-only users may have none)
- `status`: enum `Active | Locked | Invited`
- `tokenVersion`: `u32` — the global revocation counter (see §5.4)
- MFA:
  - `totpSecret`: encrypted, optional
  - WebAuthn credentials → **separate table `webauthn-credentials`** (PK `userId`, SK
    `credentialId`) **+ GSI `CredentialIndex`** (hash on `credentialId`) so an assertion can be
    resolved to a user before the user is known.
- `created`, `lastUpdated`

### 3.3 Team — table `teams`

- **PK** `tenantId`, **SK** `teamId` (composite; `with_range_index`)
- `name`, `created`, `lastUpdated`

### 3.4 Membership — table `memberships` (+ GSI `ByUserIndex`)

The tenant↔user M─N join, carrying the tenant-level role. A user can be a member of a tenant
with **zero** teams; team assignments are additive.

- **PK** `tenantId`, **SK** `userId`
- `role`: string role id (see §5.3) — tenant-level role
- `teamIds`: `Vec<String>` — teams within this tenant the user belongs to (a String Set)
- `status`: enum `Active | Invited | Suspended`
- `created`, `lastUpdated`
- **GSI `ByUserIndex`** (hash `userId`, range `tenantId`): lets a user enumerate the tenants
  they belong to (needed at login and for `/auth/me`).

> Team membership is modeled as a list on the membership record rather than a separate
> `team-members` table to keep queries cheap; revisit only if teams need independent metadata or
> huge membership counts.

### 3.5 Session — table `sessions` (+ GSI `ByUserIndex`)

One record per active login (device/browser). This is what makes per-device logout and refresh
rotation possible.

- **PK** `sessionId` (hash only) — the refresh cookie carries this id, so lookup is a direct
  `get_item`.
- `userId` → **GSI `ByUserIndex`** (hash `userId`): list a user's active devices, and revoke all.
- `activeTenantId`: the tenant this session is currently scoped to.
- `refreshHash`: hash (e.g. SHA-256) of the **current** refresh secret. Never store the secret.
- `tokenVersionAtIssue`: snapshot of `user.tokenVersion` when the session was created — a global
  bump invalidates the session at next refresh (ties §5.4 together).
- `deviceLabel`, `userAgent`, `ip` (best-effort, for the device list)
- `created`, `lastSeen`, `expiresAt`: `DateTime<Utc>`. Set a DynamoDB **TTL** on `expiresAt` so
  expired sessions self-clean.

---

## 4. wasabi-compatible access-token claims

umami issues access tokens whose claims exactly match what `wasabi::web::auth::User` reads, so
umami tokens are drop-in for the entire fleet. From `wasabi-core/src/web/auth/mod.rs` the
relevant claims are: `iss`, `sub`, `aud`, `tenant`, `name`, `email`, `locale`, `permissions`
(JSON array), plus standard `exp`/`iat`.

```jsonc
{
  "iss": "https://umami.example.com/",   // must match the AUTH_ISSUER configured in product services
  "sub": "<userId>",                     // User::user_id()
  "aud": "<audience>",                   // configured; validated by wasabi if AUTH_AUDIENCE set
  "tenant": "<activeTenantId>",          // User::tenant_id() — the ONE active tenant
  "name": "<full name>",                 // User::full_name()
  "email": "<email>",                    // User::email()
  "locale": "de-DE",                     // User::locale()
  "permissions": ["write:blocks", "..."],// User::has_any_permission() — resolved for active tenant
  "iat": 1730000000,
  "exp": 1730000900,                     // short: 5–15 min
  "ver": 3                               // custom: user.tokenVersion snapshot (optional but recommended)
}
```

Because a user can belong to many tenants, an access token is **always scoped to exactly one
active tenant**. Switching tenants (`POST /auth/switch-tenant`) re-issues the token with a
different `tenant` and re-resolved `permissions`.

---

## 5. Authentication & session design

### 5.1 Two-token model

- **Access token**: JWT, **5–15 min**, ES256-signed by umami (see §6 on algorithm choice),
  verified **offline** by product services via JWKS. Stateless — no DB hit on the product side.
- **Refresh token**: long-lived (days/weeks), delivered as an **`HttpOnly; Secure; SameSite=Lax`
  cookie**, backed by a server-side `sessions` record. Only umami's refresh endpoint ever sees it.

### 5.2 Browser storage rules (bake into the TS SDK)

- **Access token → in memory only** (JS variable / app state). **Never** `localStorage` /
  `sessionStorage` (XSS-exfiltration vector). On page reload, the SDK does a silent refresh via
  the cookie to obtain a fresh access token.
- **Refresh token → HttpOnly cookie**, not readable by JS.

### 5.3 Roles → permissions

Roles are named permission bundles. Keep them simple and configurable:

- A small built-in set (e.g. `owner`, `admin`, `member`, `viewer`) mapping to wasabi-style
  permission strings (`write:blocks`, `write:assets`, `admin:tenant`, …).
- At token-issue time, umami resolves the user's **effective permissions for the active tenant**
  (from their membership `role`) and bakes them into the `permissions` claim.
- Permission strings are the contract with product services; align them with the constants those
  services already enforce (e.g. `dbx-core/src/constants.rs`: `write:assets`, `write:blocks`,
  `write:descriptors`).

### 5.4 Revocation model — two levers

| Lever | Scope | Mechanism | Use for |
|-------|-------|-----------|---------|
| `user.tokenVersion` | ALL of a user's sessions | bump the integer; refresh checks `session.tokenVersionAtIssue == user.tokenVersion` | ban user, password change, "log out everywhere" |
| session record | ONE device | delete the `sessions` row (or fail refresh-hash match) | single-device logout, rotation/theft response |

**Critical property (same as Auth0/Keycloak):** revocation is **not instant at the product
services**. They verify access tokens offline, so a revoked user keeps working until their
current access token expires. Therefore **access-token TTL = worst-case revocation latency** →
keep it 5–15 min. Revocation bites immediately at the *refresh* boundary (no new access token
issued). Do not try to make product services introspect on every request — that defeats the
stateless design.

### 5.5 Refresh + rotation + reuse detection

Refresh cookie value = `"<sessionId>.<refreshSecret>"` (secret = high-entropy random, ≥32 bytes).

On `POST /auth/refresh`:

1. Parse cookie → `sessionId`, `refreshSecret`.
2. `get_item` session by `sessionId`. If absent → 401.
3. Constant-time compare `hash(refreshSecret)` against `session.refreshHash`.
   - **Match** → continue.
   - **No match, but session exists** → likely a stolen/replayed old token → **revoke this
     session** (and consider bumping `user.tokenVersion` to nuke the family). Return 401.
4. Check `session.expiresAt` not passed; check `user.status == Active`; check
   `session.tokenVersionAtIssue == user.tokenVersion`. Re-check tenant membership still valid and
   (optionally) usage quota.
5. **Rotate**: generate a new `refreshSecret`, store its new hash, extend `expiresAt`, update
   `lastSeen`. Set a new refresh cookie. Issue a fresh access JWT.

### 5.6 Endpoint list

Auth / session:

- `POST /auth/login` — body `{ email, password, tenant? }`. On success: create session, set
  refresh cookie, return `{ accessToken, tenants: [...] }` (tenant list so the client can prompt
  a switch if `tenant` was omitted and the user has several). If MFA is enabled, return an MFA
  challenge instead of a token (see below).
- `POST /auth/refresh` — cookie in → new access token (+ rotated cookie).
- `POST /auth/logout` — cookie in → delete session + `Set-Cookie` clear.
- `POST /auth/logout-all` — authenticated → bump `user.tokenVersion`.
- `POST /auth/switch-tenant` — authenticated + `{ tenant }` → validate membership → re-issue
  access token scoped to the new tenant (update `session.activeTenantId`).
- `GET  /auth/me` — authenticated → user profile + memberships (tenants, roles).
- MFA — TOTP: `POST /auth/mfa/totp/setup` (returns provisioning secret/QR), `POST
  /auth/mfa/totp/verify`. WebAuthn: `POST /auth/webauthn/register/start` + `/finish`, `POST
  /auth/webauthn/login/start` + `/finish`. Treat YubiKey and platform passkeys identically —
  both are WebAuthn.
- `GET /.well-known/jwks.json` — public signing keys (see §6). Also expose
  `GET /.well-known/openid-configuration` if you want standards-friendly discovery.

CRUD (permission-gated via `enforce_user_with_any_permission`):

- Tenants: `POST /tenants`, `GET /tenants/{id}`, `PATCH /tenants/{id}` (name/plan),
  `PATCH /tenants/{id}/status`, `PATCH /tenants/{id}/license`.
- Usage: `POST /tenants/{id}/usage/ai-tokens` (increment, with period rollover), `GET
  /tenants/{id}/usage`. Product services (e.g. the AI features) call this to meter/enforce quota.
- Teams: `POST /tenants/{id}/teams`, list, `PATCH`, `DELETE`.
- Users: `POST /users` (invite/create), `GET /users/{id}`, list within tenant, `PATCH`
  (deactivate/lock).
- Memberships: `PUT /tenants/{id}/members/{userId}` (add/set role + teams), `DELETE` (remove).

### 5.7 Security requirements

- Password hashing: **argon2id** with sane params (tune `m`, `t`, `p`); use the `argon2` crate.
- All secret comparisons constant-time.
- Refresh cookie: `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict` if the flows allow),
  `Path=/auth`, sensible `Max-Age`. Configurable cookie domain.
- CSRF: `SameSite` + an origin/`Origin`-header check on state-changing auth endpoints; the SPA
  and umami are first-party so this is straightforward.
- Rate-limit `POST /auth/login` and MFA verification (per-IP + per-account backoff).
- Never log secrets, tokens, or password hashes. Mirror wasabi's `#[tracing::instrument(skip(...))]`
  discipline.

---

## 6. Integration with wasabi services (the payoff)

wasabi's `Authenticator` already supports **per-issuer JWKS validation** (see
`wasabi/README.md` → `AUTH_ISSUER` syntax and `wasabi-core/src/web/auth/`). So a product service
trusts umami purely via configuration:

```bash
# in the product service (e.g. dbx-core) environment
AUTH_ISSUER=https://umami.example.com/=jwks:/.well-known/jwks.json
AUTH_ALGORITHMS=ES256
AUTH_AUDIENCE=dbx-core           # optional, if you set aud
```

- umami signs with a **private key**; product services fetch the **public key** from umami's
  `/.well-known/jwks.json` and verify **offline**. Never share a symmetric secret across services.
- The `iss` claim umami puts in tokens **must** equal the configured issuer URL (trailing slash
  matters — match wasabi's parsing).
- **Signing algorithm — use `ES256` (P-256).** wasabi's `Authenticator` validates asymmetric
  tokens via the JWKS path and its own docs/tests cite `RS256`/`ES256`; `ES256` is compact,
  modern, and universally supported by JWKS tooling, so it's the safe default. `RS256` is the
  maximally-compatible fallback. **`EdDSA` is only acceptable if you first verify end-to-end that
  wasabi's `jwks` crate + `aws_lc_rs` backend actually accepts an `OKP`/Ed25519 JWK** — do that
  interop test (phase 2) before committing to it; otherwise stay on `ES256`. Whatever you pick,
  set the matching value in the product service's `AUTH_ALGORITHMS`.
- Support **key rotation**: JWKS may expose multiple keys (each with a `kid`); sign with the
  newest, keep the previous published until old tokens expire.

Result: adding umami to an existing wasabi service is a config change, not a code change.

---

## 7. Cargo dependencies

Start from `dbx-core/Cargo.toml` and add the auth-specific crates. Match wasabi-core's AWS SDK
feature flags (`default-features = false`, `default-https-client`, `rt-tokio`) to keep the
lockfile and `cargo audit` posture consistent.

```toml
[package]
name = "umami"
version = "0.1.0"
edition = "2024"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1

[dependencies]
wasabi = { git = "https://github.com/0711sw/wasabi", tag = "<latest>", features = ["aws_dynamodb"] }
tokio = { version = "1", features = ["full"] }
warp = "0.3"
serde = { version = "1", features = ["derive"] }
serde_json = { version = "1", features = ["arbitrary_precision"] }
chrono = { version = "0.4", features = ["serde"] }
anyhow = "1"
async-trait = "0.1"
futures-util = "0.3"
tracing = "0.1"
dotenvy = "0.15"
aws-sdk-dynamodb = { version = "1", default-features = false, features = ["default-https-client", "rt-tokio"] }

# auth core
argon2 = "0.5"                 # password hashing (argon2id)
jsonwebtoken = { version = "10", default-features = false, features = ["aws_lc_rs"] }  # ES256 signing — match wasabi's crypto backend
webauthn-rs = "0.5"            # WebAuthn/FIDO2 (passkeys + YubiKey)
totp-rs = "5"                  # TOTP MFA
rand = "0.9"                   # refresh-secret generation
sha2 = "0.10"                  # refresh-secret hashing
base64 = "0.22"
cookie = "0.18"                # Set-Cookie building (or use warp header helpers)

[dev-dependencies]
mockall = "0.14"               # repository mocking — same as dbx-core
```

> Confirm exact latest patch versions against the current `wasabi` lockfile when building, so
> shared crates (aws-sdk-*, jsonwebtoken) resolve to a single version.

---

## 8. TypeScript client SDK (`clients/typescript/`)

Thin, headless-friendly SDK so integrators don't mishandle cookies, CSRF, WebAuthn ceremonies,
or the silent-refresh loop.

Responsibilities:

- `login(email, password, tenant?)`, `logout()`, `switchTenant(id)`, `getMe()`.
- Holds the access token **in memory**; exposes `getAccessToken()` and an authenticated `fetch`
  wrapper that auto-refreshes on 401 (calls `/auth/refresh`, retries once).
- Wraps WebAuthn: `registerPasskey()` / `loginWithPasskey()` calling
  `navigator.credentials.create/get` and posting to the start/finish endpoints.
- Sends the refresh cookie automatically (`credentials: 'include'`); never touches its value.

Types: generate request/response types from the Rust side (e.g. derive an OpenAPI schema or emit
TS types) so the SDK cannot drift from the server contract. Publish to npm via CI from this
subdirectory.

---

## 9. Coding conventions (copy from wasabi/dbx-core)

- **Strict lints** in `main.rs`: copy the `#![deny(...)]` block from `dbx-core/src/main.rs`
  (denies `warnings`, `missing_docs`, `unsafe_code`, `clippy::unwrap_used`, `expect_used`,
  `panic`, `indexing_slicing`, …), with the same `#![cfg_attr(test, allow(...))]` relaxation.
- **Repositories**: `#[async_trait] pub trait XRepository: Send + Sync { … }` annotated with
  `#[cfg_attr(test, mockall::automock)]`; a `DynamoXRepository { client: DynamoClient }` impl with
  `pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self>` that provisions tables
  via `client.create_table(...)` using the schema helpers. Field names as `const FIELD_*`.
- **Routes**: `pub fn x_api_route(deps…) -> BoxedFilter<(impl warp::Reply,)>`; handlers return
  `anyhow::Result<T>` / `Result<(StatusCode, T)>` and go through `into_response` /
  `into_response_with_status`. Guard with `enforce_user_with_any_permission(authenticator, &[…])`.
- **Errors**: `anyhow::Context` everywhere; convert with wasabi's `ResultExt`
  (`mark_client_error()` / `map_err_to_http()`); use `status_bail!` / `client_bail!`.
- **IDs**: `wasabi::aws::dynamodb::generate_id()` (32-char) for all entity ids.
- **Time**: `chrono` `DateTime<Utc>`, serialize RFC3339.
- **Tracing**: `#[tracing::instrument(level = "debug", skip(self|secrets), err(Display))]` on repo
  and handler fns; name route spans like `"POST /auth/login"`.
- **Tests**: `#[tokio::test]`, `warp::test::request()` for filters (see the auth tests in
  `wasabi-core/src/web/auth/mod.rs`), `mockall` mocks for repositories, `User::builder()` to mint
  test users/tokens.
- **Env / config**: `dotenvy` + `X::from_env()` constructors, exactly like wasabi components.
- **CI**: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo build`, `cargo test`
  (mirror `dbx-core/.github`).

---

## 10. Environment variables

Inherit wasabi's core + auth vars (`BIND_ADDRESS`, `APP_NAME`, `DYNAMO_TABLE_PREFIX`,
`RUST_LOG`, …). umami-specific additions:

| Variable | Description |
|----------|-------------|
| `UMAMI_ISSUER` | Issuer URL placed in `iss` and served in discovery (e.g. `https://umami.example.com/`) |
| `UMAMI_SIGNING_KEY` | Active ES256 (P-256) private key (PEM). Alternatively load from AWS KMS/SSM/Secrets Manager |
| `UMAMI_SIGNING_KID` | Key id for the active key (published in JWKS) |
| `UMAMI_PREVIOUS_KEYS` | Optional: previous public keys to keep in JWKS during rotation |
| `UMAMI_ACCESS_TTL_SECS` | Access-token lifetime (default 600) |
| `UMAMI_REFRESH_TTL_SECS` | Refresh/session lifetime (default e.g. 30d) |
| `UMAMI_COOKIE_DOMAIN` | Domain for the refresh cookie |
| `UMAMI_DEFAULT_AUDIENCE` | Default `aud` for issued tokens |

---

## 11. Implementation phases (suggested order for Claude Code)

1. **Skeleton**: crate, `main.rs` with strict lints, `DynamoClient::from_env`, `run_webserver`
   with `get_info_route()` and a stub JWKS endpoint. Wire `Authenticator::from_env()` for the
   admin-guarded routes.
2. **Users + password login**: `users` table + `EmailIndex`, argon2 in `password.rs`,
   `tokens.rs` (EdDSA sign + JWKS), `sessions` table, `POST /auth/login` + `/auth/refresh` +
   `/auth/logout` with the cookie mechanics and rotation. **Verify JWKS interop by pointing a
   local dbx-core at umami and calling a protected route.**
3. **Tenants + memberships**: tables, repositories, `/auth/me`, `/auth/switch-tenant`, tenant &
   membership CRUD, role→permission resolution baked into the token.
4. **Teams**: table + CRUD, team assignment on memberships.
5. **MFA**: TOTP, then WebAuthn (register + login ceremonies). Fold the MFA challenge into the
   login flow.
6. **CRM/licensing**: tenant `status` transitions, plan/`billedUntil`, usage metering endpoints
   with period rollover.
7. **TypeScript SDK**: implement against the finished API; generate types; set up npm publish.
8. **Hardening**: rate limiting, key rotation, session TTL, audit logging, docs.

Each phase: `cargo fmt` + `cargo clippy -- -D warnings` + `cargo test` clean before moving on.

---

## 12. Explicit non-goals for v1

- SAML, SCIM, social login beyond generic OIDC.
- A hosted/branded login UI.
- Single-table DynamoDB design (use per-aggregate tables like dbx-core).
- An embeddable `umami-core` library crate (possible later extraction; not now).
- Instant (sub-token-TTL) revocation at product services.
