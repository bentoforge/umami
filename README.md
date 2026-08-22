# umami

**A micro-IAM service for B2B SaaS platforms** — the JWT issuer and tenant/membership authority for
a fleet of back-end services. Small, self-hosted, headless, written in Rust.

> **The name.** umami is a **micro IAM** — "µIAM", read *u-IAM* — which slurs neatly into **umami**.
> Small on purpose: it does identity, tenants and token issuance well, and deliberately nothing else.

umami signs short-lived **ES256** access tokens and publishes its public keys at
`/.well-known/jwks.json`, so every downstream service verifies tokens **offline** — no callback to
umami on the hot path, no shared session store, no SDK lock-in. A service trusts umami by
configuration alone.

---

## What it is

A single binary that owns three things for a whole product suite:

1. **Identity & authentication** — who the user is, and proving it.
2. **The B2B tenant model** — tenants (customer accounts), their users, and the roles/features that
   decide what each may do.
3. **Token issuance** — minting audience-scoped JWTs for each API in the fleet, from one login.

Everything else a product needs (its own domain data, its business rules) stays in the product.
umami is the identity boundary, not the application.

## Features

**Authentication**
- Password login with **argon2id** (tuned defaults, PHC-string hashes).
- **TOTP** two-factor (secrets encrypted at rest).
- **WebAuthn / FIDO2 passkeys** — platform passkeys and hardware keys (e.g. YubiKey).
- **Passwordless messaging login** — link a Telegram/WhatsApp identity, then mint tokens for it.
- **Personal access tokens** (act as a user, optionally role-restricted) and **M2M service keys**
  (machine principals carrying `scope:*`).
- Synthetic **auth-strength markers** (`is:passkey` / `is:totp` / `is:2fa`) carried in the token.

**Sessions & tokens**
- `HttpOnly; Secure; SameSite=Lax` refresh cookie with **rotation + reuse detection** (a replayed
  old secret revokes the session), plus a short **grace window** so racing tab refreshes don't trip
  it.
- Short-lived **ES256** access tokens + a **JWKS** endpoint for offline verification.
- **Audience-agnostic sessions**: one cookie mints tokens for *any* API the user is eligible for —
  the target is chosen per request (`/auth/refresh?api=…`), not pinned at login.
- Two revocation levers: bump a user's `tokenVersion` (all sessions) or delete one session (one
  device).

**Tenancy & authorization**
- Tenant → users, with a **config-driven permission model**: subjects (`role:*`, `scope:*`,
  `feature:*`, synthetic `is:*`) are projected to permissions by an ordered, per-API rule list.
- **Per-API audiences**: each downstream service is an entry in the config `apis` catalog with its
  own eligibility gate, permission projection and claim mapping. One user, many audience-scoped
  tokens.
- **Custom fields** on tenants and users (typed, optionally self-editable, optionally surfaced in
  admin tables) — the escape hatch for deployment-specific data without schema changes.

**Operability**
- **Append-only audit log** (severity, actor, client IP) with a DynamoDB-TTL retention window.
- **Config as one live JSON document** (see below): edit it via the API, no redeploy.
- **White-labeling**: accent CSS, logo (light/dark), favicon served at runtime.
- Trusted `X-Forwarded-For` handling (opt-in, spoofing-safe) and credentialed **CORS** allow-list
  for same-site subdomain SPAs.
- Ships a **TypeScript client SDK** and an optional **React management UI**.

## How it differs from Auth0, Keycloak & co.

umami is not trying to be a general-purpose IdP. It is a small, opinionated building block.

| | **umami** | Auth0 / Okta | Keycloak | Cognito / Firebase |
|---|---|---|---|---|
| Deployment | Self-hosted single Rust binary | SaaS (hosted) | Self-hosted JVM (heavy) | Cloud-locked |
| Primary model | **B2B tenant-first** | B2C + B2B add-on | Realms/clients | B2C-first |
| Pricing pressure | None (you run it) | Per-MAU | Free (ops cost) | Per-MAU |
| Login UI | **Headless** (API + your UI) | Hosted pages | Hosted pages/themes | Hosted-ish |
| Token verification | **Offline via JWKS** | JWKS | JWKS | JWKS |
| Config | **One JSON doc, code-reviewable** | Dashboard/Terraform | Admin console/REST | Console/API |
| Scope | Identity + tenants + tokens only | Broad | Very broad (SAML, LDAP, …) | Broad |
| Data store | **DynamoDB-native** | Managed | RDBMS | Managed |

Deliberate non-goals: it is **not** a B2C consumer console, **not** a SAML IdP (bridge SAML→OIDC in
front if you must), and **not** a hosted login-page product. If you want a turnkey consumer identity
cloud, use Auth0/Cognito. If you want a kitchen-sink enterprise IdP, use Keycloak. umami is for
teams running a **fleet of their own B2B services** who want to own identity in a small, auditable,
self-hosted service.

## Architecture at a glance

- Built on the in-house **[wasabi](https://github.com/bentoforge/wasabi)** framework (warp filters,
  `DynamoClient`, JWT `Authenticator`).
- **DynamoDB** for all entities (tables auto-created on boot, prefixed per deployment).
- **S3** for the config document (versioned, cached), when configured.
- **ES256 (P-256)** signing; `jsonwebtoken` + `aws_lc_rs` — one TLS/crypto stack.

```
                       ┌──────────────┐   JWKS (public keys)
   login / refresh ───▶│    umami     │──────────────┐
   (cookie, per API)   │  (IAM core)  │              ▼
                       └──────┬───────┘        ┌───────────────┐
                              │  ES256 JWT     │ product service│  verifies the
                              └───────────────▶│  (wasabi)      │  token OFFLINE
                                 aud=that API  └───────────────┘  (no call back)
```

## Quick start

```bash
# 1. AWS creds for the target account (dev uses AWS SSO)
aws sso login --profile dbx-dev

# 2. Config from the template, then fill the secrets (see below)
cp .env.example .env
#   UMAMI_SIGNING_KEY : openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256
#   UMAMI_MFA_KEY     : openssl rand -base64 32

# 3. Bootstrap the first tenant + owner on an empty deployment
#   set UMAMI_AUTO_INIT=true — the tenant id, username and a one-time password
#   are printed ONCE to the log at startup.
cargo run --features pretty_logs
```

Build & checks:

```bash
cargo build
cargo test
cargo fmt --check
cargo clippy -- -D warnings
```

## Configuration

umami is configured in two layers: **environment** (deployment wiring — endpoints, secrets, AWS) and
the **system config document** (behavior — roles, features, APIs, security policy).

### Environment variables

**Framework (wasabi)**

| Variable | Purpose |
|---|---|
| `APP_NAME` | Service name for logging/telemetry. |
| `BIND_ADDRESS` | Listen address, e.g. `127.0.0.1:8090`. |
| `DYNAMO_TABLE_PREFIX` | Prefix for all DynamoDB tables (isolates deployments). |
| `S3_BUCKET_SUFFIX` | When set, config persists in S3 (bucket `config.<suffix>`); unset ⇒ in-memory. |
| `AWS_PROFILE` / standard AWS creds | Account for DynamoDB + S3. |
| `AUTH_ISSUER`, `AUTH_ALGORITHMS`, `AUTH_AUDIENCE` | How umami validates the tokens on **its own** admin routes (it trusts itself via JWKS). |
| `TRUST_FORWARDED_FOR` | Trust `X-Forwarded-For` for the recorded client IP. Enable **only** behind exactly one trusted proxy — otherwise IPs can be spoofed. |
| `RUST_LOG` | Log filter. |

**Token issuance**

| Variable | Purpose |
|---|---|
| `UMAMI_ISSUER` | The `iss` claim — must exactly match what product services trust (trailing slash included). |
| `UMAMI_SIGNING_KEY` | Active ES256 (P-256) private key, PKCS#8 PEM. Load from a secret store in prod. |
| `UMAMI_SIGNING_KID` | Key id published in the JWKS. |
| `UMAMI_DEFAULT_AUDIENCE` | Fallback `aud` when a call names none. |
| `UMAMI_MFA_KEY` | Key (base64 of 32 bytes) encrypting TOTP secrets at rest. |
| `UMAMI_COOKIE_DOMAIN` | Domain for the refresh cookie. |
| `UMAMI_WEBAUTHN_RP_ID`, `UMAMI_WEBAUTHN_ORIGIN` | WebAuthn relying-party id + site origin. |

**Config store, system tenant, misc**

| Variable | Purpose |
|---|---|
| `UMAMI_CONFIG_KEY` | S3 object key for the config document (default `umami/config.json`). |
| `UMAMI_CONFIG_VERSIONS_KEEP` / `_EXPIRE_DAYS` | Optional noncurrent-version retention for the config bucket. |
| `UMAMI_SYSTEM_TENANT_ID` | Members of this tenant get `is:system-tenant` ⇒ cross-tenant admin. Unset ⇒ those routes are locked. |
| `UMAMI_AUTO_INIT` | On an empty deployment, bootstrap a system tenant + owner (one-time password logged once). |
| `UMAMI_ROOT_USERNAME` | Bootstrap owner username (default `root`). |
| `UMAMI_AUDIT_RETENTION_DAYS` | Days an audit entry lives before its TTL expires it (default 365). |
| `CORS_ALLOWED_ORIGINS` | Exact origins allowed to call umami cross-origin with credentials. |
| `UMAMI_UI_DIR` | Directory of the built management SPA to serve under `/app` (absent ⇒ API-only). |

See [`.env.example`](.env.example) for the fully-commented set.

### The system config

Almost everything about *behavior* lives in **one JSON document**, not in code or env: the catalogs
(roles, scopes, features, custom-field schemas), the security policy (token lifetimes, minimum
password length), the messaging integration, branding, and — the heart of it — the **`apis`
catalog** that maps subjects to permissions per audience.

- **Where it lives.** With `S3_BUCKET_SUFFIX` set, the document is one versioned object in
  `config.<suffix>` (auto-created and seeded with a default on first boot, cached in memory).
  Without it, umami serves a built-in default in memory — non-persistent, for local dev.
- **How it's edited.** Load → edit → write back via the API (`GET`/`PUT /config`), guarded by
  `manage:config` and protected by an optimistic `version` counter. No redeploy.
- **Fail-safe.** If a stored document ever fails to parse, umami logs loudly and falls back to the
  built-in default so the service — and login — stays up; you repair and re-save via `PUT /config`.

The permission model is the important part: umami never hard-codes tenant/role checks in route
handlers. Subjects (`role:*` from the user, `scope:*` from a service key, `feature:*` from the
tenant, synthetic `is:*`) are run through the target API's ordered `permissions` rules to produce the
token's flat permission set. Product services then check plain permission strings.

Full reference: **[docs/CONFIG.md](docs/CONFIG.md)**.

## Documentation

| Doc | What |
|---|---|
| [docs/CONFIG.md](docs/CONFIG.md) | The whole config document + a copy-pasteable standard config. |
| [docs/PERMISSIONS.md](docs/PERMISSIONS.md) | The permission-string DSL and the mint algorithm. |
| [docs/AUDIENCES.md](docs/AUDIENCES.md) | Audiences, the `apis` catalog, and the token-minting paths. |
| [docs/API-KEYS.md](docs/API-KEYS.md) | Service keys vs. personal access tokens. |

The identity/tenancy data model lives in the code: the entity structs (`User`, `Tenant`, `Session`,
…) are the schema, and the model's design rationale is the module doc on
[`src/users/mod.rs`](src/users/mod.rs) — read it via `cargo doc --open`.

## Clients

- **`clients/typescript`** — the `@bentoforge/umami-iam` SDK: login/refresh, token exchange, and
  typed access to every admin route.
- **`clients/ui`** — a Vite/React management UI (tenants, users, API tokens, config, audit, profile),
  optionally served by umami itself under `/app`.

## License

MIT — see [LICENSE](LICENSE).
