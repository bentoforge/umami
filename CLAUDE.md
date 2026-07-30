# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository. The project language (code, commits, docs) is **English**.

umami is a micro-IAM service built on the in-house **wasabi** framework. It is the JWT issuer and
tenant/membership authority for a fleet of wasabi-based B2B services. The full specification lives
in [PLAN.md](PLAN.md); the step-by-step implementation plan lives in [docs/ROADMAP.md](docs/ROADMAP.md).

## Reference repositories (read these first — follow their conventions exactly)

| Repo | Local path | Use as reference for |
|------|-----------|----------------------|
| `wasabi` | `../../0711sw/wasabi` | Framework: warp filters, `Authenticator`/`User`, `DynamoClient`, schema helpers, error handling, logging |
| `dbx-core` | `../../0711sw/durablox/dbx-core` | Reference *service*: repository pattern, module layout, `main.rs` wiring, route functions, strict lints, CI |

**This spec describes _what_ to build; wasabi/dbx-core show _how_ we write code.** When in doubt
about a pattern, grep the reference repos rather than inventing something.

Concrete files worth copying patterns from:

- `dbx-core/src/main.rs` — bootstrap, `run_webserver(routes![...])`, `Arc` wiring, strict lints.
- `dbx-core/src/blox/repository.rs` — canonical repository: `#[async_trait]` trait +
  `#[cfg_attr(test, mockall::automock)]`, `DynamoXRepository { client: DynamoClient }`,
  `with_client(&DynamoClient)` that calls `create_table`, `const FIELD_*`, camelCase entities.
- `dbx-core/src/metamodel/service.rs` — canonical warp route: `pub fn x_api_route(deps) ->
  BoxedFilter<(impl warp::Reply,)>`, `into_response` / `into_response_with_status`,
  `with_body_as_string`, `with_cloneable`, `enforce_user_with_any_permission`.
- `wasabi/wasabi-core/src/web/auth/{mod.rs,user.rs,authenticator.rs}` — JWT validation, claim
  constants (`CLAIM_SUB`, `CLAIM_TENANT`, `CLAIM_PERMISSIONS`, …), `User` accessors.
- `wasabi/wasabi-core/src/aws/dynamodb/{mod.rs,schema.rs,client.rs}` — `DynamoClient`,
  `stream_all`, `find_first`, `generate_id()`, `str()`, `ItemBuilder`, `str_attribute`,
  `with_range_index`, `with_hash_index`, `replicated_range_index`.

## Build commands

```bash
cargo build
cargo build --features pretty_logs    # human-readable logging for local dev
cargo test                            # all tests
cargo test <name>                     # single test / module
cargo fmt --check                     # check formatting
cargo fmt                             # fix formatting
cargo clippy -- -D warnings           # lint (warnings are errors)
```

Every phase must be `cargo fmt` + `cargo clippy -- -D warnings` + `cargo test` clean before moving
on. (Global preference: `cargo audit` too, before commit/push.)

## Running locally

```bash
aws sso login --profile umami-dev
cp .env.example .env    # fill UMAMI_SIGNING_KEY
cargo run --features pretty_logs
```

Requires the env vars in `.env.example`. umami creates its DynamoDB tables on startup via each
repository's `with_client`. Tables are prefixed with `DYNAMO_TABLE_PREFIX`.

## Key conventions (non-negotiable — from wasabi/dbx-core)

- **Curly braces on every `if`**, even single-line bodies (global user preference).
- **Strict lints** in `main.rs`: copy the `#![deny(...)]` block from `dbx-core/src/main.rs`
  (denies `warnings`, `missing_docs`, `unsafe_code`, `clippy::unwrap_used`, `expect_used`,
  `panic`, `indexing_slicing`, …) with the same `#![cfg_attr(test, allow(...))]` relaxation.
- **Repositories**: `#[async_trait] pub trait XRepository: Send + Sync` +
  `#[cfg_attr(test, mockall::automock)]`; `DynamoXRepository { client: DynamoClient }` with
  `pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self>` provisioning tables
  via `client.create_table(...)`. Field names as `const FIELD_*`; table names as `const TABLE_*`.
- **Routes**: `pub fn x_api_route(deps…) -> BoxedFilter<(impl warp::Reply,)>`; a thin
  `#[tracing::instrument(name = "POST /auth/login", skip_all)]` handler that calls `into_response`
  / `into_response_with_status`, wrapping a pure `anyhow::Result<T>` / `Result<(StatusCode, T)>`
  business handler. Guard with `enforce_user_with_any_permission(authenticator, &[…])`.
- **Errors**: `anyhow::Context` everywhere; wasabi's `ResultExt` (`mark_client_error()` /
  `map_err_to_http()`); `status_bail!` / `client_bail!`.
- **IDs**: `wasabi::aws::dynamodb::generate_id()` (32-char) for all entity ids.
- **Time**: `chrono` `DateTime<Utc>`, serialize RFC3339 (`to_rfc3339_opts(SecondsFormat::…, true)`).
- **Tracing**: `#[tracing::instrument(level = "debug", skip(self|secrets), err(Display))]` on repo
  and handler fns. **Never** log secrets, tokens, password hashes, or refresh values.
- **Tests**: `#[tokio::test]`, `warp::test::request()` for filters, `mockall` mocks for
  repositories, `User::builder()` to mint test users.
- **Env/config**: `dotenvy` + `X::from_env()` constructors, like every wasabi component.

## wasabi-specific gotchas (discovered during design)

- **`User::builder().into_token()` signs HS256 only.** umami's own access tokens are **ES256** and
  must be signed in `auth/tokens.rs` using `jsonwebtoken` with `EncodingKey::from_ec_pem` —
  do not route umami token signing through the wasabi test helper.
- **Match the crypto backend**: `jsonwebtoken = { version = "10", default-features = false,
  features = ["aws_lc_rs"] }` — identical to `wasabi-core`. This keeps one TLS/crypto stack and a
  clean `cargo audit`.
- **JWKS validation** on the product side goes through the `jwks` crate → `DecodingKey`. `ES256`
  (P-256) is the confirmed-safe algorithm. **`EdDSA`/OKP is only allowed after an end-to-end
  interop test proves the `jwks` + `aws_lc_rs` path accepts an Ed25519 JWK** (see ROADMAP Phase 2).
- **`iss` must exactly match** the issuer configured in product services, **trailing slash
  included** (`https://umami.example.com/`).
- **AWS SDK feature flags**: `aws-sdk-dynamodb = { version = "1", default-features = false,
  features = ["default-https-client", "rt-tokio"] }` — must match wasabi-core so cargo unions to a
  single version and avoids the legacy rustls 0.21 CVE path.
- Pin `wasabi` to a released tag (currently **`2.6.0`**); confirm shared crate versions
  (`aws-sdk-*`, `jsonwebtoken`) resolve to a single version against wasabi's lockfile.

## Token claims (must match `wasabi::web::auth::User`)

umami access tokens carry exactly what wasabi reads: `iss`, `sub` (userId), `aud`, `tenant`
(the ONE active tenant), `name`, `email`, `locale`, `permissions` (JSON array), `iat`, `exp`,
plus a custom `ver` (user.tokenVersion snapshot). An access token is **always scoped to exactly
one active tenant**; `POST /auth/switch-tenant` re-issues with a different `tenant` + re-resolved
`permissions`. Claim key constants live in `wasabi-core/src/web/auth/mod.rs` — reuse them.

## Security invariants

- Passwords: **argon2id** (`argon2` crate), tuned `m`/`t`/`p`.
- Refresh cookie value = `"<sessionId>.<refreshSecret>"`; store only `hash(refreshSecret)`
  (SHA-256). All secret comparisons constant-time. Cookie: `HttpOnly; Secure; SameSite=Lax;
  Path=/auth`.
- Rotation + reuse detection on `/auth/refresh` (see PLAN §5.5). Two revocation levers:
  `user.tokenVersion` (all sessions) and deleting a `sessions` row (one device).
- Access-token TTL = worst-case revocation latency → keep 5–15 min. Product services verify
  offline; revocation bites at the refresh boundary, not instantly.
- Rate-limit `POST /auth/login` and MFA verification (per-IP + per-account backoff).

## CI/CD

Mirror `dbx-core/.github`: PRs run format check, clippy `-D warnings`, build, test. (Set up in a
later hardening phase.)
