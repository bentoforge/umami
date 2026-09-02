# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository.

**Everything in this repository is English — without exception.** Code, comments, doc
comments, identifiers, log and error messages, commit messages, PR titles, README, the
`docs/` directory. umami is open source and read by people who do not speak German; a
single German comment is a wall for them, and mixed-language repos never converge back.

The exception that is not one: `locales/*.yml` holds translations. German text there is
the product, not the project language.

Conversation with the maintainer may be in any language. This rule is about what gets
written to disk.

## Comments

Comments explain **why**, not what — the code already says what it does. A comment earns
its place when it records a constraint that is not visible locally, a trap someone would
otherwise fall into, or the reason a surprising decision is the right one.

Keep out: notes from conversations, references to earlier states ("this used to be…"),
changelog entries, narration. Whoever opens the file in six months to chase a bug was not
part of the discussion — write for them.

umami is a micro-IAM service built on the in-house **wasabi** framework. It is the JWT issuer and
tenant/membership authority for a fleet of wasabi-based B2B services. See [README.md](README.md) for
the product overview and the `docs/` directory for the reference docs (CONFIG, PERMISSIONS,
AUDIENCES, API-KEYS, CONTACTS, NOTIFICATIONS, SCHEMA).

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
aws sso login --profile dbx-dev    # dev testing runs against the shared dbx-dev account
cp .env.example .env               # fill UMAMI_SIGNING_KEY
cargo run --features pretty_logs
```

Requires the env vars in `.env.example`. umami creates its DynamoDB tables on startup via each
repository's `with_client`. Tables are prefixed with `DYNAMO_TABLE_PREFIX`.

### The management UI

```bash
cd clients/ui
npm run dev                                        # API on :8093
VITE_UMAMI_PROXY=http://localhost:8080 npm run dev # API elsewhere
```

Then open `http://localhost:5173/app/` — the trailing path matters, Vite's `base` is `/app/`.

Vite proxies the API paths so the SPA stays **same-origin**, which is what makes the HttpOnly
refresh cookie work at all. `VITE_UMAMI_PROXY` moves the proxy target; `VITE_UMAMI_URL` is a
different thing entirely — it makes the client call absolute URLs, which means cross-origin and
CORS with credentials. Reach for the first one.

## Wiring: where dependencies come from

- `src/storage/` — the storage seam. `Repositories` bundles all ten repository ports; one backend
  answers for all of them (`storage::dynamodb` today). A new backend implements the traits and
  returns a `Repositories`, so the compiler lists what it still owes.
- `src/boot/` — `Platform` holds every resolved dependency, `Platform::boot()` builds it from the
  environment, `boot::auto_init` does the first-run bootstrap.
- `src/api/` — the HTTP surface. One submodule per domain (`api::users`, `api::contacts`, …), each
  with `pub fn routes(&Platform) -> BoxedFilter<(impl Reply + use<>,)>`; `api::serve` composes them,
  mounts the token exchange under its own CORS policy and runs the server. `api::cors` holds both
  CORS policies. `src/main.rs` is the entry point and nothing else.

  A new route joins its domain's group — never `api::serve` directly. Keep the groups small: one
  81-entry `routes![…]` needed `#![recursion_limit = "512"]` to type-check, a dozen shallow ones do
  not. The `use<>` in the signature is load-bearing (edition 2024 would otherwise capture the
  `&Platform` lifetime and the filter could not escape the function).

**`&Platform` belongs to `src/api/` and `src/boot/` — nothing else.** Those two are the wiring
layer: `api::serve`, the per-domain `api::*::routes`, `Platform`'s own `*_deps()` builders and
`boot::auto_init` all take it. Nothing in a domain module (`users`, `contacts`, `auth`, …) ever
does: route builders there take explicit parameters, which is what keeps them independent of the
HTTP stack and testable with `warp::test` plus `mockall` doubles. A `&Platform` in a domain
signature turns the struct into a service locator; that is the failure mode this layout exists to
prevent.

`Platform` is deliberately a plain struct, not a `TypeId → Arc<dyn Any>` registry: `Any`
downcasting requires `Sized`, so trait objects would each need a newtype wrapper, and a missing
dependency would panic at boot instead of failing to compile.

### Selectable backends

Four seams are picked at runtime, one variable each — `UMAMI_STORAGE`, `UMAMI_CONFIG_STORE`,
`UMAMI_KEY_STORE`, `UMAMI_MAIL_TRANSPORT`. Each is resolved by a `from_env()` in the module that
owns the implementations (`storage`, `config::repository`, `auth::tokens`, `notify`), returns its
provider plus a `boot::seam::Selection`, and `boot()` logs the whole set as one block.

The rules live in `boot::seam` and are the same for every seam: **explicit wins and is strict**
(a named backend with a missing prerequisite fails the boot), **unset means auto-detect**, **an
unknown value never falls back**.

An AWS-backed provider must additionally clear `boot::aws::Aws` — one cached
`sts:GetCallerIdentity` at boot, which is the only way to know a credential chain actually produces
credentials. Explicit AWS providers call `aws.require()` (boot fails with the probe's reason);
auto-detecting ones call `aws.is_usable()` and step aside when it is false. Never probe with a
service call that needs an IAM permission — that would fail the boot on a legitimate
least-privilege policy.

Naming: a seam's selector is named after the seam (`UMAMI_MAIL_TRANSPORT`), a provider's own
settings after the provider (`UMAMI_MAIL_SQS_QUEUE_URL`, `UMAMI_CONFIG_S3_KEY`) — so two providers
of one seam cannot collide over a variable, and adding SMTP or Postgres renames nothing. The only
un-prefixed exceptions are `S3_BUCKET_SUFFIX` and `DYNAMO_TABLE_PREFIX`, which belong to wasabi's
naming schema rather than to umami. A new seam follows that shape; do not add a "production mode"
switch — strictness is derived from explicitness. A failed boot exits **1**, never 0. Full
reference: [docs/SEAMS.md](docs/SEAMS.md).

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
  interop test proves the `jwks` + `aws_lc_rs` path accepts an Ed25519 JWK**.
- **`iss` must exactly match** the issuer configured in product services, **trailing slash
  included** (`https://umami.example.com/`).
- **AWS SDK feature flags**: `aws-sdk-dynamodb = { version = "1", default-features = false,
  features = ["default-https-client", "rt-tokio"] }` — must match wasabi-core so cargo unions to a
  single version and avoids the legacy rustls 0.21 CVE path.
- Pin `wasabi` to a released tag (currently **`2.7.0`**); confirm shared crate versions
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

In `.github/`, mirroring `dbx-core`:

- **CI (Rust)** — `.github/workflows/ci-rust.yml` on PRs and pushes to `main` that touch `src/**` or
  the manifests. It delegates to the `verify-rust` composite action, which runs `cargo fmt --check`,
  `clippy -D warnings`, build, test and `cargo audit` in a pinned Rust container. Run the same four
  locally before pushing and CI holds no surprises.
- **CI (Web)** — `ci-web.yml` for the TS client library and the management UI.
- **Release** — `release.yml` on a tag: verifies, builds the multi-arch Docker image and pushes the
  manifest.

`verify-rust` takes an `audit-ignore` input for advisory IDs — only for transitive, non-exploitable
advisories waiting on an upstream fix, never to silence something in umami's own tree.
