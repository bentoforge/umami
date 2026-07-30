# umami

> **umami** = **u**IAM = **micro IAM**. A small, B2B-focused identity & tenant service in
> Rust, built on the in-house [**wasabi**](https://github.com/0711sw/wasabi) framework, hosted
> natively on AWS (DynamoDB), and intended to be published as open source.

umami is the **identity provider and tenant/membership authority** for a fleet of wasabi-based
B2B SaaS services. It is the **JWT issuer**: it signs short-lived access tokens and publishes its
public keys via a JWKS endpoint, so any wasabi service trusts umami purely by configuration — no
code change in the product services.

## What umami owns

1. **Authentication** — password login (argon2id), MFA via TOTP and WebAuthn/FIDO2 (passkeys +
   hardware keys), account lifecycle.
2. **B2B tenant model** — tenants/workspaces, teams, global user identities, and the
   many-to-many memberships between them, with roles → permissions.
3. **Token issuance** — ES256-signed access tokens (5–15 min) + `HttpOnly` refresh-cookie
   sessions with rotation and reuse detection; a `/.well-known/jwks.json` endpoint.
4. **A "micro-CRM" + light licensing layer** — per-tenant customer status, plan/package, billing
   period, and usage metering (e.g. AI tokens consumed this month).

## What umami is NOT

- Not a B2C console or a Keycloak/Auth0 clone.
- Not a SAML IdP — enterprise SSO is **OIDC-only** (bridge SAML→OIDC in front if needed).
- Not a hosted login UI — umami ships a **headless API + a thin TypeScript client SDK**. The only
  server-owned UI-ish surface is the OIDC redirect callback for enterprise login.

See [PLAN.md](PLAN.md) for the full build specification and [docs/ROADMAP.md](docs/ROADMAP.md)
for the step-by-step implementation plan.

## Architecture

Single binary crate `umami` depending on `wasabi` (`aws_dynamodb`), modular internally — mirrors
the shape of the reference service `dbx-core`. Persistence is **one DynamoDB table per aggregate
with GSIs** (not single-table design). All entities are serde `camelCase`; every persisted field
has a `const FIELD_*`.

| Module | Responsibility |
|--------|----------------|
| `auth/` | login, sessions (refresh + rotation), token signing + JWKS, argon2, TOTP, WebAuthn, `/auth/me` |
| `tenants/` | Tenant entity (status/plan/usage), CRUD + license/usage routes |
| `teams/` | Teams within a tenant |
| `users/` | Global user identities (+ `EmailIndex` GSI, WebAuthn credentials) |
| `memberships/` | tenant↔user M─N join carrying the tenant-level role |
| `clients/typescript/` | thin client SDK (in-repo monorepo) |

### Data model (relationships)

```
Tenant ──1:N── Team
Tenant ──M:N── User      (via Membership; role + teamIds live on the membership)
User   ──1:N── Session   (one per device/browser; refresh cookie carries sessionId)
```

## Development

Requires an AWS profile with DynamoDB access (local dev uses on-demand tables that umami creates
on startup via `with_client`).

```bash
cp .env.example .env        # then fill UMAMI_SIGNING_KEY (see below)
aws sso login --profile umami-dev

cargo run --features pretty_logs
```

Generate a local ES256 signing key:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec-private.pem
```

Then paste the PEM into `UMAMI_SIGNING_KEY` in `.env` (single line with `\n`, or load via a file
helper — see `auth/tokens.rs`).

### Build & test

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo build
cargo test
```

## Integrating a wasabi service with umami

Add to the product service's environment — no code change required:

```bash
AUTH_ISSUER=https://umami.example.com/=jwks:/.well-known/jwks.json
AUTH_ALGORITHMS=ES256
AUTH_AUDIENCE=<your-service>   # optional, if umami sets aud
```

The product service fetches umami's **public** keys from `/.well-known/jwks.json` and verifies
access tokens **offline** — no DB hit, no shared secret.

## License

Intended for open-source release. License TBD.
