# umami — Target Data Model (authoritative)

This document is the **living authority** for umami's identity/tenancy model. Where it differs
from [PLAN.md](../PLAN.md) §3 (the original M:N sketch), **this wins**.

## Decisions (the why)

1. **Tenant owns User.** A user belongs to exactly one tenant (`tenantId` + `role` are fields on
   the user). No `memberships` join table. The owning tenant has full authority over its users
   (lock, reset, delete) — clean ownership, no split-authority ambiguity.
   *Rejected:* the global-user + M:N-membership model (Auth0/B2C heritage), where a floating
   global identity makes "who may lock this user?" unanswerable.
2. **Global identity.** Email is **globally unique** (one human = one account = one home tenant).
   Login is `email + password`, no tenant context needed. Enforced by a `user-emails` guard item
   (a GSI cannot enforce uniqueness or be read consistently in DynamoDB — the guard item is the
   idiom).
3. **Hard tenant/user separation for v1.** No `parentTenantId`, no tenant hierarchy, no
   cross-tenant switching. A user acts only in their own tenant; the access token's `tenant` claim
   is always the user's home tenant.
4. **Future path for multi-tenant:** **user-invites**. Inviting an existing user into another
   tenant is what later enables "a user may switch tenants" — modeled as explicit invites/grants,
   *not* a parent-tenant hierarchy. Out of scope until we build invites.
5. **Teams are a separate axis (deferred).** Teams are intra-tenant *authorization* grouping
   (which users may touch which resources), orthogonal to ownership. v1 uses a role on the user;
   teams can be added later without touching the identity model.
6. **Tenant = accounting unit.** Plan / billing / usage metering live on the tenant.

## Entities

### Tenant — table `tenants`

Owns its users; carries the CRM/licensing fields.

- **PK** `tenantId` (hash) — 32-char generated id
- `name`, `slug`
- `status`: `Lead | Testing | Onboarding | Active | Suspended | Churned`
- `plan`: package id (`free` | `pro` | `enterprise` | …)
- `billedUntil`: date (ISO `YYYY-MM-DD`), optional
- `seatsLimit`: `u32`, optional
- Usage (current period): `usagePeriodStart` (date), `aiTokensUsed` (`u64`),
  `aiTokensQuota` (`u64`, optional)
- `created`, `lastUpdated`: RFC3339

### User — table `users` (+ guard table `user-emails`, + GSI `ByTenantIndex`)

Global identity, owned by exactly one tenant.

- **PK** `userId` (hash) — 32-char generated id
- `tenantId` — the owning (home) tenant → **GSI `ByTenantIndex`** (hash `tenantId`) to list a
  tenant's users
- `email` — normalized (trim + lowercase); **global uniqueness** via the `user-emails` guard
- `role`: `owner | admin | member | viewer` (tenant-level; resolves to permissions at token issue)
- `name`, `locale` (BCP-47, default `en-US`)
- `passwordHash`: argon2id (nullable — invite/SSO-only users have none)
- `status`: `Active | Locked | Invited`
- `tokenVersion`: `u32` — global revocation counter
- `created`, `lastUpdated`

**`user-emails`** — uniqueness guard + email→user lookup. **PK** `email` → `userId`. Written with
a conditional put (`attribute_not_exists`). *Best-practice note:* the guard + user writes should be
one `TransactWriteItems` (atomic); today they are sequential (small orphan-email risk) because the
wasabi `DynamoClient` wrapper doesn't expose transactions yet — tracked as hardening.

### Session — table `sessions`

One row per active login (device/browser). Backs the refresh-cookie flow.

- **PK** `sessionId` (hash) — carried (plaintext) by the refresh cookie
- `userId`
- `activeTenantId`: the tenant this session is scoped to. **v1: always the user's home tenant**
  (kept as a field so invites/switching can later change it without a migration).
- `refreshHash`: SHA-256 (base64url) of the current refresh secret — the secret is never stored
- `tokenVersionAtIssue`: `u32` snapshot of `user.tokenVersion`
- `userAgent`, `ip`: best-effort device metadata
- `created`, `lastSeen`, `expiresAt`: RFC3339; `ttl`: epoch-seconds mirror for a DynamoDB TTL
- **GSI `ByUserIndex`** (hash `userId`) — list a user's sessions / revoke all (added with
  logout-all in Phase 3)

## Access-token claims (unchanged wire contract)

`iss`, `sub` (userId), `aud`, `tenant` (= user's home tenant), `name`, `email`, `locale`,
`permissions` (resolved from `role`), `iat`, `exp`, `ver` (tokenVersion snapshot). Matches
`wasabi::web::auth::User`.

## Roles → permissions

Built-in roles map to wasabi-style permission strings baked into the `permissions` claim:

| Role | Permissions (illustrative) |
|------|----------------------------|
| `owner` | `admin:tenant`, `write:members`, `write:teams`, + all product perms |
| `admin` | `write:members`, `write:teams`, + product write perms |
| `member` | product write perms (e.g. `write:blocks`, `write:assets`) |
| `viewer` | read-only |

Align product-permission strings with what the product services enforce (e.g. dbx-core:
`write:assets`, `write:blocks`, `write:descriptors`).

## Endpoints (revised for this model)

**Auth:** `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`,
`POST /auth/logout-all` (bump `tokenVersion`), `GET /auth/me` (profile: user + tenant + role),
`GET /.well-known/jwks.json`.
*No `POST /auth/switch-tenant` in v1* (single tenant per user).

**Tenants:** `POST /tenants` (self-serve: creates the tenant **and its first `owner` user** — this
replaces the dev-bootstrap open signup), `GET /tenants/{id}`, `PATCH /tenants/{id}`,
`PATCH /tenants/{id}/status`, `PATCH /tenants/{id}/license`, usage endpoints.

**Users (within the caller's tenant, permission-gated):** `POST /users` (invite/create — requires
`write:members`), `GET /users/{id}`, list, `PATCH` (role/status).

## Deferred (with the future path)

- **User-invites** → basis for later cross-tenant membership/switching.
- **Teams** (intra-tenant resource authorization).
- **MFA** (TOTP, WebAuthn), **enterprise SSO** (OIDC).
- **`TransactWriteItems`** for atomic email-guard + user creation.
- **Parent-tenant / hierarchy:** explicitly *not* planned — invites cover the group case.
