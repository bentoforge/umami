# umami — Target Data Model (authoritative)

This document is the **living authority** for umami's identity/tenancy model.

## Decisions (the why)

1. **Tenant owns User.** A user belongs to exactly one tenant (`tenantId` + `role` are fields on
   the user). No `memberships` join table. The owning tenant has full authority over its users
   (lock, reset, delete) — clean ownership, no split-authority ambiguity.
   *Rejected:* the global-user + M:N-membership model (Auth0/B2C heritage), where a floating
   global identity makes "who may lock this user?" unanswerable.
2. **Username identity.** The login id is the **`username`** — globally unique (case-insensitively).
   Login is `username + password`, no tenant context needed. Uniqueness is enforced by a
   `user-usernames` guard item (a GSI cannot enforce uniqueness or be read consistently in DynamoDB
   — the guard item is the idiom). **`email` is optional and NOT unique** (plain contact info); when
   a user is created without a username, the email is used as the username. `userId` stays the `users`
   PK (so all id-keyed reads/writes are strongly consistent) — the guard table is the price of a
   second unique attribute, chosen over "username as PK + userId GSI" which would push the hot
   userId path onto an eventually-consistent index.
3. **Hard tenant/user separation for v1.** No `parentTenantId`, no tenant hierarchy, no
   cross-tenant switching. A user acts only in their own tenant; the access token's `tenant` claim
   is always the user's home tenant.
4. **Future path for multi-tenant:** **user-invites**. Inviting an existing user into another
   tenant is what later enables "a user may switch tenants" — modeled as explicit invites/grants,
   *not* a parent-tenant hierarchy. Out of scope until we build invites.
5. **Teams are a separate axis (deferred).** Teams are intra-tenant *authorization* grouping
   (which users may touch which resources), orthogonal to ownership. v1 uses a role on the user;
   teams can be added later without touching the identity model.
6. **Tenant = account/ownership unit.** It owns its users and carries the authorization
   `feature:*` grants plus deployment-defined custom fields. No CRM / billing / licensing layer —
   anything a deployment needs beyond identity lives in custom fields.

## Entities

### Tenant — table `tenants` (+ GSI `ByLastActiveIndex`)

Owns its users; carries authorization features + custom fields.

- **PK** `tenantId` (hash) — 32-char generated id
- **GSI `ByLastActiveIndex`** — hash = a constant `listShard` value injected at write time
  (storage-only, not in the API model), range = `lastActiveOrCreated`; lets `GET /tenants` list every
  tenant in one query (no table scan), sorted active-first with inactive tenants stable by creation.
  Standard constant-partition pattern for a small global list at admin scale.
- `name`, `slug` (URL-friendly handle derived from `name`; a display convenience, not enforced unique)
- `features`: `[String]` — the granted `feature:*` authorization set the permission mapping reads
  (see [PERMISSIONS.md](PERMISSIONS.md))
- `customFields`: values for the config-defined custom tenant fields
- `created`, `lastUpdated`: RFC3339
- `lastActive`: RFC3339, `null` until first token activity; `lastActiveOrCreated`: the GSI range key
  (`lastActive` else `created`, bumped on activity)

### User — table `users` (+ guard table `user-usernames`, + GSI `ByTenantIndex`)

Owned by exactly one tenant.

- **PK** `userId` (hash) — 32-char generated id
- `tenantId` — the owning (home) tenant → **GSI `ByTenantIndex`** (hash `tenantId`, **range
  `lastActiveOrCreated`** = `lastSeen` else `created`) to list a tenant's users active-first, with
  never-active users stable by creation
- `username` — login id, stored as entered (trimmed); **global uniqueness** (case-insensitive) via
  the `user-usernames` guard
- `email` — optional contact info, normalized (trim + lowercase) when present; **not unique**
- `roles`: `[owner | admin | member | viewer | …]` (tenant-level; resolve to permissions at token issue)
- `name`, `locale` (BCP-47, default `en-US`)
- `passwordHash`: argon2id (nullable — invite/SSO-only users have none)
- `status`: `Active | Locked | Invited`
- `tokenVersion`: `u32` — global revocation counter
- `created`, `lastUpdated`, `lastSeen` (bumped best-effort on login + refresh)

**`user-usernames`** — uniqueness guard + username→user lookup. **PK** `username` (normalized) →
`userId`. Written with a conditional put (`attribute_not_exists`). *Best-practice note:* the guard +
user writes should be one `TransactWriteItems` (atomic); today they are sequential (small orphan-guard
risk) because the wasabi `DynamoClient` wrapper doesn't expose transactions yet — tracked as hardening.

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
- **GSI `ByUserIndex`** (hash `userId`) — list a user's sessions / revoke all (backs logout-all)

## Access-token claims (the wire contract)

`iss`, `sub` (userId), `aud`, `tenant` (= user's home tenant), `name`, `email`, `locale`,
`permissions` (resolved from `role`), `iat`, `exp`, `ver` (tokenVersion snapshot). Matches
`wasabi::web::auth::User`.

## Roles → permissions

Built-in roles map to wasabi-style permission strings baked into the `permissions` claim:

| Role | Permissions (illustrative) |
|------|----------------------------|
| `owner` | `admin:tenant`, `manage:users`, `manage:config`, + all product perms |
| `admin` | `manage:users`, + product write perms |
| `member` | product write perms (e.g. `write:blocks`, `write:assets`) |
| `viewer` | read-only |

Align product-permission strings with what the product services enforce (e.g. dbx-core:
`write:assets`, `write:blocks`, `write:descriptors`).

## Endpoints (revised for this model)

**Auth:** `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`,
`POST /auth/logout-all` (bump `tokenVersion`), `GET /auth/me` (profile: user + tenant + role),
`POST /auth/switch-tenant` (re-issue for another tenant; gated by `switch:tenant`),
`GET /.well-known/jwks.json`. The target audience is chosen by the optional `api` parameter on
login / refresh (default `umami`).

**Tenants:** `POST /tenants` (self-serve: creates the tenant **and its first `owner` user** — this
replaces the dev-bootstrap open signup), `GET /tenants/{id}`, `PATCH /tenants/{id}` (name + custom
fields only).

**Users (within the caller's tenant, permission-gated):** `POST /users` (invite/create — requires
`manage:users`), `GET /users/{id}`, list, `PATCH` (roles/lock).

## Deferred (with the future path)

- **User-invites** → basis for later cross-tenant membership/switching.
- **Teams** (intra-tenant resource authorization).
- **MFA** (TOTP, WebAuthn), **enterprise SSO** (OIDC).
- **`TransactWriteItems`** for atomic email-guard + user creation.
- **Parent-tenant / hierarchy:** explicitly *not* planned — invites cover the group case.
