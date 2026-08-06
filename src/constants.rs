//! Application-wide constants for umami.
//!
//! Centralizes body-size limits, cookie names, token/session TTL defaults, and the built-in
//! permission strings consumed across the auth and tenant layers.

// ── Defaults ──────────────────────────────────────────────────────────────────

/// Default BCP-47 locale for users created without an explicit one.
pub const DEFAULT_LOCALE: &str = "en-US";

/// Hard cap on entries returned by the admin list endpoints (`GET /tenants`, `GET /users`). At the
/// target scale (< ~10k tenants, 1–10 users/tenant) results are read wholesale and filtered in
/// memory, so a cap replaces cursor pagination; the caller narrows results with the `q` search.
pub const MAX_LIST_RESULTS: usize = 250;

// ── Permission strings (umami's own admin surface) ────────────────────────────
//
// Provisional role→permission map (see `users::role_permissions`). Product-service permission
// strings (e.g. dbx-core's `write:blocks`) will be folded in when the permission model is
// redesigned; for now these gate umami's own tenant/user administration.

/// Full administrative control over a tenant (settings, license).
pub const ADMIN_TENANT_PERMISSION: &str = "admin:tenant";

/// Manage a tenant's users (create/list/patch, roles, status).
pub const WRITE_MEMBERS_PERMISSION: &str = "write:members";

/// Read/write the global config document. **Global scope** — in a multi-tenant deployment this
/// must be restricted to a platform admin, not a tenant owner; the default config grants it to
/// `owner` for now (single-operator dev).
pub const MANAGE_CONFIG_PERMISSION: &str = "manage:config";

/// Read and increment a tenant's usage counters (metering). Product services meter usage with a
/// token carrying this permission.
pub const WRITE_USAGE_PERMISSION: &str = "write:usage";

// ── Built-in role codes (defined in the default config) ───────────────────────

/// Role code for a tenant's first/owning user.
pub const ROLE_OWNER: &str = "owner";

/// Default role code assigned to a newly created user.
pub const ROLE_MEMBER: &str = "member";

// ── Body size limits ──────────────────────────────────────────────────────────

/// Maximum accepted size for JSON request bodies (login, user creation), in bytes (1 MiB).
///
/// Auth payloads are small structured documents — anything approaching this ceiling indicates a
/// client bug or abuse rather than legitimate data.
pub const MAX_TEXT_BODY_SIZE: u64 = 1024 * 1024;

// ── Cookie names ──────────────────────────────────────────────────────────────

/// Name of the `HttpOnly; Secure; SameSite=Lax` refresh cookie. Its value is
/// `"<sessionId>.<refreshSecret>"`; only umami's refresh endpoint ever reads it.
pub const REFRESH_COOKIE_NAME: &str = "umami_refresh";

// ── Token / session TTL defaults (overridable via env) ────────────────────────

/// Default access-token lifetime in seconds (10 min). Kept short because it equals the worst-case
/// revocation latency at product services (they verify offline). Override via `UMAMI_ACCESS_TTL_SECS`.
pub const DEFAULT_ACCESS_TTL_SECS: u64 = 600;

/// Default refresh/session lifetime in seconds (30 days). Override via `UMAMI_REFRESH_TTL_SECS`.
pub const DEFAULT_REFRESH_TTL_SECS: u64 = 30 * 24 * 60 * 60;
