//! Application-wide constants for umami.
//!
//! Centralizes body-size limits, cookie names, token/session TTL defaults, and the built-in
//! permission strings consumed across the auth and tenant layers.

// ── Defaults ──────────────────────────────────────────────────────────────────

/// Hard cap on entries returned by the admin list endpoints (`GET /tenants`, `GET /users`). At the
/// target scale (< ~10k tenants, 1–10 users/tenant) results are read wholesale and filtered in
/// memory, so a cap replaces cursor pagination; the caller narrows results with the `q` search.
pub const MAX_LIST_RESULTS: usize = 250;

// ── Permission strings (umami's own admin surface) ────────────────────────────
//
// The route handlers check ONLY these plain permission strings; the mapping from roles/scopes/
// features/markers to permissions lives entirely in the config `apis` block (see `docs/CONFIG.md`).
// Product-service permission strings (e.g. dbx-core's `write:blocks`) are defined by those services.

/// Administer the caller's **own** tenant (settings, features, custom fields, audit).
pub const ADMIN_TENANT_PERMISSION: &str = "admin:tenant";

/// Manage a tenant's users (create/list/patch/delete, roles, status, password reset).
pub const MANAGE_USERS_PERMISSION: &str = "manage:users";

/// Manage a tenant's **service keys** (M2M API tokens): create/list/revoke + assignable scopes.
pub const MANAGE_SERVICE_KEYS_PERMISSION: &str = "manage:service-keys";

/// Manage one's **own** personal access tokens (`/auth/me/api-keys`).
pub const MANAGE_PAT_PERMISSION: &str = "manage:pat";

/// Read/write the global config document. **Global scope** — restrict to platform admins.
pub const MANAGE_CONFIG_PERMISSION: &str = "manage:config";

/// Cross-tenant administration: create/list/delete tenants + grant/revoke tenant features. Mapped
/// (in the config `apis`) from `is:system-tenant`, so it only lands in system-tenant tokens.
pub const MANAGE_TENANTS_PERMISSION: &str = "manage:tenants";

/// Re-scope one's token to another tenant (`POST /auth/switch-tenant`). Mapped from
/// `is:system-tenant`.
pub const SWITCH_TENANT_PERMISSION: &str = "switch:tenant";

/// **Deny** marker: when present, blocks the caller's self-service mutations (profile edit,
/// password change). Checked via `!self:readonly` at the route (see `with_user_with`).
pub const SELF_READONLY_PERMISSION: &str = "self:readonly";

/// Claim a `(platform, externalId) → user` messaging mapping via a link code. Held by a bot backend
/// (a system-tenant service key carrying `scope:messaging-linker`).
pub const MESSAGING_LINK_PERMISSION: &str = "messaging:link";

/// Resolve a messaging identity back to a user. Held by a system-tenant service key carrying
/// `scope:messaging-resolver`.
pub const MESSAGING_RESOLVE_PERMISSION: &str = "messaging:resolve";

/// Self-service management of one's own messaging links (get/regenerate code, list/unlink).
/// Derived (in the config `apis`) from `is:messaging-configured`, so it only appears when the
/// deployment actually has a Telegram bot and/or WhatsApp number configured.
pub const MESSAGING_SELF_PERMISSION: &str = "messaging:self";

// ── Synthetic subject markers (computed at mint time, never stored) ────────────

/// Added to the subject set when the token's tenant is the configured `UMAMI_SYSTEM_TENANT_ID`.
pub const SYSTEM_TENANT_MARKER: &str = "is:system-tenant";

/// Added to every token's subject set when the config has a Telegram bot and/or WhatsApp number
/// set (`messaging.telegramBot` / `messaging.whatsappNumber`). A global capability marker.
pub const MESSAGING_CONFIGURED_MARKER: &str = "is:messaging-configured";

/// Added to the subject set when the session authenticated with a passkey (WebAuthn).
pub const PASSKEY_MARKER: &str = "is:passkey";

/// Added to the subject set when the session authenticated with a TOTP second factor.
pub const TOTP_MARKER: &str = "is:totp";

/// Added whenever the session used a strong second factor (passkey or TOTP), so permission rules
/// can gate on "2FA present" regardless of the specific method.
pub const TWO_FACTOR_MARKER: &str = "is:2fa";

// ── Built-in role codes (defined in the default config, namespaced `role:*`) ───

/// Role code for a tenant's first/owning user.
pub const ROLE_OWNER: &str = "role:owner";

/// Default role code assigned to a newly created user.
pub const ROLE_MEMBER: &str = "role:member";

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

/// Default validity window for a messaging link code (10 min). A code older than this is treated as
/// expired: the self endpoint rotates it, and the machine link endpoint rejects it.
pub const DEFAULT_MESSAGING_CODE_TTL_SECS: u64 = 600;

// ── Rate-limit defaults (config `security.rateLimits`; overridable per-config) ──
//
// Chosen so a well-behaved token-caching client (≈6 exchanges/hour) sits far below the token
// exchange cap while a >1/s dumb loop trips within ~1s. See `docs/CONFIG.md`. A policy `max` of 0
// disables that policy.

/// Default `login.maxFailures` — failed password attempts (per account) before a login block.
pub const DEFAULT_LOGIN_MAX_FAILURES: u32 = 5;
/// Default `login.windowSecs` — the failure-count window (5 min); a success resets the counter.
pub const DEFAULT_LOGIN_WINDOW_SECS: u32 = 300;
/// Default `login.blockSecs` — how long an account stays blocked after too many failures (15 min).
pub const DEFAULT_LOGIN_BLOCK_SECS: u32 = 900;

/// Default `tokenExchange.maxPerWindow` — per-key `/auth/token` exchanges per window.
pub const DEFAULT_TOKEN_MAX_PER_WINDOW: u32 = 60;
/// Default `tokenExchange.windowSecs` — the per-key exchange window (1 min).
pub const DEFAULT_TOKEN_WINDOW_SECS: u32 = 60;
/// Default `tokenExchange.blockSecs` — how long a hammering key stays blocked (5 min).
pub const DEFAULT_TOKEN_BLOCK_SECS: u32 = 300;

/// Default `perIp.maxPerWindow` — requests per client IP **per endpoint** per window.
pub const DEFAULT_PER_IP_MAX_PER_WINDOW: u32 = 300;
/// Default `perIp.windowSecs` — the per-IP window (1 min → 5 req/s).
pub const DEFAULT_PER_IP_WINDOW_SECS: u32 = 60;
/// Default `perIp.blockSecs` — how long an IP stays blocked after flooding an endpoint (5 min).
pub const DEFAULT_PER_IP_BLOCK_SECS: u32 = 300;

/// Default upper bound on the per-node in-memory LRU block cache (distinct blocked subjects held in
/// memory). Bounded so many distinct IPs cannot memory-DoS a node. Override with
/// `UMAMI_RATELIMIT_CACHE_CAP`.
pub const DEFAULT_RATELIMIT_CACHE_CAP: usize = 50_000;
