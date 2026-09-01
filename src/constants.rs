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

/// Read a tenant's audit trail — and nothing else.
///
/// Narrow on purpose: reading the log and administering the tenant are different jobs, and a
/// support role needs the first without the second. Editing a tenant record is `manage:tenants`,
/// so granting this does not let a tenant rename itself or touch its custom fields.
pub const VIEW_AUDIT_PERMISSION: &str = "view:audit";

/// Read the deployment-wide rate-limit overview (which IPs, accounts and keys tripped a policy).
///
/// Separate from [`VIEW_AUDIT_PERMISSION`] because the two have different blast radii: the audit
/// log is tenant-scoped, whereas client IPs belong to no tenant at all. Granting a tenant admin
/// `view:audit` shows them their own trail; granting them this would show them everyone's traffic.
pub const VIEW_RATELIMITS_PERMISSION: &str = "view:ratelimits";

/// Manage a tenant's users (create/list/patch/delete, roles, status, password reset).
pub const MANAGE_USERS_PERMISSION: &str = "manage:users";

/// Manage a tenant's **service keys** (M2M API tokens): create/list/revoke + assignable scopes.
pub const MANAGE_SERVICE_KEYS_PERMISSION: &str = "manage:service-keys";

/// Edit one's **own** profile — the base data (name parts + self-editable custom fields) via
/// `PATCH /auth/me`. One of the five granular self-service permissions (replacing the old
/// `self:readonly` deny marker).
pub const MANAGE_PROFILE_PERMISSION: &str = "manage:profile";

/// Manage one's **own** security settings: password change (`POST /auth/me/password`), TOTP setup,
/// and passkey registration.
pub const MANAGE_PASSWORDS_PERMISSION: &str = "manage:passwords";

/// Manage one's **own** personal access tokens (`/auth/me/api-keys`).
pub const MANAGE_PERSONAL_TOKENS_PERMISSION: &str = "manage:personal-tokens";

/// See and revoke one's **own** login sessions (`/auth/sessions`, `/auth/logout-all`).
pub const MANAGE_SESSIONS_PERMISSION: &str = "manage:sessions";

/// Read/write the global config document. **Global scope** — restrict to platform admins.
pub const MANAGE_CONFIG_PERMISSION: &str = "manage:config";

/// Cross-tenant administration: create/list/delete tenants + grant/revoke tenant features. Mapped
/// (in the config `apis`) from `is:system-tenant`, so it only lands in system-tenant tokens.
pub const MANAGE_TENANTS_PERMISSION: &str = "manage:tenants";

/// Re-scope one's token to another tenant (`POST /auth/switch-tenant`). Mapped from
/// `is:system-tenant`.
pub const SWITCH_TENANT_PERMISSION: &str = "switch:tenant";

/// Config `apis` code of umami's own admin API — the default audience for the console flows
/// (`/auth/refresh`, `/auth/switch-tenant`) and the catalog entry whose permission mapping decides
/// who may switch tenants.
pub const UMAMI_API_CODE: &str = "umami";

/// Claim a `(platform, externalId) → user` messaging mapping via a link code. Held by a bot backend
/// (a system-tenant service key carrying `scope:messaging-linker`).
pub const MESSAGING_LINK_PERMISSION: &str = "messaging:link";

/// Resolve a messaging identity back to a user. Held by a system-tenant service key carrying
/// `scope:messaging-resolver`.
pub const MESSAGING_RESOLVE_PERMISSION: &str = "messaging:resolve";

/// Self-service management of one's own messaging links (get/regenerate code, list/unlink).
/// Derived (in the config `apis`) from `is:messaging-configured`, so it only appears when the
/// deployment actually has a Telegram bot and/or WhatsApp number configured.
pub const MANAGE_MESSAGING_PERMISSION: &str = "manage:messaging";

/// Self-service management of one's own **email contacts** (list/add/remove, verify, preferred).
///
/// Part of the baseline self-service set rather than gated on a marker: keeping your own addresses
/// current is profile data, not a deployment capability. What *is* gated on infrastructure is
/// verification and password recovery — both need a configured mail path, and neither exists yet.
pub const MANAGE_CONTACTS_PERMISSION: &str = "manage:contacts";

/// Resolve who hears about one notification firing. Held by a system-tenant service key carrying
/// `scope:notifier`.
///
/// Separate from [`NOTIFICATIONS_SEND_PERMISSION`] on purpose: an app that only needs to *send* must
/// not also be able to enumerate a tenant's users, and the two are different jobs even where they
/// happen to be the same app today.
pub const NOTIFICATIONS_AUDIENCE_PERMISSION: &str = "notifications:audience";

/// Hand finished notification messages over for delivery. Held by a system-tenant service key
/// carrying `scope:notifier`.
pub const NOTIFICATIONS_SEND_PERMISSION: &str = "notifications:send";

/// Report back that a message could not be delivered. Held by the **mail worker** — the thing that
/// consumes the queue — via a system-tenant service key carrying `scope:mail-worker`.
///
/// Its own permission and its own scope, separate from `notifications:send`: the worker and the app
/// that asks for a send are different principals, and the worker has no business resolving an
/// audience or sending anything of its own.
pub const NOTIFICATIONS_REPORT_PERMISSION: &str = "notifications:report";

// ── Synthetic subject markers (computed at mint time, never stored) ────────────

/// Added to the subject set when the token's tenant is the configured `UMAMI_SYSTEM_TENANT_ID`.
/// The **tenant being acted in** is the system tenant. Describes *where*, not *who*.
pub const SYSTEM_TENANT_MARKER: &str = "is:system-tenant";
/// The principal's **home** tenant is the system tenant. Describes *who*, and survives a tenant
/// switch — support staff live in the system tenant and work inside customer tenants, where they
/// keep this marker but lose [`SYSTEM_TENANT_MARKER`]. Splitting the two is what lets a rule say
/// "manage users anywhere except in the system tenant itself".
pub const SYSTEM_TENANT_MEMBER_MARKER: &str = "is:system-tenant-member";

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

/// Name of the `HttpOnly; Path=/auth` refresh cookie (`Secure`/`SameSite` per
/// [`crate::auth::cookies::CookiePolicy`]). Its value is
/// `"<sessionId>.<refreshSecret>"`; only umami's refresh endpoint ever reads it.
pub const REFRESH_COOKIE_NAME: &str = "umami_refresh";

// ── Token / session TTL defaults (config `security`; overridable per-config) ───

/// Default `security.accessTtlSecs` — access-token lifetime in seconds (10 min). Kept short because
/// it equals the worst-case revocation latency at product services (they verify offline).
pub const DEFAULT_ACCESS_TTL_SECS: u64 = 600;

/// Default `security.refreshTtlSecs` — refresh/session lifetime in seconds (30 days).
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

/// Default `mailSend.maxPerWindow` — verification/recovery mails a single user may trigger per
/// window. Low on purpose: without a cap, anyone with an account can add a stranger's address to
/// their own list and have umami mail that stranger on repeat.
pub const DEFAULT_MAIL_SEND_MAX_PER_WINDOW: u32 = 5;
/// Default `mailSend.windowSecs` — the per-user send window (1 hour).
pub const DEFAULT_MAIL_SEND_WINDOW_SECS: u32 = 3600;
/// Default `mailSend.blockSecs` — how long a user stays blocked after exceeding it (1 hour).
pub const DEFAULT_MAIL_SEND_BLOCK_SECS: u32 = 3600;

/// Default validity window for a password-reset link (1 hour).
///
/// Much shorter than the confirmation link: this one is account takeover in a click for whoever
/// reads it, and someone who just asked for it is looking at their inbox now.
pub const DEFAULT_PASSWORD_RESET_TTL_SECS: u64 = 3600;

/// Default validity window for an address-verification challenge (24 hours). Long enough that a
/// mail read the next morning still works, short enough that a link left in an inbox goes stale.
pub const DEFAULT_CONTACT_CHALLENGE_TTL_SECS: u64 = 86_400;

/// Default upper bound on the per-node in-memory LRU block cache (distinct blocked subjects held in
/// memory). Bounded so many distinct IPs cannot memory-DoS a node. Override with
/// `UMAMI_RATELIMIT_CACHE_CAP`.
pub const DEFAULT_RATELIMIT_CACHE_CAP: usize = 50_000;

/// Default window the rate-limit overview looks back over (1 hour).
pub const DEFAULT_RATELIMIT_LOOKBACK_SECS: i64 = 3_600;
/// Default number of blocks the rate-limit overview returns.
pub const DEFAULT_RATELIMIT_BLOCK_LIMIT: i32 = 100;
/// Hard cap on that number — the overview reads one bounded index page, never a scan.
pub const MAX_RATELIMIT_BLOCK_LIMIT: i32 = 250;
