//! Configuration: the global catalog + system settings that define the shape of the system.
//!
//! Loaded and saved as one whole document via [`repository::ConfigRepository`] (cached), and edited
//! by the client (load → edit → write back). See `docs/CONFIG.md`. Per-tenant/user *assignments*
//! (user roles, tenant features, custom-field values) live on the entities, not here.

pub mod repository;
pub mod service;

use crate::constants::{
    DEFAULT_ACCESS_TTL_SECS, DEFAULT_LOGIN_BLOCK_SECS, DEFAULT_LOGIN_MAX_FAILURES,
    DEFAULT_LOGIN_WINDOW_SECS, DEFAULT_MESSAGING_CODE_TTL_SECS, DEFAULT_PER_IP_BLOCK_SECS,
    DEFAULT_PER_IP_MAX_PER_WINDOW, DEFAULT_PER_IP_WINDOW_SECS, DEFAULT_REFRESH_TTL_SECS,
    DEFAULT_TOKEN_BLOCK_SECS, DEFAULT_TOKEN_MAX_PER_WINDOW, DEFAULT_TOKEN_WINDOW_SECS,
    MANAGE_CONFIG_PERMISSION, MANAGE_MESSAGING_PERMISSION, MANAGE_PASSWORDS_PERMISSION,
    MANAGE_PERSONAL_TOKENS_PERMISSION, MANAGE_PROFILE_PERMISSION, MANAGE_SERVICE_KEYS_PERMISSION,
    MANAGE_SESSIONS_PERMISSION, MANAGE_TENANTS_PERMISSION, MANAGE_USERS_PERMISSION,
    MESSAGING_CONFIGURED_MARKER, MESSAGING_LINK_PERMISSION, MESSAGING_RESOLVE_PERMISSION,
    ROLE_MEMBER, ROLE_OWNER, SWITCH_TENANT_PERMISSION, SYSTEM_TENANT_MARKER,
    SYSTEM_TENANT_MEMBER_MARKER, VIEW_AUDIT_PERMISSION,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use wasabi::client_bail;

/// One rule in an API's ordered permission mapping: when `when` holds against the current set
/// (subjects ∪ permissions granted by earlier rules), the permissions in `grant` are added.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRule {
    /// Condition (permission-string DSL) over subjects ∪ already-granted permissions.
    pub when: String,
    /// Permissions granted when the condition holds.
    pub grant: Vec<String>,
}

/// A target API (audience) umami can mint tokens for — see `docs/AUDIENCES.md` + `docs/PERMISSIONS.md`.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApiDef {
    /// Internal id of this API (audience), named by the `api` param at login/refresh/key-exchange.
    pub code: String,
    /// The `aud` claim written into tokens minted for this API.
    pub audience: String,
    /// Permission-string DSL that must hold (against subjects ∪ granted permissions) to obtain a
    /// token for this API; `None` = no gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligibility: Option<String>,
    /// Ordered permission mapping: rules fire top-to-bottom, later rules seeing earlier grants.
    #[serde(default)]
    pub permissions: Vec<PermissionRule>,
    /// Claim mapping `claimName → source`, where `source` is a literal string, a `$user.<field>` /
    /// `$tenant.<field>` reference, or `$user.custom.<code>` / `$tenant.custom.<code>` (see
    /// [`resolve_claim_source`]).
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
}

/// Evaluates a permission-string expression against a subject set (subjects ∪ granted permissions).
/// `,` = OR (lowest precedence), `+` = AND, `!term` = NOT. An empty expression holds (no gate).
///
/// Thin wrapper over wasabi's [`eval_permission_expr`](wasabi::web::auth::permission_expr) — the
/// single grammar/implementation shared with the route guards (`with_user_with`) and product
/// services.
pub fn eval_expression(expression: &str, set: &BTreeSet<&str>) -> bool {
    wasabi::web::auth::permission_expr::eval_permission_expr(expression, |term| set.contains(term))
}

impl ApiDef {
    /// Resolves the token's permissions for a subject set, then checks eligibility.
    ///
    /// Ordered accumulate: start from `subjects` (namespaced `role:*`/`scope:*`/`feature:*`/`is:*`),
    /// fire each `permissions` rule whose `when` holds against the current set (subjects ∪ granted
    /// so far), adding its grant. Then evaluate `eligibility` against the final set. Returns the
    /// sorted permissions when eligible, or `None` when not (⇒ the caller returns 403).
    pub fn resolve(&self, subjects: &[String]) -> Option<Vec<String>> {
        let mut working: BTreeSet<String> = subjects.iter().cloned().collect();
        let mut granted: BTreeSet<String> = BTreeSet::new();

        for rule in &self.permissions {
            let view: BTreeSet<&str> = working.iter().map(String::as_str).collect();
            if eval_expression(&rule.when, &view) {
                for permission in &rule.grant {
                    if granted.insert(permission.clone()) {
                        let _ = working.insert(permission.clone());
                    }
                }
            }
        }

        let eligible = match &self.eligibility {
            Some(expr) => {
                let view: BTreeSet<&str> = working.iter().map(String::as_str).collect();
                eval_expression(expr, &view)
            }
            None => true,
        };
        if !eligible {
            return None;
        }
        Some(granted.into_iter().collect())
    }

    /// Builds the configured extra claims for a token, resolving each source via the single
    /// [`resolve_claim_source`] interpreter against `ctx`. Sources that resolve to nothing (unknown
    /// `$…` reference, or an absent field/custom value) are omitted.
    pub fn build_claims(&self, ctx: &ClaimContext<'_>) -> BTreeMap<String, Value> {
        let mut out = BTreeMap::new();
        for (name, source) in &self.claims {
            if let Some(value) = resolve_claim_source(source, ctx) {
                let _ = out.insert(name.clone(), value);
            }
        }
        out
    }
}

/// Everything a claim mapping can reference: the principal (user, or a machine key with empty user
/// fields) and its tenant. Assembled once by the token broker; the single input to
/// [`resolve_claim_source`].
pub struct ClaimContext<'a> {
    pub user_id: &'a str,
    pub username: &'a str,
    pub email: &'a str,
    pub display_names: &'a crate::users::DisplayNames,
    pub title: Option<&'a str>,
    pub salutation: &'a str,
    /// The effective language: the user's own `locale`, else the config's `defaultLocale`. Already
    /// resolved, so a product service never has to know about the fallback.
    pub locale: &'a str,
    pub firstname: Option<&'a str>,
    pub lastname: Option<&'a str>,
    pub roles: &'a [String],
    pub user_custom: &'a BTreeMap<String, Value>,
    pub tenant_id: &'a str,
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub tenant_features: &'a [String],
    pub tenant_custom: &'a BTreeMap<String, Value>,
}

/// The **single** place a claim-mapping *source* string is interpreted:
/// - a plain string is used **literally** (e.g. `"dbx-core"` → `"dbx-core"`);
/// - `$user.<field>` — one of `id`, `username`, `email`, `title`, `salutation`, `firstname`,
///   `lastname`, `locale`, `name`, `fullName`, `addressableName`, `roles`;
/// - `$tenant.<field>` — one of `id`, `name`, `slug`, `features`;
/// - `$user.custom.<code>` / `$tenant.custom.<code>` — the named custom field's value.
///
/// An unknown `$…` reference, or an absent optional field / custom value, yields `None` so the
/// claim is simply omitted.
pub fn resolve_claim_source(source: &str, ctx: &ClaimContext<'_>) -> Option<Value> {
    let Some(reference) = source.strip_prefix('$') else {
        return Some(Value::String(source.to_owned()));
    };
    if let Some(key) = reference.strip_prefix("user.custom.") {
        return ctx.user_custom.get(key).cloned();
    }
    if let Some(key) = reference.strip_prefix("tenant.custom.") {
        return ctx.tenant_custom.get(key).cloned();
    }
    match reference {
        "user.id" => Some(json!(ctx.user_id)),
        "user.username" => Some(json!(ctx.username)),
        "user.email" => Some(json!(ctx.email)),
        "user.title" => ctx.title.map(|value| json!(value)),
        "user.salutation" => Some(json!(ctx.salutation)),
        "user.firstname" => ctx.firstname.map(|value| json!(value)),
        "user.lastname" => ctx.lastname.map(|value| json!(value)),
        "user.name" => Some(json!(ctx.display_names.name)),
        "user.fullName" => Some(json!(ctx.display_names.full_name)),
        "user.addressableName" => Some(json!(ctx.display_names.addressable_name)),
        "user.locale" => Some(json!(ctx.locale)),
        "user.roles" => Some(json!(ctx.roles)),
        "tenant.id" => Some(json!(ctx.tenant_id)),
        "tenant.name" => Some(json!(ctx.tenant_name)),
        "tenant.slug" => Some(json!(ctx.tenant_slug)),
        "tenant.features" => Some(json!(ctx.tenant_features)),
        _ => None,
    }
}

/// A role: a code, a display name, and the permission strings it grants.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RoleDef {
    /// Stable code referenced by `user.roles` (namespaced `role:*`).
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// Optional human-readable description (shown muted under the name in the admin UI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// DSL over the tenant's features (`feature:*`/`is:*`) — the role is assignable to a user in a
    /// tenant only when this holds. `None` = always assignable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignable_if: Option<String>,
}

/// A scope: the M2M analogue of a role, assigned to an API service key (namespaced `scope:*`).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDef {
    /// Stable code referenced by `apiKey.scopes` (namespaced `scope:*`).
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// Optional human-readable description (shown muted under the name in the admin UI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// DSL over the tenant's features (`feature:*`/`is:*`) gating assignability to a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignable_if: Option<String>,
}

/// A feature: granted to a tenant (namespaced `feature:*`), checked in the permission game.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FeatureDef {
    /// Stable code.
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// Optional human-readable description (shown muted under the name in the admin UI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// DSL over the tenant's **current** features — the feature is grantable only when this holds
    /// (encodes prerequisites). `None` = always grantable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignable_if: Option<String>,
}

/// A custom-field schema entry (tenant- or user-level).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldDef {
    /// Stable code the field's value is stored under (in a tenant's/user's `customFields` map).
    pub code: String,
    /// Display label.
    pub label: String,
    /// Field type: `string`, `number`, `bool`/`boolean`, or `select` (constrained to `options`).
    #[serde(rename = "type")]
    pub field_type: String,
    /// Allowed values for a `select` field (ignored for other types).
    #[serde(default)]
    pub options: Vec<String>,
    /// Whether the field must be set (a non-null, non-empty value).
    #[serde(default)]
    pub required: bool,
    /// Whether admin list tables should surface this field as a column.
    #[serde(default)]
    pub show_in_table: bool,
    /// Whether a user may edit this field on themselves via `PATCH /auth/me` (self-service). Off by
    /// default — admin-managed fields stay admin-only; opt profile-ish fields in explicitly.
    #[serde(default)]
    pub self_editable: bool,
}

/// Messaging integration settings. When either endpoint is set, umami can hand out ready-made
/// deep links from `GET /auth/me/messaging-code` and synthesizes `is:messaging-configured`.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct MessagingConfig {
    /// WhatsApp business number (digits, e.g. `4915112345678`) for click-to-chat links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub whatsapp_number: Option<String>,
    /// Telegram bot username (without `@`) for `t.me/<bot>?start=<code>` deep links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram_bot: Option<String>,
}

impl MessagingConfig {
    /// Whether any messaging endpoint is configured.
    pub fn is_configured(&self) -> bool {
        self.whatsapp_number
            .as_ref()
            .is_some_and(|v| !v.trim().is_empty())
            || self
                .telegram_bot
                .as_ref()
                .is_some_and(|v| !v.trim().is_empty())
    }
}

/// White-labeling for the management UI. All optional; empty fields fall back to the built-in
/// defaults. `logo`/`favicon` may be a `data:` URI (self-contained in the config) or an `http(s)`
/// URL. Served by umami at `/app/branding.css`, `/app/logo`, `/app/favicon` (see `web_ui`).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct BrandingConfig {
    /// Extra CSS injected after the app's stylesheet — override the accent via
    /// `:root{--brand: <r> <g> <b>; --brand-dark: <r> <g> <b>}` (space-separated RGB channels).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_css: Option<String>,
    /// Logo for **light** backgrounds — a `data:` URI or an `http(s)` URL. Empty → falls back to the
    /// dark logo, then a built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_light: Option<String>,
    /// Logo for **dark** backgrounds. Empty → falls back to the light logo, then a built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_dark: Option<String>,
    /// Favicon — a `data:` URI or an `http(s)` URL. Empty → the built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favicon: Option<String>,
    /// Browser tab title (the document `<title>`), served at `/app/branding.json` and applied by the
    /// SPA at runtime. Empty → `"umami"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// System security/token settings.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SecuritySettings {
    /// Minimum accepted password length.
    pub min_password_length: u32,
    /// Access-token lifetime (seconds).
    pub access_ttl_secs: u64,
    /// Refresh/session lifetime (seconds).
    pub refresh_ttl_secs: u64,
    /// Validity window for a messaging link code (seconds). Older codes are rotated on read and
    /// rejected on link.
    #[serde(default = "default_messaging_code_ttl_secs")]
    pub messaging_code_ttl_secs: u64,
    /// Rate-limit policies for the auth endpoints (see [`RateLimitsConfig`] and `docs/CONFIG.md`).
    #[serde(default)]
    pub rate_limits: RateLimitsConfig,
    /// Exact URLs `GET /auth/authorize` may redirect back to.
    ///
    /// Top-level rather than per-API, because logging in is not an API-scoped act: the session it
    /// establishes is audience-agnostic, and which APIs the user can then call follows from their
    /// roles, not from who sent them to the login page.
    ///
    /// **Matched exactly — no prefixes, no wildcards.** Prefix matching is the classic hole here
    /// (`https://app.example.com.evil.test` prefix-matches `https://app.example.com`), and without
    /// an allow-list at all, `authorize` is an open redirector that lends the IAM domain's
    /// credibility to any destination. Empty list = the flow is off.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
}

/// Serde default for [`SecuritySettings::messaging_code_ttl_secs`] (back-compat for older configs).
fn default_messaging_code_ttl_secs() -> u64 {
    DEFAULT_MESSAGING_CODE_TTL_SECS
}

/// Brute-force policy for `POST /auth/login`: counts **failed** attempts per account, resets the
/// counter on a successful login, and blocks the account for `block_secs` once `max_failures` is
/// reached within `window_secs`. A `max_failures` of 0 disables the policy.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LoginRateLimit {
    /// Failed attempts (per account) tolerated within the window before a block.
    pub max_failures: u32,
    /// The rolling failure-count window, in seconds.
    pub window_secs: u32,
    /// How long the account is blocked once the threshold is reached, in seconds.
    pub block_secs: u32,
}

/// Volume policy: counts **all** requests for a subject in a fixed window and blocks it for
/// `block_secs` once `max_per_window` is exceeded. Used for the per-IP and per-key caps (see
/// [`RateLimitsConfig`]). A `max_per_window` of 0 disables the policy.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VolumeRateLimit {
    /// Requests tolerated within the window before a block.
    pub max_per_window: u32,
    /// The fixed counting window, in seconds.
    pub window_secs: u32,
    /// How long the subject is blocked once the threshold is exceeded, in seconds.
    pub block_secs: u32,
}

/// Rate-limit policies for the auth endpoints. Layered so per-IP (the primary blunt instrument)
/// is backed by a per-key volume cap (catches one key hammering across many IPs) and a per-account
/// failure cap (catches distributed brute-force). Set any policy's `max` to 0 to run per-IP-only.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitsConfig {
    /// Per-account failed-login policy (`POST /auth/login`).
    #[serde(default = "default_login_rate_limit")]
    pub login: LoginRateLimit,
    /// Per-API-key volume policy for the `POST /auth/token` exchange.
    #[serde(default = "default_token_exchange_rate_limit")]
    pub token_exchange: VolumeRateLimit,
    /// Per-client-IP volume policy, applied **per endpoint** (`/auth/login` and `/auth/token` keep
    /// separate counters, so a flood on one does not consume the other's budget).
    #[serde(default = "default_per_ip_rate_limit")]
    pub per_ip: VolumeRateLimit,
}

impl Default for RateLimitsConfig {
    fn default() -> Self {
        RateLimitsConfig {
            login: default_login_rate_limit(),
            token_exchange: default_token_exchange_rate_limit(),
            per_ip: default_per_ip_rate_limit(),
        }
    }
}

/// Serde default for [`RateLimitsConfig::login`] (back-compat for older configs).
fn default_login_rate_limit() -> LoginRateLimit {
    LoginRateLimit {
        max_failures: DEFAULT_LOGIN_MAX_FAILURES,
        window_secs: DEFAULT_LOGIN_WINDOW_SECS,
        block_secs: DEFAULT_LOGIN_BLOCK_SECS,
    }
}

/// Serde default for [`RateLimitsConfig::token_exchange`] (back-compat for older configs).
fn default_token_exchange_rate_limit() -> VolumeRateLimit {
    VolumeRateLimit {
        max_per_window: DEFAULT_TOKEN_MAX_PER_WINDOW,
        window_secs: DEFAULT_TOKEN_WINDOW_SECS,
        block_secs: DEFAULT_TOKEN_BLOCK_SECS,
    }
}

/// Serde default for [`RateLimitsConfig::per_ip`] (back-compat for older configs).
fn default_per_ip_rate_limit() -> VolumeRateLimit {
    VolumeRateLimit {
        max_per_window: DEFAULT_PER_IP_MAX_PER_WINDOW,
        window_secs: DEFAULT_PER_IP_WINDOW_SECS,
        block_secs: DEFAULT_PER_IP_BLOCK_SECS,
    }
}

/// The whole configuration document.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// Optimistic-concurrency counter, bumped on every save.
    pub version: u64,
    /// Role catalog (assigned to users).
    pub roles: Vec<RoleDef>,
    /// Scope catalog (assigned to M2M service keys).
    #[serde(default)]
    pub scopes: Vec<ScopeDef>,
    /// Feature catalog (granted to tenants).
    #[serde(default)]
    pub features: Vec<FeatureDef>,
    /// Custom tenant field schemas.
    #[serde(default)]
    pub custom_tenant_fields: Vec<CustomFieldDef>,
    /// Custom user field schemas.
    #[serde(default)]
    pub custom_user_fields: Vec<CustomFieldDef>,
    /// Language used wherever umami renders text itself and no user preference applies — BCP-47
    /// (e.g. `de`, `en`). A user's own `locale` takes precedence.
    ///
    /// Salutation *words* are no longer configured here: they are per-locale constants in code, so
    /// that a reader gets their own language rather than the deployment's. See
    /// [`crate::users::compose_display_names`].
    #[serde(default = "default_locale")]
    pub default_locale: String,
    /// Security/token settings.
    pub security: SecuritySettings,
    /// Messaging integration (Telegram/WhatsApp) settings.
    #[serde(default)]
    pub messaging: MessagingConfig,
    /// White-labeling for the management UI (accent CSS, logo, favicon).
    #[serde(default)]
    pub branding: BrandingConfig,
    /// Target APIs (audiences) umami can mint tokens for — see [`ApiDef`] and `docs/AUDIENCES.md`.
    #[serde(default)]
    pub apis: Vec<ApiDef>,
}

/// A tenant's feature set *including* the synthetic markers `assignableIf` gates on
/// (`is:system-tenant`, `feature:messaging-configured`).
///
/// A newtype rather than a bare `Vec<String>`, and only producible by
/// [`Config::eval_feature_set`], because the distinction is invisible at a call site and easy to
/// get wrong: the markers are derived, not stored on the tenant. Three of five call sites once
/// passed the raw stored features, which silently made every `is:system-tenant`-gated role and
/// feature unassignable — in the system tenant too. That mistake no longer compiles.
#[derive(Debug, Clone)]
pub struct EffectiveFeatures(Vec<String>);

impl EffectiveFeatures {
    fn as_set(&self) -> BTreeSet<&str> {
        self.0.iter().map(String::as_str).collect()
    }
}

impl Config {
    /// Finds a target API by code.
    pub fn find_api(&self, code: &str) -> Option<&ApiDef> {
        self.apis.iter().find(|api| api.code == code)
    }

    /// Rejects a password shorter than `security.min_password_length` (counted in characters) with
    /// a client error.
    pub fn validate_password(&self, password: &str) -> anyhow::Result<()> {
        let length = password.chars().count() as u32;
        if length < self.security.min_password_length {
            client_bail!(
                "Password must be at least {} characters",
                self.security.min_password_length
            );
        }
        Ok(())
    }

    /// Validates provided custom-field values against a schema: every key must be defined and, for
    /// the known types, the JSON value must match (a `select` value must be one of its `options`).
    /// A `null` value counts as "unset". Finally, every `required` field must be present with a
    /// non-null, non-empty value. `values` is treated as the complete set (callers replace, not
    /// merge). Returns a client error otherwise.
    pub fn validate_custom_fields(
        definitions: &[CustomFieldDef],
        values: &BTreeMap<String, Value>,
    ) -> anyhow::Result<()> {
        for (key, value) in values {
            let definition = match definitions.iter().find(|def| &def.code == key) {
                Some(definition) => definition,
                None => client_bail!("Unknown custom field '{key}'"),
            };

            // A null is an explicit "unset" — skip the type check (required is handled below).
            if value.is_null() {
                continue;
            }

            match definition.field_type.as_str() {
                "string" if !value.is_string() => {
                    client_bail!("Custom field '{key}' must be a string")
                }
                "number" if !value.is_number() => {
                    client_bail!("Custom field '{key}' must be a number")
                }
                "bool" | "boolean" if !value.is_boolean() => {
                    client_bail!("Custom field '{key}' must be a boolean")
                }
                "select" => {
                    let ok = value
                        .as_str()
                        .is_some_and(|v| definition.options.iter().any(|opt| opt == v));
                    if !ok {
                        client_bail!(
                            "Custom field '{key}' must be one of: {}",
                            definition.options.join(", ")
                        );
                    }
                }
                // Known types matched above; anything else is accepted as-is.
                _ => {}
            }
        }

        // Enforce required fields against the (complete) provided value set.
        for definition in definitions {
            if !definition.required {
                continue;
            }
            let present = values
                .get(&definition.code)
                .is_some_and(|value| match value {
                    Value::Null => false,
                    Value::String(text) => !text.trim().is_empty(),
                    _ => true,
                });
            if !present {
                client_bail!("Custom field '{}' is required", definition.code);
            }
        }
        Ok(())
    }

    /// The role codes assignable to a user in a tenant with the given (namespaced) feature set —
    /// i.e. those whose `assignableIf` holds against `feature:*`/`is:*`.
    pub fn assignable_roles(&self, features: &EffectiveFeatures) -> Vec<String> {
        let set = features.as_set();
        self.roles
            .iter()
            .filter(|role| assignable(&role.assignable_if, &set))
            .map(|role| role.code.clone())
            .collect()
    }

    /// Whether a specific role is assignable in a tenant with the given feature set (and is defined).
    pub fn can_assign_role(&self, code: &str, features: &EffectiveFeatures) -> bool {
        let set = features.as_set();
        self.roles
            .iter()
            .find(|role| role.code == code)
            .is_some_and(|role| assignable(&role.assignable_if, &set))
    }

    /// Augments a tenant's stored feature set with the synthetic markers that apply to it, so
    /// `assignableIf` can gate on `is:*` (e.g. `is:system-tenant`) exactly as the mint layer does.
    /// Mirror of the broker's subject-set construction, minus the principal's own subjects.
    pub fn eval_feature_set(
        &self,
        tenant_features: &[String],
        is_system_tenant: bool,
    ) -> EffectiveFeatures {
        let mut set: Vec<String> = tenant_features.to_vec();
        if is_system_tenant {
            set.push(SYSTEM_TENANT_MARKER.to_owned());
        }
        if self.messaging.is_configured() {
            set.push(MESSAGING_CONFIGURED_MARKER.to_owned());
        }
        EffectiveFeatures(set)
    }

    /// The scope codes assignable to a key in a tenant with the given feature set.
    pub fn assignable_scopes(&self, features: &EffectiveFeatures) -> Vec<String> {
        let set = features.as_set();
        self.scopes
            .iter()
            .filter(|scope| assignable(&scope.assignable_if, &set))
            .map(|scope| scope.code.clone())
            .collect()
    }

    /// Whether a specific scope is assignable in a tenant with the given feature set (and is defined).
    pub fn can_assign_scope(&self, code: &str, features: &EffectiveFeatures) -> bool {
        let set = features.as_set();
        self.scopes
            .iter()
            .find(|scope| scope.code == code)
            .is_some_and(|scope| assignable(&scope.assignable_if, &set))
    }

    /// Whether a feature is grantable given the tenant's **current** features (its `assignableIf`
    /// holds and it is defined and not synthetic).
    pub fn can_grant_feature(&self, code: &str, features: &EffectiveFeatures) -> bool {
        if is_synthetic(code) {
            return false;
        }
        let set = features.as_set();
        self.features
            .iter()
            .find(|feature| feature.code == code)
            .is_some_and(|feature| assignable(&feature.assignable_if, &set))
    }

    /// Feature codes grantable to a tenant right now: defined, non-synthetic, not already granted,
    /// and whose `assignableIf` holds against the current feature set.
    pub fn assignable_features(&self, features: &EffectiveFeatures) -> Vec<String> {
        let set = features.as_set();
        self.features
            .iter()
            .filter(|feature| !is_synthetic(&feature.code))
            .filter(|feature| !set.contains(feature.code.as_str()))
            .filter(|feature| assignable(&feature.assignable_if, &set))
            .map(|feature| feature.code.clone())
            .collect()
    }

    /// Looks up a feature's `assignableIf` (for the revoke dependency check). `None` if unknown.
    pub fn feature_assignable_if(&self, code: &str) -> Option<&str> {
        self.features
            .iter()
            .find(|feature| feature.code == code)
            .and_then(|feature| feature.assignable_if.as_deref())
    }
}

/// Whether a synthetic marker (`is:*`, computed and never stored, so never grantable/revocable).
pub fn is_synthetic(code: &str) -> bool {
    code.starts_with("is:")
}

/// Serde default for [`Config::default_locale`].
fn default_locale() -> String {
    "en".to_owned()
}

/// Evaluates an optional `assignableIf` against a feature set — `None` means always assignable.
fn assignable(assignable_if: &Option<String>, set: &BTreeSet<&str>) -> bool {
    match assignable_if {
        Some(expr) => eval_expression(expr, set),
        None => true,
    }
}

impl Default for Config {
    fn default() -> Self {
        let role = |code: &str, name: &str| RoleDef {
            code: code.to_owned(),
            name: name.to_owned(),
            description: None,
            assignable_if: None,
        };
        let rule = |when: &str, grant: &[&str]| PermissionRule {
            when: when.to_owned(),
            grant: grant.iter().map(|p| (*p).to_owned()).collect(),
        };
        let scope = |code: &str, name: &str, assignable_if: Option<&str>| ScopeDef {
            code: code.to_owned(),
            name: name.to_owned(),
            description: None,
            assignable_if: assignable_if.map(str::to_owned),
        };
        Config {
            version: 1,
            roles: vec![
                role(ROLE_OWNER, "Owner"),
                role("role:admin", "Administrator"),
                role(ROLE_MEMBER, "Member"),
                role("role:viewer", "Viewer"),
                role("role:readonly", "Read-only (blocks self-service edits)"),
            ],
            scopes: vec![
                // Only assignable to a system-tenant service key (and shown only there).
                scope(
                    "scope:messaging-linker",
                    "Messaging linker (bot backend)",
                    Some(SYSTEM_TENANT_MARKER),
                ),
                scope(
                    "scope:messaging-resolver",
                    "Messaging resolver",
                    Some(SYSTEM_TENANT_MARKER),
                ),
            ],
            features: Vec::new(),
            custom_tenant_fields: Vec::new(),
            custom_user_fields: Vec::new(),
            default_locale: default_locale(),
            security: SecuritySettings {
                min_password_length: 8,
                access_ttl_secs: DEFAULT_ACCESS_TTL_SECS,
                refresh_ttl_secs: DEFAULT_REFRESH_TTL_SECS,
                messaging_code_ttl_secs: DEFAULT_MESSAGING_CODE_TTL_SECS,
                rate_limits: RateLimitsConfig::default(),
                // Empty by default: the hosted-login redirect stays off until a deployment
                // names the URLs it trusts.
                redirect_uris: Vec::new(),
            },
            messaging: MessagingConfig::default(),
            branding: BrandingConfig::default(),
            // The umami admin API. This is a deliberately MINIMAL, bootstrap-only mapping: it grants
            // the system-tenant owner enough to log in and administer (so they can then write the
            // real config), maps the cross-tenant + messaging + readonly markers, and stops there.
            // The full role matrix (admin/member/viewer → …) is NOT hardcoded — see the standard
            // config in docs/CONFIG.md. Routes only ever check the resulting plain permissions.
            apis: vec![ApiDef {
                code: "umami".to_owned(),
                audience: "umami".to_owned(),
                eligibility: None,
                permissions: vec![
                    // Baseline self-service for any logged-in user: manage your own profile,
                    // security settings, personal access tokens, and sessions. (Empty `when` = always
                    // fires.) A deployment that wants a read-only role simply writes a config that
                    // does not grant these to that role — there is no separate deny marker.
                    rule(
                        "",
                        &[
                            MANAGE_PROFILE_PERMISSION,
                            MANAGE_PASSWORDS_PERMISSION,
                            MANAGE_PERSONAL_TOKENS_PERMISSION,
                            MANAGE_SESSIONS_PERMISSION,
                        ],
                    ),
                    // Bootstrap owner: full self-tenant administration + config.
                    rule(
                        ROLE_OWNER,
                        &[
                            VIEW_AUDIT_PERMISSION,
                            MANAGE_USERS_PERMISSION,
                            MANAGE_SERVICE_KEYS_PERMISSION,
                            MANAGE_CONFIG_PERMISSION,
                        ],
                    ),
                    // Cross-tenant admin comes from system-tenant *membership*, not from
                    // currently acting inside it: a support user who switched into a customer
                    // tenant has to keep `switch:tenant`, or they cannot switch back.
                    rule(
                        SYSTEM_TENANT_MEMBER_MARKER,
                        &[MANAGE_TENANTS_PERMISSION, SWITCH_TENANT_PERMISSION],
                    ),
                    // Self-service messaging is available to everyone once the deployment has a bot
                    // and/or number configured.
                    rule(MESSAGING_CONFIGURED_MARKER, &[MANAGE_MESSAGING_PERMISSION]),
                    // Messaging M2M: only system-tenant service keys carrying the scope get the
                    // cross-tenant link/resolve permissions.
                    rule(
                        &format!("scope:messaging-linker + {SYSTEM_TENANT_MARKER}"),
                        &[MESSAGING_LINK_PERMISSION],
                    ),
                    rule(
                        &format!("scope:messaging-resolver + {SYSTEM_TENANT_MARKER}"),
                        &[MESSAGING_RESOLVE_PERMISSION],
                    ),
                ],
                claims: BTreeMap::new(),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set<'a>(items: &'a [&'a str]) -> BTreeSet<&'a str> {
        items.iter().copied().collect()
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| (*i).to_owned()).collect()
    }

    fn field(code: &str, field_type: &str, required: bool, options: &[&str]) -> CustomFieldDef {
        CustomFieldDef {
            code: code.to_owned(),
            label: code.to_owned(),
            field_type: field_type.to_owned(),
            options: s(options),
            required,
            show_in_table: false,
            self_editable: false,
        }
    }

    #[test]
    fn custom_fields_select_and_required() {
        let defs = vec![
            field("plan", "select", true, &["gold", "silver"]),
            field("seats", "number", false, &[]),
        ];

        // Happy path: valid select value + number.
        let ok = BTreeMap::from([
            ("plan".to_owned(), Value::from("gold")),
            ("seats".to_owned(), Value::from(5)),
        ]);
        assert!(Config::validate_custom_fields(&defs, &ok).is_ok());

        // Select value outside the option set is rejected.
        let bad_option = BTreeMap::from([("plan".to_owned(), Value::from("bronze"))]);
        assert!(Config::validate_custom_fields(&defs, &bad_option).is_err());

        // Wrong type for a number is rejected.
        let bad_type = BTreeMap::from([
            ("plan".to_owned(), Value::from("gold")),
            ("seats".to_owned(), Value::from("lots")),
        ]);
        assert!(Config::validate_custom_fields(&defs, &bad_type).is_err());

        // Missing required field is rejected...
        let missing = BTreeMap::from([("seats".to_owned(), Value::from(1))]);
        assert!(Config::validate_custom_fields(&defs, &missing).is_err());

        // ...and so is an empty-string / null required value.
        let empty = BTreeMap::from([("plan".to_owned(), Value::from(""))]);
        assert!(Config::validate_custom_fields(&defs, &empty).is_err());
        let null = BTreeMap::from([("plan".to_owned(), Value::Null)]);
        assert!(Config::validate_custom_fields(&defs, &null).is_err());

        // Unknown key is rejected.
        let unknown = BTreeMap::from([
            ("plan".to_owned(), Value::from("gold")),
            ("nope".to_owned(), Value::from("x")),
        ]);
        assert!(Config::validate_custom_fields(&defs, &unknown).is_err());
    }

    #[test]
    fn older_security_config_without_rate_limits_uses_defaults() {
        // A stored `security` block from before rate limiting existed must still deserialize, with
        // the new `rateLimits` filled from the built-in defaults (serde `#[serde(default)]`).
        let json = r#"{
            "minPasswordLength": 8,
            "accessTtlSecs": 600,
            "refreshTtlSecs": 2592000
        }"#;
        let security: SecuritySettings = serde_json::from_str(json).expect("deserializes");
        assert_eq!(
            security.rate_limits.login.max_failures,
            DEFAULT_LOGIN_MAX_FAILURES
        );
        assert_eq!(
            security.rate_limits.token_exchange.max_per_window,
            DEFAULT_TOKEN_MAX_PER_WINDOW
        );
        assert_eq!(
            security.rate_limits.per_ip.max_per_window,
            DEFAULT_PER_IP_MAX_PER_WINDOW
        );

        // A partial `rateLimits` (only `login`) keeps the other policies at their defaults.
        let partial = r#"{
            "minPasswordLength": 8,
            "accessTtlSecs": 600,
            "refreshTtlSecs": 2592000,
            "rateLimits": { "login": { "maxFailures": 3, "windowSecs": 60, "blockSecs": 120 } }
        }"#;
        let security: SecuritySettings = serde_json::from_str(partial).expect("deserializes");
        assert_eq!(security.rate_limits.login.max_failures, 3);
        assert_eq!(
            security.rate_limits.per_ip.max_per_window,
            DEFAULT_PER_IP_MAX_PER_WINDOW
        );
    }

    #[test]
    fn expression_or_and_not_precedence() {
        // a OR (b AND c)
        assert!(eval_expression("a,b+c", &set(&["a"])));
        assert!(eval_expression("a,b+c", &set(&["b", "c"])));
        assert!(!eval_expression("a,b+c", &set(&["b"])));
        assert!(!eval_expression("a,b+c", &set(&["x"])));
        // negation
        assert!(eval_expression("a+!b", &set(&["a"])));
        assert!(!eval_expression("a+!b", &set(&["a", "b"])));
        assert!(eval_expression("!b", &set(&["a"])));
        // empty expression = no restriction
        assert!(eval_expression("", &set(&["a"])));
    }

    fn dbx_api() -> ApiDef {
        ApiDef {
            code: "dbx-core".to_owned(),
            audience: "dbx-core".to_owned(),
            eligibility: Some("role:member,role:admin".to_owned()),
            permissions: vec![
                PermissionRule {
                    when: "role:admin".to_owned(),
                    grant: s(&["admin:blocks", "write:blocks"]),
                },
                PermissionRule {
                    when: "feature:ai + role:ai".to_owned(),
                    grant: s(&["use:ai"]),
                },
                // chains off an earlier grant
                PermissionRule {
                    when: "write:blocks".to_owned(),
                    grant: s(&["read:blocks"]),
                },
            ],
            claims: BTreeMap::from([("svc".to_owned(), "dbx-core".to_owned())]),
        }
    }

    #[test]
    fn resolve_ordered_accumulate_with_chaining() {
        let api = dbx_api();
        // role:admin → admin:blocks, write:blocks → (chained) read:blocks
        let perms = api.resolve(&s(&["role:admin"])).expect("eligible");
        assert_eq!(perms, s(&["admin:blocks", "read:blocks", "write:blocks"]));
    }

    #[test]
    fn resolve_respects_eligibility_and_features() {
        let api = dbx_api();
        // role:ai alone is eligible? eligibility is role:member,role:admin → no.
        assert!(api.resolve(&s(&["role:ai", "feature:ai"])).is_none());
        // role:member is eligible but grants nothing here.
        assert_eq!(api.resolve(&s(&["role:member"])), Some(Vec::new()));
        // admin + ai feature + ai role
        let perms = api
            .resolve(&s(&["role:admin", "role:ai", "feature:ai"]))
            .expect("eligible");
        assert!(perms.contains(&"use:ai".to_owned()));
        assert!(perms.contains(&"write:blocks".to_owned()));
    }

    #[test]
    fn default_umami_maps_roles_and_system_marker() {
        let umami = Config::default().find_api("umami").unwrap().clone();
        let owner = umami.resolve(&s(&["role:owner"])).unwrap();
        assert!(owner.contains(&"view:audit".to_owned()));
        assert!(owner.contains(&"manage:users".to_owned()));
        assert!(owner.contains(&"manage:config".to_owned()));
        // cross-tenant permissions come only from the system-tenant marker, never a plain role
        assert!(!owner.contains(&"manage:tenants".to_owned()));
        assert!(!owner.contains(&"switch:tenant".to_owned()));
        // Cross-tenant admin follows *membership*, not where the token currently acts. Three
        // situations, and the markers tell them apart:

        // 1. At home in the system tenant — both markers hold.
        let at_home = umami
            .resolve(&s(&[
                "role:owner",
                "is:system-tenant",
                "is:system-tenant-member",
            ]))
            .unwrap();
        assert!(at_home.contains(&"manage:tenants".to_owned()));
        assert!(at_home.contains(&"switch:tenant".to_owned()));

        // 2. Switched into a customer tenant — member, but no longer acting in the system
        //    tenant. Keeping `switch:tenant` here is the point of the split: without it the
        //    token in hand cannot switch back.
        let switched = umami
            .resolve(&s(&["role:owner", "is:system-tenant-member"]))
            .unwrap();
        assert!(switched.contains(&"switch:tenant".to_owned()));

        // 3. Acting inside the system tenant without being a member grants nothing cross-tenant.
        let acting_only = umami
            .resolve(&s(&["role:owner", "is:system-tenant"]))
            .unwrap();
        assert!(!acting_only.contains(&"manage:tenants".to_owned()));
        assert!(!acting_only.contains(&"switch:tenant".to_owned()));
        // Baseline self-service (empty `when`) is granted to any logged-in user, so even an
        // otherwise-unmapped viewer gets the granular self-service permissions — and there is no
        // longer a `self:readonly` deny marker.
        let viewer = umami.resolve(&s(&["role:viewer"])).unwrap();
        assert!(viewer.contains(&"manage:profile".to_owned()));
        assert!(viewer.contains(&"manage:passwords".to_owned()));
        assert!(viewer.contains(&"manage:personal-tokens".to_owned()));
        assert!(viewer.contains(&"manage:sessions".to_owned()));
        assert!(!viewer.contains(&"self:readonly".to_owned()));
        // Tenant administration still requires the owner role, not just the self-service baseline.
        assert!(!viewer.contains(&"view:audit".to_owned()));
    }

    #[test]
    fn assignability_gates_on_tenant_features() {
        let config = Config {
            roles: vec![RoleDef {
                code: "role:ai".to_owned(),
                name: "AI".to_owned(),
                description: None,
                assignable_if: Some("feature:ai".to_owned()),
            }],
            features: vec![
                FeatureDef {
                    code: "feature:base".to_owned(),
                    name: "Base".to_owned(),
                    description: None,
                    assignable_if: None,
                },
                FeatureDef {
                    code: "feature:ai".to_owned(),
                    name: "AI".to_owned(),
                    description: None,
                    assignable_if: Some("feature:base".to_owned()),
                },
            ],
            ..Config::default()
        };
        // role:ai only assignable when the tenant has feature:ai
        let none = config.eval_feature_set(&[], false);
        assert!(!config.can_assign_role("role:ai", &none));
        let ai = config.eval_feature_set(&s(&["feature:ai"]), false);
        assert!(config.can_assign_role("role:ai", &ai));
        // feature:ai grantable only once feature:base is present; and not if already granted
        assert!(!config.can_grant_feature("feature:ai", &none));
        let base = config.eval_feature_set(&s(&["feature:base"]), false);
        assert!(config.can_grant_feature("feature:ai", &base));
        assert_eq!(config.assignable_features(&base), s(&["feature:ai"]));
        // synthetic markers are never grantable
        assert!(!config.can_grant_feature("is:system-tenant", &base));
    }

    /// The bug this newtype exists to prevent: `is:system-tenant` is synthetic — it is never
    /// stored on the tenant — so a caller that hands over the *stored* features makes every role
    /// gated on it unassignable, in the system tenant too. `assignable_roles` and
    /// `validate_roles` both did exactly that, which is why no admin role could be granted.
    #[test]
    fn system_tenant_roles_need_the_synthetic_marker() {
        let config = Config {
            roles: vec![RoleDef {
                code: "role:platform-admin".to_owned(),
                name: "Platform admin".to_owned(),
                description: None,
                assignable_if: Some(SYSTEM_TENANT_MARKER.to_owned()),
            }],
            ..Config::default()
        };

        // Stored features of the system tenant — empty, as they are in practice.
        let stored: Vec<String> = Vec::new();

        let outside = config.eval_feature_set(&stored, false);
        assert!(
            !config.can_assign_role("role:platform-admin", &outside),
            "a normal tenant must not reach a system-tenant role"
        );
        assert!(config.assignable_roles(&outside).is_empty());

        let inside = config.eval_feature_set(&stored, true);
        assert!(
            config.can_assign_role("role:platform-admin", &inside),
            "the system tenant must reach it — the marker is added, not stored"
        );
        assert_eq!(
            config.assignable_roles(&inside),
            vec!["role:platform-admin"]
        );
    }

    #[test]
    fn claim_mapping_resolves_sources() {
        let mut api = dbx_api();
        api.claims = BTreeMap::from([
            ("svc".to_owned(), "dbx-core".to_owned()), // literal
            ("uname".to_owned(), "$user.username".to_owned()),
            ("dept".to_owned(), "$user.custom.department".to_owned()),
            ("tid".to_owned(), "$tenant.id".to_owned()),
            ("feats".to_owned(), "$tenant.features".to_owned()),
            ("missing".to_owned(), "$user.custom.nope".to_owned()),
            ("bogus".to_owned(), "$user.nope".to_owned()),
        ]);
        let names = crate::users::DisplayNames::default();
        let user_cf = BTreeMap::from([("department".to_owned(), json!("engineering"))]);
        let tenant_cf = BTreeMap::new();
        let features = vec!["feature:ai".to_owned()];
        let ctx = ClaimContext {
            user_id: "u1",
            username: "jane",
            email: "jane@x",
            display_names: &names,
            title: None,
            salutation: "",
            locale: "de",
            firstname: None,
            lastname: None,
            roles: &[],
            user_custom: &user_cf,
            tenant_id: "t1",
            tenant_name: "Acme",
            tenant_slug: "acme",
            tenant_features: &features,
            tenant_custom: &tenant_cf,
        };
        let claims = api.build_claims(&ctx);
        assert_eq!(claims.get("svc"), Some(&json!("dbx-core")));
        assert_eq!(claims.get("uname"), Some(&json!("jane")));
        assert_eq!(claims.get("dept"), Some(&json!("engineering")));
        assert_eq!(claims.get("tid"), Some(&json!("t1")));
        assert_eq!(claims.get("feats"), Some(&json!(["feature:ai"])));
        // Absent custom value and unknown reference are omitted entirely.
        assert_eq!(claims.get("missing"), None);
        assert_eq!(claims.get("bogus"), None);
    }
}
