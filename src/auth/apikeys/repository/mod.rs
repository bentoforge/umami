//! Persistence for API keys: each key's metadata + the SHA-256 hash of its secret. The secret
//! itself is never stored.

pub mod dynamodb;
pub mod postgres;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Lifecycle state of an API key.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyStatus {
    /// Usable.
    Active,
    /// Revoked — exchange rejected.
    Revoked,
}

/// Per-key override of the global `tokenExchange` rate-limit policy (see `docs/API-KEYS.md`).
/// Mainly used to **raise** the cap for a legitimate high-fanout backend, or to **disable** the
/// per-key cap for a controlled public-token flow (the per-IP cap still applies). Any unset field
/// falls back to the global `security.rateLimits.tokenExchange` value.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct KeyRateLimit {
    /// When true, the per-key volume cap is switched off for this key entirely.
    #[serde(default)]
    pub disabled: bool,
    /// Overrides `tokenExchange.maxPerWindow` for this key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_window: Option<u32>,
    /// Overrides `tokenExchange.windowSecs` for this key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_secs: Option<u32>,
    /// Overrides `tokenExchange.blockSecs` for this key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_secs: Option<u32>,
}

/// A persisted API key (metadata + secret hash).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApiKey {
    /// Primary key.
    pub key_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// SHA-256 (base64url) of the secret.
    pub secret_hash: String,
    /// Human-readable label.
    pub name: String,
    /// **Subject discriminator.** `None` → a *service key* that acts as itself (subjects are its
    /// `scopes`). `Some(userId)` → a *personal access token* that acts as that user (its `role:*`,
    /// optionally restricted by `roles`). See `docs/API-KEYS.md`.
    #[serde(default)]
    pub user_id: Option<String>,
    /// PAT role restriction: when non-empty, the token acts with the user's roles **intersected**
    /// with this set (never an escalation). Empty = the user's full roles. Ignored for service keys.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Service-key subjects: the `scope:*` codes this machine key carries at exchange. Ignored for
    /// PATs (which derive their subjects from the acting user).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Lifecycle state.
    pub status: ApiKeyStatus,
    /// Whether the raw-secret exchange (Mode 1) is accepted for this key. Default **false** ⇒ the key
    /// is HMAC-only (Mode 2): presenting the raw secret is refused even if it is correct.
    #[serde(default)]
    pub allow_secret_login: bool,
    /// Origins permitted to exchange this key (Mode 1); empty = unrestricted.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Optional per-key override of the `tokenExchange` rate-limit policy. `None` = use the global
    /// policy (see [`KeyRateLimit`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<KeyRateLimit>,
    /// Optional per-key lifetime for the tokens this key mints, in seconds. `None` = the global
    /// `security.accessTtlSecs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_ttl_secs: Option<u64>,
    /// Optional expiry.
    pub expires_at: Option<DateTime<Utc>>,
    /// Last successful exchange.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created: DateTime<Utc>,
}

/// Parameters for creating an API key.
pub struct NewApiKey {
    pub key_id: String,
    pub tenant_id: String,
    pub secret_hash: String,
    pub name: String,
    /// `Some(userId)` → personal access token; `None` → tenant service key.
    pub user_id: Option<String>,
    pub roles: Vec<String>,
    /// PAT down-scoping (ignored for service keys).
    pub scopes: Vec<String>,
    /// Whether the raw-secret exchange (Mode 1) is allowed; `false` ⇒ HMAC-only.
    pub allow_secret_login: bool,
    pub allowed_origins: Vec<String>,
    /// Optional per-key rate-limit override (`None` = use the global `tokenExchange` policy).
    pub rate_limit: Option<KeyRateLimit>,
    /// Optional per-key token lifetime in seconds (`None` = the global `security.accessTtlSecs`).
    pub access_ttl_secs: Option<u64>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Persistence for API keys.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait ApiKeyRepository: Send + Sync {
    /// Stores a new key.
    async fn create(&self, new_key: NewApiKey) -> anyhow::Result<()>;

    /// Fetches a key by id.
    async fn get(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>>;

    /// Lists a tenant's keys (via `ByTenantIndex`).
    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<ApiKey>>;

    /// Deletes (revokes) a key.
    async fn delete(&self, key_id: &str) -> anyhow::Result<()>;

    /// Deletes a user's **personal access tokens** in `tenant_id`, returning how many there were.
    ///
    /// For deleting the user. Only rows whose `userId` is theirs: a service key carries `None` there
    /// and belongs to the tenant, so it survives the person who happened to create it.
    async fn delete_all_for_user(&self, tenant_id: &str, user_id: &str) -> anyhow::Result<usize>;

    /// Best-effort `lastUsedAt` bump after a successful exchange.
    async fn touch_last_used(&self, key_id: &str) -> anyhow::Result<()>;
}
