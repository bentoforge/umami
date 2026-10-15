//! Persistence for user identities: the [`UserRepository`] trait and the helpers its backends
//! share.

pub mod dynamodb;
pub mod postgres;

use crate::search::value_search_text;
use crate::users::{User, normalize_name, normalize_username};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use wasabi::aws::dynamodb::generate_id;
use wasabi::client_bail;

/// A `user-usernames` row: the uniqueness guard + username→user pointer.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct UserName {
    /// Normalized username — hash key.
    username: String,
    /// The user this username belongs to.
    user_id: String,
    /// RFC 3339 creation timestamp.
    created: chrono::DateTime<chrono::Utc>,
}

/// Parameters for creating a user.
pub struct NewUser {
    /// Owning tenant.
    pub tenant_id: String,
    /// Role codes within the tenant (defined in the config catalog).
    pub roles: Vec<String>,
    /// Login username — required, globally unique (normalized). Stored as given (trimmed).
    pub username: String,
    /// Optional honorific/title.
    pub title: Option<String>,
    /// How to address the user.
    pub salutation: crate::users::Salutation,
    /// Given name.
    pub firstname: Option<String>,
    /// Family name.
    pub lastname: Option<String>,
    /// The user's own language (BCP-47), or `None` for the deployment default.
    pub locale: Option<String>,
    /// argon2id hash, or `None` for invite/SSO-only users.
    pub password_hash: Option<String>,
    /// Values for the config-defined custom user fields.
    pub custom_fields: std::collections::BTreeMap<String, serde_json::Value>,
    /// User id creating this user (audit); `None` for the auto-init bootstrap owner.
    pub created_by: Option<String>,
    /// Whether the initial password was admin-generated (vs. explicitly supplied) — stamps
    /// `last_password_reset` so the "generated password" flag shows until the user changes it.
    pub password_generated: bool,
}

/// Persistence interface for user identities.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait UserRepository: Send + Sync {
    /// Creates a new user, enforcing global username uniqueness (via the `user-usernames` table).
    /// Returns a client error if the username is already taken. Email is not unique.
    async fn create_user(&self, new_user: NewUser) -> anyhow::Result<User>;

    /// Looks up a user by (normalized) username via the `user-usernames` table. `None` if unknown.
    async fn find_by_username(&self, username: &str) -> anyhow::Result<Option<User>>;

    /// Fetches a user by id. `None` if unknown.
    async fn get_user(&self, user_id: &str) -> anyhow::Result<Option<User>>;

    /// Finds users in `tenant_id` matching `query` (case-insensitive over username/name/custom
    /// fields; empty = all), newest-active first, returning at most `limit` plus a `truncated` flag.
    /// The DynamoDB backend streams the per-tenant GSI and stops once the cap is reached.
    async fn find_users(
        &self,
        tenant_id: &str,
        query: &str,
        limit: usize,
    ) -> anyhow::Result<(Vec<User>, bool)>;

    /// Overwrites a user record (used by PATCH after a read-modify).
    async fn put_user(&self, user: User) -> anyhow::Result<User>;

    /// Atomically increments `tokenVersion` — the global "log out everywhere" lever.
    async fn bump_token_version(&self, user_id: &str) -> anyhow::Result<()>;

    /// Best-effort bump of `lastSeen` to now (called on authentication). Keeps the per-tenant
    /// listing GSI ordered by activity.
    async fn touch_last_seen(&self, user_id: &str) -> anyhow::Result<()>;

    /// Marks the user as having at least one passkey (denormalized flag; idempotent).
    async fn set_has_passkey(&self, user_id: &str) -> anyhow::Result<()>;

    /// Moves the username-uniqueness guard from `old_username` to `new_username` (reserve new, then
    /// release old). A no-op when the normalized name is unchanged (case-only edit). Fails if the
    /// new name is already taken. The caller still writes `user.username` via [`Self::put_user`].
    async fn rename_username(
        &self,
        user_id: &str,
        old_username: &str,
        new_username: &str,
    ) -> anyhow::Result<()>;

    /// Hard-deletes a user and releases its username-uniqueness guard so the name can be reused.
    /// `username` is the user's stored login username.
    async fn delete_user(&self, user_id: &str, username: &str) -> anyhow::Result<()>;
}

/// The user a [`NewUser`] becomes, and the username guard that reserves its name — shared by every
/// backend, so what a new account looks like does not depend on where it is stored.
fn new_user_records(new_user: NewUser) -> anyhow::Result<(User, UserName)> {
    let username = new_user.username.trim().to_owned();
    if username.is_empty() {
        client_bail!("A username is required");
    }
    let normalized = normalize_username(&username);
    let now = Utc::now();

    let user = User {
        locale: new_user
            .locale
            .map(|locale| locale.trim().to_owned())
            .filter(|locale| !locale.is_empty()),
        user_id: generate_id(),
        tenant_id: new_user.tenant_id,
        roles: new_user.roles,
        username,
        title: normalize_name(new_user.title),
        salutation: new_user.salutation,
        firstname: normalize_name(new_user.firstname),
        lastname: normalize_name(new_user.lastname),
        password_hash: new_user.password_hash,
        locked: false,
        token_version: 0,
        totp_secret: None,
        totp_pending: None,
        custom_fields: new_user.custom_fields,
        created: now,
        last_updated: now,
        last_seen: None,
        last_active_or_created: now,
        last_password_reset: if new_user.password_generated {
            Some(now)
        } else {
            None
        },
        last_password_change: None,
        has_passkey: false,
        created_by: new_user.created_by.clone(),
        last_changed_by: new_user.created_by,
        preferred_contact: None,
        notification_choices: Default::default(),
    };

    let guard = UserName {
        username: normalized,
        user_id: user.user_id.clone(),
        created: now,
    };

    Ok((user, guard))
}

/// Concatenates a user's searchable text: username, name parts, and every custom-field value.
/// Fed to `query_matches` for the in-memory tenant-scoped search.
///
/// Addresses are deliberately absent: they live in `user-contacts`, and pulling them in would mean
/// a per-user read for every row this scan touches. Looking a user up *by* an address is a direct
/// query on the by-address GSI instead — cheaper than the scan this feeds.
fn user_haystack(user: &User) -> String {
    let mut haystack = format!(
        "{} {} {} {}",
        user.username,
        user.title.as_deref().unwrap_or(""),
        user.firstname.as_deref().unwrap_or(""),
        user.lastname.as_deref().unwrap_or("")
    );
    for value in user.custom_fields.values() {
        haystack.push(' ');
        haystack.push_str(&value_search_text(value));
    }
    haystack
}
