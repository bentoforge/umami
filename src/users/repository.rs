//! DynamoDB persistence for user identities.
//!
//! Uses `users` (keyed by `userId`, with a `ByTenantIndex` GSI to list a tenant's users) and a
//! `user-usernames` guard table (keyed by the normalized `username`) that enforces global username
//! uniqueness via a conditional put and serves the strongly-consistent username→user login lookup.
//! Email is optional contact info and is not indexed.

use crate::search::{query_matches, value_search_text};
use crate::users::{User, normalize_name, normalize_username};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType,
};
use chrono::{SecondsFormat, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, generate_id, str, stream_all};
use wasabi::client_bail;

// ── Table names ────────────────────────────────────────────────────────────────

/// Primary table storing user identities, keyed by `userId`.
const TABLE_USERS: &str = "users";

/// Uniqueness + lookup table mapping a normalized `username` to its `userId`.
const TABLE_USER_USERNAMES: &str = "user-usernames";

// ── Field / index names ──────────────────────────────────────────────────────

/// Hash key of the `users` table.
const FIELD_USER_ID: &str = "userId";

/// Owning tenant — GSI hash key.
const FIELD_TENANT_ID: &str = "tenantId";

/// Global revocation counter attribute.
const FIELD_TOKEN_VERSION: &str = "tokenVersion";

/// RFC 3339 last-update attribute.
const FIELD_LAST_UPDATED: &str = "lastUpdated";

/// RFC 3339 last-authentication attribute — absent until the user is first active.
const FIELD_LAST_SEEN: &str = "lastSeen";

/// `lastActiveOrCreated` attribute — range key of `ByTenantIndex` (`last_seen` else `created`;
/// bumped on activity), so a tenant's users sort activity-first, inactive ones stably by creation.
const FIELD_LAST_ACTIVE_OR_CREATED: &str = "lastActiveOrCreated";

/// Hash key of the `user-usernames` guard table (holds the normalized username).
const FIELD_USERNAME: &str = "username";

/// `hasPasskey` flag attribute — set by [`UserRepository::set_has_passkey`] on passkey registration.
const FIELD_HAS_PASSKEY: &str = "hasPasskey";

/// GSI listing a tenant's users (hash on `tenantId`).
const INDEX_BY_TENANT: &str = "ByTenantIndex";

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

/// DynamoDB-backed implementation of [`UserRepository`].
#[derive(Clone)]
pub struct DynamoUserRepository {
    client: DynamoClient,
}

impl DynamoUserRepository {
    #[tracing::instrument(skip(client), err(Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_USERS, |table| {
                let by_tenant = GlobalSecondaryIndex::builder()
                    .index_name(INDEX_BY_TENANT)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(FIELD_TENANT_ID)
                            .key_type(KeyType::Hash)
                            .build()?,
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(FIELD_LAST_ACTIVE_OR_CREATED)
                            .key_type(KeyType::Range)
                            .build()?,
                    )
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .build()?;

                let table = table
                    .attribute_definitions(str_attribute(FIELD_USER_ID)?)
                    .attribute_definitions(str_attribute(FIELD_TENANT_ID)?)
                    .attribute_definitions(str_attribute(FIELD_LAST_ACTIVE_OR_CREATED)?);
                let table = with_hash_index(table, FIELD_USER_ID)?;

                Ok(table
                    .global_secondary_indexes(by_tenant)
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        client
            .create_table(TABLE_USER_USERNAMES, |table| {
                let table = table.attribute_definitions(str_attribute(FIELD_USERNAME)?);
                let table = with_hash_index(table, FIELD_USERNAME)?;
                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        Ok(Self {
            client: client.clone(),
        })
    }
}

#[async_trait]
impl UserRepository for DynamoUserRepository {
    #[tracing::instrument(level = "debug", skip(self, new_user), err(Display))]
    async fn create_user(&self, new_user: NewUser) -> anyhow::Result<User> {
        let username = new_user.username.trim().to_owned();
        if username.is_empty() {
            client_bail!("A username is required");
        }
        let normalized = normalize_username(&username);
        let now = Utc::now();

        let user = User {
            locale: None,
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

        // Claim the username first: a conditional put fails if it's already taken, giving strict
        // uniqueness before we write the user record.
        let guard = UserName {
            username: normalized,
            user_id: user.user_id.clone(),
            created: now,
        };

        let put_guard = self
            .client
            .put_entity(TABLE_USER_USERNAMES, &guard)?
            .condition_expression("attribute_not_exists(#username)")
            .expression_attribute_names("#username", FIELD_USERNAME)
            .send()
            .await;

        if let Err(err) = put_guard {
            if err
                .as_service_error()
                .map(|service_err| service_err.is_conditional_check_failed_exception())
                .unwrap_or(false)
            {
                client_bail!("A user with this username already exists");
            }
            return Err(
                anyhow::Error::new(err).context("Error reserving username in 'user-usernames'")
            );
        }

        // Defensive: the id is the PK, so `attribute_not_exists` turns a (near-impossible) id
        // collision into a loud failure rather than a silent overwrite — for free.
        let _ = self
            .client
            .put_entity(TABLE_USERS, &user)?
            .condition_expression("attribute_not_exists(#userId)")
            .expression_attribute_names("#userId", FIELD_USER_ID)
            .send()
            .await
            .context("Error inserting entity into 'users' table (id collision?)")?;

        Ok(user)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn find_by_username(&self, username: &str) -> anyhow::Result<Option<User>> {
        let normalized = normalize_username(username);

        let result = self
            .client
            .get_item(TABLE_USER_USERNAMES)
            .key(FIELD_USERNAME, str(normalized))
            .send()
            .await
            .context("Error searching table 'user-usernames'")?;

        let guard_row: Option<UserName> = deserialize_entity(result.item)?;

        match guard_row {
            Some(row) => self.get_user(&row.user_id).await,
            None => Ok(None),
        }
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn get_user(&self, user_id: &str) -> anyhow::Result<Option<User>> {
        let result = self
            .client
            .get_item(TABLE_USERS)
            .key(FIELD_USER_ID, str(user_id))
            .send()
            .await
            .context("Error searching table 'users'")?;

        deserialize_entity(result.item)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn find_users(
        &self,
        tenant_id: &str,
        query: &str,
        limit: usize,
    ) -> anyhow::Result<(Vec<User>, bool)> {
        // Per-tenant GSI, newest-active first. Stream the pages and filter in-memory (DynamoDB can't
        // search), stopping once we have `limit`+1 matches so we never drain the whole tenant.
        let request = self
            .client
            .query(TABLE_USERS)
            .index_name(INDEX_BY_TENANT)
            .key_condition_expression("#tenantId = :tenantId")
            .expression_attribute_names("#tenantId", FIELD_TENANT_ID)
            .expression_attribute_values(":tenantId", str(tenant_id))
            .scan_index_forward(false)
            .limit(100);

        let mut stream = stream_all::<User>(request)?;
        let mut matched = Vec::new();
        let mut truncated = false;
        while let Some(item) = stream.next().await {
            let user = item.context("Error listing users by tenant")?;
            if query_matches(&user_haystack(&user), query) {
                if matched.len() >= limit {
                    truncated = true;
                    break;
                }
                matched.push(user);
            }
        }
        Ok((matched, truncated))
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn put_user(&self, mut user: User) -> anyhow::Result<User> {
        user.last_updated = Utc::now();

        let _ = self
            .client
            .put_entity(TABLE_USERS, &user)?
            .send()
            .await
            .context("Error updating 'users' table")?;

        Ok(user)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn bump_token_version(&self, user_id: &str) -> anyhow::Result<()> {
        let _ = self
            .client
            .update_item(TABLE_USERS)
            .key(FIELD_USER_ID, str(user_id))
            .update_expression("ADD #tokenVersion :one SET #lastUpdated = :now")
            .condition_expression("attribute_exists(#userId)")
            .expression_attribute_names("#userId", FIELD_USER_ID)
            .expression_attribute_names("#tokenVersion", FIELD_TOKEN_VERSION)
            .expression_attribute_names("#lastUpdated", FIELD_LAST_UPDATED)
            .expression_attribute_values(":one", AttributeValue::N("1".to_owned()))
            .expression_attribute_values(
                ":now",
                str(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
            )
            .send()
            .await
            .context("Error bumping tokenVersion in 'users' table")?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn touch_last_seen(&self, user_id: &str) -> anyhow::Result<()> {
        let _ = self
            .client
            .update_item(TABLE_USERS)
            .key(FIELD_USER_ID, str(user_id))
            .update_expression("SET #lastSeen = :now, #lastActiveOrCreated = :now")
            .condition_expression("attribute_exists(#userId)")
            .expression_attribute_names("#userId", FIELD_USER_ID)
            .expression_attribute_names("#lastSeen", FIELD_LAST_SEEN)
            .expression_attribute_names("#lastActiveOrCreated", FIELD_LAST_ACTIVE_OR_CREATED)
            .expression_attribute_values(
                ":now",
                str(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
            )
            .send()
            .await
            .context("Error updating lastSeen in 'users' table")?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn set_has_passkey(&self, user_id: &str) -> anyhow::Result<()> {
        let _ = self
            .client
            .update_item(TABLE_USERS)
            .key(FIELD_USER_ID, str(user_id))
            .update_expression("SET #hasPasskey = :true")
            .condition_expression("attribute_exists(#userId)")
            .expression_attribute_names("#userId", FIELD_USER_ID)
            .expression_attribute_names("#hasPasskey", FIELD_HAS_PASSKEY)
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .send()
            .await
            .context("Error updating hasPasskey in 'users' table")?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn rename_username(
        &self,
        user_id: &str,
        old_username: &str,
        new_username: &str,
    ) -> anyhow::Result<()> {
        let normalized_new = normalize_username(new_username);
        let normalized_old = normalize_username(old_username);
        if normalized_new == normalized_old {
            // Only the display form (case/spacing) changed — the guard key is unchanged.
            return Ok(());
        }

        // Reserve the new name (fails if already taken), then release the old one.
        let guard = UserName {
            username: normalized_new,
            user_id: user_id.to_owned(),
            created: Utc::now(),
        };
        let reserved = self
            .client
            .put_entity(TABLE_USER_USERNAMES, &guard)?
            .condition_expression("attribute_not_exists(#username)")
            .expression_attribute_names("#username", FIELD_USERNAME)
            .send()
            .await;
        if let Err(err) = reserved {
            if err
                .as_service_error()
                .map(|service_err| service_err.is_conditional_check_failed_exception())
                .unwrap_or(false)
            {
                client_bail!("A user with this username already exists");
            }
            return Err(
                anyhow::Error::new(err).context("Error reserving username in 'user-usernames'")
            );
        }

        let _ = self
            .client
            .delete_item(TABLE_USER_USERNAMES)
            .key(FIELD_USERNAME, str(normalized_old))
            .send()
            .await
            .context("Error releasing old username in 'user-usernames'")?;
        Ok(())
    }

    async fn delete_user(&self, user_id: &str, username: &str) -> anyhow::Result<()> {
        // Remove the user row, then release the username guard so the name can be reused.
        let _ = self
            .client
            .delete_item(TABLE_USERS)
            .key(FIELD_USER_ID, str(user_id))
            .send()
            .await
            .context("Error deleting from 'users' table")?;

        let _ = self
            .client
            .delete_item(TABLE_USER_USERNAMES)
            .key(FIELD_USERNAME, str(normalize_username(username)))
            .send()
            .await
            .context("Error deleting from 'user-usernames' table")?;

        Ok(())
    }
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
