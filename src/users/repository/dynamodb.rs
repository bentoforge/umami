//! DynamoDB persistence for user identities.
//!
//! Uses `users` (keyed by `userId`, with a `ByTenantIndex` GSI to list a tenant's users) and a
//! `user-usernames` guard table (keyed by the normalized `username`) that enforces global username
//! uniqueness via a conditional put and serves the strongly-consistent username→user login lookup.
//! Email is optional contact info and is not indexed.

use super::{NewUser, UserName, UserRepository, new_user_records, user_haystack};
use crate::search::query_matches;
use crate::users::{User, normalize_username};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType,
};
use chrono::{SecondsFormat, Utc};
use futures_util::StreamExt;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, str, stream_all};
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

/// DynamoDB-backed implementation of [`UserRepository`].
#[derive(Clone)]
pub struct DynamoUserRepository {
    client: DynamoClient,
}

impl DynamoUserRepository {
    #[tracing::instrument(skip(client), err(level = "debug", Display))]
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
    #[tracing::instrument(level = "debug", skip(self, new_user), err(level = "debug", Display))]
    async fn create_user(&self, new_user: NewUser) -> anyhow::Result<User> {
        let (user, guard) = new_user_records(new_user)?;

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

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
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

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
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

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
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

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
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

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
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

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
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

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
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

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
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
