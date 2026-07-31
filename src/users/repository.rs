//! DynamoDB persistence for user identities.
//!
//! Uses `users` (keyed by `userId`, with a `ByTenantIndex` GSI to list a tenant's users) and a
//! `user-emails` guard table (keyed by the normalized `email`) that enforces global email
//! uniqueness via a conditional put and serves the strongly-consistent email→user login lookup.

use crate::users::{User, UserRole, UserStatus, normalize_email};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType,
};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, find_all, generate_id, str};
use wasabi::client_bail;

// ── Table names ────────────────────────────────────────────────────────────────

/// Primary table storing user identities, keyed by `userId`.
const TABLE_USERS: &str = "users";

/// Uniqueness + lookup table mapping a normalized `email` to its `userId`.
const TABLE_USER_EMAILS: &str = "user-emails";

// ── Field / index names ──────────────────────────────────────────────────────

/// Hash key of the `users` table.
const FIELD_USER_ID: &str = "userId";

/// Owning tenant — GSI hash key.
const FIELD_TENANT_ID: &str = "tenantId";

/// Global revocation counter attribute.
const FIELD_TOKEN_VERSION: &str = "tokenVersion";

/// RFC 3339 last-update attribute.
const FIELD_LAST_UPDATED: &str = "lastUpdated";

/// Hash key of the `user-emails` table (also an attribute on `users`).
const FIELD_EMAIL: &str = "email";

/// GSI listing a tenant's users (hash on `tenantId`).
const INDEX_BY_TENANT: &str = "ByTenantIndex";

/// A `user-emails` row: the uniqueness guard + email→user pointer.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct UserEmail {
    /// Normalized email — hash key.
    email: String,
    /// The user this email belongs to.
    user_id: String,
    /// RFC 3339 creation timestamp.
    created: chrono::DateTime<chrono::Utc>,
}

/// Parameters for creating a user.
pub struct NewUser {
    /// Owning tenant.
    pub tenant_id: String,
    /// Role within the tenant.
    pub role: UserRole,
    /// Login email (will be normalized).
    pub email: String,
    /// Display name.
    pub name: String,
    /// BCP-47 locale.
    pub locale: String,
    /// argon2id hash, or `None` for invite/SSO-only users.
    pub password_hash: Option<String>,
}

/// Persistence interface for user identities.
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Creates a new user, enforcing global email uniqueness. Returns a client error if the
    /// (normalized) email is already registered.
    async fn create_user(&self, new_user: NewUser) -> anyhow::Result<User>;

    /// Looks up a user by (normalized) email via the `user-emails` table. `None` if unknown.
    async fn find_by_email(&self, email: &str) -> anyhow::Result<Option<User>>;

    /// Fetches a user by id. `None` if unknown.
    async fn get_user(&self, user_id: &str) -> anyhow::Result<Option<User>>;

    /// Lists all users in a tenant (via the `ByTenantIndex` GSI).
    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<User>>;

    /// Overwrites a user record (used by PATCH after a read-modify).
    async fn put_user(&self, user: User) -> anyhow::Result<User>;

    /// Atomically increments `tokenVersion` — the global "log out everywhere" lever.
    async fn bump_token_version(&self, user_id: &str) -> anyhow::Result<()>;
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
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .build()?;

                let table = table
                    .attribute_definitions(str_attribute(FIELD_USER_ID)?)
                    .attribute_definitions(str_attribute(FIELD_TENANT_ID)?);
                let table = with_hash_index(table, FIELD_USER_ID)?;

                Ok(table
                    .global_secondary_indexes(by_tenant)
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        client
            .create_table(TABLE_USER_EMAILS, |table| {
                let table = table.attribute_definitions(str_attribute(FIELD_EMAIL)?);
                let table = with_hash_index(table, FIELD_EMAIL)?;
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
        let normalized = normalize_email(&new_user.email);
        let now = Utc::now();

        let user = User {
            user_id: generate_id(),
            tenant_id: new_user.tenant_id,
            role: new_user.role,
            email: normalized.clone(),
            name: new_user.name,
            locale: new_user.locale,
            password_hash: new_user.password_hash,
            status: UserStatus::Active,
            token_version: 0,
            created: now,
            last_updated: now,
        };

        // Claim the email first: a conditional put fails if the email is already registered,
        // giving strict uniqueness before we write the user record.
        let email_guard = UserEmail {
            email: normalized,
            user_id: user.user_id.clone(),
            created: now,
        };

        let put_email = self
            .client
            .put_entity(TABLE_USER_EMAILS, &email_guard)?
            .condition_expression("attribute_not_exists(#email)")
            .expression_attribute_names("#email", FIELD_EMAIL)
            .send()
            .await;

        if let Err(err) = put_email {
            if err
                .as_service_error()
                .map(|service_err| service_err.is_conditional_check_failed_exception())
                .unwrap_or(false)
            {
                client_bail!("A user with this email address already exists");
            }
            return Err(anyhow::Error::new(err).context("Error reserving email in 'user-emails'"));
        }

        let _ = self
            .client
            .put_entity(TABLE_USERS, &user)?
            .send()
            .await
            .context("Error inserting entity into 'users' table")?;

        Ok(user)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn find_by_email(&self, email: &str) -> anyhow::Result<Option<User>> {
        let normalized = normalize_email(email);

        let result = self
            .client
            .get_item(TABLE_USER_EMAILS)
            .key(FIELD_EMAIL, str(normalized))
            .send()
            .await
            .context("Error searching table 'user-emails'")?;

        let email_row: Option<UserEmail> = deserialize_entity(result.item)?;

        match email_row {
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
    async fn list_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<User>> {
        let query = self
            .client
            .query(TABLE_USERS)
            .index_name(INDEX_BY_TENANT)
            .key_condition_expression("#tenantId = :tenantId")
            .expression_attribute_names("#tenantId", FIELD_TENANT_ID)
            .expression_attribute_values(":tenantId", str(tenant_id))
            .limit(100);

        find_all(query)
            .await
            .context("Error listing users by tenant")
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
}
