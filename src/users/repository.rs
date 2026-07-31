//! DynamoDB persistence for user identities.
//!
//! Uses two tables: `users` (keyed by `userId`) and `user-emails` (keyed by the normalized
//! `email`), the latter enforcing email uniqueness via a conditional put and serving the
//! strongly-consistent email→user lookup at login (chosen over an eventually-consistent
//! `EmailIndex` GSI so login and uniqueness are both exact).

use crate::users::{User, UserStatus, normalize_email};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::BillingMode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, generate_id, str};
use wasabi::client_bail;

// ── Table names ────────────────────────────────────────────────────────────────

/// Primary table storing user identities, keyed by `userId`.
const TABLE_USERS: &str = "users";

/// Uniqueness + lookup table mapping a normalized `email` to its `userId`.
const TABLE_USER_EMAILS: &str = "user-emails";

// ── Field names ────────────────────────────────────────────────────────────────

/// Hash key of the `users` table.
const FIELD_USER_ID: &str = "userId";

/// Hash key of the `user-emails` table (also an attribute on `users`).
const FIELD_EMAIL: &str = "email";

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

/// Persistence interface for user identities.
///
/// (A `#[cfg_attr(test, mockall::automock)]` will be added alongside the first mock-based unit
/// test — an unused generated mock would trip `dead_code` under the strict test lints.)
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Creates a new user, enforcing email uniqueness. Returns a client error if the (normalized)
    /// email is already registered. The `password_hash` is `None` for invite/SSO-only users.
    async fn create_user(
        &self,
        email: &str,
        name: &str,
        locale: &str,
        password_hash: Option<String>,
    ) -> anyhow::Result<User>;

    /// Looks up a user by (normalized) email via the `user-emails` table. `None` if unknown.
    async fn find_by_email(&self, email: &str) -> anyhow::Result<Option<User>>;

    /// Fetches a user by id. `None` if unknown.
    async fn get_user(&self, user_id: &str) -> anyhow::Result<Option<User>>;
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
                let table = table.attribute_definitions(str_attribute(FIELD_USER_ID)?);
                let table = with_hash_index(table, FIELD_USER_ID)?;
                Ok(table.billing_mode(BillingMode::PayPerRequest))
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
    #[tracing::instrument(level = "debug", skip(self, password_hash), err(Display))]
    async fn create_user(
        &self,
        email: &str,
        name: &str,
        locale: &str,
        password_hash: Option<String>,
    ) -> anyhow::Result<User> {
        let normalized = normalize_email(email);
        let now = Utc::now();

        let user = User {
            user_id: generate_id(),
            email: normalized.clone(),
            name: name.to_owned(),
            locale: locale.to_owned(),
            password_hash,
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
}
