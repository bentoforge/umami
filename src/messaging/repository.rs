//! DynamoDB persistence for messaging links + per-user link codes.
//!
//! Two tables:
//! - `messaging-codes` (PK `code`) with GSI `ByUserIndex` (hash `userId`) — the stable per-user
//!   link code; the GSI resolves "the user's current code" for the profile.
//! - `messaging-links` (PK `linkKey` = `<platform>#<externalId>`) with GSI `ByUserIndex`
//!   (hash `userId`, range `created`) — the external-identity mappings. The composite PK makes a
//!   `(platform, externalId)` mapping unique and O(1) to resolve.

use crate::messaging::{MessagingLink, generate_code, link_key};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection, ProjectionType,
    ReturnValue,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use warp::http::StatusCode;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, find_all, str};
use wasabi::status_bail;

const TABLE_CODES: &str = "messaging-codes";
const FIELD_CODE: &str = "code";

const TABLE_LINKS: &str = "messaging-links";
const FIELD_LINK_KEY: &str = "linkKey";

const FIELD_USER_ID: &str = "userId";
const FIELD_CREATED: &str = "created";
const INDEX_BY_USER: &str = "ByUserIndex";

/// A stored per-user link code (`messaging-codes`).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct CodeEntity {
    code: String,
    user_id: String,
    tenant_id: String,
    created: String,
}

/// The subject a resolved external identity or code maps to.
#[derive(Debug, Clone)]
pub struct LinkSubject {
    pub user_id: String,
    pub tenant_id: String,
}

/// Persistence for messaging codes + links.
#[async_trait]
pub trait MessagingRepository: Send + Sync {
    /// Returns the user's current code when it is younger than `ttl_secs`; otherwise mints a fresh
    /// one. The bool is `true` when a new code was generated (so callers can audit only real mints).
    async fn current_code(
        &self,
        user_id: &str,
        tenant_id: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<(String, bool)>;

    /// Replaces the user's code with a fresh one (invalidating the old), returning it.
    async fn regenerate_code(&self, user_id: &str, tenant_id: &str) -> anyhow::Result<String>;

    /// Atomically **consumes** a link code (single-use): deletes it and, when it existed and was
    /// still within `ttl_secs`, returns its owning subject. Expired/absent → `None` (⇒ reject).
    async fn consume_code(&self, code: &str, ttl_secs: i64) -> anyhow::Result<Option<LinkSubject>>;

    /// Creates a `(platform, externalId) → user` mapping. Idempotent for the same user; a conflict
    /// (already mapped to a different user) is a client error.
    async fn create_link(
        &self,
        subject: &LinkSubject,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<()>;

    /// Resolves a `(platform, externalId)` to its subject.
    async fn subject_for_external(
        &self,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<Option<LinkSubject>>;

    /// Lists a user's external-identity mappings.
    async fn list_links(&self, user_id: &str) -> anyhow::Result<Vec<MessagingLink>>;

    /// Removes a `(platform, externalId)` mapping (only if it belongs to `user_id`).
    async fn delete_link(
        &self,
        user_id: &str,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<()>;
}

/// DynamoDB-backed [`MessagingRepository`].
#[derive(Clone)]
pub struct DynamoMessagingRepository {
    client: DynamoClient,
}

impl DynamoMessagingRepository {
    #[tracing::instrument(skip(client), err(Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_CODES, |table| {
                let by_user = hash_gsi(INDEX_BY_USER, FIELD_USER_ID)?;
                let table = table
                    .attribute_definitions(str_attribute(FIELD_CODE)?)
                    .attribute_definitions(str_attribute(FIELD_USER_ID)?);
                let table = with_hash_index(table, FIELD_CODE)?;
                Ok(table
                    .global_secondary_indexes(by_user)
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        client
            .create_table(TABLE_LINKS, |table| {
                let by_user = hash_range_gsi(INDEX_BY_USER, FIELD_USER_ID, FIELD_CREATED)?;
                let table = table
                    .attribute_definitions(str_attribute(FIELD_LINK_KEY)?)
                    .attribute_definitions(str_attribute(FIELD_USER_ID)?)
                    .attribute_definitions(str_attribute(FIELD_CREATED)?);
                let table = with_hash_index(table, FIELD_LINK_KEY)?;
                Ok(table
                    .global_secondary_indexes(by_user)
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        Ok(Self {
            client: client.clone(),
        })
    }

    /// Fetches the (at most one) code row for a user via the `ByUser` GSI.
    async fn code_entity(&self, user_id: &str) -> anyhow::Result<Option<CodeEntity>> {
        let query = self
            .client
            .query(TABLE_CODES)
            .index_name(INDEX_BY_USER)
            .key_condition_expression("#u = :u")
            .expression_attribute_names("#u", FIELD_USER_ID)
            .expression_attribute_values(":u", str(user_id))
            .limit(1);
        let mut rows: Vec<CodeEntity> = find_all(query)
            .await
            .context("Error querying 'messaging-codes' by user")?;
        Ok(rows.pop())
    }

    /// Inserts a fresh unique code for the user, returning it.
    async fn put_new_code(&self, user_id: &str, tenant_id: &str) -> anyhow::Result<String> {
        // Collisions in a 31^8 space are astronomically unlikely; retry a few times regardless.
        for _ in 0..5 {
            let entity = CodeEntity {
                code: generate_code(),
                user_id: user_id.to_owned(),
                tenant_id: tenant_id.to_owned(),
                created: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            };
            let result = self
                .client
                .put_entity(TABLE_CODES, &entity)?
                .condition_expression("attribute_not_exists(#c)")
                .expression_attribute_names("#c", FIELD_CODE)
                .send()
                .await;
            match result {
                Ok(_) => return Ok(entity.code),
                Err(err)
                    if err
                        .as_service_error()
                        .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
                {
                    continue;
                }
                Err(err) => {
                    return Err(anyhow::Error::new(err).context("Error inserting messaging code"));
                }
            }
        }
        status_bail!(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not allocate a unique messaging code"
        )
    }
}

/// Whether an RFC3339 `created` timestamp is within `ttl_secs` of now (unparseable → expired).
fn is_fresh(created: &str, ttl_secs: i64) -> bool {
    match DateTime::parse_from_rfc3339(created) {
        Ok(ts) => (Utc::now() - ts.with_timezone(&Utc)).num_seconds() < ttl_secs,
        Err(_) => false,
    }
}

/// A GSI keyed by a single hash attribute, projecting all attributes.
fn hash_gsi(
    index_name: &str,
    hash_field: &str,
) -> Result<GlobalSecondaryIndex, aws_sdk_dynamodb::error::BuildError> {
    GlobalSecondaryIndex::builder()
        .index_name(index_name)
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(hash_field)
                .key_type(KeyType::Hash)
                .build()?,
        )
        .projection(
            Projection::builder()
                .projection_type(ProjectionType::All)
                .build(),
        )
        .build()
}

/// A GSI keyed `(hash, range)`, projecting all attributes.
fn hash_range_gsi(
    index_name: &str,
    hash_field: &str,
    range_field: &str,
) -> Result<GlobalSecondaryIndex, aws_sdk_dynamodb::error::BuildError> {
    GlobalSecondaryIndex::builder()
        .index_name(index_name)
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(hash_field)
                .key_type(KeyType::Hash)
                .build()?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name(range_field)
                .key_type(KeyType::Range)
                .build()?,
        )
        .projection(
            Projection::builder()
                .projection_type(ProjectionType::All)
                .build(),
        )
        .build()
}

#[async_trait]
impl MessagingRepository for DynamoMessagingRepository {
    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn current_code(
        &self,
        user_id: &str,
        tenant_id: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<(String, bool)> {
        if let Some(entity) = self.code_entity(user_id).await?
            && is_fresh(&entity.created, ttl_secs)
        {
            return Ok((entity.code, false));
        }
        // None yet, or the existing one has expired → rotate.
        let code = self.regenerate_code(user_id, tenant_id).await?;
        Ok((code, true))
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn regenerate_code(&self, user_id: &str, tenant_id: &str) -> anyhow::Result<String> {
        // Drop the old code first so it stops resolving, then mint a new one.
        if let Some(existing) = self.code_entity(user_id).await? {
            let _ = self
                .client
                .delete_item(TABLE_CODES)
                .key(FIELD_CODE, str(&existing.code))
                .send()
                .await
                .context("Error deleting old messaging code")?;
        }
        self.put_new_code(user_id, tenant_id).await
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn consume_code(&self, code: &str, ttl_secs: i64) -> anyhow::Result<Option<LinkSubject>> {
        // Atomic single-use: delete the row and inspect what was there. Under a race, only one
        // caller receives the old item; a concurrent second delete returns nothing. Expired rows are
        // deleted too (cleanup) but still rejected.
        let output = self
            .client
            .delete_item(TABLE_CODES)
            .key(FIELD_CODE, str(code))
            .return_values(ReturnValue::AllOld)
            .send()
            .await
            .context("Error consuming 'messaging-codes'")?;
        let entity: Option<CodeEntity> = deserialize_entity(output.attributes)?;
        Ok(entity.and_then(|entity| {
            if is_fresh(&entity.created, ttl_secs) {
                Some(LinkSubject {
                    user_id: entity.user_id,
                    tenant_id: entity.tenant_id,
                })
            } else {
                None
            }
        }))
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn create_link(
        &self,
        subject: &LinkSubject,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<()> {
        let key = link_key(platform, external_id);

        // Idempotent for the same user; conflict if already mapped to someone else.
        if let Some(existing) = self.subject_for_external(platform, external_id).await? {
            if existing.user_id == subject.user_id {
                return Ok(());
            }
            status_bail!(
                StatusCode::CONFLICT,
                "This messaging identity is already linked to another user"
            );
        }

        let link = MessagingLink {
            link_key: key,
            user_id: subject.user_id.clone(),
            tenant_id: subject.tenant_id.clone(),
            platform: platform.to_owned(),
            external_id: external_id.to_owned(),
            created: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        };
        let _ = self
            .client
            .put_entity(TABLE_LINKS, &link)?
            .condition_expression("attribute_not_exists(#k)")
            .expression_attribute_names("#k", FIELD_LINK_KEY)
            .send()
            .await
            .context("Error inserting messaging link (already linked?)")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn subject_for_external(
        &self,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<Option<LinkSubject>> {
        let result = self
            .client
            .get_item(TABLE_LINKS)
            .key(FIELD_LINK_KEY, str(link_key(platform, external_id)))
            .consistent_read(true)
            .send()
            .await
            .context("Error reading 'messaging-links'")?;
        let link: Option<MessagingLink> = deserialize_entity(result.item)?;
        Ok(link.map(|link| LinkSubject {
            user_id: link.user_id,
            tenant_id: link.tenant_id,
        }))
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn list_links(&self, user_id: &str) -> anyhow::Result<Vec<MessagingLink>> {
        let query = self
            .client
            .query(TABLE_LINKS)
            .index_name(INDEX_BY_USER)
            .key_condition_expression("#u = :u")
            .expression_attribute_names("#u", FIELD_USER_ID)
            .expression_attribute_values(":u", str(user_id))
            .scan_index_forward(false)
            .limit(100);
        find_all(query)
            .await
            .context("Error listing 'messaging-links' by user")
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn delete_link(
        &self,
        user_id: &str,
        platform: &str,
        external_id: &str,
    ) -> anyhow::Result<()> {
        // Only delete when the mapping belongs to the caller (avoid cross-user unlink).
        let _ = self
            .client
            .delete_item(TABLE_LINKS)
            .key(FIELD_LINK_KEY, str(link_key(platform, external_id)))
            .condition_expression("#u = :u")
            .expression_attribute_names("#u", FIELD_USER_ID)
            .expression_attribute_values(":u", str(user_id))
            .send()
            .await
            .map(|_| ())
            .or_else(|err| {
                // A missing/foreign row (condition failed) is treated as "nothing to delete".
                if err
                    .as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception())
                {
                    Ok(())
                } else {
                    Err(anyhow::Error::new(err).context("Error deleting 'messaging-links'"))
                }
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::is_fresh;
    use chrono::{Duration, SecondsFormat, Utc};

    #[test]
    fn freshness_respects_ttl() {
        let recent =
            (Utc::now() - Duration::seconds(60)).to_rfc3339_opts(SecondsFormat::Millis, true);
        let old =
            (Utc::now() - Duration::seconds(1200)).to_rfc3339_opts(SecondsFormat::Millis, true);
        assert!(is_fresh(&recent, 600));
        assert!(!is_fresh(&old, 600));
        assert!(!is_fresh("not-a-timestamp", 600));
    }
}
