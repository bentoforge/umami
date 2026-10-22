//! DynamoDB persistence for external recipients.
//!
//! **One table, `tenant-recipients`, keyed by `recipientId`.** The id is what every caller holds —
//! an admin path, a send message, a management link — so the primary key is the id and every
//! read is a keyed get. A GSI on `(tenantId, address)` serves the listing (sorted by address, so
//! the order is stable as rows come and go), the per-tenant uniqueness check and the bounce
//! report's lookup.
//!
//! Uniqueness of an address within a tenant is therefore a **query before the put** rather than a
//! conditional write, because a GSI cannot carry a uniqueness constraint. The window that leaves
//! open is two admins adding the same address within the same few milliseconds, and what it costs
//! is two rows for one mailbox — both visible, both deletable, and neither able to reach the
//! mailbox before it confirms. That is a tidiness problem, not a security one, which is why no
//! guard table is spent on it.

use super::RecipientRepository;
use crate::recipients::ExternalRecipient;
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType,
};
use chrono::{SecondsFormat, Utc};
use warp::http::StatusCode;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, find_all, str};
use wasabi::status_bail;

/// The only table: external recipients, keyed by id.
const TABLE_RECIPIENTS: &str = "tenant-recipients";

/// Hash key — the recipient id.
const FIELD_RECIPIENT_ID: &str = "recipientId";

/// GSI hash key — the owning tenant.
const FIELD_TENANT_ID: &str = "tenantId";

/// GSI range key — the normalized address.
const FIELD_ADDRESS: &str = "address";

/// Confirmation flag attribute.
const FIELD_CONFIRMED: &str = "confirmed";

/// Confirmation timestamp attribute.
const FIELD_CONFIRMED_AT: &str = "confirmedAt";

/// Last-change timestamp attribute.
const FIELD_LAST_UPDATED: &str = "lastUpdated";

/// GSI listing a tenant's recipients by address.
const INDEX_BY_TENANT: &str = "ByTenantIndex";

/// DynamoDB-backed [`RecipientRepository`].
#[derive(Clone)]
pub struct DynamoRecipientRepository {
    client: DynamoClient,
}

impl DynamoRecipientRepository {
    #[tracing::instrument(skip(client), err(level = "debug", Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_RECIPIENTS, |table| {
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
                            .attribute_name(FIELD_ADDRESS)
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
                    .attribute_definitions(str_attribute(FIELD_RECIPIENT_ID)?)
                    .attribute_definitions(str_attribute(FIELD_TENANT_ID)?)
                    .attribute_definitions(str_attribute(FIELD_ADDRESS)?);
                let table = with_hash_index(table, FIELD_RECIPIENT_ID)?;
                Ok(table
                    .global_secondary_indexes(by_tenant)
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        Ok(Self {
            client: client.clone(),
        })
    }

    /// Sets or clears the confirmation flag on one row.
    async fn set_confirmed(&self, recipient_id: &str, confirmed: bool) -> anyhow::Result<bool> {
        let now = str(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true));
        let update = if confirmed {
            "SET #c = :c, #ca = :now, #lu = :now"
        } else {
            "SET #c = :c, #lu = :now REMOVE #ca"
        };
        let result = self
            .client
            .update_item(TABLE_RECIPIENTS)
            .key(FIELD_RECIPIENT_ID, str(recipient_id))
            .update_expression(update)
            .condition_expression("attribute_exists(#id)")
            .expression_attribute_names("#c", FIELD_CONFIRMED)
            .expression_attribute_names("#ca", FIELD_CONFIRMED_AT)
            .expression_attribute_names("#lu", FIELD_LAST_UPDATED)
            .expression_attribute_names("#id", FIELD_RECIPIENT_ID)
            .expression_attribute_values(":c", AttributeValue::Bool(confirmed))
            .expression_attribute_values(":now", now)
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                Ok(false)
            }
            Err(err) => {
                Err(anyhow::Error::new(err).context("Error updating a recipient's confirmation"))
            }
        }
    }
}

#[async_trait]
impl RecipientRepository for DynamoRecipientRepository {
    #[tracing::instrument(level = "debug", skip(self, recipient), err(level = "debug", Display))]
    async fn add_recipient(&self, recipient: ExternalRecipient) -> anyhow::Result<()> {
        if self
            .find_by_address(&recipient.tenant_id, &recipient.address)
            .await?
            .is_some()
        {
            status_bail!(
                StatusCode::CONFLICT,
                "This tenant already has a recipient with that address"
            );
        }
        let _ = self
            .client
            .put_entity(TABLE_RECIPIENTS, &recipient)?
            // The id is freshly generated, so this only guards against the astronomically
            // unlikely collision — failing beats overwriting somebody else's row.
            .condition_expression("attribute_not_exists(#id)")
            .expression_attribute_names("#id", FIELD_RECIPIENT_ID)
            .send()
            .await
            .context("Error inserting a recipient")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn get_recipient(&self, recipient_id: &str) -> anyhow::Result<Option<ExternalRecipient>> {
        let result = self
            .client
            .get_item(TABLE_RECIPIENTS)
            .key(FIELD_RECIPIENT_ID, str(recipient_id))
            .consistent_read(true)
            .send()
            .await
            .context("Error reading 'tenant-recipients'")?;
        deserialize_entity(result.item)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_recipients(&self, tenant_id: &str) -> anyhow::Result<Vec<ExternalRecipient>> {
        let query = self
            .client
            .query(TABLE_RECIPIENTS)
            .index_name(INDEX_BY_TENANT)
            .key_condition_expression("#t = :t")
            .expression_attribute_names("#t", FIELD_TENANT_ID)
            .expression_attribute_values(":t", str(tenant_id))
            .scan_index_forward(true)
            .limit(crate::constants::MAX_LIST_RESULTS as i32);
        find_all(query)
            .await
            .context("Error listing 'tenant-recipients' by tenant")
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn find_by_address(
        &self,
        tenant_id: &str,
        address: &str,
    ) -> anyhow::Result<Option<ExternalRecipient>> {
        let query = self
            .client
            .query(TABLE_RECIPIENTS)
            .index_name(INDEX_BY_TENANT)
            .key_condition_expression("#t = :t AND #a = :a")
            .expression_attribute_names("#t", FIELD_TENANT_ID)
            .expression_attribute_names("#a", FIELD_ADDRESS)
            .expression_attribute_values(":t", str(tenant_id))
            .expression_attribute_values(":a", str(address))
            .limit(1);
        let found: Vec<ExternalRecipient> = find_all(query)
            .await
            .context("Error querying 'tenant-recipients' by address")?;
        Ok(found.into_iter().next())
    }

    #[tracing::instrument(level = "debug", skip(self, recipient), err(level = "debug", Display))]
    async fn put_recipient(&self, recipient: ExternalRecipient) -> anyhow::Result<()> {
        let _ = self
            .client
            .put_entity(TABLE_RECIPIENTS, &recipient)?
            .send()
            .await
            .context("Error updating a recipient")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn mark_confirmed(&self, recipient_id: &str) -> anyhow::Result<()> {
        if !self.set_confirmed(recipient_id, true).await? {
            status_bail!(StatusCode::NOT_FOUND, "No such recipient");
        }
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn mark_unconfirmed(&self, recipient_id: &str) -> anyhow::Result<()> {
        // A bounce for a recipient somebody deleted in the meantime is nothing to do.
        let _ = self.set_confirmed(recipient_id, false).await?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_recipient(&self, recipient_id: &str) -> anyhow::Result<()> {
        let _ = self
            .client
            .delete_item(TABLE_RECIPIENTS)
            .key(FIELD_RECIPIENT_ID, str(recipient_id))
            .send()
            .await
            .context("Error deleting from 'tenant-recipients'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_all_for_tenant(&self, tenant_id: &str) -> anyhow::Result<usize> {
        let recipients = self.list_recipients(tenant_id).await?;
        let count = recipients.len();
        for recipient in recipients {
            self.delete_recipient(&recipient.recipient_id).await?;
        }
        Ok(count)
    }
}
