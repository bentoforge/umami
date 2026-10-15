//! DynamoDB persistence for email contacts.
//!
//! **One table, `user-contacts`, keyed `(userId, address)`.** The composite primary key does three
//! jobs that would otherwise need extra machinery:
//!
//! - *uniqueness per user* is the key itself — no guard table, and a re-add of the same address is a
//!   conditional put that fails rather than a read-then-write race;
//! - *listing a user's addresses* is a query on the hash key — no by-user index;
//! - *deleting one* is a keyed delete — no ownership check to get wrong, because the caller's own
//!   `userId` is half the key.
//!
//! A single GSI on `address` answers "who holds this address" for the password-reset entry point,
//! where there is no session and therefore no tenant to scope by.

use super::{ContactRepository, NewContact};
use crate::contacts::{Contact, normalize_label};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection,
    ProjectionType,
};
use chrono::{SecondsFormat, Utc};
use warp::http::StatusCode;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_range_index};
use wasabi::aws::dynamodb::{deserialize_entity, find_all, str};
use wasabi::status_bail;

/// The only table: email contacts, keyed `(userId, address)`.
const TABLE_CONTACTS: &str = "user-contacts";

/// Verification flag attribute.
const FIELD_VERIFIED: &str = "verified";

/// Verification timestamp attribute.
const FIELD_VERIFIED_AT: &str = "verifiedAt";

/// Hash key — the owning user.
const FIELD_USER_ID: &str = "userId";

/// Range key — the normalized address.
const FIELD_ADDRESS: &str = "address";

/// GSI resolving an address to whoever holds it, across tenants.
const INDEX_BY_ADDRESS: &str = "ByAddressIndex";

/// DynamoDB-backed [`ContactRepository`].
#[derive(Clone)]
pub struct DynamoContactRepository {
    client: DynamoClient,
}

impl DynamoContactRepository {
    #[tracing::instrument(skip(client), err(level = "debug", Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_CONTACTS, |table| {
                let by_address = GlobalSecondaryIndex::builder()
                    .index_name(INDEX_BY_ADDRESS)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(FIELD_ADDRESS)
                            .key_type(KeyType::Hash)
                            .build()?,
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(FIELD_USER_ID)
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
                    .attribute_definitions(str_attribute(FIELD_ADDRESS)?);
                let table = with_range_index(table, FIELD_USER_ID, FIELD_ADDRESS)?;
                Ok(table
                    .global_secondary_indexes(by_address)
                    .billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        Ok(Self {
            client: client.clone(),
        })
    }
}

#[async_trait]
impl ContactRepository for DynamoContactRepository {
    #[tracing::instrument(
        level = "debug",
        skip(self, new_contact),
        err(level = "debug", Display)
    )]
    async fn add_contact(&self, new_contact: NewContact) -> anyhow::Result<Contact> {
        // An address a user typed is never verified on arrival: typing a string proves nothing about
        // who owns the mailbox.
        let contact = Contact {
            user_id: new_contact.user_id,
            address: new_contact.address,
            tenant_id: new_contact.tenant_id,
            label: normalize_label(new_contact.label),
            verified: false,
            verified_at: None,
            created: Utc::now(),
        };

        // The composite key *is* the uniqueness constraint, so one conditional put both writes the
        // row and rejects a duplicate — no separate guard, no read-then-write window.
        let result = self
            .client
            .put_entity(TABLE_CONTACTS, &contact)?
            .condition_expression("attribute_not_exists(#a)")
            .expression_attribute_names("#a", FIELD_ADDRESS)
            .send()
            .await;
        match result {
            Ok(_) => Ok(contact),
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                status_bail!(
                    StatusCode::CONFLICT,
                    "You already have that address on file"
                )
            }
            Err(err) => Err(anyhow::Error::new(err).context("Error inserting a contact")),
        }
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn get_contact(&self, user_id: &str, address: &str) -> anyhow::Result<Option<Contact>> {
        let result = self
            .client
            .get_item(TABLE_CONTACTS)
            .key(FIELD_USER_ID, str(user_id))
            .key(FIELD_ADDRESS, str(address))
            .consistent_read(true)
            .send()
            .await
            .context("Error reading 'user-contacts'")?;
        deserialize_entity(result.item)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn list_contacts(&self, user_id: &str) -> anyhow::Result<Vec<Contact>> {
        let query = self
            .client
            .query(TABLE_CONTACTS)
            .key_condition_expression("#u = :u")
            .expression_attribute_names("#u", FIELD_USER_ID)
            .expression_attribute_values(":u", str(user_id))
            .scan_index_forward(true)
            .limit(50);
        find_all(query)
            .await
            .context("Error listing 'user-contacts' by user")
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn contacts_for_address(&self, address: &str) -> anyhow::Result<Vec<Contact>> {
        let query = self
            .client
            .query(TABLE_CONTACTS)
            .index_name(INDEX_BY_ADDRESS)
            .key_condition_expression("#a = :a")
            .expression_attribute_names("#a", FIELD_ADDRESS)
            .expression_attribute_values(":a", str(address))
            // A handful is all any legitimate case needs; the cap keeps a shared address from
            // turning one recovery attempt into an unbounded read.
            .limit(25);
        find_all(query)
            .await
            .context("Error querying 'user-contacts' by address")
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn mark_verified(&self, user_id: &str, address: &str) -> anyhow::Result<()> {
        let result = self
            .client
            .update_item(TABLE_CONTACTS)
            .key(FIELD_USER_ID, str(user_id))
            .key(FIELD_ADDRESS, str(address))
            .update_expression("SET #v = :true, #va = :now")
            // Both key halves are known, so this only guards against the row having been deleted
            // between the challenge being issued and the link being clicked.
            .condition_expression("attribute_exists(#a)")
            .expression_attribute_names("#v", FIELD_VERIFIED)
            .expression_attribute_names("#va", FIELD_VERIFIED_AT)
            .expression_attribute_names("#a", FIELD_ADDRESS)
            .expression_attribute_values(":true", AttributeValue::Bool(true))
            .expression_attribute_values(
                ":now",
                str(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
            )
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                status_bail!(StatusCode::NOT_FOUND, "You have no such address on file")
            }
            Err(err) => Err(anyhow::Error::new(err).context("Error verifying a contact")),
        }
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn mark_unverified(&self, user_id: &str, address: &str) -> anyhow::Result<()> {
        let result = self
            .client
            .update_item(TABLE_CONTACTS)
            .key(FIELD_USER_ID, str(user_id))
            .key(FIELD_ADDRESS, str(address))
            .update_expression("SET #v = :false REMOVE #va")
            .condition_expression("attribute_exists(#a)")
            .expression_attribute_names("#v", FIELD_VERIFIED)
            .expression_attribute_names("#va", FIELD_VERIFIED_AT)
            .expression_attribute_names("#a", FIELD_ADDRESS)
            .expression_attribute_values(":false", AttributeValue::Bool(false))
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            // The address is already gone. A bounce for something the user deleted in the meantime
            // is not a failure — there is simply nothing left to withdraw.
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
            {
                Ok(())
            }
            Err(err) => {
                Err(anyhow::Error::new(err).context("Error withdrawing a contact's confirmation"))
            }
        }
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn delete_all_for_user(&self, user_id: &str) -> anyhow::Result<usize> {
        let contacts = self.list_contacts(user_id).await?;
        let count = contacts.len();
        for contact in contacts {
            self.delete_contact(user_id, &contact.address).await?;
        }
        Ok(count)
    }

    async fn delete_contact(&self, user_id: &str, address: &str) -> anyhow::Result<()> {
        // Both halves of the key come from the caller's own session, so there is no cross-user
        // delete to guard against — a foreign address simply is not in this user's partition.
        let _ = self
            .client
            .delete_item(TABLE_CONTACTS)
            .key(FIELD_USER_ID, str(user_id))
            .key(FIELD_ADDRESS, str(address))
            .send()
            .await
            .context("Error deleting 'user-contacts'")?;
        Ok(())
    }
}
