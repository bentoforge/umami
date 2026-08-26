//! DynamoDB persistence for WebAuthn credentials and short-lived ceremony state.
//!
//! `webauthn-credentials` (PK `userId`, SK `credentialId`) stores each registered passkey as JSON.
//! `webauthn-ceremonies` (PK `ceremonyId`, with a `ttl`) holds the serialized register/authenticate
//! state between `start` and `finish`, consumed once.

use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{BillingMode, ReturnValue};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index, with_range_index};
use wasabi::aws::dynamodb::{deserialize_entity, find_all, str};

const TABLE_CREDENTIALS: &str = "webauthn-credentials";
const TABLE_CEREMONIES: &str = "webauthn-ceremonies";

/// Epoch-seconds attribute DynamoDB expires ceremony rows on.
const FIELD_TTL: &str = "ttl";

const FIELD_USER_ID: &str = "userId";
const FIELD_CREDENTIAL_ID: &str = "credentialId";
const FIELD_CEREMONY_ID: &str = "ceremonyId";

/// A stored passkey credential.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct CredentialRecord {
    user_id: String,
    credential_id: String,
    /// Serialized `webauthn_rs::prelude::Passkey`.
    passkey: String,
    created: chrono::DateTime<chrono::Utc>,
}

/// A stored ceremony (register or authenticate) state.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct CeremonyRecord {
    ceremony_id: String,
    user_id: String,
    /// Serialized `PasskeyRegistration` or `PasskeyAuthentication`.
    state: String,
    /// Epoch-seconds DynamoDB TTL.
    ttl: i64,
}

/// A ceremony loaded for `finish`.
pub struct StoredCeremony {
    /// The user the ceremony belongs to.
    pub user_id: String,
    /// The serialized ceremony state.
    pub state: String,
}

/// Persistence for passkeys + ceremony state.
#[async_trait]
pub trait WebauthnRepository: Send + Sync {
    /// Stores (or overwrites) a passkey for a user.
    async fn put_credential(
        &self,
        user_id: &str,
        credential_id: &str,
        passkey: String,
    ) -> anyhow::Result<()>;

    /// Lists a user's serialized passkeys.
    async fn list_passkeys(&self, user_id: &str) -> anyhow::Result<Vec<String>>;

    /// Stores ceremony state under a fresh id with the given lifetime.
    async fn store_ceremony(
        &self,
        ceremony_id: &str,
        user_id: &str,
        state: String,
        ttl_secs: i64,
    ) -> anyhow::Result<()>;

    /// Atomically consumes (get + delete) a ceremony. `None` if unknown/expired.
    async fn take_ceremony(&self, ceremony_id: &str) -> anyhow::Result<Option<StoredCeremony>>;
}

/// DynamoDB-backed implementation of [`WebauthnRepository`].
#[derive(Clone)]
pub struct DynamoWebauthnRepository {
    client: DynamoClient,
}

impl DynamoWebauthnRepository {
    #[tracing::instrument(skip(client), err(Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_CREDENTIALS, |table| {
                let table = table
                    .attribute_definitions(str_attribute(FIELD_USER_ID)?)
                    .attribute_definitions(str_attribute(FIELD_CREDENTIAL_ID)?);
                let table = with_range_index(table, FIELD_USER_ID, FIELD_CREDENTIAL_ID)?;
                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        client
            .create_table_with_ttl(TABLE_CEREMONIES, FIELD_TTL, |table| {
                let table = table.attribute_definitions(str_attribute(FIELD_CEREMONY_ID)?);
                let table = with_hash_index(table, FIELD_CEREMONY_ID)?;
                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        Ok(Self {
            client: client.clone(),
        })
    }
}

#[async_trait]
impl WebauthnRepository for DynamoWebauthnRepository {
    #[tracing::instrument(level = "debug", skip(self, passkey), err(Display))]
    async fn put_credential(
        &self,
        user_id: &str,
        credential_id: &str,
        passkey: String,
    ) -> anyhow::Result<()> {
        let record = CredentialRecord {
            user_id: user_id.to_owned(),
            credential_id: credential_id.to_owned(),
            passkey,
            created: Utc::now(),
        };
        let _ = self
            .client
            .put_entity(TABLE_CREDENTIALS, &record)?
            .send()
            .await
            .context("Error inserting into 'webauthn-credentials'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn list_passkeys(&self, user_id: &str) -> anyhow::Result<Vec<String>> {
        let query = self
            .client
            .query(TABLE_CREDENTIALS)
            .key_condition_expression("#userId = :userId")
            .expression_attribute_names("#userId", FIELD_USER_ID)
            .expression_attribute_values(":userId", str(user_id))
            .limit(50);

        let records: Vec<CredentialRecord> = find_all(query)
            .await
            .context("Error listing 'webauthn-credentials'")?;
        Ok(records.into_iter().map(|record| record.passkey).collect())
    }

    #[tracing::instrument(level = "debug", skip(self, state), err(Display))]
    async fn store_ceremony(
        &self,
        ceremony_id: &str,
        user_id: &str,
        state: String,
        ttl_secs: i64,
    ) -> anyhow::Result<()> {
        let record = CeremonyRecord {
            ceremony_id: ceremony_id.to_owned(),
            user_id: user_id.to_owned(),
            state,
            ttl: (Utc::now() + Duration::seconds(ttl_secs)).timestamp(),
        };
        let _ = self
            .client
            .put_entity(TABLE_CEREMONIES, &record)?
            .send()
            .await
            .context("Error inserting into 'webauthn-ceremonies'")?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn take_ceremony(&self, ceremony_id: &str) -> anyhow::Result<Option<StoredCeremony>> {
        // Delete-and-return so a ceremony can be consumed exactly once (replay-safe).
        let result = self
            .client
            .delete_item(TABLE_CEREMONIES)
            .key(FIELD_CEREMONY_ID, str(ceremony_id))
            .return_values(ReturnValue::AllOld)
            .send()
            .await
            .context("Error consuming from 'webauthn-ceremonies'")?;

        let record: Option<CeremonyRecord> = deserialize_entity(result.attributes)?;
        Ok(record.map(|record| StoredCeremony {
            user_id: record.user_id,
            state: record.state,
        }))
    }
}
