//! DynamoDB persistence for single-use mailed challenges.

use super::{
    Challenge, ChallengeRepository, Proven, Purpose, generate_secret, hash_secret, redeemable,
};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{BillingMode, ReturnValue};
use chrono::{Duration, Utc};
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, str};

/// Table holding pending challenges, keyed by the secret's hash and self-expiring via TTL.
const TABLE_CHALLENGES: &str = "auth-challenges";

/// Hash key — `sha256(secret)`, hex.
const FIELD_SECRET_HASH: &str = "secretHash";

/// Epoch-seconds attribute DynamoDB expires rows on.
const FIELD_TTL: &str = "ttl";

/// DynamoDB-backed [`ChallengeRepository`].
#[derive(Clone)]
pub struct DynamoChallengeRepository {
    client: DynamoClient,
}

impl DynamoChallengeRepository {
    #[tracing::instrument(skip(client), err(level = "debug", Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table_with_ttl(TABLE_CHALLENGES, FIELD_TTL, |table| {
                let table = table.attribute_definitions(str_attribute(FIELD_SECRET_HASH)?);
                let table = with_hash_index(table, FIELD_SECRET_HASH)?;
                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;
        Ok(Self {
            client: client.clone(),
        })
    }
}

#[async_trait]
impl ChallengeRepository for DynamoChallengeRepository {
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn issue(
        &self,
        purpose: Purpose,
        user_id: &str,
        tenant_id: &str,
        address: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<String> {
        let secret = generate_secret();
        let now = Utc::now();
        let challenge = Challenge {
            secret_hash: hash_secret(&secret),
            user_id: user_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            purpose,
            address: address.to_owned(),
            created: now,
            ttl: (now + Duration::seconds(ttl_secs)).timestamp(),
        };
        let _ = self
            .client
            .put_entity(TABLE_CHALLENGES, &challenge)?
            .send()
            .await
            .context("Error inserting a contact challenge")?;
        Ok(secret)
    }

    #[tracing::instrument(level = "debug", skip(self, secret), err(level = "debug", Display))]
    async fn consume(&self, purpose: Purpose, secret: &str) -> anyhow::Result<Option<Proven>> {
        // Single-use by construction: the delete *is* the consumption, so two concurrent clicks on
        // the same link cannot both succeed — only one receives the old item.
        let output = self
            .client
            .delete_item(TABLE_CHALLENGES)
            .key(FIELD_SECRET_HASH, str(hash_secret(secret)))
            .return_values(ReturnValue::AllOld)
            .send()
            .await
            .context("Error consuming a contact challenge")?;
        let challenge: Option<Challenge> = deserialize_entity(output.attributes)?;

        // Two checks the table cannot make for us:
        //   * a row DynamoDB has not got round to expiring is still expired to us — TTL deletion is
        //     eventual;
        //   * the purpose must match, or a confirmation link would work as a password reset.
        // The row is already gone either way, which is fine: a secret offered to the wrong endpoint
        // is spent, and a legitimate holder still has the other link.
        let now = Utc::now().timestamp();
        Ok(challenge.and_then(|challenge| {
            if redeemable(challenge.purpose, purpose, challenge.ttl, now) {
                Some(Proven {
                    user_id: challenge.user_id,
                    tenant_id: challenge.tenant_id,
                    address: challenge.address,
                })
            } else {
                None
            }
        }))
    }
}
