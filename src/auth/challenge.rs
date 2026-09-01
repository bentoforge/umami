//! Single-use, mailed challenge secrets — the mechanism behind both address confirmation and
//! password recovery.
//!
//! ## The shape of the proof
//!
//! Both ceremonies ask a question only the holder of a mailbox can answer, and the only honest way to
//! ask it is to send a secret there and see it come back:
//!
//! 1. umami mints a secret, stores its **hash** with a purpose and a TTL, and queues a mail carrying
//!    the secret in a link.
//! 2. The link comes back to an **unauthenticated** endpoint. That is deliberate: the link is opened
//!    in a mail client, which is regularly a different browser or device than the one that started
//!    the flow. The secret *is* the proof, and demanding a session on top would lock out exactly the
//!    people reading mail on their phone.
//!
//! ## Why the purpose is stored and checked
//!
//! The two ceremonies authorize very different things — one says "this address is yours", the other
//! "set a new password on this account". Sharing one table without a purpose would let a *
//! confirmation* link be redeemed as a *reset*, which turns "can receive mail here" into "can take
//! over this account". [`ChallengeRepository::consume`] therefore takes the purpose it expects and
//! refuses a secret minted for the other one.
//!
//! ## Why only the hash is stored
//!
//! Same reason as the refresh secrets: a leaked table dump must not hand out working challenges. The
//! row is keyed by `sha256(secret)`, so a read of the table proves nothing and the lookup is still a
//! single keyed get. DynamoDB's TTL expires rows on its own, and the row is deleted on use — the
//! challenge is single-use because consuming it *removes* it, not because a flag says so.

use crate::contacts::repository::ContactRepository;
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{BillingMode, ReturnValue};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_hash_index};
use wasabi::aws::dynamodb::{deserialize_entity, str};

/// Table holding pending challenges, keyed by the secret's hash and self-expiring via TTL.
const TABLE_CHALLENGES: &str = "auth-challenges";

/// Hash key — `sha256(secret)`, hex.
const FIELD_SECRET_HASH: &str = "secretHash";

/// Epoch-seconds attribute DynamoDB expires rows on.
const FIELD_TTL: &str = "ttl";

/// Bytes of entropy in a challenge secret. 32 bytes is the same order as the refresh secrets and far
/// beyond guessing; the secret travels in a URL, so it is base64url-encoded.
const SECRET_BYTES: usize = 32;

/// What a challenge secret authorizes. Stored on the row and checked on consume, so a secret minted
/// for one ceremony can never be redeemed in the other.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    /// Proves the holder can read mail at an address.
    ConfirmAddress,
    /// Authorizes setting a new password on the account.
    ResetPassword,
}

/// A pending challenge.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Challenge {
    /// `sha256(secret)`, hex — the hash key. The secret itself is never stored.
    secret_hash: String,
    /// The user the address belongs to.
    user_id: String,
    /// That user's tenant.
    tenant_id: String,
    /// What this secret authorizes.
    purpose: Purpose,
    /// The address the secret was mailed to.
    address: String,
    /// RFC 3339 creation time (diagnostics; expiry is the TTL's job).
    created: DateTime<Utc>,
    /// Epoch-seconds DynamoDB TTL.
    ttl: i64,
}

/// What a consumed challenge proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proven {
    /// The user whose address it is.
    pub user_id: String,
    /// That user's tenant.
    pub tenant_id: String,
    /// The address the secret was mailed to.
    pub address: String,
}

/// Persistence for pending challenges.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait ChallengeRepository: Send + Sync {
    /// Mints a challenge and returns the **secret** — the only time it exists outside the mail.
    async fn issue(
        &self,
        purpose: Purpose,
        user_id: &str,
        tenant_id: &str,
        address: &str,
        ttl_secs: i64,
    ) -> anyhow::Result<String>;

    /// Atomically consumes a secret: deletes the row and returns what it proved.
    ///
    /// `None` for an unknown, already-used, expired **or wrong-purpose** secret — the caller cannot
    /// tell which, and neither can a holder of a stale link.
    async fn consume(&self, purpose: Purpose, secret: &str) -> anyhow::Result<Option<Proven>>;
}

/// DynamoDB-backed [`ChallengeRepository`].
#[derive(Clone)]
pub struct DynamoChallengeRepository {
    client: DynamoClient,
}

impl DynamoChallengeRepository {
    #[tracing::instrument(skip(client), err(Display))]
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

/// Hashes a challenge secret for storage and lookup.
fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    // Lowercase hex: a stable, key-safe encoding of the digest.
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether a consumed row may be redeemed for `expected`.
///
/// Pulled out of the storage path so the one invariant that matters most here is testable on its
/// own: if a `ConfirmAddress` secret were ever accepted where a `ResetPassword` one is expected,
/// "can receive mail at this address" would become "can take over this account".
fn redeemable(stored: Purpose, expected: Purpose, ttl: i64, now: i64) -> bool {
    stored == expected && ttl >= now
}

/// Generates a fresh URL-safe challenge secret.
fn generate_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0_u8; SECRET_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[async_trait]
impl ChallengeRepository for DynamoChallengeRepository {
    #[tracing::instrument(level = "debug", skip(self), err(Display))]
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

    #[tracing::instrument(level = "debug", skip(self, secret), err(Display))]
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

/// Marks the proven address verified, if the user still has it.
///
/// A challenge outliving its address is normal — the user may have removed it between receiving the
/// mail and clicking the link — so a missing contact is not an error here, just nothing to do.
pub async fn confirm_address(
    contacts: &Arc<dyn ContactRepository>,
    proven: &Proven,
) -> anyhow::Result<bool> {
    match contacts
        .get_contact(&proven.user_id, &proven.address)
        .await?
    {
        Some(_) => {
            contacts
                .mark_verified(&proven.user_id, &proven.address)
                .await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The takeover path this check exists to close: a confirmation secret must never be redeemable
    /// as a password reset, however it is offered.
    #[test]
    fn a_secret_is_useless_for_the_other_ceremony() {
        let now = 1_000;
        let valid = now + 60;
        assert!(redeemable(
            Purpose::ConfirmAddress,
            Purpose::ConfirmAddress,
            valid,
            now
        ));
        assert!(redeemable(
            Purpose::ResetPassword,
            Purpose::ResetPassword,
            valid,
            now
        ));
        assert!(
            !redeemable(Purpose::ConfirmAddress, Purpose::ResetPassword, valid, now),
            "a confirmation secret must not reset a password"
        );
        assert!(
            !redeemable(Purpose::ResetPassword, Purpose::ConfirmAddress, valid, now),
            "and not the other way round either"
        );
    }

    /// TTL deletion is eventual, so a row that is still present but past its time must be rejected
    /// on read rather than trusted because DynamoDB has not swept it yet.
    #[test]
    fn an_unswept_but_expired_row_is_rejected() {
        let now = 1_000;
        assert!(redeemable(
            Purpose::ResetPassword,
            Purpose::ResetPassword,
            now,
            now
        ));
        assert!(!redeemable(
            Purpose::ResetPassword,
            Purpose::ResetPassword,
            now - 1,
            now
        ));
    }

    #[test]
    fn secret_is_url_safe_and_unpredictable() {
        let a = generate_secret();
        let b = generate_secret();
        assert_ne!(a, b);
        // It travels in a link, so it must survive a URL without escaping.
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "secret '{a}' is not URL-safe"
        );
    }

    /// The stored form must not be the secret: a table dump has to be useless for redeeming a
    /// challenge, exactly as it is for refresh secrets.
    #[test]
    fn only_a_stable_hash_is_derived() {
        let secret = generate_secret();
        let hash = hash_secret(&secret);
        assert_ne!(hash, secret);
        assert_eq!(hash, hash_secret(&secret), "hashing must be stable");
        assert_eq!(hash.len(), 64, "sha256 as hex");
        assert_ne!(hash, hash_secret(&generate_secret()));
    }
}
