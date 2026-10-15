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

pub mod dynamodb;
pub mod postgres;

use crate::contacts::repository::ContactRepository;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

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
