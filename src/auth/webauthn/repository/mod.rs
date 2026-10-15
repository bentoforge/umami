//! Persistence for WebAuthn credentials and short-lived ceremony state.

pub mod dynamodb;
pub mod postgres;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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
    /// Absent for a discoverable ceremony: no user is known until `finish` identifies one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    /// Serialized `PasskeyRegistration` or `PasskeyAuthentication`.
    state: String,
    /// Epoch-seconds DynamoDB TTL.
    ttl: i64,
}

/// A ceremony loaded for `finish`.
pub struct StoredCeremony {
    /// The user the ceremony belongs to, or `None` for a discoverable ceremony.
    pub user_id: Option<String>,
    /// The serialized ceremony state.
    pub state: String,
}

/// Persistence for passkeys + ceremony state.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
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

    /// Stores ceremony state under a fresh id with the given lifetime. `user_id` is `None` for
    /// a discoverable ceremony, where the user is only identified at `finish`.
    async fn store_ceremony(
        &self,
        ceremony_id: &str,
        user_id: Option<&str>,
        state: String,
        ttl_secs: i64,
    ) -> anyhow::Result<()>;

    /// Finds the user owning a credential id (base64url, as stored). Used by discoverable login.
    async fn find_user_by_credential(&self, credential_id: &str) -> anyhow::Result<Option<String>>;

    /// Atomically consumes (get + delete) a ceremony. `None` if unknown/expired.
    async fn take_ceremony(&self, ceremony_id: &str) -> anyhow::Result<Option<StoredCeremony>>;

    /// Deletes every credential a user registered, returning how many there were.
    ///
    /// For deleting the user. In-flight ceremonies are deliberately left: they are keyed on the
    /// ceremony id with a TTL of minutes, there is no way to find a user's without an index nobody
    /// else needs, and one that outlives its user finishes into a `find_user_by_credential` that no
    /// longer resolves.
    async fn delete_all_for_user(&self, user_id: &str) -> anyhow::Result<usize>;
}
