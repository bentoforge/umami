//! Messaging links: associate a user with one or more external messaging identities
//! (Telegram/WhatsApp) so downstream bot services can resolve an incoming chat to a umami user.
//!
//! Flow: each user has a stable, regenerable **link code** (shown in their profile). The user hands
//! it to a bot (Telegram deep-link `?start=<code>`, or a WhatsApp click-to-chat prefilled message);
//! the bot's backend — a service key carrying `messaging:link` — submits `(code, platform,
//! externalId)` to claim the mapping. Another service carrying `messaging:resolve` turns a
//! `(platform, externalId)` back into user info (or a minted token). See `repository` + `service`.

pub mod repository;
pub mod service;

use serde::{Deserialize, Serialize};
use wasabi::client_bail;

/// Unambiguous code alphabet: uppercase letters + digits, minus the easily-confused
/// `0`/`O`, `1`/`I`/`L`. 31 symbols.
const CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// Length of a generated link code.
const CODE_LEN: usize = 8;

/// The supported external messaging platforms.
pub const PLATFORMS: [&str; 2] = ["telegram", "whatsapp"];

/// Generates a fresh link code from the unambiguous alphabet (CSPRNG-backed).
pub fn generate_code() -> String {
    use rand::RngCore;
    let mut rng = rand::rng();
    (0..CODE_LEN)
        .map(|_| {
            let index = (rng.next_u32() as usize) % CODE_ALPHABET.len();
            // Index is always in range by construction of the modulo.
            char::from(CODE_ALPHABET.get(index).copied().unwrap_or(b'2'))
        })
        .collect()
}

/// Validates + normalizes a platform string to its canonical lowercase form.
pub fn normalize_platform(platform: &str) -> anyhow::Result<String> {
    let lower = platform.trim().to_lowercase();
    if PLATFORMS.contains(&lower.as_str()) {
        Ok(lower)
    } else {
        client_bail!(
            "Unsupported platform '{platform}' (expected one of: {})",
            PLATFORMS.join(", ")
        )
    }
}

/// A stored external-identity mapping for a user.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MessagingLink {
    /// Composite storage key `"<platform>#<externalId>"` (the table hash key).
    pub link_key: String,
    /// The umami user this identity belongs to.
    pub user_id: String,
    /// The user's tenant (snapshotted for convenient resolve responses).
    pub tenant_id: String,
    /// Messaging platform (`telegram`/`whatsapp`).
    pub platform: String,
    /// The platform-native identity (e.g. a Telegram chat id).
    pub external_id: String,
    /// RFC3339 creation time.
    pub created: String,
}

/// Builds the composite `<platform>#<externalId>` key.
pub fn link_key(platform: &str, external_id: &str) -> String {
    format!("{platform}#{external_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_code_is_unambiguous_and_sized() {
        for _ in 0..200 {
            let code = generate_code();
            assert_eq!(code.len(), CODE_LEN);
            assert!(
                code.bytes().all(|b| CODE_ALPHABET.contains(&b)),
                "code {code} contains a symbol outside the alphabet"
            );
            // Explicitly never the confusable symbols.
            assert!(!code.contains(['0', '1', 'I', 'O', 'L']));
        }
    }

    #[test]
    fn platform_is_validated_and_normalized() {
        assert_eq!(normalize_platform(" Telegram ").unwrap(), "telegram");
        assert_eq!(normalize_platform("WHATSAPP").unwrap(), "whatsapp");
        assert!(normalize_platform("signal").is_err());
    }

    #[test]
    fn link_key_is_composite() {
        assert_eq!(link_key("telegram", "12345"), "telegram#12345");
    }
}
