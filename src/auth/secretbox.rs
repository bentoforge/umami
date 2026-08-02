//! Authenticated symmetric encryption for secrets at rest (AES-256-GCM).
//!
//! Used to encrypt the TOTP secret before it is stored on the user record, so a database dump
//! never exposes usable MFA seeds. The key is loaded from `UMAMI_MFA_KEY` (base64 of 32 bytes).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rand::RngCore;

/// Number of key bytes for AES-256.
const KEY_LEN: usize = 32;

/// AES-GCM nonce length (96 bits).
const NONCE_LEN: usize = 12;

/// Symmetric encryptor for small secrets. The ciphertext token is `base64url(nonce || ct)`.
#[derive(Clone)]
pub struct SecretBox {
    key: [u8; KEY_LEN],
}

impl SecretBox {
    /// Loads the key from `UMAMI_MFA_KEY` (base64 of exactly 32 bytes).
    pub fn from_env() -> anyhow::Result<Self> {
        let encoded = std::env::var("UMAMI_MFA_KEY").context(
            "Please provide UMAMI_MFA_KEY (base64 of 32 random bytes) for MFA encryption",
        )?;
        let bytes = STANDARD
            .decode(encoded.trim())
            .context("UMAMI_MFA_KEY must be valid base64")?;
        let key: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("UMAMI_MFA_KEY must decode to exactly {KEY_LEN} bytes"))?;
        Ok(Self { key })
    }

    /// Encrypts plaintext, returning a `base64url(nonce || ciphertext)` token.
    pub fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<String> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|err| anyhow!("Failed to encrypt secret: {err}"))?;

        let mut token = nonce_bytes.to_vec();
        token.extend_from_slice(&ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(token))
    }

    /// Decrypts a token produced by [`encrypt`](Self::encrypt).
    pub fn decrypt(&self, token: &str) -> anyhow::Result<Vec<u8>> {
        let data = URL_SAFE_NO_PAD
            .decode(token)
            .context("Invalid encrypted secret encoding")?;
        if data.len() <= NONCE_LEN {
            return Err(anyhow!("Encrypted secret is too short"));
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));

        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|err| anyhow!("Failed to decrypt secret: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn box_with_test_key() -> SecretBox {
        SecretBox {
            key: [7u8; KEY_LEN],
        }
    }

    #[test]
    fn roundtrips() {
        let secret_box = box_with_test_key();
        let token = secret_box.encrypt(b"super-secret-seed").unwrap();
        assert_eq!(secret_box.decrypt(&token).unwrap(), b"super-secret-seed");
    }

    #[test]
    fn distinct_nonces_produce_distinct_tokens() {
        let secret_box = box_with_test_key();
        let a = secret_box.encrypt(b"same").unwrap();
        let b = secret_box.encrypt(b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tampered_token_fails() {
        let secret_box = box_with_test_key();
        assert!(secret_box.decrypt("not-valid").is_err());
    }
}
