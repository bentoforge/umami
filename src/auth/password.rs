//! Password hashing and verification using argon2id.
//!
//! Hashes are self-describing PHC strings (algorithm, version, parameters and salt are embedded),
//! so [`verify`] needs only the stored hash and the candidate password. Uses argon2's default
//! parameters (argon2id, ~19 MiB, t=2, p=1).

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// Hashes a plaintext password into an argon2id PHC string suitable for storage.
pub fn hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| anyhow::anyhow!("Failed to hash password: {err}"))?;

    Ok(hash.to_string())
}

/// Verifies a candidate password against a stored argon2id hash.
///
/// Returns `Ok(false)` on a mismatch and `Err` only when the stored hash is malformed (corrupt
/// data), so callers can treat a wrong password distinctly from a storage problem. The comparison
/// is constant-time within argon2's verifier.
pub fn verify(password: &str, stored_hash: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|err| anyhow::anyhow!("Stored password hash is malformed: {err}"))?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(err) => Err(anyhow::anyhow!("Failed to verify password: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrip() {
        let hash = hash("correct horse battery staple").unwrap();
        assert!(verify("correct horse battery staple", &hash).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_password() {
        let hash = hash("s3cret").unwrap();
        assert!(!verify("not-the-password", &hash).unwrap());
    }

    #[test]
    fn verify_errors_on_malformed_hash() {
        assert!(verify("whatever", "not-a-phc-string").is_err());
    }
}
