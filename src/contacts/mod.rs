//! Contacts: the email addresses a user can be reached at.
//!
//! One concept, one channel. A contact is an **email address plus whether its owner has proven
//! possession of it** — nothing more. Chat identities (Telegram/WhatsApp) are a different thing and
//! live in [`crate::messaging`]: they answer "which user sent this message", which ends in a minted
//! token rather than a delivered mail. Sharing one table between the two made every function branch
//! on which half of the data it was looking at, so they stay apart.
//!
//! ## Why a list rather than one field on the user
//!
//! The deciding case is a **change of address**. With a list the user adds the new address, verifies
//! it, and only then drops the old one — reachable the whole way through. With a single field the
//! new address overwrites a verified one while still unverified, so the user is unreachable exactly
//! when the confirmation mail has to arrive. "Work and private" is the second reason, and the
//! cheaper one.
//!
//! ## Verification
//!
//! `verified` records one fact: *this address really belongs to this user*, proven by them answering
//! a challenge sent to it. An address **an admin typed in is never verified** — verification is
//! proof of possession and nobody can supply it on the owner's behalf. Only a verified address is
//! ever sent to.
//!
//! ## Storage
//!
//! One table, `user-contacts`, keyed `(userId, address)`. That composite key is the whole design:
//! uniqueness per user *is* the primary key, so there is no guard table, and listing a user's
//! addresses is a query on the hash key, so there is no by-user index. A single GSI on `address`
//! answers "who holds this address" for the password-reset entry point, where no session — and
//! therefore no tenant — exists yet.

pub mod repository;
pub mod service;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wasabi::client_bail;

/// One email address a user can be reached at.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    /// Owning user — hash key.
    pub user_id: String,
    /// The normalized address (see [`normalize_email`]) — range key.
    pub address: String,
    /// The user's tenant, snapshotted so a lookup by address needs no second read.
    pub tenant_id: String,
    /// Optional user-supplied label ("work", "private"). Display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Whether possession has been proven by the user. Only a verified address is ever sent to.
    #[serde(default)]
    pub verified: bool,
    /// When verification completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<DateTime<Utc>>,
    /// RFC 3339 creation timestamp.
    pub created: DateTime<Utc>,
}

/// Normalizes an email address to the single stored form, rejecting what cannot be one.
///
/// Normalization is load-bearing rather than cosmetic: the address is the table's range key, so two
/// spellings of one address must collapse to one string — otherwise the same mailbox lands in two
/// rows and only one of them ever gets verified.
///
/// Deliberately not an RFC 5322 parse: that rejects addresses which work and accepts ones which do
/// not. What matters is that the result cannot be confused with another address, and that an obvious
/// typo is caught before a verification mail is spent on it.
pub fn normalize_email(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        client_bail!("An email address is required");
    }
    let lower = trimmed.to_lowercase();
    if lower.chars().any(char::is_whitespace) {
        client_bail!("An email address must not contain whitespace");
    }
    let mut parts = lower.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if local.is_empty() || domain.is_empty() || parts.next().is_some() {
        client_bail!("'{trimmed}' is not a valid email address");
    }
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        client_bail!("'{trimmed}' is not a valid email address");
    }
    Ok(lower)
}

/// Normalizes an optional free-text label: trims, and treats empty as unset.
pub fn normalize_label(label: Option<String>) -> Option<String> {
    label
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_is_lowercased_and_trimmed() {
        assert_eq!(
            normalize_email("  Jane.Doe@Example.COM ").unwrap(),
            "jane.doe@example.com"
        );
    }

    /// Every rejection here is a verification mail not sent to nowhere — and, because the address is
    /// the range key, a duplicate row not created for the same mailbox.
    #[test]
    fn implausible_addresses_are_rejected() {
        for bad in [
            "",
            "   ",
            "jane",
            "jane@",
            "@example.com",
            "jane@example",
            "jane@@example.com",
            "jane doe@example.com",
            "jane@.com",
            "jane@example.",
        ] {
            assert!(normalize_email(bad).is_err(), "'{bad}' should be rejected");
        }
    }

    #[test]
    fn label_trims_and_nulls_empty() {
        assert_eq!(
            normalize_label(Some("  work ".to_owned())),
            Some("work".to_owned())
        );
        assert_eq!(normalize_label(Some("   ".to_owned())), None);
        assert_eq!(normalize_label(None), None);
    }
}
