//! External recipients: a tenant-owned notification address with no identity behind it.
//!
//! ## What it is, and what it is not
//!
//! A recipient is **an address, a display name, a language and one choice per notification
//! type** — owned by a tenant. That is the whole concept. It has no role, no password, no session
//! and no membership: it does not appear in the user list, is not counted as a seat, cannot own a
//! tenant and cannot be switched to. The case it exists for is a shared mailbox nobody logs in
//! with — `info@example.com`, read by whoever is at the front desk — that a tenant wants to hear
//! about something an app fires, such as a form submission.
//!
//! Why not a user without a login, and why not a raw address on `POST /notifications/send`:
//! ADR 0021.
//!
//! ## Consent
//!
//! A recipient is confirmed exactly as a contact is: a single-use challenge mailed to the address,
//! answered by an unauthenticated endpoint. **Unconfirmed, a recipient is in no audience.** The
//! confirmation mail names the tenant and the types chosen, so the mailbox agrees to something
//! specific. A hard bounce or a complaint withdraws the confirmation through the same report the
//! mail worker files for a contact.
//!
//! Choices are **explicit, never defaulted**: a type the recipient has no stored choice for is
//! off, whatever the type's `default` says. A user sees the picker and the default beside it; a
//! recipient never sees a screen, so a default switched on later would subscribe mailboxes to
//! something their owners were never told about.
//!
//! ## The management token
//!
//! Every mail sent to a recipient carries a link with a long-lived, per-recipient token —
//! `<recipientId>.<secret>`, the same shape as a refresh cookie — behind which the recipient can
//! read and change its choices or remove itself, without ever signing in. The secret is stored
//! **encrypted** (not hashed): umami has to put the plaintext into every mail it sends the
//! recipient, so a hash alone would not do, and a table dump must still not hand out working
//! links. The token is a capability over this recipient's choices only; it can never change the
//! address, so a leaked link costs at most a subscription.
//!
//! ## Storage
//!
//! One table, `tenant-recipients`, keyed by the recipient id, with an index on
//! `(tenantId, address)` for the listing, the per-tenant uniqueness check and the bounce report.
//! Separate from `user-contacts` for the reason ADR 0011 gave for keeping chat identities out of
//! that table: shared rows make every function branch on which kind it is looking at.

pub mod repository;
pub mod service;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wasabi::client_bail;

/// Bytes of entropy in a management secret — the same order as a refresh secret.
const SECRET_BYTES: usize = 32;

/// What separates the recipient id from the secret in a management token.
const TOKEN_SEPARATOR: char = '.';

/// A notification recipient without an identity: an address a tenant may reach, plus consent.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExternalRecipient {
    /// Primary key — 32-char generated id. The handle apps and paths use; never the address.
    pub recipient_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// The normalized address (see [`crate::contacts::normalize_email`]). Unique per tenant.
    pub address: String,
    /// How the mailbox is addressed in a mail ("Küchen Müller Info"). Used as entered; no
    /// salutation is composed around it.
    pub display_name: String,
    /// The language mail to this recipient is written in (BCP-47), set by the admin.
    pub locale: String,
    /// Choice per notification type — `off`, `on` or a cadence code. A type absent here is off;
    /// the type's `default` never applies to a recipient.
    #[serde(default)]
    pub choices: BTreeMap<String, String>,
    /// Whether the mailbox answered the confirmation challenge. Only a confirmed recipient is ever
    /// in an audience.
    #[serde(default)]
    pub confirmed: bool,
    /// When the confirmation completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<DateTime<Utc>>,
    /// The management secret, **encrypted** with the deployment's secret box. See the module docs
    /// for why it is not a hash.
    pub manage_secret: String,
    /// RFC 3339 creation timestamp.
    pub created: DateTime<Utc>,
    /// RFC 3339 timestamp of the last change.
    pub last_updated: DateTime<Utc>,
}

/// A recipient as the API shows it: everything but the secret.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RecipientView {
    pub recipient_id: String,
    pub tenant_id: String,
    pub address: String,
    pub display_name: String,
    pub locale: String,
    pub choices: BTreeMap<String, String>,
    pub confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
}

impl From<&ExternalRecipient> for RecipientView {
    fn from(recipient: &ExternalRecipient) -> Self {
        RecipientView {
            recipient_id: recipient.recipient_id.clone(),
            tenant_id: recipient.tenant_id.clone(),
            address: recipient.address.clone(),
            display_name: recipient.display_name.clone(),
            locale: recipient.locale.clone(),
            choices: recipient.choices.clone(),
            confirmed: recipient.confirmed,
            confirmed_at: recipient.confirmed_at,
            created: recipient.created,
            last_updated: recipient.last_updated,
        }
    }
}

/// Generates a fresh URL-safe management secret.
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0_u8; SECRET_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Composes the token a management link carries: the recipient id, then the secret.
///
/// The id travels in the clear so the lookup is a keyed read; the secret is what proves the link
/// is the recipient's own. Same shape as the refresh cookie, for the same reason.
pub fn compose_token(recipient_id: &str, secret: &str) -> String {
    format!("{recipient_id}{TOKEN_SEPARATOR}{secret}")
}

/// Splits a presented token back into recipient id and secret. A token with no separator, or an
/// empty half, is a client error — there is nothing to look up.
pub fn split_token(token: &str) -> anyhow::Result<(&str, &str)> {
    match token.trim().split_once(TOKEN_SEPARATOR) {
        Some((id, secret)) if !id.is_empty() && !secret.is_empty() => Ok((id, secret)),
        _ => client_bail!("This link is invalid"),
    }
}

/// Normalizes a display name: trimmed, and required — a mail has to address the mailbox somehow.
pub fn normalize_display_name(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        client_bail!("A display name is required");
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_round_trips_through_its_two_halves() {
        let secret = generate_secret();
        let token = compose_token("recipient-1", &secret);
        let (id, presented) = split_token(&token).unwrap();
        assert_eq!(id, "recipient-1");
        assert_eq!(presented, secret);
    }

    /// The secret travels in a link, so it must survive a URL without escaping — and it must not
    /// contain the separator, or the split would hand back the wrong secret.
    #[test]
    fn a_secret_is_url_safe_and_free_of_the_separator() {
        let secret = generate_secret();
        assert!(
            secret
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "secret '{secret}' is not URL-safe"
        );
        assert_ne!(secret, generate_secret());
    }

    #[test]
    fn a_malformed_token_is_refused() {
        for bad in ["", "   ", "no-separator", ".secret", "id.", "."] {
            assert!(split_token(bad).is_err(), "'{bad}' should be refused");
        }
    }

    #[test]
    fn a_display_name_is_trimmed_and_required() {
        assert_eq!(
            normalize_display_name("  Front desk ").unwrap(),
            "Front desk"
        );
        assert!(normalize_display_name("   ").is_err());
    }

    /// The secret must never leave the service, so the API view has no field for it.
    #[test]
    fn the_view_carries_no_secret() {
        let recipient = ExternalRecipient {
            recipient_id: "r1".to_owned(),
            tenant_id: "t1".to_owned(),
            address: "info@example.com".to_owned(),
            display_name: "Info".to_owned(),
            locale: "de".to_owned(),
            choices: BTreeMap::new(),
            confirmed: false,
            confirmed_at: None,
            manage_secret: "encrypted".to_owned(),
            created: Utc::now(),
            last_updated: Utc::now(),
        };
        let json = serde_json::to_string(&RecipientView::from(&recipient)).unwrap();
        assert!(!json.contains("encrypted"));
        assert!(!json.contains("manageSecret"));
    }
}
