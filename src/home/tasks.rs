//! The concrete start-page task providers.
//!
//! Each is a zero-sized type implementing [`HomeTask`] — the logic is a pure decision over the
//! [`HomeContext`], and keeping them separate makes each condition legible on its own and trivially
//! testable. A new suggestion is a new type here plus a line in [`super::providers`] and two
//! catalogue entries; nothing else moves.

use super::{HomeContext, HomeTask, Task};

/// The account is on an admin-generated password. Important: until it is changed, whoever ran the
/// reset knows the credential.
pub struct ChangePassword;

impl HomeTask for ChangePassword {
    fn evaluate(&self, ctx: &HomeContext<'_>) -> Option<Task> {
        ctx.password_generated.then_some(Task {
            code: "change-password",
            url: "/profile#security",
            important: true,
        })
    }
}

/// No confirmed address on file. Folds link-vs-verify into one card by code, and — this is the
/// recovery angle — turns **important** when the user signs in with a device-bound factor, because
/// then a missing recovery address is a lockout waiting to happen rather than a mild omission.
pub struct ConfirmEmail;

impl HomeTask for ConfirmEmail {
    fn evaluate(&self, ctx: &HomeContext<'_>) -> Option<Task> {
        if ctx.has_verified_email() {
            return None;
        }
        // Nothing on file at all vs. an address typed but not yet proven — different first step, so
        // different words, but the same destination.
        let code = if ctx.contacts.is_empty() {
            "link-email"
        } else {
            "verify-email"
        };
        Some(Task {
            code,
            url: "/profile#contacts",
            important: ctx.has_second_factor(),
        })
    }
}

/// No second factor at all — offer a passkey. The authenticator card ([`LinkAuthenticator`]) fires
/// on the same condition, so the user is shown both routes to a second factor and picks one.
pub struct AddPasskey;

impl HomeTask for AddPasskey {
    fn evaluate(&self, ctx: &HomeContext<'_>) -> Option<Task> {
        (!ctx.has_second_factor()).then_some(Task {
            code: "add-passkey",
            url: "/profile#security",
            important: false,
        })
    }
}

/// No second factor at all — offer TOTP. Companion to [`AddPasskey`]; see its note.
pub struct LinkAuthenticator;

impl HomeTask for LinkAuthenticator {
    fn evaluate(&self, ctx: &HomeContext<'_>) -> Option<Task> {
        (!ctx.has_second_factor()).then_some(Task {
            code: "link-authenticator",
            url: "/profile#security",
            important: false,
        })
    }
}

/// The user has no name on file — a first or last name is missing. Cosmetic, never important: it
/// only makes them addressable by name in mails and the UI.
pub struct CompleteProfile;

impl HomeTask for CompleteProfile {
    fn evaluate(&self, ctx: &HomeContext<'_>) -> Option<Task> {
        let missing = ctx.user.firstname.as_deref().unwrap_or_default().is_empty()
            || ctx.user.lastname.as_deref().unwrap_or_default().is_empty();
        missing.then_some(Task {
            code: "complete-profile",
            url: "/profile#profile",
            important: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{HomeContext, evaluate};
    use crate::contacts::Contact;
    use crate::users::User;
    use chrono::Utc;

    fn user() -> User {
        // A fully set-up account: named, with a passkey, on a self-chosen password — every task
        // quiet. Each test then removes exactly one thing.
        let now = Utc::now();
        User {
            user_id: "u1".to_owned(),
            tenant_id: "t1".to_owned(),
            roles: Vec::new(),
            username: "jo".to_owned(),
            title: None,
            locale: None,
            salutation: crate::users::Salutation::Unspecified,
            firstname: Some("Jo".to_owned()),
            lastname: Some("Vance".to_owned()),
            password_hash: Some("argon2".to_owned()),
            locked: false,
            token_version: 1,
            totp_secret: None,
            totp_pending: None,
            custom_fields: Default::default(),
            created: now,
            last_updated: now,
            last_seen: None,
            last_active_or_created: now,
            last_password_reset: None,
            last_password_change: Some(now),
            has_passkey: true,
            created_by: None,
            last_changed_by: None,
            preferred_contact: None,
            notification_choices: Default::default(),
        }
    }

    fn verified_email() -> Contact {
        Contact {
            user_id: "u1".to_owned(),
            address: "jo@example.com".to_owned(),
            tenant_id: "t1".to_owned(),
            label: None,
            verified: true,
            verified_at: Some(Utc::now()),
            created: Utc::now(),
        }
    }

    fn codes(user: &User, contacts: &[Contact]) -> Vec<&'static str> {
        evaluate(&HomeContext::new(user, contacts))
            .into_iter()
            .map(|task| task.code)
            .collect()
    }

    #[test]
    fn a_set_up_account_has_nothing_to_do() {
        assert!(codes(&user(), &[verified_email()]).is_empty());
    }

    #[test]
    fn a_generated_password_is_flagged_important() {
        let mut user = user();
        user.last_password_change = None;
        user.last_password_reset = Some(Utc::now());
        let tasks = evaluate(&HomeContext::new(&user, &[verified_email()]));
        let change = tasks.iter().find(|t| t.code == "change-password").unwrap();
        assert!(change.important);
    }

    #[test]
    fn no_second_factor_offers_both_routes() {
        let mut user = user();
        user.has_passkey = false;
        let got = codes(&user, &[verified_email()]);
        assert!(got.contains(&"add-passkey"));
        assert!(got.contains(&"link-authenticator"));
    }

    #[test]
    fn an_unverified_address_asks_to_verify_not_link() {
        let mut contact = verified_email();
        contact.verified = false;
        contact.verified_at = None;
        let got = codes(&user(), &[contact]);
        assert!(got.contains(&"verify-email"));
        assert!(!got.contains(&"link-email"));
    }

    #[test]
    fn no_address_asks_to_link() {
        let got = codes(&user(), &[]);
        assert!(got.contains(&"link-email"));
    }

    #[test]
    fn a_missing_recovery_address_is_important_only_under_a_device_factor() {
        // Passkey present, no verified address → lockout risk → important.
        assert!(
            evaluate(&HomeContext::new(&user(), &[]))
                .iter()
                .find(|t| t.code == "link-email")
                .unwrap()
                .important
        );
        // Same gap, but a password-only account can still recover by other means → a gentle nudge.
        let mut pw_only = user();
        pw_only.has_passkey = false;
        assert!(
            !evaluate(&HomeContext::new(&pw_only, &[]))
                .iter()
                .find(|t| t.code == "link-email")
                .unwrap()
                .important
        );
    }

    #[test]
    fn a_missing_name_is_a_gentle_nudge() {
        let mut user = user();
        user.lastname = None;
        let tasks = evaluate(&HomeContext::new(&user, &[verified_email()]));
        let complete = tasks.iter().find(|t| t.code == "complete-profile").unwrap();
        assert!(!complete.important);
    }
}
