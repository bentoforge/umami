//! The start page's two sections: the **apps** this deployment fronts, and the **tasks** it nudges
//! the signed-in user to do.
//!
//! ## Apps
//!
//! Config-driven ([`crate::config::AppDef`]): launch cards for the other services, each gated by
//! `enabledIf` against the caller's subjects (`feature:*`/`role:*`/`is:*`). The gate runs here, on
//! the server, because a plain member cannot read the config and the visibility decision does not
//! belong in a client.
//!
//! ## Tasks
//!
//! umami's own suggestions — set a real password, add a second factor, confirm an address. Each is a
//! [`HomeTask`]: given a [`HomeContext`] loaded once, it either fires with a [`Task`] or stays quiet.
//! The registry is fixed in code (not config): these are facts about account hygiene that umami
//! knows how to check, not a per-deployment vocabulary. A task's words live in the message catalogue
//! (`home.task.<code>.{label,description}`) and are resolved into the caller's language by the
//! service, so a provider never touches locale.

pub mod service;
mod tasks;

use crate::contacts::Contact;
use crate::users::User;

/// Everything a [`HomeTask`] may inspect, gathered once so no provider does its own I/O.
///
/// The booleans are derived from the same signals the profile screen reads, computed here so each
/// provider is a pure, synchronous decision over already-loaded data.
pub struct HomeContext<'a> {
    /// The caller's fresh user record.
    pub user: &'a User,
    /// The caller's email contacts (all of them — a task decides what "missing" means).
    pub contacts: &'a [Contact],
    /// Whether the current password came from an admin reset and was never changed.
    pub password_generated: bool,
    /// Whether the account has at least one passkey.
    pub has_passkey: bool,
    /// Whether TOTP MFA is configured.
    pub mfa_enabled: bool,
}

impl<'a> HomeContext<'a> {
    /// Builds the context from the loaded records, deriving the hygiene flags.
    pub fn new(user: &'a User, contacts: &'a [Contact]) -> Self {
        HomeContext {
            password_generated: user.password_generated(),
            has_passkey: user.has_passkey,
            mfa_enabled: user.totp_secret.is_some(),
            user,
            contacts,
        }
    }

    /// Whether the user relies on a device-bound factor to sign in — the case where a missing
    /// recovery address turns "inconvenient" into "locked out".
    fn has_second_factor(&self) -> bool {
        self.has_passkey || self.mfa_enabled
    }

    /// Whether any of the user's addresses is confirmed. Only a verified address can be sent to, so
    /// this — not merely *having* an address — is what the recovery-channel tasks care about.
    fn has_verified_email(&self) -> bool {
        self.contacts.iter().any(|contact| contact.verified)
    }
}

/// A fired task: a stable `code` (which also keys its catalogue text), where it takes the user, and
/// whether it is urgent enough to stand out.
pub struct Task {
    /// Stable code; the catalogue holds `home.task.<code>.label` / `.description`.
    pub code: &'static str,
    /// In-app path the card links to (opened in the same tab — it is umami's own UI).
    pub url: &'static str,
    /// Whether the card is highlighted: a real risk, not a gentle nudge.
    pub important: bool,
}

/// A provider that decides whether one kind of task applies to the caller.
pub trait HomeTask: Send + Sync {
    /// Returns a [`Task`] when it applies, `None` otherwise.
    fn evaluate(&self, ctx: &HomeContext<'_>) -> Option<Task>;
}

/// The fixed set of task providers, in the order their cards should appear.
fn providers() -> Vec<Box<dyn HomeTask>> {
    vec![
        Box::new(tasks::ChangePassword),
        Box::new(tasks::ConfirmEmail),
        Box::new(tasks::AddPasskey),
        Box::new(tasks::LinkAuthenticator),
        Box::new(tasks::CompleteProfile),
    ]
}

/// Runs every provider against the context, keeping the ones that fired, in provider order.
pub fn evaluate(ctx: &HomeContext<'_>) -> Vec<Task> {
    providers()
        .iter()
        .filter_map(|provider| provider.evaluate(ctx))
        .collect()
}
