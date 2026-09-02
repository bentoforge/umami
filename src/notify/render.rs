//! Rendering umami's **own** mail texts.
//!
//! Two kinds of text pass through here, and only two:
//!
//! - The catalogue entries in `locales/app.yml` — umami's subjects and bodies, which ship with
//!   umami and are covered by its tests.
//! - The deployment's `mail.footer` from the config, which nobody else validates.
//!
//! An app's own layouts are **not** here. Those travel as a [`crate::notify::OutboundMail::template`]
//! name plus a context and are rendered by the worker; umami forwards them without looking. That
//! split is the whole design of the outbound seam and this module does not move it — what it moves
//! is the four `str::replace` calls that used to substitute `%{name}` and `%{link}` with nothing
//! checking either side.
//!
//! ## Why an engine rather than a substitution
//!
//! The failure that mattered was silent, in both directions: a placeholder a text used and nobody
//! supplied stayed in the mail verbatim, and a value nobody used vanished. [`UndefinedBehavior`]
//! `Strict` turns the first into an error, and rendering the footer at publish time (see
//! [`crate::config::validate_mail`]) turns a typo in deployment-supplied text into a `400` instead
//! of an imprint that reads `{{ globalContext.baseUrl }}` in every mail.
//!
//! ## The context is the payload
//!
//! What a template sees is the shape a worker receives — `recipient`, `context`, `globalContext` —
//! so umami and a worker render the same mail from the same data, with the same syntax. That is
//! also why [`crate::notify::Recipient::salutation_key`] is a stable code: `{% if
//! recipient.salutationKey == "MADAM" %}` has to mean the same thing on both sides.

use crate::notify::{NotificationMeta, Recipient};
use anyhow::Context as _;
use minijinja::{Environment, UndefinedBehavior};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// An empty map to borrow, so [`MailContext`] has a `Default` despite holding references.
static NO_GLOBALS: BTreeMap<String, String> = BTreeMap::new();

/// What a mail template can see. Serializes to the same names the payload uses.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MailContext<'a> {
    /// Every name form for the reader. Present even when nothing is known about them — the fields
    /// are then empty strings, because a template asking for a name it cannot get should render
    /// nothing rather than fail a password reset.
    pub recipient: Option<&'a Recipient>,
    /// The sender's own values — for umami's mails, the single-use link.
    pub context: Option<&'a Value>,
    /// The deployment's constants from `mail.globalContext`.
    pub global_context: &'a BTreeMap<String, String>,
    /// Which notification this is, when it is one.
    pub notification: Option<&'a NotificationMeta>,
}

impl Default for MailContext<'_> {
    fn default() -> Self {
        MailContext {
            recipient: None,
            context: None,
            global_context: &NO_GLOBALS,
            notification: None,
        }
    }
}

/// The one environment, built once.
///
/// No templates are registered in it: everything here is rendered from a string that came from the
/// catalogue or the config, so there is nothing to name and nothing to load from disk. That also
/// means no template can include another — which is a feature, not a gap, for text a deployment
/// edits through an API.
fn environment() -> &'static Environment<'static> {
    static ENVIRONMENT: OnceLock<Environment<'static>> = OnceLock::new();
    ENVIRONMENT.get_or_init(|| {
        let mut environment = Environment::new();
        // The whole reason for the engine: `{{ recipent.firstName }}` has to be an error, not an
        // empty string in a mail nobody re-reads.
        environment.set_undefined_behavior(UndefinedBehavior::Strict);
        environment
    })
}

/// Renders one template string.
pub fn render(template: &str, context: &MailContext<'_>) -> anyhow::Result<String> {
    environment()
        .render_str(template, context)
        .with_context(|| "Failed to render a mail template".to_owned())
}

/// Renders a catalogue entry in `locale`.
pub fn message(locale: &str, key: &str, context: &MailContext<'_>) -> anyhow::Result<String> {
    render(&crate::i18n::message(locale, key), context)
        .with_context(|| format!("Failed to render '{key}' for locale '{locale}'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::Salutation;

    /// Every mail text umami renders itself, so a placeholder that no context supplies is caught
    /// here rather than in somebody's inbox.
    const MAIL_KEYS: [&str; 4] = [
        "auth.reset.subject",
        "auth.reset.body",
        "contact.verify.subject",
        "contact.verify.body",
    ];

    fn a_recipient() -> Recipient {
        Recipient::from_parts(None, Salutation::Madam, Some("Jane"), Some("Doe"), "de")
    }

    /// The guard the old `str::replace` never had, in both directions: `Strict` makes a placeholder
    /// nothing supplies an error, and running it per locale catches a translation that renamed one.
    /// A German text that lost `{{ context.link }}` used to be a mail without a link and a green
    /// test suite.
    #[test]
    fn every_mail_text_renders_in_every_language() {
        let recipient = a_recipient();
        let link = serde_json::json!({ "link": "https://umami.example.com/app/x?token=y" });
        let context = MailContext {
            recipient: Some(&recipient),
            context: Some(&link),
            ..MailContext::default()
        };

        for locale in rust_i18n::available_locales!() {
            for key in MAIL_KEYS {
                let rendered = message(&locale, key, &context)
                    .unwrap_or_else(|err| panic!("'{key}' in {locale}: {err:#}"));
                assert!(
                    !rendered.contains("{{"),
                    "'{key}' in {locale} still holds a placeholder: {rendered}"
                );
            }
        }
    }

    /// The bodies have to actually *use* the values, or the reset link is missing and everything
    /// above still passes.
    #[test]
    fn the_bodies_carry_the_link_and_the_greeting() {
        let recipient = a_recipient();
        let link = serde_json::json!({ "link": "https://umami.example.com/reset?token=abc" });
        let context = MailContext {
            recipient: Some(&recipient),
            context: Some(&link),
            ..MailContext::default()
        };

        for locale in rust_i18n::available_locales!() {
            for key in ["auth.reset.body", "contact.verify.body"] {
                let rendered = message(&locale, key, &context).unwrap();
                assert!(
                    rendered.contains("token=abc"),
                    "'{key}' in {locale} has no link"
                );
                assert!(
                    rendered.contains("Frau Doe"),
                    "'{key}' in {locale} has no greeting"
                );
            }
        }
    }

    /// Nothing here may reach the filesystem or another template: these strings come from a config
    /// document an admin edits through an API.
    #[test]
    fn a_template_cannot_pull_in_anything_else() {
        let context = MailContext::default();
        assert!(render("{% include 'other' %}", &context).is_err());
        assert!(render("{% extends 'other' %}", &context).is_err());
    }
}
