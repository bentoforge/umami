//! Localized, machine-identifiable error messages.
//!
//! Two audiences, one throw site. A CLI or a chat bot needs prose it can show as-is; a service
//! relaying the failure to *its* users needs something stable to hang its own wording on. Every
//! message therefore travels as both: the catalogue key doubles as the API's `code`, so there is
//! no second list that can drift out of step with the first.
//!
//! # Where the language comes from
//!
//! The `locale` claim on the caller's token, which is umami's own OIDC claim and is read by
//! [`wasabi::web::auth::user::User::locale`]. Not `Accept-Language`: that header describes the
//! *device*, and someone who set German in their profile should not be answered in Spanish
//! because they opened a laptop in Barcelona. Where no user exists — a machine-to-machine key —
//! the caller states the language of the person it is acting for when exchanging the key, and it
//! lands in the same claim (see `ExchangeRequest::locale`).
//!
//! Unauthenticated routes have no token; they fall back to [`Config::default_locale`].
//!
//! # What is *not* localized
//!
//! Internal failures — "Failed to serialize passkey", a DynamoDB error — stay English. They are
//! developer text, they end up in logs, and translating them would only make an incident harder
//! to search.

use crate::config::Config;

// The catalogue itself is loaded at the crate root (see `main.rs`): `i18n!` generates items that
// `t!` resolves against `crate::`, so it only works from there.
/// Renders `key` in `locale`, falling back to English when the catalogue has no entry.
///
/// The tag is normalized first — lowercased, and reduced to its primary subtag when the full one
/// is unknown, so `de-AT`, `DE` and `de_CH` all reach the German entry. Without that they land on
/// the English fallback *silently*, which is the worst kind of wrong: a German user sees English
/// and nothing anywhere says why.
pub fn message(locale: &str, key: &str) -> String {
    let tag = locale.trim().to_ascii_lowercase();
    let effective = if rust_i18n::available_locales!().iter().any(|l| l == &tag) {
        tag
    } else {
        tag.split(['-', '_']).next().unwrap_or_default().to_owned()
    };
    rust_i18n::t!(key, locale = &effective).to_string()
}

/// Early return with a localized, coded API error.
///
/// The catalogue key *is* the code, so `bail_i18n!(StatusCode::UNAUTHORIZED, locale,
/// "auth.no_passkey")` answers with `{"code": "auth.no_passkey", "message": "…"}`. The `anyhow`
/// error underneath carries the key rather than the prose, so logs stay greppable and in one
/// language regardless of who was talking.
#[macro_export]
macro_rules! bail_i18n {
    ($status:expr, $locale:expr, $key:literal $(,)?) => {
        return Err(
            ::anyhow::anyhow!($key).context(::wasabi::web::error::ApiError::with_code(
                $status,
                $key,
                $crate::i18n::message($locale, $key),
            )),
        )
    };
}

/// The languages this deployment answers in.
///
/// Derived from the catalogue, not configured. A config list would be free to claim a language we
/// cannot write and to omit one we ship — and the two consumers, header negotiation and the
/// language picker in the user editor, would then be wrong in the same invisible way. What a
/// deployment *may* do is offer fewer than we ship; it can never offer more, so `config.locales`
/// narrows this set and never extends it.
pub fn supported(config: &Config) -> Vec<String> {
    let catalogue: Vec<String> = rust_i18n::available_locales!()
        .into_iter()
        .map(|l| l.to_string())
        .collect();
    if config.locales.is_empty() {
        return catalogue;
    }
    let wanted: Vec<String> = config
        .locales
        .iter()
        .map(|l| l.trim().to_ascii_lowercase())
        .collect();
    let narrowed: Vec<String> = catalogue
        .iter()
        .filter(|l| wanted.contains(l))
        .cloned()
        .collect();
    if narrowed.is_empty() {
        // A misconfigured list must not leave the deployment with no language at all.
        tracing::warn!(
            "config `locales` {:?} matches none of the translations we ship — ignoring it",
            config.locales
        );
        return catalogue;
    }
    narrowed
}

/// The language for a token, in the order that respects what people have told us.
///
/// 1. the user's own `locale` — a stated preference, and the only one that survives a borrowed
///    laptop in another country
/// 2. `Accept-Language` of the request that is minting the token — before someone signs in there
///    is no preference to honour, so the device's hint is the only signal there is
/// 3. the deployment's `defaultLocale`
///
/// Resolved once, here, and written into the claim. Downstream services then read one value
/// instead of re-deriving this chain — and getting it subtly different.
pub fn resolve(
    config: &Config,
    user_locale: Option<&str>,
    accept_language: Option<&str>,
) -> String {
    if let Some(locale) = user_locale.map(str::trim).filter(|l| !l.is_empty()) {
        return locale.to_owned();
    }
    let supported = supported(config);
    let refs: Vec<&str> = supported.iter().map(String::as_str).collect();
    wasabi::web::locale::negotiate_language(accept_language, &refs, &config.default_locale)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every key the code throws, so a missing translation fails here rather than reaching a user
    /// as a raw `auth.something` string. rust-i18n answers a miss with the key itself, which looks
    /// enough like a message to survive review.
    const KEYS: &[&str] = &[
        "salutation.SIR",
        "salutation.MADAM",
        "auth.invalid_credentials",
        "auth.account_inactive",
        "auth.user_gone",
        "auth.password_wrong",
        "auth.mfa_invalid",
        "auth.session_none",
        "auth.session_expired",
        "auth.session_revoked",
        "auth.refresh_missing",
        "auth.refresh_rejected",
        "auth.passkey_unavailable",
        "auth.ceremony_expired",
        "auth.ceremony_wrong_kind",
        "auth.ceremony_foreign",
        "apikey.invalid",
        "apikey.expired",
        "apikey.origin_denied",
        "tenant.foreign",
        "tenant.system_undeletable",
        "user.self_undeletable",
    ];

    #[test]
    fn every_key_is_translated_in_every_language() {
        for locale in rust_i18n::available_locales!() {
            for key in KEYS {
                let text = message(&locale, key);
                assert_ne!(
                    &text.as_str(),
                    key,
                    "'{key}' has no {locale} translation — rust-i18n returned the key"
                );
                assert!(!text.trim().is_empty(), "'{key}' is empty in {locale}");
            }
        }
    }

    /// A guard against a copy-paste catalogue where one language was never actually written.
    #[test]
    fn german_and_english_actually_differ() {
        let same: Vec<&str> = KEYS
            .iter()
            .filter(|key| message("de", key) == message("en", key))
            .copied()
            .collect();
        assert!(same.is_empty(), "identical in de and en: {same:?}");
    }

    #[test]
    fn unknown_tags_reach_the_language_they_name() {
        assert_eq!(message("de-AT", "salutation.SIR"), "Herr");
        assert_eq!(message("DE", "salutation.SIR"), "Herr");
        assert_eq!(message("fr", "salutation.SIR"), "Mr", "unknown → fallback");
    }
}
