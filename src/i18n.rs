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
    let effective = if SUPPORTED.contains(&tag.as_str()) {
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

/// The languages the catalogue actually speaks. Anything else negotiates down to the default.
pub const SUPPORTED: &[&str] = &["de", "en"];

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
pub fn resolve(user_locale: Option<&str>, accept_language: Option<&str>, default: &str) -> String {
    if let Some(locale) = user_locale.map(str::trim).filter(|l| !l.is_empty()) {
        return locale.to_owned();
    }
    wasabi::web::locale::negotiate_language(accept_language, SUPPORTED, default)
}
