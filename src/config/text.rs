//! Text in the config document that a person reads — in as many languages as the deployment cares
//! to write.
//!
//! Every label in the catalogues (role, scope and feature names, custom-field labels, notification
//! types and their cadences) is authored by the deployment, not by umami, so no message catalogue
//! we ship could know what to call them. [`LocalizedText`] is how one such label carries more than
//! one language:
//!
//! ```json
//! { "code": "role:owner", "name": "Owner" }
//! { "code": "role:owner", "name": { "de": "Eigentümer", "en": "Owner", "*": "Owner" } }
//! ```
//!
//! A bare string **is** the map `{"*": "…"}` — same value, shorter spelling — so every config
//! written before this existed keeps meaning exactly what it meant.

use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt;

/// The locale key that answers for every language without an entry of its own.
const ANY: &str = "*";

/// One label, in one or more languages.
///
/// Resolution ([`LocalizedText::resolve`]) mirrors [`crate::i18n::message`]: the tag as asked for,
/// then its primary subtag, so `de-AT` reaches a `de` entry. What it does *not* do is fall through
/// to a language nobody asked for without saying so — `*` is that fallback, spelled out by whoever
/// wrote the config.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalizedText(BTreeMap<String, String>);

impl LocalizedText {
    /// Whether there is no text here at all — no entries, or nothing but blanks.
    pub fn is_empty(&self) -> bool {
        self.0.values().all(|text| text.trim().is_empty())
    }

    /// The text for `locale`, falling back through `*` and then `default_locale`.
    ///
    /// 1. the exact tag, normalized (`de-AT`, `DE`, `de_CH` all look themselves up lowercased)
    /// 2. its primary subtag (`de-AT` → `de`)
    /// 3. `*` — the deployment's own "anything else"
    /// 4. the same two steps for `default_locale`
    /// 5. whatever entry sorts first, so a label never renders as nothing
    ///
    /// `*` sits above `default_locale` on purpose: an author who wrote one is stating what an
    /// unlisted language should read, and that is a stronger signal than the deployment-wide
    /// default, which only says which language umami itself writes in.
    pub fn resolve(&self, locale: &str, default_locale: &str) -> &str {
        self.pick(locale)
            .or_else(|| self.get(ANY))
            .or_else(|| self.pick(default_locale))
            .or_else(|| self.0.values().map(String::as_str).find(|t| !t.is_empty()))
            .unwrap_or_default()
    }

    /// A tag and then its primary subtag, both normalized.
    fn pick(&self, locale: &str) -> Option<&str> {
        let tag = normalize(locale);
        if tag.is_empty() {
            return None;
        }
        self.get(&tag).or_else(|| {
            let primary = tag.split(['-', '_']).next().unwrap_or_default();
            if primary == tag {
                None
            } else {
                self.get(primary)
            }
        })
    }

    /// A non-blank entry under `key`. Blanks are treated as absent so a half-filled translation
    /// falls through to a language that actually says something.
    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .map(String::as_str)
            .filter(|text| !text.trim().is_empty())
    }
}

/// Lowercased and trimmed — the one spelling everything else compares against.
fn normalize(locale: &str) -> String {
    locale.trim().to_ascii_lowercase()
}

impl From<&str> for LocalizedText {
    fn from(text: &str) -> Self {
        LocalizedText(BTreeMap::from([(ANY.to_owned(), text.to_owned())]))
    }
}

impl From<String> for LocalizedText {
    fn from(text: String) -> Self {
        LocalizedText(BTreeMap::from([(ANY.to_owned(), text)]))
    }
}

impl Serialize for LocalizedText {
    /// Writes back the shorter spelling when that is all there is.
    ///
    /// The config editor loads the document, edits it and saves it whole, so a label that went out
    /// as `"Owner"` has to come back as `"Owner"` — turning it into `{"*": "Owner"}` on every read
    /// would rewrite half the document the first time anyone touches a different setting.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.iter().next() {
            Some((key, text)) if self.0.len() == 1 && key == ANY => serializer.serialize_str(text),
            _ => {
                let mut map = serializer.serialize_map(Some(self.0.len()))?;
                for (key, text) in &self.0 {
                    map.serialize_entry(key, text)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for LocalizedText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(LocalizedTextVisitor)
    }
}

struct LocalizedTextVisitor;

impl<'de> Visitor<'de> for LocalizedTextVisitor {
    type Value = LocalizedText;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string, or a map of locale tag to string")
    }

    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
        Ok(LocalizedText::from(text))
    }

    fn visit_string<E: serde::de::Error>(self, text: String) -> Result<Self::Value, E> {
        Ok(LocalizedText::from(text))
    }

    /// Keys are normalized on the way in, so `"DE"` in a hand-written config reaches a `de` reader
    /// rather than sitting in the map unmatched by anything.
    fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
        let mut entries = BTreeMap::new();
        while let Some((key, text)) = access.next_entry::<String, String>()? {
            let _ = entries.insert(normalize(&key), text);
        }
        Ok(LocalizedText(entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> LocalizedText {
        serde_json::from_str(json).expect("valid")
    }

    #[test]
    fn a_bare_string_is_the_any_entry() {
        let text = parse(r#""Owner""#);
        assert_eq!(text, LocalizedText::from("Owner"));
        assert_eq!(text.resolve("de", "en"), "Owner");
        assert_eq!(text.resolve("fr", "en"), "Owner");
    }

    #[test]
    fn a_bare_string_round_trips_as_a_bare_string() {
        let text = parse(r#""Owner""#);
        assert_eq!(serde_json::to_string(&text).unwrap(), r#""Owner""#);
    }

    #[test]
    fn a_map_round_trips_as_a_map() {
        let json = r#"{"de":"Eigentümer","en":"Owner"}"#;
        assert_eq!(serde_json::to_string(&parse(json)).unwrap(), json);
    }

    #[test]
    fn regional_tags_reach_the_language_they_name() {
        let text = parse(r#"{"de":"Eigentümer","en":"Owner"}"#);
        assert_eq!(text.resolve("de-AT", "en"), "Eigentümer");
        assert_eq!(text.resolve("DE", "en"), "Eigentümer");
        assert_eq!(text.resolve("de_CH", "en"), "Eigentümer");
    }

    #[test]
    fn keys_are_normalized_on_the_way_in() {
        let text = parse(r#"{"DE":"Eigentümer","en-GB":"Owner"}"#);
        assert_eq!(text.resolve("de", "en"), "Eigentümer");
        assert_eq!(text.resolve("en-GB", "de"), "Owner");
    }

    #[test]
    fn any_beats_the_default_locale() {
        let text = parse(r#"{"de":"Eigentümer","*":"Owner"}"#);
        assert_eq!(text.resolve("fr", "de"), "Owner");
    }

    #[test]
    fn the_default_locale_answers_when_nothing_else_does() {
        let text = parse(r#"{"de":"Eigentümer","en":"Owner"}"#);
        assert_eq!(text.resolve("fr", "de"), "Eigentümer");
        assert_eq!(text.resolve("fr", "en"), "Owner");
    }

    #[test]
    fn an_unwritable_locale_still_renders_something() {
        let text = parse(r#"{"de":"Eigentümer"}"#);
        assert_eq!(text.resolve("fr", "es"), "Eigentümer");
    }

    #[test]
    fn a_blank_entry_falls_through_rather_than_rendering_empty() {
        let text = parse(r#"{"de":"   ","en":"Owner"}"#);
        assert_eq!(text.resolve("de", "en"), "Owner");
    }

    #[test]
    fn emptiness_sees_through_blanks() {
        assert!(parse(r#""""#).is_empty());
        assert!(parse(r#"{"de":"  ","en":""}"#).is_empty());
        assert!(!parse(r#"{"de":"","en":"Owner"}"#).is_empty());
    }
}
