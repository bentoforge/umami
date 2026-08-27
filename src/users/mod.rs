//! User identities — and the identity/tenancy model's design decisions.
//!
//! This module owns the [`User`] entity, its persistence (`repository`), and the tenant-scoped
//! user-administration API (`service`): create, list, get, patch, delete, password reset, sessions
//! and audit. The entity's fields are documented on [`User`] itself — the struct is the schema.
//!
//! ## Why the model is shaped this way
//!
//! - **A tenant owns its users** (a user has exactly one `tenant_id`; no memberships join table).
//!   The owning tenant has full authority (lock, reset, delete). *Rejected:* the global-user +
//!   many-to-many-membership model (Auth0/B2C heritage) — a floating global identity makes "who may
//!   lock this user?" unanswerable.
//! - **The username is the login identity** — globally unique (case-insensitive), so login is
//!   `username + password` with no tenant context. `email` is optional contact info and **not**
//!   unique. Uniqueness is enforced by the `user-usernames` guard table (DynamoDB can't enforce a
//!   second unique attribute via a GSI); `userId` stays the `users` PK so id-keyed reads/writes are
//!   strongly consistent. See `repository` for the guard mechanics (and its atomicity caveat).
//! - **One user acts in one tenant** for now: no parent-tenant hierarchy, no cross-tenant identity.
//!   The token's `tenant` claim is always the user's home tenant. The future path to multi-tenant is
//!   explicit **user-invites** (grant an existing user into another tenant), *not* a tenant
//!   hierarchy — which is why [`crate::auth::session::Session`] keeps `active_tenant_id` as a field
//!   even though it currently always equals the home tenant.
//! - **No CRM / billing / licensing layer** — a tenant carries only its `feature:*` grants and
//!   deployment-defined custom fields; anything else a deployment needs lives in custom fields.

pub mod repository;
pub mod service;

use serde::{Deserialize, Serialize};

/// How to address a user. Only the stable code is stored; the word (e.g. "Mr"/"Herr", "Ms"/"Frau")
/// is looked up per locale — server-side from [`SALUTATION_WORDS`] where there is no reader to ask,
/// and from its own catalogue in the management UI, which knows the reader's language.
/// `Unspecified` serializes to `""`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Salutation {
    /// No salutation set (wire value `""`).
    #[default]
    #[serde(rename = "")]
    Unspecified,
    /// Male honorific ("Sir"/"Mr"/"Herr"/…).
    #[serde(rename = "SIR")]
    Sir,
    /// Female honorific ("Madam"/"Ms"/"Frau"/…).
    #[serde(rename = "MADAM")]
    Madam,
}

impl Salutation {
    /// The stable wire code (`""` / `"SIR"` / `"MADAM"`), used for the `$user.salutation` claim.
    pub fn code(self) -> &'static str {
        match self {
            Salutation::Unspecified => "",
            Salutation::Sir => "SIR",
            Salutation::Madam => "MADAM",
        }
    }
}

/// A global user identity as stored in DynamoDB.
///
/// Credentials (`password_hash`) and the revocation counter (`token_version`) live here. The login
/// identifier is the **`username`** — required and globally unique (case-insensitively), guarded by
/// the `user-usernames` lookup table (see [`repository`]). The `email` is optional contact info and
/// is **not** unique.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// Primary key — 32-char generated id.
    pub user_id: String,
    /// The owning (home) tenant. A user belongs to exactly one tenant.
    pub tenant_id: String,
    /// Role codes within the owning tenant (defined in the config catalog); resolve to the token's
    /// permissions. `#[serde(default)]` tolerates older records written before roles were a list.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Login identifier — required, globally unique (case-insensitively via the `user-usernames`
    /// guard). Stored as entered (trimmed); uniqueness/lookup use the normalized form.
    pub username: String,
    /// Optional contact email — **not** unique, may be absent. Normalized (trimmed + lowercased)
    /// when present.
    #[serde(default)]
    pub email: Option<String>,
    /// Optional honorific/title (e.g. "Dr.", "Prof."). A structured name part composed server-side
    /// into the display names.
    #[serde(default)]
    pub title: Option<String>,
    /// Preferred language as a BCP-47 tag (e.g. `de`, `de-AT`). `None` falls back to the config's
    /// `defaultLocale`. Drives the server-composed display names and, once localized, the texts
    /// umami renders itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// How to address the user; the word is resolved per locale (see [`Salutation`]).
    #[serde(default)]
    pub salutation: Salutation,
    /// Given name.
    #[serde(default)]
    pub firstname: Option<String>,
    /// Family name.
    #[serde(default)]
    pub lastname: Option<String>,
    /// argon2id hash string. `None` for SSO-only users that never set a password.
    pub password_hash: Option<String>,
    /// Admin lock. When `true` the user cannot log in, regardless of credentials. Defaults to
    /// `false` (older records predate the field). A user without a `password_hash` also cannot log
    /// in (the former "invited" state), so lifecycle beyond this toggle lives in custom fields.
    #[serde(default)]
    pub locked: bool,
    /// Global revocation counter. Bumping it invalidates every session at its next refresh
    /// (see the `sessions` reuse/rotation logic).
    pub token_version: u32,
    /// Active TOTP secret (AES-GCM encrypted). `Some` means TOTP MFA is enabled.
    #[serde(default)]
    pub totp_secret: Option<String>,
    /// Pending TOTP secret during setup (encrypted), before it is confirmed by a valid code.
    #[serde(default)]
    pub totp_pending: Option<String>,
    /// Values for the config-defined custom user fields.
    #[serde(default)]
    pub custom_fields: std::collections::BTreeMap<String, serde_json::Value>,
    /// RFC 3339 creation timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// RFC 3339 timestamp of the last update to this record.
    pub last_updated: chrono::DateTime<chrono::Utc>,
    /// RFC 3339 timestamp of the user's last authentication (login or refresh). `None` until the
    /// user is first active — never a placeholder like the creation time.
    #[serde(default)]
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    /// Range key of the per-tenant listing GSI: `last_seen` when present, else `created`. Initialised
    /// to `created` and bumped on every activity, so a `scan_index_forward(false)` query returns
    /// active users first and keeps inactive ones stably ordered by creation. Defaults to the epoch
    /// for records written before this field existed.
    #[serde(default = "epoch")]
    pub last_active_or_created: chrono::DateTime<chrono::Utc>,
    /// RFC 3339 timestamp of the last admin password reset. Combined with `last_password_change`
    /// to flag a reset password the user has not changed yet.
    #[serde(default)]
    pub last_password_reset: Option<chrono::DateTime<chrono::Utc>>,
    /// RFC 3339 timestamp of the last self-service password change.
    #[serde(default)]
    pub last_password_change: Option<chrono::DateTime<chrono::Utc>>,
    /// Denormalized "has at least one passkey" flag — set when a passkey is registered, so listing
    /// users needs no per-user credential lookup. (No passkey-removal path exists yet.)
    #[serde(default)]
    pub has_passkey: bool,
    /// User id that created this user (audit; not surfaced in the UI yet). `None` for the
    /// auto-init bootstrap owner.
    #[serde(default)]
    pub created_by: Option<String>,
    /// User id of the last change to this user (audit; not surfaced in the UI yet).
    #[serde(default)]
    pub last_changed_by: Option<String>,
}

/// The Unix epoch — the `last_active_or_created` fallback for user records predating the field.
fn epoch() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::UNIX_EPOCH
}

/// Normalizes a username for lookup and uniqueness: trims surrounding whitespace and lowercases,
/// so `UMAMI`, `umami`, and ` Umami ` all collide.
pub fn normalize_username(username: &str) -> String {
    username.trim().to_lowercase()
}

/// Normalizes an email for storage: trims surrounding whitespace and lowercases.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Normalizes an optional name part: trims, and treats an empty result as unset (`None`), so an
/// explicit `""` clears the field.
pub fn normalize_name(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

/// The composed display names derived from a user's structured name parts — ready for API responses
/// and token claims. Each is space-joined from the present parts (absent/empty parts skipped).
#[derive(Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DisplayNames {
    /// `title firstname lastname` (no salutation).
    pub name: String,
    /// `salutation title firstname lastname`.
    pub full_name: String,
    /// `salutation title lastname` — how you would address them.
    pub addressable_name: String,
}

impl User {
    /// Composes [`DisplayNames`] from this user's structured parts (see [`compose_display_names`]).
    ///
    /// The user's own `locale` wins; `default_locale` is the deployment's fallback from the config.
    pub fn display_names(&self, default_locale: &str) -> DisplayNames {
        compose_display_names(
            self.title.as_deref(),
            self.salutation,
            self.firstname.as_deref(),
            self.lastname.as_deref(),
            self.locale.as_deref().unwrap_or(default_locale),
        )
    }
}

/// Salutation words per locale, as `(locale, SIR, MADAM)`.
///
/// Fixed in code, not configurable. The word belongs to the language, not to the deployment — a
/// single configurable map made every consumer speak the deployment's language rather than the
/// reader's, which is how a German installation ended up greeting people as "Mr". Adding a
/// language is deliberately a code change: it is a translation, and translations belong with the
/// other translations.
const SALUTATION_WORDS: &[(&str, &str, &str)] = &[("de", "Herr", "Frau"), ("en", "Mr", "Ms")];

/// The locale used when the tag is unknown or absent — also the last resort if a deployment
/// configures a `defaultLocale` nothing translates into.
const FALLBACK_LOCALE: &str = "en";

/// Resolves a BCP-47 tag against [`SALUTATION_WORDS`]: exact match first, then the primary subtag
/// (`de-AT` → `de`), then [`FALLBACK_LOCALE`]. Case-insensitive, because tags arrive as typed.
fn salutation_row(locale: &str) -> (&'static str, &'static str) {
    let tag = locale.trim().to_ascii_lowercase();
    let primary = tag.split(['-', '_']).next().unwrap_or_default().to_owned();
    for candidate in [tag.as_str(), primary.as_str(), FALLBACK_LOCALE] {
        if let Some(row) = SALUTATION_WORDS
            .iter()
            .find(|(code, _, _)| *code == candidate)
        {
            return (row.1, row.2);
        }
    }
    // Unreachable while FALLBACK_LOCALE is in the table, but stating a value beats an unwrap.
    ("", "")
}

/// Composes [`DisplayNames`] from structured name parts, resolving the salutation word for
/// `locale`. `Unspecified` contributes nothing. Shared by the entity views and the token broker.
///
/// `name` carries **no** salutation, and that is the field a localized UI should render: it can
/// prepend its own word for the reader's language. `fullName`/`addressableName` exist for what the
/// server renders alone — claims, mail and messaging templates — where no reader can be asked.
pub fn compose_display_names(
    title: Option<&str>,
    salutation: Salutation,
    firstname: Option<&str>,
    lastname: Option<&str>,
    locale: &str,
) -> DisplayNames {
    let word = salutation_word(salutation, locale);
    DisplayNames {
        name: join_name_parts(&[title, firstname, lastname]),
        full_name: join_name_parts(&[word, title, firstname, lastname]),
        addressable_name: join_name_parts(&[word, title, lastname]),
    }
}

/// The word for a salutation in `locale`. `Unspecified` yields `None`.
fn salutation_word(salutation: Salutation, locale: &str) -> Option<&'static str> {
    let (sir, madam) = salutation_row(locale);
    match salutation {
        Salutation::Unspecified => None,
        Salutation::Sir => Some(sir),
        Salutation::Madam => Some(madam),
    }
}

/// Space-joins the present, non-empty name parts.
fn join_name_parts(parts: &[Option<&str>]) -> String {
    parts
        .iter()
        .filter_map(|part| part.map(str::trim).filter(|s| !s.is_empty()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn composes_all_name_forms() {
        let names = compose_display_names(
            Some("Dr."),
            Salutation::Madam,
            Some("Jane"),
            Some("Doe"),
            "en",
        );
        assert_eq!(names.name, "Dr. Jane Doe");
        assert_eq!(names.full_name, "Ms Dr. Jane Doe");
        assert_eq!(names.addressable_name, "Ms Dr. Doe");
    }

    /// The reason the words moved out of the config: the same user reads differently per language,
    /// and `name` stays free of the salutation so a localized UI can prepend its own word.
    #[test]
    fn salutation_word_follows_the_locale() {
        let compose = |locale: &str| {
            compose_display_names(
                None,
                Salutation::Sir,
                Some("Andreas"),
                Some("Haufler"),
                locale,
            )
        };
        assert_eq!(compose("de").full_name, "Herr Andreas Haufler");
        assert_eq!(compose("en").full_name, "Mr Andreas Haufler");
        assert_eq!(compose("de").name, "Andreas Haufler");
    }

    /// Region subtags resolve to their language; anything unknown lands on the fallback rather
    /// than dropping the salutation silently.
    #[test]
    fn locale_tags_fall_back_predictably() {
        let compose = |locale: &str| {
            compose_display_names(None, Salutation::Madam, None, Some("Doe"), locale).full_name
        };
        assert_eq!(compose("de-AT"), "Frau Doe");
        assert_eq!(compose("DE"), "Frau Doe");
        assert_eq!(compose("de_CH"), "Frau Doe");
        assert_eq!(compose("fr"), "Ms Doe", "unknown locale uses the fallback");
        assert_eq!(compose(""), "Ms Doe");
    }

    #[test]
    fn skips_absent_parts_and_unspecified_salutation() {
        let names = compose_display_names(None, Salutation::Unspecified, Some("Jane"), None, "en");
        assert_eq!(names.name, "Jane");
        assert_eq!(names.full_name, "Jane");
        assert_eq!(names.addressable_name, "");
    }

    #[test]
    fn normalize_name_trims_and_nulls_empty() {
        assert_eq!(
            normalize_name(Some("  Jane ".to_owned())),
            Some("Jane".to_owned())
        );
        assert_eq!(normalize_name(Some("   ".to_owned())), None);
        assert_eq!(normalize_name(None), None);
    }
}
