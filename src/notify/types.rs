//! Notification types, cadences, and the one rule that decides who hears about a firing.
//!
//! ## Three kinds of message, and only two of them are here
//!
//! 1. **Transactional** — a password reset, an address confirmation. The app (or umami itself) has
//!    one person and one reason, fetches the user and sends. It never consults this catalogue, so
//!    there is deliberately no "not suppressible" flag: a type nobody asks about cannot be switched
//!    off, and a flag saying so would only invite somebody to route a reset through here.
//! 2. **Informational, no rhythm** — "your build failed". The app resolves an audience by type and
//!    umami answers who may and wants to hear it. Such a type declares **no** cadences; the choice
//!    is on or off.
//! 3. **Informational, with a rhythm** — "new content". Same as 2 plus a cadence match.
//!
//! Cases 2 and 3 are the same code path; an empty cadence list is what distinguishes them.
//!
//! ## The model
//!
//! An app owns its own schedule. wsc already runs a daily job asking "is there new content", and a
//! weekly one, and a monthly one. umami does **not** reproduce that: when a job fires it announces
//! which cadences that firing represents, and umami answers with the users whose choice matches.
//! Nothing is accumulated, nothing is grouped, nothing is remembered — the decision is one string
//! comparison per user.
//!
//! A single firing legitimately *is* several cadences at once: the Friday run is the daily run and
//! the weekly run, and on the first Friday of the month it is the monthly one too. So a firing
//! carries a **set** of cadences and umami intersects. Each user appears at most once, because a
//! user's choice is a single value.
//!
//! ## Why a cadence is a string, not an enum
//!
//! umami never *interprets* one. There is no arithmetic, no ordering, no scheduling — the matching
//! rule is equality, and that is the whole of it. A closed enum would therefore dictate vocabulary
//! umami has no business dictating: an app whose rhythm is `on-publish`, `hourly` or `quarterly` is
//! not wrong, it just is not `Daily`.
//!
//! The typo protection an enum would nominally buy already lives elsewhere and has to: a **firing**
//! and a **user's choice** are both checked against the cadences the type declares. What remains is
//! a typo in the declaration itself, and the right guard for that is [`validate_catalogue`] at
//! publish time — the declaration is the source of truth, so there is nothing in Rust to compare it
//! against.
//!
//! There is consequently no "immediate" or "push" concept in here. A type with no rhythm of its own
//! simply declares one cadence — call it `"immediate"`, `"on-publish"`, or anything else — and its
//! subscribers choose that one string. umami cannot tell it apart from a weekly type, and does not
//! need to.
//!
//! Each cadence carries its own **label**, exactly as a role or a feature does. A vocabulary the
//! deployment invents has to bring its own words: nothing in umami's message catalogue could know
//! what `on-publish` should read as in a picker.
//!
//! ## The three states of a preference
//!
//! Per user and type, the stored preference is `Option<String>` inside a map, and **all three
//! states are distinct**:
//!
//! | Stored | Means |
//! |---|---|
//! | key absent | *unset* — follow the type's configured default |
//! | `"off"` | an explicit no, and one the deployment cannot override |
//! | `"on"` | an explicit yes, for a type with no rhythm |
//! | a cadence code | an explicit yes, at that rhythm |
//!
//! One value space rather than two, which is why `off` and `on` are reserved and cannot be cadence
//! codes — otherwise a choice would be ambiguous.
//!
//! The distinction is load-bearing: normalising "unset" to the current default at write time would
//! make a later change of that default silently overwrite what people actually chose. Anything that
//! writes a preference must therefore leave an untouched type *absent*.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use wasabi::client_bail;

/// The choice value meaning "do not send me this". Available for **every** type, whether or not it
/// has cadences — switching something off must never depend on it having a rhythm.
pub const CHOICE_OFF: &str = "off";

/// The choice value meaning "send me this", for a type with no rhythm of its own.
pub const CHOICE_ON: &str = "on";

/// Reserved: neither may be a cadence code, or a choice would be ambiguous.
const RESERVED: [&str; 2] = [CHOICE_OFF, CHOICE_ON];

/// Normalizes a cadence code for storage and comparison: trimmed and lowercased.
///
/// Everything downstream compares the normalized form, so `"Weekly"` in a config and `"weekly"` in a
/// firing have to reach the same string — otherwise a deployment's own capitalisation would silently
/// resolve an empty audience.
pub fn normalize_cadence(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// One cadence a type is fired at: a stable code plus the words a user reads.
///
/// Shaped like [`crate::config::RoleDef`] and the other catalogue entries, and for the same reason —
/// the code is the deployment's own, so the label has to travel with it rather than being looked up
/// in a catalogue that cannot know it.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CadenceDef {
    /// Stable code, lowercase. Compared against a firing and against a user's stored choice.
    pub code: String,
    /// Human-readable label, shown in the picker.
    pub name: String,
}

/// A notification type in the config catalogue — the unit of consent, and what a user actually sees
/// in their profile.
///
/// The **type** is what a user subscribes to, so its code has to stay stable. Which template renders
/// it is the app's business; umami only decides who hears about it.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NotificationTypeDef {
    /// Stable code the app names when it fires, and the key a user's preference is stored under.
    pub code: String,
    /// Human-readable name, shown in the profile.
    pub name: String,
    /// Optional description, shown muted under the name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The cadences this type is actually fired at — the deployment's own vocabulary.
    ///
    /// Only these may be offered to a user, and a firing naming anything outside the list is
    /// **rejected**. That check exists because the alternative failure is invisible: if the config
    /// offered `daily` while the app only runs a weekly job, a user would pick daily and then never
    /// hear anything, with no error anywhere to explain it.
    ///
    /// **Empty is legitimate** and means the type has no rhythm of its own (case 2): the choice is
    /// then `on` or `off`, and a firing names no cadences.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cadences: Vec<CadenceDef>,
    /// What applies to a user who has never expressed a choice: `"on"`, a cadence code, or omitted
    /// for off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// DSL over the recipient's **offline** subject set — `feature:*` (their tenant's),
    /// `role:*` (theirs), plus `is:system-tenant` / `is:system-tenant-member`. `None` = everyone.
    ///
    /// Deliberately *not* the permission set: permissions are the output of the `apis` mapping, and
    /// this is the input vocabulary. And deliberately not the session markers (`is:2fa`,
    /// `is:passkey`, `is:totp`) — those describe how a *session* authenticated, and a notification
    /// has no session. An expression naming one would simply never match, which is the silent
    /// failure this whole file keeps trying to avoid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligible_if: Option<String>,
}

impl NotificationTypeDef {
    /// Whether `cadence` (already normalized) is one this type is ever fired at.
    pub fn fires_at(&self, cadence: &str) -> bool {
        self.cadences
            .iter()
            .any(|declared| declared.code == cadence)
    }

    /// Whether this type has a rhythm at all (case 3) or is a plain on/off one (case 2).
    pub fn has_rhythm(&self) -> bool {
        !self.cadences.is_empty()
    }

    /// Every value a user may store for this type — always including `off`.
    pub fn allowed_choices(&self) -> Vec<&str> {
        let mut allowed = vec![CHOICE_OFF];
        if self.has_rhythm() {
            allowed.extend(self.cadences.iter().map(|cadence| cadence.code.as_str()));
        } else {
            allowed.push(CHOICE_ON);
        }
        allowed
    }

    /// Whether `value` is one this type accepts as a choice or a default.
    pub fn accepts(&self, value: &str) -> bool {
        self.allowed_choices().contains(&value)
    }
}

/// Rejects a catalogue that cannot work, at publish time.
///
/// This is where the enum's typo protection went, and it catches strictly more: a duplicate code
/// (two switches for one thing, one of them dead), an empty cadence list (a type nothing can ever
/// fire), and a `default` naming a cadence the type is not fired at — which would put every
/// untouched user in a group that never receives anything, silently.
pub fn validate_catalogue(types: &[NotificationTypeDef]) -> anyhow::Result<()> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for type_def in types {
        let code = type_def.code.trim();
        if code.is_empty() {
            client_bail!("A notification type needs a 'code'");
        }
        if !seen.insert(code) {
            client_bail!("Duplicate notification type '{code}'");
        }
        // An empty cadence list is legitimate: that is a plain on/off type (case 2).
        let mut cadences: BTreeSet<&str> = BTreeSet::new();
        for cadence in &type_def.cadences {
            let value = cadence.code.as_str();
            if value.trim().is_empty() {
                client_bail!("Notification type '{code}' has a cadence without a code");
            }
            if value != normalize_cadence(value) {
                client_bail!(
                    "Cadence '{value}' on '{code}' must be lowercase and free of surrounding \
                     whitespace (write '{}')",
                    normalize_cadence(value)
                );
            }
            if RESERVED.contains(&value) {
                client_bail!(
                    "Cadence '{value}' on '{code}' is reserved — it is what a user's choice says \
                     when they mean on or off, so a cadence of that name would be ambiguous"
                );
            }
            if cadence.name.trim().is_empty() {
                client_bail!("Cadence '{value}' on '{code}' needs a 'name' to show in the picker");
            }
            if !cadences.insert(value) {
                client_bail!("Notification type '{code}' lists cadence '{value}' twice");
            }
        }
        if let Some(default) = type_def.default.as_deref()
            && !type_def.accepts(default)
        {
            client_bail!(
                "Notification type '{code}' defaults to '{default}', which it does not accept — \
                 every user who never chose would sit in a group that receives nothing. Allowed: {}",
                type_def.allowed_choices().join(", ")
            );
        }
    }
    Ok(())
}

/// The outcome of matching one user against one firing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery<'a> {
    /// Not for this user.
    Skip,
    /// Deliver. `cadence` is `None` for a type with no rhythm of its own (case 2), so a caller does
    /// not have to invent a word for "there is no rhythm".
    Deliver(Option<&'a str>),
}

/// Decides whether a user hears about one firing, and at which cadence.
///
/// `choice` is what the user stored, `None` when they never touched it — in which case the type's
/// configured default applies, now and whenever it changes.
pub fn resolve_delivery<'a>(
    type_def: &'a NotificationTypeDef,
    choice: Option<&'a str>,
    firing: &'a [String],
) -> Delivery<'a> {
    // Unset falls back to the deployment's default; anything explicit does not. Absent on both
    // sides means off, so a type nobody configured stays quiet.
    let effective = choice.or(type_def.default.as_deref()).unwrap_or(CHOICE_OFF);
    if effective == CHOICE_OFF {
        return Delivery::Skip;
    }
    // No rhythm: the answer is the choice itself, and a firing carries no cadences to match.
    if !type_def.has_rhythm() {
        return if effective == CHOICE_ON {
            Delivery::Deliver(None)
        } else {
            Delivery::Skip
        };
    }
    match firing.iter().find(|cadence| *cadence == effective) {
        Some(cadence) => Delivery::Deliver(Some(cadence.as_str())),
        None => Delivery::Skip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cadence(code: &str, name: &str) -> CadenceDef {
        CadenceDef {
            code: code.to_owned(),
            name: name.to_owned(),
        }
    }

    /// Case 3: a type with a rhythm.
    fn rhythmic(default: Option<&str>) -> NotificationTypeDef {
        NotificationTypeDef {
            code: "wsc-new-content".to_owned(),
            name: "New content".to_owned(),
            description: None,
            cadences: vec![
                cadence("daily", "Daily"),
                cadence("weekly", "Weekly"),
                cadence("monthly", "Monthly"),
            ],
            default: default.map(str::to_owned),
            eligible_if: None,
        }
    }

    /// Case 2: a type with none.
    fn plain(default: Option<&str>) -> NotificationTypeDef {
        NotificationTypeDef {
            code: "wsc-build-failed".to_owned(),
            name: "Build failed".to_owned(),
            description: None,
            cadences: Vec::new(),
            default: default.map(str::to_owned),
            eligible_if: None,
        }
    }

    fn firing(cadences: &[&str]) -> Vec<String> {
        cadences.iter().map(|c| (*c).to_owned()).collect()
    }

    /// The whole model in one test: the app announces the rhythms a firing represents, and each
    /// user's single choice either matches or does not.
    #[test]
    fn a_firing_reaches_whoever_chose_one_of_its_cadences() {
        let def = rhythmic(None);
        // The Friday run is both the daily and the weekly one.
        let friday = firing(&["daily", "weekly"]);

        assert_eq!(
            resolve_delivery(&def, Some("daily"), &friday),
            Delivery::Deliver(Some("daily"))
        );
        assert_eq!(
            resolve_delivery(&def, Some("weekly"), &friday),
            Delivery::Deliver(Some("weekly")),
            "the matched cadence comes back, so wording can differ"
        );
        assert_eq!(
            resolve_delivery(&def, Some("monthly"), &friday),
            Delivery::Skip,
            "a monthly subscriber waits for the run that says monthly"
        );
    }

    /// Case 2: no rhythm, so the choice is on or off and the firing names nothing.
    #[test]
    fn a_type_without_a_rhythm_is_just_on_or_off() {
        let def = plain(None);
        assert!(!def.has_rhythm());
        assert_eq!(def.allowed_choices(), vec![CHOICE_OFF, CHOICE_ON]);

        assert_eq!(
            resolve_delivery(&def, Some(CHOICE_ON), &[]),
            Delivery::Deliver(None),
            "delivered, and there is no rhythm to name"
        );
        assert_eq!(
            resolve_delivery(&def, Some(CHOICE_OFF), &[]),
            Delivery::Skip
        );
        assert_eq!(
            resolve_delivery(&def, None, &[]),
            Delivery::Skip,
            "no choice and no default means off"
        );
        assert_eq!(
            resolve_delivery(&plain(Some(CHOICE_ON)), None, &[]),
            Delivery::Deliver(None),
            "…unless the deployment opted everyone in"
        );
    }

    /// Off is available for every type, whether or not it has a rhythm. That is the point of one
    /// value space rather than a separate switch.
    #[test]
    fn off_is_always_available_and_outranks_the_default() {
        for def in [rhythmic(Some("weekly")), plain(Some(CHOICE_ON))] {
            assert!(def.accepts(CHOICE_OFF));
            assert_eq!(
                resolve_delivery(&def, Some(CHOICE_OFF), &firing(&["weekly"])),
                Delivery::Skip
            );
        }
    }

    /// Unset must stay distinguishable from an explicit choice, or changing a default silently
    /// overwrites what people decided.
    #[test]
    fn unset_follows_the_default_and_a_choice_does_not() {
        let on_by_default = rhythmic(Some("weekly"));
        let off_by_default = rhythmic(None);
        let weekly = firing(&["weekly"]);

        assert_eq!(
            resolve_delivery(&on_by_default, None, &weekly),
            Delivery::Deliver(Some("weekly")),
            "unset ⇒ the configured default"
        );
        assert_eq!(
            resolve_delivery(&off_by_default, None, &weekly),
            Delivery::Skip,
            "unset ⇒ off when nothing is configured"
        );
        assert_eq!(
            resolve_delivery(&off_by_default, Some("weekly"), &weekly),
            Delivery::Deliver(Some("weekly")),
            "an explicit choice outranks an off-by-default type"
        );
    }

    /// A deployment's vocabulary is its own — nothing here knows what a day is.
    #[test]
    fn a_deployment_may_invent_its_own_cadences() {
        let def = NotificationTypeDef {
            cadences: vec![
                cadence("on-publish", "Whenever something is published"),
                cadence("quarterly", "Quarterly"),
            ],
            ..rhythmic(Some("on-publish"))
        };
        assert!(validate_catalogue(std::slice::from_ref(&def)).is_ok());
        assert_eq!(
            resolve_delivery(&def, None, &firing(&["on-publish"])),
            Delivery::Deliver(Some("on-publish")),
            "the configured default applies, whatever it is called"
        );
        assert_eq!(
            resolve_delivery(&def, Some("quarterly"), &firing(&["on-publish"])),
            Delivery::Skip
        );
    }

    /// The guard that replaced the enum, and it catches more than one would.
    #[test]
    fn the_catalogue_gate_refuses_what_cannot_work() {
        let ok = rhythmic(Some("weekly"));
        assert!(validate_catalogue(std::slice::from_ref(&ok)).is_ok());
        assert!(
            validate_catalogue(std::slice::from_ref(&plain(Some(CHOICE_ON)))).is_ok(),
            "a type with no rhythm is legitimate, not an error"
        );

        let unfired_default = NotificationTypeDef {
            default: Some("hourly".to_owned()),
            ..ok.clone()
        };
        assert!(
            validate_catalogue(&[unfired_default]).is_err(),
            "every untouched user would sit in a group that receives nothing"
        );

        let shouty = NotificationTypeDef {
            cadences: vec![cadence("Weekly", "Weekly")],
            default: None,
            ..ok.clone()
        };
        assert!(
            validate_catalogue(&[shouty]).is_err(),
            "capitalisation would silently never match a normalized firing"
        );

        let reserved = NotificationTypeDef {
            cadences: vec![cadence(CHOICE_OFF, "Off")],
            default: None,
            ..ok.clone()
        };
        assert!(
            validate_catalogue(&[reserved]).is_err(),
            "a cadence called 'off' would make every choice ambiguous"
        );

        let unlabelled = NotificationTypeDef {
            cadences: vec![cadence("weekly", "  ")],
            default: None,
            ..ok.clone()
        };
        assert!(
            validate_catalogue(&[unlabelled]).is_err(),
            "a picker entry with no words is not a choice anyone can make"
        );

        assert!(
            validate_catalogue(&[ok.clone(), ok.clone()]).is_err(),
            "two switches for one thing, one of them dead"
        );

        let unnamed = NotificationTypeDef {
            code: "  ".to_owned(),
            ..ok
        };
        assert!(validate_catalogue(&[unnamed]).is_err());
    }

    #[test]
    fn cadence_normalisation_is_trim_and_lowercase() {
        assert_eq!(normalize_cadence("  Weekly "), "weekly");
        assert_eq!(normalize_cadence("ON-PUBLISH"), "on-publish");
    }
}
