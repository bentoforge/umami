//! Which address a user is actually reached at.
//!
//! `user.preferredContact` records what the user *chose*, and only that. Where mail actually goes is
//! **derived** from it by [`preference_for`], every time, by both the profile screen and every
//! sender:
//!
//! - the chosen address, while the user still holds it and has confirmed it;
//! - otherwise the oldest confirmed address they hold;
//! - otherwise nothing — the user is unreachable.
//!
//! Deriving rather than storing is the whole point. The alternative is to rewrite the stored value
//! whenever an address is added, removed, confirmed or bounced — and since a sender still cannot
//! trust a value written by an earlier version of that logic, it needs the fallback anyway. Two
//! mechanisms answering one question is how a profile screen and a password reset end up disagreeing
//! about which mailbox is the user's.
//!
//! So the derived answer moves on its own: confirming a first address makes it the one, deleting the
//! chosen one hands over to the next, and a bounce that withdraws a confirmation does the same
//! without anything having to be written.
//!
//! Setting a preference is where the rule is enforced up front instead — `PUT
//! /auth/me/preferred-contact` refuses an unconfirmed address, because there the user is present and
//! can be told why.

use crate::contacts::Contact;

/// The address `current` resolves to, given what the user holds right now.
///
/// Falls back to the **oldest** confirmed address, not the newest: the one proven longest is the one
/// the user has been reachable at longest, and picking by age gives every caller the same answer.
/// Address breaks a tie between two identical timestamps, so the choice cannot depend on the order
/// rows came back in.
pub fn preference_for(current: Option<&str>, contacts: &[Contact]) -> Option<String> {
    let still_valid = current.filter(|address| {
        contacts
            .iter()
            .any(|contact| contact.verified && contact.address == *address)
    });
    if let Some(address) = still_valid {
        return Some(address.to_owned());
    }
    contacts
        .iter()
        .filter(|contact| contact.verified)
        .min_by(|a, b| {
            a.created
                .cmp(&b.created)
                .then_with(|| a.address.cmp(&b.address))
        })
        .map(|contact| contact.address.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0)
            .single()
            .unwrap_or_default()
    }

    fn contact(address: &str, verified: bool, created: i64) -> Contact {
        Contact {
            user_id: "u1".to_owned(),
            address: address.to_owned(),
            tenant_id: "t1".to_owned(),
            label: None,
            verified,
            verified_at: None,
            created: at(created),
        }
    }

    #[test]
    fn a_verified_preference_is_left_alone() {
        let held = [
            contact("old@example.com", true, 0),
            contact("new@example.com", true, 10),
        ];
        assert_eq!(
            preference_for(Some("new@example.com"), &held),
            Some("new@example.com".to_owned())
        );
    }

    #[test]
    fn the_first_verified_address_becomes_the_preference() {
        let held = [contact("only@example.com", true, 0)];
        assert_eq!(
            preference_for(None, &held),
            Some("only@example.com".to_owned())
        );
    }

    #[test]
    fn a_deleted_preference_falls_back_to_the_oldest_verified() {
        let held = [
            contact("newer@example.com", true, 10),
            contact("older@example.com", true, 0),
        ];
        assert_eq!(
            preference_for(Some("gone@example.com"), &held),
            Some("older@example.com".to_owned())
        );
    }

    #[test]
    fn a_bounced_preference_falls_back_to_a_still_verified_one() {
        let held = [
            contact("bounced@example.com", false, 0),
            contact("works@example.com", true, 10),
        ];
        assert_eq!(
            preference_for(Some("bounced@example.com"), &held),
            Some("works@example.com".to_owned())
        );
    }

    #[test]
    fn unverified_addresses_are_never_promoted() {
        let held = [contact("pending@example.com", false, 0)];
        assert_eq!(preference_for(None, &held), None);
        assert_eq!(preference_for(Some("pending@example.com"), &held), None);
    }

    #[test]
    fn an_equal_timestamp_is_broken_by_address_not_by_row_order() {
        let held = [
            contact("b@example.com", true, 0),
            contact("a@example.com", true, 0),
        ];
        assert_eq!(
            preference_for(None, &held),
            Some("a@example.com".to_owned())
        );
    }
}
