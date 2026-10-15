//! Persistence for email contacts: the [`ContactRepository`] trait.

pub mod dynamodb;
pub mod postgres;

use crate::contacts::Contact;
use async_trait::async_trait;

/// Parameters for adding an address.
pub struct NewContact {
    /// Owning user.
    pub user_id: String,
    /// Owning user's tenant.
    pub tenant_id: String,
    /// The **already normalized** address (see [`crate::contacts::normalize_email`]).
    pub address: String,
    /// Optional display label.
    pub label: Option<String>,
}

/// Persistence for email contacts.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait ContactRepository: Send + Sync {
    /// Adds an address, **unverified**. A duplicate for the same user is a client error.
    async fn add_contact(&self, new_contact: NewContact) -> anyhow::Result<Contact>;

    /// Fetches one of a user's addresses.
    async fn get_contact(&self, user_id: &str, address: &str) -> anyhow::Result<Option<Contact>>;

    /// Lists a user's addresses, ascending by address (a stable order as addresses come and go).
    async fn list_contacts(&self, user_id: &str) -> anyhow::Result<Vec<Contact>>;

    /// Every contact holding `address`, across tenants.
    ///
    /// Password recovery needs exactly this: at that moment there is no session and therefore no
    /// tenant, and an address that two accounts share has to be recognised as **ambiguous** rather
    /// than resolved to whichever row came back first.
    async fn contacts_for_address(&self, address: &str) -> anyhow::Result<Vec<Contact>>;

    /// Marks one of a user's addresses verified. Idempotent; a missing row is a client error, so a
    /// verification that quietly did nothing cannot be mistaken for success.
    async fn mark_verified(&self, user_id: &str, address: &str) -> anyhow::Result<()>;

    /// Withdraws an address's confirmed status, without removing it.
    ///
    /// For a hard bounce: the address was proven once and has since stopped existing, so the proof
    /// is stale rather than the row wrong. Keeping the row and clearing the flag lets the user see
    /// what happened and confirm it again if the mailbox comes back. Idempotent; a missing row is
    /// nothing to do, because a bounce for an address somebody already deleted is not an error.
    async fn mark_unverified(&self, user_id: &str, address: &str) -> anyhow::Result<()>;

    /// Deletes one of a user's addresses. A missing row is treated as "nothing to delete".
    async fn delete_contact(&self, user_id: &str, address: &str) -> anyhow::Result<()>;

    /// Deletes every address a user holds, returning how many there were.
    ///
    /// For deleting the user themselves. Nothing else reaches these rows once the user is gone —
    /// every read is keyed on a `userId` that no longer resolves — so they would sit in the table
    /// holding addresses of somebody who asked to be removed, which is the one kind of leftover
    /// that is not merely untidy.
    async fn delete_all_for_user(&self, user_id: &str) -> anyhow::Result<usize>;
}
