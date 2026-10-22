//! Persistence for external recipients: the [`RecipientRepository`] trait.

pub mod dynamodb;
pub mod postgres;

use crate::recipients::ExternalRecipient;
use async_trait::async_trait;

/// Persistence for external recipients.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait RecipientRepository: Send + Sync {
    /// Stores a new recipient. An address already held by another recipient of the same tenant is
    /// a `409`.
    async fn add_recipient(&self, recipient: ExternalRecipient) -> anyhow::Result<()>;

    /// Fetches one recipient by id, whichever tenant it belongs to. Callers scope the result
    /// themselves: an admin route compares the tenant, a send only needs the row.
    async fn get_recipient(&self, recipient_id: &str) -> anyhow::Result<Option<ExternalRecipient>>;

    /// Lists a tenant's recipients, ascending by address.
    async fn list_recipients(&self, tenant_id: &str) -> anyhow::Result<Vec<ExternalRecipient>>;

    /// The tenant's recipient holding `address`, if any.
    async fn find_by_address(
        &self,
        tenant_id: &str,
        address: &str,
    ) -> anyhow::Result<Option<ExternalRecipient>>;

    /// Overwrites a recipient's record. Used for the fields an admin or the recipient edits —
    /// display name, language, choices. The address and the tenant never change this way.
    async fn put_recipient(&self, recipient: ExternalRecipient) -> anyhow::Result<()>;

    /// Marks a recipient confirmed. Idempotent; a missing row is a client error, so a
    /// confirmation that quietly did nothing cannot be mistaken for success.
    async fn mark_confirmed(&self, recipient_id: &str) -> anyhow::Result<()>;

    /// Withdraws a recipient's confirmation without removing it — for a hard bounce. Idempotent;
    /// a missing row is nothing to do.
    async fn mark_unconfirmed(&self, recipient_id: &str) -> anyhow::Result<()>;

    /// Deletes one recipient. A missing row is treated as "nothing to delete".
    async fn delete_recipient(&self, recipient_id: &str) -> anyhow::Result<()>;

    /// Deletes every recipient a tenant holds, returning how many there were. For deleting the
    /// tenant itself: nothing reaches these rows once the tenant is gone.
    async fn delete_all_for_tenant(&self, tenant_id: &str) -> anyhow::Result<usize>;
}
