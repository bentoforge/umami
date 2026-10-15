//! Persistence for tenants: the [`TenantRepository`] trait and the helpers its backends share.

pub mod dynamodb;
pub mod postgres;

use crate::search::value_search_text;
use crate::tenants::Tenant;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::BTreeMap;

/// Persistence interface for tenants.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait TenantRepository: Send + Sync {
    /// Creates a tenant, returning it. `created_by` records the acting user id (`None` for
    /// system/auto-init).
    async fn create_tenant(
        &self,
        name: &str,
        slug: &str,
        created_by: Option<&str>,
    ) -> anyhow::Result<Tenant>;

    /// Creates a tenant with a caller-supplied id (auto-init's system tenant, or an id an admin
    /// chose on creation). Same defaults as `create_tenant`; an existing id fails.
    async fn create_tenant_with_id(
        &self,
        tenant_id: &str,
        name: &str,
        slug: &str,
        created_by: Option<&str>,
    ) -> anyhow::Result<Tenant>;

    /// Best-effort bump of the tenant's `lastActive` timestamp (token activity heartbeat). Does not
    /// touch `version`/`lastUpdated` — it is not a logical change.
    async fn touch_last_active(&self, tenant_id: &str) -> anyhow::Result<()>;

    /// Fetches a tenant by id. `None` if unknown.
    async fn get_tenant(&self, tenant_id: &str) -> anyhow::Result<Option<Tenant>>;

    /// Finds tenants matching `query` (case-insensitive over name/slug/custom fields; empty = all),
    /// newest-active first, returning at most `limit` plus a `truncated` flag when more matched.
    /// The DynamoDB backend streams the listing GSI and stops as soon as the cap is reached; a
    /// smarter store can push the filter + limit down to the server.
    async fn find_tenants(&self, query: &str, limit: usize) -> anyhow::Result<(Vec<Tenant>, bool)>;

    /// Overwrites a tenant record (used by PATCH after a read-modify), bumping `lastUpdated`.
    async fn put_tenant(&self, tenant: Tenant) -> anyhow::Result<Tenant>;

    /// Deletes a tenant by id. Callers must enforce any preconditions (e.g. no remaining users).
    async fn delete_tenant(&self, tenant_id: &str) -> anyhow::Result<()>;
}

/// A fresh tenant with the defaults every backend creates it with.
fn new_tenant(tenant_id: &str, name: &str, slug: &str, created_by: Option<&str>) -> Tenant {
    let now = Utc::now();
    Tenant {
        tenant_id: tenant_id.to_owned(),
        version: 0,
        features: Vec::new(),
        custom_fields: BTreeMap::new(),
        limits: BTreeMap::new(),
        name: name.to_owned(),
        slug: slug.to_owned(),
        created: now,
        last_updated: now,
        last_active: None,
        last_active_or_created: now,
        created_by: created_by.map(str::to_owned),
        last_changed_by: created_by.map(str::to_owned),
    }
}

/// Concatenates a tenant's searchable text: name, slug, and every custom-field value (customer
/// number / address live in custom fields). Fed to `query_matches` for the in-memory filter.
fn tenant_haystack(tenant: &Tenant) -> String {
    let mut haystack = format!("{} {}", tenant.name, tenant.slug);
    for value in tenant.custom_fields.values() {
        haystack.push(' ');
        haystack.push_str(&value_search_text(value));
    }
    haystack
}
