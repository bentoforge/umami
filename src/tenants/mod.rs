//! Tenants — the account/ownership + billing unit.
//!
//! A tenant owns its users (see `users`) and carries the CRM/licensing fields (status, plan,
//! usage). This module owns the `Tenant` entity, its persistence (`repository`) and routes
//! (`service`). Status transitions and usage metering land in a later CRM phase.

pub mod repository;
pub mod service;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// Customer lifecycle state of a tenant (micro-CRM).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    /// Prospective, not yet signed up.
    Lead,
    /// Evaluating (trial).
    Testing,
    /// Signed up, being set up.
    Onboarding,
    /// Live, paying/usable.
    Active,
    /// Temporarily disabled (e.g. non-payment).
    Suspended,
    /// Left.
    Churned,
}

/// A tenant as stored in DynamoDB.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Tenant {
    /// Primary key — 32-char generated id.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// URL-friendly handle derived from the name (not enforced unique in v1).
    pub slug: String,
    /// Customer lifecycle state.
    pub status: TenantStatus,
    /// Package id (`free` | `pro` | `enterprise` | …).
    pub plan: String,
    /// Paid-through date, if any.
    pub billed_until: Option<NaiveDate>,
    /// Seat cap, if any.
    pub seats_limit: Option<u32>,
    /// Start of the current usage period.
    pub usage_period_start: Option<NaiveDate>,
    /// AI tokens consumed this period.
    pub ai_tokens_used: u64,
    /// AI-token quota for the period, if any.
    pub ai_tokens_quota: Option<u64>,
    /// RFC 3339 creation timestamp.
    pub created: DateTime<Utc>,
    /// RFC 3339 timestamp of the last update.
    pub last_updated: DateTime<Utc>,
}

/// Derives a URL-friendly slug from a display name: lowercase, non-alphanumerics collapsed to
/// single hyphens, trimmed. Falls back to `"tenant"` if nothing usable remains.
pub fn slugify(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut last_was_dash = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            slug.push('-');
            last_was_dash = true;
        }
    }
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "tenant".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_normalizes() {
        assert_eq!(slugify("Acme Inc."), "acme-inc");
        assert_eq!(slugify("  Hello   World  "), "hello-world");
        assert_eq!(slugify("!!!"), "tenant");
    }
}
