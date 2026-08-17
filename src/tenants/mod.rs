//! Tenants — the account/ownership unit.
//!
//! A tenant owns its users (see `users`) and carries the **authorization** feature grants plus any
//! deployment-defined custom fields. This module owns the `Tenant` entity, its persistence
//! (`repository`) and routes (`service`). CRM/licensing/billing is intentionally out of scope —
//! anything a deployment needs beyond identity lives in custom fields.

pub mod repository;
pub mod service;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A tenant as stored in DynamoDB.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Tenant {
    /// Primary key — 32-char generated id.
    pub tenant_id: String,
    /// Optimistic-concurrency counter — every write requires the last-read value and bumps it, so
    /// concurrent updates can never clobber each other from a stale read.
    #[serde(default)]
    pub version: u64,
    /// Granted **authorization** features (namespaced `feature:*`) — the flat set the permission
    /// game reads (see `docs/PERMISSIONS.md`).
    #[serde(default)]
    pub features: Vec<String>,
    /// Values for the config-defined custom tenant fields.
    #[serde(default)]
    pub custom_fields: BTreeMap<String, Value>,
    /// Display name.
    pub name: String,
    /// URL-friendly handle derived from the name (not enforced unique in v1).
    pub slug: String,
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
