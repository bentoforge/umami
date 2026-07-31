//! Configuration: the global catalog + system settings that define the shape of the system.
//!
//! Loaded and saved as one whole document via [`repository::ConfigRepository`] (cached), and edited
//! by the client (load → edit → write back). See `docs/CONFIG.md`. Per-tenant/user *assignments*
//! (user roles, tenant packages, overrides, custom-field values) live on the entities, not here.

pub mod repository;
pub mod service;

use crate::constants::{
    ADMIN_TENANT_PERMISSION, MANAGE_CONFIG_PERMISSION, WRITE_MEMBERS_PERMISSION,
};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A role: a code, a display name, and the permission strings it grants.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RoleDef {
    /// Stable code referenced by `user.roles`.
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// Permission strings baked into the token for users holding this role.
    pub permissions: Vec<String>,
}

/// A feature flag definition (togglable per tenant).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FeatureDef {
    /// Stable code.
    pub code: String,
    /// Human-readable name.
    pub name: String,
}

/// A quantitative limit definition (e.g. "AI Tokens", "Max Items").
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LimitDef {
    /// Stable code.
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// Optional unit label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Baseline value when no package raises it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<Decimal>,
}

/// A limit raised by a package.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PackageLimit {
    /// Limit code being raised.
    pub code: String,
    /// The value the package grants.
    pub value: Decimal,
}

/// A dated list price for a package.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PriceEntry {
    /// Date from which this price applies.
    pub valid_from: NaiveDate,
    /// Monthly list price (exact decimal, never a float).
    pub price: Decimal,
}

/// A package: bundles features + raised limits, with a dated price schedule.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PackageDef {
    /// Stable code referenced by a tenant's package assignments.
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// Feature codes this package turns on.
    #[serde(default)]
    pub features: Vec<String>,
    /// Limits this package raises.
    #[serde(default)]
    pub limits: Vec<PackageLimit>,
    /// Dated list-price schedule.
    #[serde(default)]
    pub prices: Vec<PriceEntry>,
}

/// A custom-field schema entry (tenant- or user-level).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldDef {
    /// Storage key.
    pub key: String,
    /// Display label.
    pub label: String,
    /// Field type (e.g. `string`, `number`, `bool`).
    #[serde(rename = "type")]
    pub field_type: String,
    /// Whether the field must be set.
    #[serde(default)]
    pub required: bool,
}

/// System security/token settings.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SecuritySettings {
    /// Minimum accepted password length.
    pub min_password_length: u32,
    /// Access-token lifetime (seconds).
    pub access_ttl_secs: u64,
    /// Refresh/session lifetime (seconds).
    pub refresh_ttl_secs: u64,
}

/// The whole configuration document.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// Optimistic-concurrency counter, bumped on every save.
    pub version: u64,
    /// Role catalog.
    pub roles: Vec<RoleDef>,
    /// Feature catalog.
    #[serde(default)]
    pub features: Vec<FeatureDef>,
    /// Limit catalog.
    #[serde(default)]
    pub limits: Vec<LimitDef>,
    /// Package catalog.
    #[serde(default)]
    pub packages: Vec<PackageDef>,
    /// Custom tenant field schemas.
    #[serde(default)]
    pub custom_tenant_fields: Vec<CustomFieldDef>,
    /// Custom user field schemas.
    #[serde(default)]
    pub custom_user_fields: Vec<CustomFieldDef>,
    /// Security/token settings.
    pub security: SecuritySettings,
    /// Which optional claims to include in issued tokens.
    #[serde(default)]
    pub token_claims: Vec<String>,
}

impl Config {
    /// Resolves the union of permissions granted by the given role codes (sorted, deduped).
    pub fn permissions_for_roles(&self, role_codes: &[String]) -> Vec<String> {
        let mut granted: HashSet<&str> = HashSet::new();
        for role in &self.roles {
            if role_codes.iter().any(|code| code == &role.code) {
                for permission in &role.permissions {
                    let _ = granted.insert(permission.as_str());
                }
            }
        }
        let mut permissions: Vec<String> = granted.into_iter().map(str::to_owned).collect();
        permissions.sort();
        permissions
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: 1,
            roles: vec![
                RoleDef {
                    code: "owner".to_owned(),
                    name: "Owner".to_owned(),
                    permissions: vec![
                        ADMIN_TENANT_PERMISSION.to_owned(),
                        WRITE_MEMBERS_PERMISSION.to_owned(),
                        MANAGE_CONFIG_PERMISSION.to_owned(),
                    ],
                },
                RoleDef {
                    code: "admin".to_owned(),
                    name: "Administrator".to_owned(),
                    permissions: vec![WRITE_MEMBERS_PERMISSION.to_owned()],
                },
                RoleDef {
                    code: "member".to_owned(),
                    name: "Member".to_owned(),
                    permissions: Vec::new(),
                },
                RoleDef {
                    code: "viewer".to_owned(),
                    name: "Viewer".to_owned(),
                    permissions: Vec::new(),
                },
            ],
            features: Vec::new(),
            limits: Vec::new(),
            packages: Vec::new(),
            custom_tenant_fields: Vec::new(),
            custom_user_fields: Vec::new(),
            security: SecuritySettings {
                min_password_length: 8,
                access_ttl_secs: 600,
                refresh_ttl_secs: 2_592_000,
            },
            token_claims: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_owner_has_admin_permissions() {
        let config = Config::default();
        let perms = config.permissions_for_roles(&["owner".to_owned()]);
        assert!(perms.contains(&"admin:tenant".to_owned()));
        assert!(perms.contains(&"write:members".to_owned()));
        assert!(perms.contains(&"manage:config".to_owned()));
    }

    #[test]
    fn unknown_and_empty_roles_grant_nothing() {
        let config = Config::default();
        assert!(
            config
                .permissions_for_roles(&["nope".to_owned()])
                .is_empty()
        );
        assert!(config.permissions_for_roles(&[]).is_empty());
        assert!(
            config
                .permissions_for_roles(&["viewer".to_owned()])
                .is_empty()
        );
    }

    #[test]
    fn union_dedupes_across_roles() {
        let config = Config::default();
        // owner + admin both grant write:members → appears once
        let perms = config.permissions_for_roles(&["owner".to_owned(), "admin".to_owned()]);
        assert_eq!(
            perms
                .iter()
                .filter(|p| p.as_str() == "write:members")
                .count(),
            1
        );
    }
}
