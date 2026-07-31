//! Tenants — the account/ownership + billing unit.
//!
//! A tenant owns its users (see `users`) and carries the CRM/licensing fields (status, plan,
//! usage). This module owns the `Tenant` entity, its persistence (`repository`) and routes
//! (`service`). Status transitions and usage metering land in a later CRM phase.

pub mod packages;
pub mod repository;
pub mod service;

use crate::config::Config;
use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Per-tenant feature toggle: inherit from packages, or force on/off.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FeatureToggle {
    /// Inherit from the tenant's active packages (the default).
    #[default]
    Standard,
    /// Force the feature on regardless of packages.
    On,
    /// Force the feature off regardless of packages.
    Off,
}

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

/// A package assigned to a tenant (the same package code may be assigned more than once). Carries
/// the accounting fields, so licensing + billing derive from this list.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PackageAssignment {
    /// Generated id so a specific assignment can be targeted for removal.
    pub id: String,
    /// Package code from the config catalog.
    pub code: String,
    /// When the package was assigned.
    pub assigned_at: NaiveDate,
    /// Billed through this date, if tracked.
    pub accounted_until: Option<NaiveDate>,
    /// Negotiated monthly price; when `None`, the catalog list price applies.
    pub monthly_price: Option<Decimal>,
    /// The negotiated price is fixed until this date, if set.
    pub price_fixed_until: Option<NaiveDate>,
    /// Whether the assignment currently counts toward entitlements/billing.
    pub active: bool,
}

/// A tenant as stored in DynamoDB.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Tenant {
    /// Primary key — 32-char generated id.
    pub tenant_id: String,
    /// Optimistic-concurrency counter — every write requires the last-read value and bumps it, so
    /// accounting mutations can never clobber a concurrent update from a stale read.
    #[serde(default)]
    pub version: u64,
    /// Assigned packages (accounting records).
    #[serde(default)]
    pub packages: Vec<PackageAssignment>,
    /// Per-tenant limit overrides (`limitCode` → value); when absent a limit is computed from the
    /// active packages.
    #[serde(default)]
    pub limit_overrides: BTreeMap<String, Decimal>,
    /// Per-tenant feature toggles (`featureCode` → on/off); absent means inherit from packages.
    #[serde(default)]
    pub feature_overrides: BTreeMap<String, FeatureToggle>,
    /// Values for the config-defined custom tenant fields.
    #[serde(default)]
    pub custom_fields: BTreeMap<String, Value>,
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

/// Resolves a tenant's effective limits: for each catalog limit, the highest value raised by an
/// active package (starting from the limit's default), unless the tenant has an explicit override.
pub fn effective_limits(config: &Config, tenant: &Tenant) -> BTreeMap<String, Decimal> {
    let mut resolved = BTreeMap::new();

    for limit in &config.limits {
        let mut value = limit.default.unwrap_or(Decimal::ZERO);

        for assignment in tenant
            .packages
            .iter()
            .filter(|assignment| assignment.active)
        {
            if let Some(package) = config
                .packages
                .iter()
                .find(|package| package.code == assignment.code)
                && let Some(raised) = package
                    .limits
                    .iter()
                    .find(|package_limit| package_limit.code == limit.code)
                && raised.value > value
            {
                value = raised.value;
            }
        }

        if let Some(override_value) = tenant.limit_overrides.get(&limit.code) {
            value = *override_value;
        }

        let _ = resolved.insert(limit.code.clone(), value);
    }

    resolved
}

/// Resolves the effective monthly price of a single assignment at a date: the negotiated
/// `monthly_price` if set, otherwise the catalog list price in effect on that date.
pub fn effective_price(
    config: &Config,
    assignment: &PackageAssignment,
    at: NaiveDate,
) -> Option<Decimal> {
    if let Some(price) = assignment.monthly_price {
        return Some(price);
    }

    let package = config
        .packages
        .iter()
        .find(|package| package.code == assignment.code)?;

    package
        .prices
        .iter()
        .filter(|entry| entry.valid_from <= at)
        .max_by_key(|entry| entry.valid_from)
        .map(|entry| entry.price)
}

/// Resolves the set of enabled feature codes for a tenant: a feature is on if an active package
/// provides it (the `Standard` baseline), unless the tenant forces it `On`/`Off`.
pub fn effective_features(config: &Config, tenant: &Tenant) -> BTreeSet<String> {
    let mut enabled = BTreeSet::new();

    for feature in &config.features {
        let baseline = tenant
            .packages
            .iter()
            .filter(|assignment| assignment.active)
            .any(|assignment| {
                config
                    .packages
                    .iter()
                    .find(|package| package.code == assignment.code)
                    .is_some_and(|package| package.features.contains(&feature.code))
            });

        let on = match tenant
            .feature_overrides
            .get(&feature.code)
            .copied()
            .unwrap_or_default()
        {
            FeatureToggle::Standard => baseline,
            FeatureToggle::On => true,
            FeatureToggle::Off => false,
        };

        if on {
            let _ = enabled.insert(feature.code.clone());
        }
    }

    enabled
}

/// Sums the effective monthly price of a tenant's active packages at a date.
pub fn monthly_total(config: &Config, tenant: &Tenant, at: NaiveDate) -> Decimal {
    tenant
        .packages
        .iter()
        .filter(|assignment| assignment.active)
        .filter_map(|assignment| effective_price(config, assignment, at))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LimitDef, PackageDef, PackageLimit, PriceEntry};
    use rust_decimal::prelude::FromPrimitive;

    #[test]
    fn slugify_normalizes() {
        assert_eq!(slugify("Acme Inc."), "acme-inc");
        assert_eq!(slugify("  Hello   World  "), "hello-world");
        assert_eq!(slugify("!!!"), "tenant");
    }

    fn dec(n: i64) -> Decimal {
        Decimal::from_i64(n).unwrap()
    }

    fn config_with_plus() -> Config {
        Config {
            limits: vec![LimitDef {
                code: "ai-tokens".to_owned(),
                name: "AI Tokens".to_owned(),
                unit: None,
                default: Some(dec(100)),
            }],
            packages: vec![PackageDef {
                code: "plus".to_owned(),
                name: "Plus".to_owned(),
                features: vec![],
                limits: vec![PackageLimit {
                    code: "ai-tokens".to_owned(),
                    value: dec(1000),
                }],
                prices: vec![PriceEntry {
                    valid_from: NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
                    price: dec(49),
                }],
            }],
            ..Config::default()
        }
    }

    fn tenant_with(packages: Vec<PackageAssignment>) -> Tenant {
        let now = Utc::now();
        Tenant {
            tenant_id: "t1".to_owned(),
            version: 0,
            packages,
            limit_overrides: BTreeMap::new(),
            feature_overrides: BTreeMap::new(),
            custom_fields: BTreeMap::new(),
            name: "T".to_owned(),
            slug: "t".to_owned(),
            status: TenantStatus::Active,
            plan: "free".to_owned(),
            billed_until: None,
            seats_limit: None,
            usage_period_start: None,
            ai_tokens_used: 0,
            ai_tokens_quota: None,
            created: now,
            last_updated: now,
        }
    }

    fn plus_assignment(monthly_price: Option<Decimal>) -> PackageAssignment {
        PackageAssignment {
            id: "a1".to_owned(),
            code: "plus".to_owned(),
            assigned_at: NaiveDate::from_ymd_opt(2026, 6, 1).unwrap(),
            accounted_until: None,
            monthly_price,
            price_fixed_until: None,
            active: true,
        }
    }

    #[test]
    fn effective_limits_raises_from_active_package() {
        let config = config_with_plus();
        let tenant = tenant_with(vec![plus_assignment(None)]);
        let limits = effective_limits(&config, &tenant);
        assert_eq!(limits.get("ai-tokens"), Some(&dec(1000)));
    }

    #[test]
    fn effective_limits_uses_default_without_package() {
        let config = config_with_plus();
        let tenant = tenant_with(vec![]);
        assert_eq!(
            effective_limits(&config, &tenant).get("ai-tokens"),
            Some(&dec(100))
        );
    }

    #[test]
    fn tenant_override_wins() {
        let config = config_with_plus();
        let mut tenant = tenant_with(vec![plus_assignment(None)]);
        let _ = tenant
            .limit_overrides
            .insert("ai-tokens".to_owned(), dec(500));
        assert_eq!(
            effective_limits(&config, &tenant).get("ai-tokens"),
            Some(&dec(500))
        );
    }

    #[test]
    fn price_falls_back_to_catalog_schedule() {
        let config = config_with_plus();
        let at = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        assert_eq!(
            effective_price(&config, &plus_assignment(None), at),
            Some(dec(49))
        );
        // negotiated price overrides the catalog
        assert_eq!(
            effective_price(&config, &plus_assignment(Some(dec(30))), at),
            Some(dec(30))
        );
    }

    #[test]
    fn monthly_total_sums_active_packages() {
        let config = config_with_plus();
        let at = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        let tenant = tenant_with(vec![plus_assignment(None), plus_assignment(Some(dec(30)))]);
        assert_eq!(monthly_total(&config, &tenant, at), dec(79));
    }

    fn config_with_feature() -> Config {
        Config {
            features: vec![crate::config::FeatureDef {
                code: "ai".to_owned(),
                name: "AI".to_owned(),
            }],
            packages: vec![PackageDef {
                code: "plus".to_owned(),
                name: "Plus".to_owned(),
                features: vec!["ai".to_owned()],
                limits: vec![],
                prices: vec![],
            }],
            ..Config::default()
        }
    }

    #[test]
    fn feature_inherited_from_active_package() {
        let config = config_with_feature();
        let tenant = tenant_with(vec![plus_assignment(None)]);
        assert!(effective_features(&config, &tenant).contains("ai"));
    }

    #[test]
    fn feature_override_forces_on_and_off() {
        let config = config_with_feature();

        // Force ON without any package.
        let mut on = tenant_with(vec![]);
        let _ = on
            .feature_overrides
            .insert("ai".to_owned(), FeatureToggle::On);
        assert!(effective_features(&config, &on).contains("ai"));

        // Force OFF despite the package providing it.
        let mut off = tenant_with(vec![plus_assignment(None)]);
        let _ = off
            .feature_overrides
            .insert("ai".to_owned(), FeatureToggle::Off);
        assert!(!effective_features(&config, &off).contains("ai"));
    }
}
