//! Configuration: the global catalog + system settings that define the shape of the system.
//!
//! Loaded and saved as one whole document via [`repository::ConfigRepository`] (cached), and edited
//! by the client (load → edit → write back). See `docs/CONFIG.md`. Per-tenant/user *assignments*
//! (user roles, tenant packages, overrides, custom-field values) live on the entities, not here.

pub mod repository;
pub mod service;

use crate::constants::{
    ADMIN_SYSTEM_PERMISSION, ADMIN_TENANT_PERMISSION, DEFAULT_ACCESS_TTL_SECS,
    DEFAULT_REFRESH_TTL_SECS, MANAGE_CONFIG_PERMISSION, MESSAGING_LINK_PERMISSION,
    MESSAGING_RESOLVE_PERMISSION, ROLE_MEMBER, ROLE_OWNER, SYSTEM_TENANT_MARKER,
    WRITE_MEMBERS_PERMISSION, WRITE_USAGE_PERMISSION,
};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use wasabi::client_bail;

/// One rule in an API's ordered permission mapping: when `when` holds against the current set
/// (subjects ∪ permissions granted by earlier rules), the permissions in `grant` are added.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRule {
    /// Condition (permission-string DSL) over subjects ∪ already-granted permissions.
    pub when: String,
    /// Permissions granted when the condition holds.
    pub grant: Vec<String>,
}

/// A target API (audience) umami can mint tokens for — see `docs/AUDIENCES.md` + `docs/PERMISSIONS.md`.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ApiDef {
    /// Internal id, referenced by API keys and the exchange call.
    pub code: String,
    /// The `aud` claim written into tokens minted for this API.
    pub audience: String,
    /// Permission-string DSL that must hold (against subjects ∪ granted permissions) to obtain a
    /// token for this API; `None` = no gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligibility: Option<String>,
    /// Ordered permission mapping: rules fire top-to-bottom, later rules seeing earlier grants.
    #[serde(default)]
    pub permissions: Vec<PermissionRule>,
    /// Claim mapping `claimName → source` (`"features"`, `"customUser:<k>"`, `"customTenant:<k>"`,
    /// or a literal).
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
}

/// Evaluates a permission-string expression against a token set (subjects ∪ granted permissions).
/// `,` = OR (lowest precedence), `+` = AND, `!term` = NOT. An empty expression holds (no gate); an
/// empty clause is skipped.
pub fn eval_expression(expression: &str, set: &BTreeSet<&str>) -> bool {
    let clauses: Vec<&str> = expression
        .split(',')
        .map(str::trim)
        .filter(|clause| !clause.is_empty())
        .collect();
    if clauses.is_empty() {
        return true;
    }
    clauses.iter().any(|clause| {
        let terms: Vec<&str> = clause
            .split('+')
            .map(str::trim)
            .filter(|term| !term.is_empty())
            .collect();
        !terms.is_empty()
            && terms.iter().all(|term| match term.strip_prefix('!') {
                Some(negated) => !set.contains(negated.trim()),
                None => set.contains(term),
            })
    })
}

impl ApiDef {
    /// Resolves the token's permissions for a subject set, then checks eligibility.
    ///
    /// Ordered accumulate: start from `subjects` (namespaced `role:*`/`scope:*`/`feature:*`/`is:*`),
    /// fire each `permissions` rule whose `when` holds against the current set (subjects ∪ granted
    /// so far), adding its grant. Then evaluate `eligibility` against the final set. Returns the
    /// sorted permissions when eligible, or `None` when not (⇒ the caller returns 403).
    pub fn resolve(&self, subjects: &[String]) -> Option<Vec<String>> {
        let mut working: BTreeSet<String> = subjects.iter().cloned().collect();
        let mut granted: BTreeSet<String> = BTreeSet::new();

        for rule in &self.permissions {
            let view: BTreeSet<&str> = working.iter().map(String::as_str).collect();
            if eval_expression(&rule.when, &view) {
                for permission in &rule.grant {
                    if granted.insert(permission.clone()) {
                        let _ = working.insert(permission.clone());
                    }
                }
            }
        }

        let eligible = match &self.eligibility {
            Some(expr) => {
                let view: BTreeSet<&str> = working.iter().map(String::as_str).collect();
                eval_expression(expr, &view)
            }
            None => true,
        };
        if !eligible {
            return None;
        }
        Some(granted.into_iter().collect())
    }

    /// Builds the configured extra claims for a token minted for this API.
    pub fn build_claims(
        &self,
        features: &[String],
        user_custom_fields: &BTreeMap<String, Value>,
        tenant_custom_fields: &BTreeMap<String, Value>,
    ) -> BTreeMap<String, Value> {
        let mut out = BTreeMap::new();
        for (name, source) in &self.claims {
            let value = if source == "features" {
                json!(features)
            } else if let Some(key) = source.strip_prefix("customUser:") {
                match user_custom_fields.get(key) {
                    Some(value) => value.clone(),
                    None => continue,
                }
            } else if let Some(key) = source.strip_prefix("customTenant:") {
                match tenant_custom_fields.get(key) {
                    Some(value) => value.clone(),
                    None => continue,
                }
            } else {
                json!(source)
            };
            let _ = out.insert(name.clone(), value);
        }
        out
    }
}

/// A role: a code, a display name, and the permission strings it grants.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RoleDef {
    /// Stable code referenced by `user.roles` (namespaced `role:*`).
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// DSL over the tenant's features (`feature:*`/`is:*`) — the role is assignable to a user in a
    /// tenant only when this holds. `None` = always assignable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignable_if: Option<String>,
}

/// A scope: the M2M analogue of a role, assigned to an API service key (namespaced `scope:*`).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ScopeDef {
    /// Stable code referenced by `apiKey.scopes` (namespaced `scope:*`).
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// DSL over the tenant's features (`feature:*`/`is:*`) gating assignability to a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignable_if: Option<String>,
}

/// A feature: granted to a tenant (namespaced `feature:*`), checked in the permission game.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FeatureDef {
    /// Stable code.
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// DSL over the tenant's **current** features — the feature is grantable only when this holds
    /// (encodes prerequisites). `None` = always grantable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignable_if: Option<String>,
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
    /// Field type: `string`, `number`, `bool`/`boolean`, or `select` (constrained to [`options`]).
    #[serde(rename = "type")]
    pub field_type: String,
    /// Allowed values for a `select` field (ignored for other types).
    #[serde(default)]
    pub options: Vec<String>,
    /// Whether the field must be set (a non-null, non-empty value).
    #[serde(default)]
    pub required: bool,
    /// Whether admin list tables should surface this field as a column.
    #[serde(default)]
    pub show_in_table: bool,
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
    /// Role catalog (assigned to users).
    pub roles: Vec<RoleDef>,
    /// Scope catalog (assigned to M2M service keys).
    #[serde(default)]
    pub scopes: Vec<ScopeDef>,
    /// Feature catalog (granted to tenants).
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
    /// Target APIs (audiences) umami can mint tokens for — see [`ApiDef`] and `docs/AUDIENCES.md`.
    #[serde(default)]
    pub apis: Vec<ApiDef>,
}

impl Config {
    /// Finds a target API by code.
    pub fn find_api(&self, code: &str) -> Option<&ApiDef> {
        self.apis.iter().find(|api| api.code == code)
    }

    /// Rejects a password shorter than `security.min_password_length` (counted in characters) with
    /// a client error.
    pub fn validate_password(&self, password: &str) -> anyhow::Result<()> {
        let length = password.chars().count() as u32;
        if length < self.security.min_password_length {
            client_bail!(
                "Password must be at least {} characters",
                self.security.min_password_length
            );
        }
        Ok(())
    }

    /// Validates provided custom-field values against a schema: every key must be defined and, for
    /// the known types, the JSON value must match (a `select` value must be one of its `options`).
    /// A `null` value counts as "unset". Finally, every `required` field must be present with a
    /// non-null, non-empty value. `values` is treated as the complete set (callers replace, not
    /// merge). Returns a client error otherwise.
    pub fn validate_custom_fields(
        definitions: &[CustomFieldDef],
        values: &BTreeMap<String, Value>,
    ) -> anyhow::Result<()> {
        for (key, value) in values {
            let definition = match definitions.iter().find(|def| &def.key == key) {
                Some(definition) => definition,
                None => client_bail!("Unknown custom field '{key}'"),
            };

            // A null is an explicit "unset" — skip the type check (required is handled below).
            if value.is_null() {
                continue;
            }

            match definition.field_type.as_str() {
                "string" if !value.is_string() => {
                    client_bail!("Custom field '{key}' must be a string")
                }
                "number" if !value.is_number() => {
                    client_bail!("Custom field '{key}' must be a number")
                }
                "bool" | "boolean" if !value.is_boolean() => {
                    client_bail!("Custom field '{key}' must be a boolean")
                }
                "select" => {
                    let ok = value
                        .as_str()
                        .is_some_and(|v| definition.options.iter().any(|opt| opt == v));
                    if !ok {
                        client_bail!(
                            "Custom field '{key}' must be one of: {}",
                            definition.options.join(", ")
                        );
                    }
                }
                // Known types matched above; anything else is accepted as-is.
                _ => {}
            }
        }

        // Enforce required fields against the (complete) provided value set.
        for definition in definitions {
            if !definition.required {
                continue;
            }
            let present = values
                .get(&definition.key)
                .is_some_and(|value| match value {
                    Value::Null => false,
                    Value::String(text) => !text.trim().is_empty(),
                    _ => true,
                });
            if !present {
                client_bail!("Custom field '{}' is required", definition.key);
            }
        }
        Ok(())
    }

    /// The role codes assignable to a user in a tenant with the given (namespaced) feature set —
    /// i.e. those whose `assignableIf` holds against `feature:*`/`is:*`.
    pub fn assignable_roles(&self, tenant_features: &[String]) -> Vec<String> {
        let set: BTreeSet<&str> = tenant_features.iter().map(String::as_str).collect();
        self.roles
            .iter()
            .filter(|role| assignable(&role.assignable_if, &set))
            .map(|role| role.code.clone())
            .collect()
    }

    /// Whether a specific role is assignable in a tenant with the given feature set (and is defined).
    pub fn can_assign_role(&self, code: &str, tenant_features: &[String]) -> bool {
        let set: BTreeSet<&str> = tenant_features.iter().map(String::as_str).collect();
        self.roles
            .iter()
            .find(|role| role.code == code)
            .is_some_and(|role| assignable(&role.assignable_if, &set))
    }

    /// The scope codes assignable to a key in a tenant with the given feature set.
    pub fn assignable_scopes(&self, tenant_features: &[String]) -> Vec<String> {
        let set: BTreeSet<&str> = tenant_features.iter().map(String::as_str).collect();
        self.scopes
            .iter()
            .filter(|scope| assignable(&scope.assignable_if, &set))
            .map(|scope| scope.code.clone())
            .collect()
    }

    /// Whether a specific scope is assignable in a tenant with the given feature set (and is defined).
    pub fn can_assign_scope(&self, code: &str, tenant_features: &[String]) -> bool {
        let set: BTreeSet<&str> = tenant_features.iter().map(String::as_str).collect();
        self.scopes
            .iter()
            .find(|scope| scope.code == code)
            .is_some_and(|scope| assignable(&scope.assignable_if, &set))
    }

    /// Whether a feature is grantable given the tenant's **current** features (its `assignableIf`
    /// holds and it is defined and not synthetic).
    pub fn can_grant_feature(&self, code: &str, current_features: &[String]) -> bool {
        if is_synthetic(code) {
            return false;
        }
        let set: BTreeSet<&str> = current_features.iter().map(String::as_str).collect();
        self.features
            .iter()
            .find(|feature| feature.code == code)
            .is_some_and(|feature| assignable(&feature.assignable_if, &set))
    }

    /// Feature codes grantable to a tenant right now: defined, non-synthetic, not already granted,
    /// and whose `assignableIf` holds against the current feature set.
    pub fn assignable_features(&self, current_features: &[String]) -> Vec<String> {
        let set: BTreeSet<&str> = current_features.iter().map(String::as_str).collect();
        self.features
            .iter()
            .filter(|feature| !is_synthetic(&feature.code))
            .filter(|feature| !current_features.iter().any(|f| f == &feature.code))
            .filter(|feature| assignable(&feature.assignable_if, &set))
            .map(|feature| feature.code.clone())
            .collect()
    }

    /// Looks up a feature's `assignableIf` (for the revoke dependency check). `None` if unknown.
    pub fn feature_assignable_if(&self, code: &str) -> Option<&str> {
        self.features
            .iter()
            .find(|feature| feature.code == code)
            .and_then(|feature| feature.assignable_if.as_deref())
    }
}

/// Whether a synthetic marker (`is:*`, computed and never stored, so never grantable/revocable).
pub fn is_synthetic(code: &str) -> bool {
    code.starts_with("is:")
}

/// Evaluates an optional `assignableIf` against a feature set — `None` means always assignable.
fn assignable(assignable_if: &Option<String>, set: &BTreeSet<&str>) -> bool {
    match assignable_if {
        Some(expr) => eval_expression(expr, set),
        None => true,
    }
}

impl Default for Config {
    fn default() -> Self {
        let role = |code: &str, name: &str| RoleDef {
            code: code.to_owned(),
            name: name.to_owned(),
            assignable_if: None,
        };
        let rule = |when: &str, grant: &[&str]| PermissionRule {
            when: when.to_owned(),
            grant: grant.iter().map(|p| (*p).to_owned()).collect(),
        };
        let scope = |code: &str, name: &str| ScopeDef {
            code: code.to_owned(),
            name: name.to_owned(),
            assignable_if: None,
        };
        Config {
            version: 1,
            roles: vec![
                role(ROLE_OWNER, "Owner"),
                role("role:admin", "Administrator"),
                role(ROLE_MEMBER, "Member"),
                role("role:viewer", "Viewer"),
            ],
            scopes: vec![
                scope("scope:messaging-linker", "Messaging linker (bot backend)"),
                scope("scope:messaging-resolver", "Messaging resolver"),
            ],
            features: Vec::new(),
            limits: Vec::new(),
            packages: Vec::new(),
            custom_tenant_fields: Vec::new(),
            custom_user_fields: Vec::new(),
            security: SecuritySettings {
                min_password_length: 8,
                access_ttl_secs: DEFAULT_ACCESS_TTL_SECS,
                refresh_ttl_secs: DEFAULT_REFRESH_TTL_SECS,
            },
            // The umami admin API: role → permission mapping lives here (not on the roles), plus the
            // synthetic is:system-tenant → cross-tenant admin permission.
            apis: vec![ApiDef {
                code: "umami".to_owned(),
                audience: "umami".to_owned(),
                eligibility: None,
                permissions: vec![
                    rule(
                        ROLE_OWNER,
                        &[
                            ADMIN_TENANT_PERMISSION,
                            WRITE_MEMBERS_PERMISSION,
                            MANAGE_CONFIG_PERMISSION,
                            WRITE_USAGE_PERMISSION,
                        ],
                    ),
                    rule(
                        "role:admin",
                        &[WRITE_MEMBERS_PERMISSION, WRITE_USAGE_PERMISSION],
                    ),
                    rule(ROLE_MEMBER, &[WRITE_USAGE_PERMISSION]),
                    rule(SYSTEM_TENANT_MARKER, &[ADMIN_SYSTEM_PERMISSION]),
                    // Messaging M2M: only system-tenant service keys carrying the scope get the
                    // cross-tenant link/resolve permissions.
                    rule(
                        &format!("scope:messaging-linker + {SYSTEM_TENANT_MARKER}"),
                        &[MESSAGING_LINK_PERMISSION],
                    ),
                    rule(
                        &format!("scope:messaging-resolver + {SYSTEM_TENANT_MARKER}"),
                        &[MESSAGING_RESOLVE_PERMISSION],
                    ),
                ],
                claims: BTreeMap::new(),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set<'a>(items: &'a [&'a str]) -> BTreeSet<&'a str> {
        items.iter().copied().collect()
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| (*i).to_owned()).collect()
    }

    fn field(key: &str, field_type: &str, required: bool, options: &[&str]) -> CustomFieldDef {
        CustomFieldDef {
            key: key.to_owned(),
            label: key.to_owned(),
            field_type: field_type.to_owned(),
            options: s(options),
            required,
            show_in_table: false,
        }
    }

    #[test]
    fn custom_fields_select_and_required() {
        let defs = vec![
            field("plan", "select", true, &["gold", "silver"]),
            field("seats", "number", false, &[]),
        ];

        // Happy path: valid select value + number.
        let ok = BTreeMap::from([
            ("plan".to_owned(), Value::from("gold")),
            ("seats".to_owned(), Value::from(5)),
        ]);
        assert!(Config::validate_custom_fields(&defs, &ok).is_ok());

        // Select value outside the option set is rejected.
        let bad_option = BTreeMap::from([("plan".to_owned(), Value::from("bronze"))]);
        assert!(Config::validate_custom_fields(&defs, &bad_option).is_err());

        // Wrong type for a number is rejected.
        let bad_type = BTreeMap::from([
            ("plan".to_owned(), Value::from("gold")),
            ("seats".to_owned(), Value::from("lots")),
        ]);
        assert!(Config::validate_custom_fields(&defs, &bad_type).is_err());

        // Missing required field is rejected...
        let missing = BTreeMap::from([("seats".to_owned(), Value::from(1))]);
        assert!(Config::validate_custom_fields(&defs, &missing).is_err());

        // ...and so is an empty-string / null required value.
        let empty = BTreeMap::from([("plan".to_owned(), Value::from(""))]);
        assert!(Config::validate_custom_fields(&defs, &empty).is_err());
        let null = BTreeMap::from([("plan".to_owned(), Value::Null)]);
        assert!(Config::validate_custom_fields(&defs, &null).is_err());

        // Unknown key is rejected.
        let unknown = BTreeMap::from([
            ("plan".to_owned(), Value::from("gold")),
            ("nope".to_owned(), Value::from("x")),
        ]);
        assert!(Config::validate_custom_fields(&defs, &unknown).is_err());
    }

    #[test]
    fn expression_or_and_not_precedence() {
        // a OR (b AND c)
        assert!(eval_expression("a,b+c", &set(&["a"])));
        assert!(eval_expression("a,b+c", &set(&["b", "c"])));
        assert!(!eval_expression("a,b+c", &set(&["b"])));
        assert!(!eval_expression("a,b+c", &set(&["x"])));
        // negation
        assert!(eval_expression("a+!b", &set(&["a"])));
        assert!(!eval_expression("a+!b", &set(&["a", "b"])));
        assert!(eval_expression("!b", &set(&["a"])));
        // empty expression = no restriction
        assert!(eval_expression("", &set(&["a"])));
    }

    fn dbx_api() -> ApiDef {
        ApiDef {
            code: "dbx-core".to_owned(),
            audience: "dbx-core".to_owned(),
            eligibility: Some("role:member,role:admin".to_owned()),
            permissions: vec![
                PermissionRule {
                    when: "role:admin".to_owned(),
                    grant: s(&["admin:blocks", "write:blocks"]),
                },
                PermissionRule {
                    when: "feature:ai + role:ai".to_owned(),
                    grant: s(&["use:ai"]),
                },
                // chains off an earlier grant
                PermissionRule {
                    when: "write:blocks".to_owned(),
                    grant: s(&["read:blocks"]),
                },
            ],
            claims: BTreeMap::from([("svc".to_owned(), "dbx-core".to_owned())]),
        }
    }

    #[test]
    fn resolve_ordered_accumulate_with_chaining() {
        let api = dbx_api();
        // role:admin → admin:blocks, write:blocks → (chained) read:blocks
        let perms = api.resolve(&s(&["role:admin"])).expect("eligible");
        assert_eq!(perms, s(&["admin:blocks", "read:blocks", "write:blocks"]));
    }

    #[test]
    fn resolve_respects_eligibility_and_features() {
        let api = dbx_api();
        // role:ai alone is eligible? eligibility is role:member,role:admin → no.
        assert!(api.resolve(&s(&["role:ai", "feature:ai"])).is_none());
        // role:member is eligible but grants nothing here.
        assert_eq!(api.resolve(&s(&["role:member"])), Some(Vec::new()));
        // admin + ai feature + ai role
        let perms = api
            .resolve(&s(&["role:admin", "role:ai", "feature:ai"]))
            .expect("eligible");
        assert!(perms.contains(&"use:ai".to_owned()));
        assert!(perms.contains(&"write:blocks".to_owned()));
    }

    #[test]
    fn default_umami_maps_roles_and_system_marker() {
        let umami = Config::default().find_api("umami").unwrap().clone();
        let owner = umami.resolve(&s(&["role:owner"])).unwrap();
        assert!(owner.contains(&"admin:tenant".to_owned()));
        assert!(owner.contains(&"manage:config".to_owned()));
        // no role maps to admin:system — only the synthetic marker does
        assert!(!owner.contains(&"admin:system".to_owned()));
        let sys = umami
            .resolve(&s(&["role:owner", "is:system-tenant"]))
            .unwrap();
        assert!(sys.contains(&"admin:system".to_owned()));
        // viewer maps to nothing
        assert_eq!(umami.resolve(&s(&["role:viewer"])), Some(Vec::new()));
    }

    #[test]
    fn assignability_gates_on_tenant_features() {
        let config = Config {
            roles: vec![RoleDef {
                code: "role:ai".to_owned(),
                name: "AI".to_owned(),
                assignable_if: Some("feature:ai".to_owned()),
            }],
            features: vec![
                FeatureDef {
                    code: "feature:base".to_owned(),
                    name: "Base".to_owned(),
                    assignable_if: None,
                },
                FeatureDef {
                    code: "feature:ai".to_owned(),
                    name: "AI".to_owned(),
                    assignable_if: Some("feature:base".to_owned()),
                },
            ],
            ..Config::default()
        };
        // role:ai only assignable when the tenant has feature:ai
        assert!(!config.can_assign_role("role:ai", &[]));
        assert!(config.can_assign_role("role:ai", &s(&["feature:ai"])));
        // feature:ai grantable only once feature:base is present; and not if already granted
        assert!(!config.can_grant_feature("feature:ai", &[]));
        assert!(config.can_grant_feature("feature:ai", &s(&["feature:base"])));
        assert_eq!(
            config.assignable_features(&s(&["feature:base"])),
            s(&["feature:ai"])
        );
        // synthetic markers are never grantable
        assert!(!config.can_grant_feature("is:system-tenant", &s(&["feature:base"])));
    }

    #[test]
    fn claim_mapping_resolves_sources() {
        let api = dbx_api();
        let user_cf = BTreeMap::from([("department".to_owned(), json!("engineering"))]);
        let claims = api.build_claims(&["feature:ai".to_owned()], &user_cf, &BTreeMap::new());
        assert_eq!(claims.get("svc"), Some(&json!("dbx-core")));
    }
}
