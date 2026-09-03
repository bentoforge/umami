//! Config read/write routes.
//!
//! `GET /config` returns the whole document; `PUT /config` overwrites it (client loads → edits →
//! writes back). Both require `manage:config`. `PUT` uses optimistic concurrency: the body's
//! `version` must match the current one, and the saved document's version is bumped.
//!
//! `GET /config/catalogue` and `GET /config/custom-fields` are the *reading* half, for any
//! authenticated caller: the labels a screen needs to name a role, a feature or a form field, with
//! nothing else from the document attached. They exist because rendering a form is not
//! administering the deployment — a member looking at their own roles must not need
//! `manage:config` — and because they are where a [`LocalizedText`] becomes one string, in the
//! language of the caller's `locale` claim. The whole document keeps its label maps intact, so the
//! editor above can load, edit and write it back without flattening the translations it never
//! showed.

use crate::config::repository::ConfigRepository;
use crate::config::text::LocalizedText;
use crate::config::{Config, CustomFieldDef};
use crate::constants::{MANAGE_CONFIG_PERMISSION, MAX_TEXT_BODY_SIZE};
use serde::Serialize;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::{with_user, with_user_with_any_permission};
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};

/// Permission required to read/write the global config.
const REQUIRE_MANAGE_CONFIG: &[&str] = &[MANAGE_CONFIG_PERMISSION];

/// One catalogue entry as a screen shows it: the code it sends back, and the words to show.
///
/// Roles, scopes and features are the same shape and are rendered by the same components, so they
/// arrive as the same type — the difference between them is which list they came in, not what a
/// picker does with them. `assignableIf` is deliberately absent: assignability is answered by
/// `/users/{id}/assignable-roles` and its siblings against a *specific* tenant, so shipping the
/// expression here would only invite a client to evaluate it against the wrong feature set.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CatalogueEntry {
    code: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl CatalogueEntry {
    /// Resolves one entry's labels into `locale`.
    fn new(
        code: &str,
        name: &LocalizedText,
        description: Option<&LocalizedText>,
        locale: &str,
        default_locale: &str,
    ) -> Self {
        CatalogueEntry {
            code: code.to_owned(),
            name: name.resolve(locale, default_locale).to_owned(),
            description: description.map(|text| text.resolve(locale, default_locale).to_owned()),
        }
    }
}

/// The label catalogues, in the caller's language.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CatalogueResponse {
    roles: Vec<CatalogueEntry>,
    scopes: Vec<CatalogueEntry>,
    features: Vec<CatalogueEntry>,
}

/// One custom-field schema with its label resolved — otherwise [`CustomFieldDef`] verbatim.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CustomFieldView {
    code: String,
    label: String,
    #[serde(rename = "type")]
    field_type: String,
    options: Vec<String>,
    required: bool,
    show_in_table: bool,
    self_editable: bool,
}

impl CustomFieldView {
    fn new(def: &CustomFieldDef, locale: &str, default_locale: &str) -> Self {
        CustomFieldView {
            code: def.code.clone(),
            label: def.label.resolve(locale, default_locale).to_owned(),
            field_type: def.field_type.clone(),
            options: def.options.clone(),
            required: def.required,
            show_in_table: def.show_in_table,
            self_editable: def.self_editable,
        }
    }
}

/// What any authenticated admin needs to render user/tenant forms + tables.
///
/// Deliberately not behind `manage:config`: rendering a form is not administering the deployment.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CustomFieldsResponse {
    user: Vec<CustomFieldView>,
    tenant: Vec<CustomFieldView>,
    /// Languages offered in the user editor's picker.
    ///
    /// Comes from here rather than from a list in the UI, because the truth is the message
    /// catalogue the server was built with. A UI-side list would offer languages the server
    /// cannot answer in — the user picks Bulgarian and is answered in English, with nothing
    /// anywhere saying why.
    locales: Vec<String>,
    /// The one used when a user expresses no preference.
    default_locale: String,
}

/// `GET /config` — return the whole config document (requires `manage:config`).
pub fn get_config_route(
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config")
        .and(warp::get())
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_CONFIG,
        ))
        .and_then(handle_get_config_route)
        .boxed()
}

/// `GET /config/custom-fields` — the user + tenant custom-field schemas. Authenticated only (not
/// `manage:config`): every admin who edits users/tenants needs these to render forms, and the
/// schema carries no secrets.
pub fn custom_fields_route(
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "custom-fields")
        .and(warp::get())
        .and(with_cloneable(config))
        .and(with_user(authenticator))
        .and_then(handle_custom_fields_route)
        .boxed()
}

/// `GET /config/catalogue` — role, scope and feature labels in the caller's language.
/// Authenticated only (not `manage:config`), for the same reason as `/config/custom-fields`.
pub fn catalogue_route(
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config" / "catalogue")
        .and(warp::get())
        .and(with_cloneable(config))
        .and(with_user(authenticator))
        .and_then(handle_catalogue_route)
        .boxed()
}

/// `PUT /config` — overwrite the whole config document (requires `manage:config`).
pub fn put_config_route(
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("config")
        .and(warp::put())
        .and(with_body_as_json::<Config>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_CONFIG,
        ))
        .and_then(handle_put_config_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /config", skip_all)]
async fn handle_get_config_route(
    config: Arc<dyn ConfigRepository>,
    _caller: wasabi::web::auth::user::User,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(get_config(config).await)
}

#[tracing::instrument(level = "debug", name = "PUT /config", skip_all)]
async fn handle_put_config_route(
    request: Config,
    config: Arc<dyn ConfigRepository>,
    _caller: wasabi::web::auth::user::User,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(put_config(request, config).await)
}

#[tracing::instrument(level = "debug", name = "GET /config/custom-fields", skip_all)]
async fn handle_custom_fields_route(
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(custom_fields(config, caller.locale()).await)
}

#[tracing::instrument(level = "debug", name = "GET /config/catalogue", skip_all)]
async fn handle_catalogue_route(
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(catalogue(config, caller.locale()).await)
}

async fn get_config(config: Arc<dyn ConfigRepository>) -> anyhow::Result<Config> {
    Ok((*config.current().await?).clone())
}

async fn catalogue(
    config: Arc<dyn ConfigRepository>,
    locale: &str,
) -> anyhow::Result<CatalogueResponse> {
    let config = config.current().await?;
    let default_locale = config.default_locale.as_str();
    let entries = |code: &str, name: &LocalizedText, description: Option<&LocalizedText>| {
        CatalogueEntry::new(code, name, description, locale, default_locale)
    };
    Ok(CatalogueResponse {
        roles: config
            .roles
            .iter()
            .map(|def| entries(&def.code, &def.name, def.description.as_ref()))
            .collect(),
        scopes: config
            .scopes
            .iter()
            .map(|def| entries(&def.code, &def.name, def.description.as_ref()))
            .collect(),
        features: config
            .features
            .iter()
            .map(|def| entries(&def.code, &def.name, def.description.as_ref()))
            .collect(),
    })
}

async fn custom_fields(
    config: Arc<dyn ConfigRepository>,
    locale: &str,
) -> anyhow::Result<CustomFieldsResponse> {
    let config = config.current().await?;
    let view = |def: &CustomFieldDef| CustomFieldView::new(def, locale, &config.default_locale);
    Ok(CustomFieldsResponse {
        user: config.custom_user_fields.iter().map(view).collect(),
        tenant: config.custom_tenant_fields.iter().map(view).collect(),
        locales: crate::i18n::supported(&config),
        default_locale: config.default_locale.clone(),
    })
}

async fn put_config(request: Config, config: Arc<dyn ConfigRepository>) -> anyhow::Result<Config> {
    // Validate before publishing. This is where the notification catalogue's typo protection lives
    // now that a cadence is a plain string: a duplicate code, a type nothing can fire, or a default
    // naming a cadence the type is never fired at would all otherwise fail invisibly, as an audience
    // that silently resolves to nobody.
    crate::notify::types::validate_catalogue(&request.notification_types)?;
    crate::config::validate_labels(&request)?;
    for api in &request.apis {
        crate::config::validate_claims(&api.code, &api.claims)?;
    }
    crate::config::validate_mail(&request.mail)?;

    // The version guard is the store's, because only the store can compare against what is
    // actually stored rather than against a cached read. A stale editor gets its `409` from there.
    let expected_version = request.version;
    config.save(request, expected_version).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::repository::StaticConfigRepository;
    use crate::config::{FeatureDef, RoleDef};

    /// A config whose catalogues are written in two languages plus a fallback.
    async fn multilingual() -> Arc<dyn ConfigRepository> {
        let repository = StaticConfigRepository::with_default();
        let stored = repository.current().await.expect("seeded");
        let config = Config {
            default_locale: "en".to_owned(),
            roles: vec![RoleDef {
                code: "role:owner".to_owned(),
                name: serde_json::from_str(r#"{"de":"Eigentümer","en":"Owner"}"#).expect("valid"),
                description: Some(
                    serde_json::from_str(r#"{"de":"Darf alles","*":"May do anything"}"#)
                        .expect("valid"),
                ),
                assignable_if: None,
            }],
            features: vec![FeatureDef {
                code: "feature:ai".to_owned(),
                name: "AI".into(),
                description: None,
                assignable_if: None,
            }],
            ..(*stored).clone()
        };
        repository
            .save(config, stored.version)
            .await
            .expect("saved");
        Arc::new(repository)
    }

    #[tokio::test]
    async fn the_catalogue_answers_in_the_callers_language() {
        let config = multilingual().await;

        let german = catalogue(config.clone(), "de-AT").await.expect("resolved");
        assert_eq!(german.roles[0].name, "Eigentümer");
        assert_eq!(german.roles[0].description.as_deref(), Some("Darf alles"));

        let english = catalogue(config.clone(), "en").await.expect("resolved");
        assert_eq!(english.roles[0].name, "Owner");

        // Nothing written in French: `*` answers for the description, the default locale for the
        // name — the two fallbacks a config can spell out, and neither renders as nothing.
        let french = catalogue(config, "fr").await.expect("resolved");
        assert_eq!(french.roles[0].name, "Owner");
        assert_eq!(
            french.roles[0].description.as_deref(),
            Some("May do anything")
        );
    }

    #[tokio::test]
    async fn a_single_language_catalogue_reads_the_same_in_every_language() {
        let config = multilingual().await;
        for locale in ["de", "en", "fr"] {
            let resolved = catalogue(config.clone(), locale).await.expect("resolved");
            assert_eq!(resolved.features[0].name, "AI", "in {locale}");
        }
    }

    /// The editor loads the whole document and writes it back — so a label that was authored as a
    /// map has to survive that trip as a map. Flattening it here would delete every language the
    /// editing admin does not read, and nothing on screen would say so.
    #[tokio::test]
    async fn the_whole_document_keeps_its_label_maps() {
        let config = multilingual().await;
        let loaded = get_config(config.clone()).await.expect("loaded");
        let saved = put_config(loaded, config).await.expect("saved");

        let json = serde_json::to_value(&saved).expect("serializable");
        assert_eq!(json["roles"][0]["name"]["de"], "Eigentümer");
        assert_eq!(json["roles"][0]["name"]["en"], "Owner");
        // The one written as a bare string stays a bare string rather than growing a `*` wrapper.
        assert_eq!(json["features"][0]["name"], "AI");
    }

    #[tokio::test]
    async fn a_label_with_no_words_is_refused() {
        let config = multilingual().await;
        let mut document = get_config(config.clone()).await.expect("loaded");
        document.roles[0].name = "   ".into();

        let err = put_config(document, config)
            .await
            .expect_err("a nameless role is not publishable");
        assert!(
            format!("{err:#}").contains("role:owner"),
            "the error names the offender: {err:#}"
        );
    }
}
