//! Config read/write routes.
//!
//! `GET /config` returns the whole document; `PUT /config` overwrites it (client loads → edits →
//! writes back). Both require `manage:config`. `PUT` uses optimistic concurrency: the body's
//! `version` must match the current one, and the saved document's version is bumped.

use crate::config::repository::ConfigRepository;
use crate::config::{Config, CustomFieldDef};
use crate::constants::{MANAGE_CONFIG_PERMISSION, MAX_TEXT_BODY_SIZE};
use serde::Serialize;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::status_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::{with_user, with_user_with_any_permission};
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};

/// Permission required to read/write the global config.
const REQUIRE_MANAGE_CONFIG: &[&str] = &[MANAGE_CONFIG_PERMISSION];

/// What any authenticated admin needs to render user/tenant forms + tables.
///
/// Deliberately not behind `manage:config`: rendering a form is not administering the deployment.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CustomFieldsResponse {
    user: Vec<CustomFieldDef>,
    tenant: Vec<CustomFieldDef>,
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
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(custom_fields(config).await)
}

async fn get_config(config: Arc<dyn ConfigRepository>) -> anyhow::Result<Config> {
    Ok((*config.current().await?).clone())
}

async fn custom_fields(config: Arc<dyn ConfigRepository>) -> anyhow::Result<CustomFieldsResponse> {
    let config = config.current().await?;
    Ok(CustomFieldsResponse {
        user: config.custom_user_fields.clone(),
        tenant: config.custom_tenant_fields.clone(),
        locales: crate::i18n::supported(&config),
        default_locale: config.default_locale.clone(),
    })
}

async fn put_config(request: Config, config: Arc<dyn ConfigRepository>) -> anyhow::Result<Config> {
    let current = config.current().await?;

    if request.version != current.version {
        status_bail!(
            StatusCode::CONFLICT,
            "Config version mismatch: expected {}, got {} — reload and re-apply",
            current.version,
            request.version
        );
    }

    // Validate before publishing. This is where the notification catalogue's typo protection lives
    // now that a cadence is a plain string: a duplicate code, a type nothing can fire, or a default
    // naming a cadence the type is never fired at would all otherwise fail invisibly, as an audience
    // that silently resolves to nobody.
    crate::notify::types::validate_catalogue(&request.notification_types)?;
    for api in &request.apis {
        crate::config::validate_claims(&api.code, &api.claims)?;
    }
    crate::config::validate_mail(&request.mail)?;

    let mut next = request;
    next.version = current.version + 1;
    config.save(next.clone()).await?;

    Ok(next)
}
