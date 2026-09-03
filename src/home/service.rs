//! `GET /auth/me/home` — the signed-in user's start page: the apps they may open and the tasks
//! umami suggests, both resolved into the caller's language.
//!
//! Authenticated only (no permission): it is the caller's own landing page. The apps are gated
//! per-caller by `enabledIf`, and the tasks are computed from the caller's own account state.

use crate::config::repository::ConfigRepository;
use crate::config::{Config, eval_expression};
use crate::contacts::repository::ContactRepository;
use crate::home::{HomeContext, evaluate};
use crate::tenants::repository::TenantRepository;
use crate::users::repository::UserRepository;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::status_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user;
use wasabi::web::warp::{into_response, with_cloneable};

/// Dependencies of the start-page route.
#[derive(Clone)]
pub struct HomeDeps {
    /// User store — the caller's fresh record (hygiene flags, name).
    pub users: Arc<dyn UserRepository>,
    /// Tenant store — the tenant's features, for the apps' `enabledIf`.
    pub tenants: Arc<dyn TenantRepository>,
    /// Contact store — the caller's addresses, for the confirm-email task.
    pub contacts: Arc<dyn ContactRepository>,
    /// Config — the app catalogue and the default locale.
    pub config: Arc<dyn ConfigRepository>,
    /// System tenant id, for the `is:system-tenant*` markers in `enabledIf`.
    pub system_tenant_id: Option<String>,
}

/// One launch card, labels resolved into the caller's language.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AppCard {
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    url: String,
}

/// One task card, text resolved from the catalogue into the caller's language.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TaskCard {
    label: String,
    description: String,
    /// In-app path the card links to.
    url: String,
    /// Whether the card is highlighted.
    important: bool,
}

/// The start page: what to launch, and what to fix.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct HomeResponse {
    apps: Vec<AppCard>,
    tasks: Vec<TaskCard>,
}

/// `GET /auth/me/home` — apps + tasks for the caller.
pub fn home_route(
    deps: HomeDeps,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "home")
        .and(warp::get())
        .and(with_cloneable(deps))
        .and(with_user(authenticator))
        .and_then(handle_home_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /auth/me/home", skip_all)]
async fn handle_home_route(
    deps: HomeDeps,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(home(deps, caller).await)
}

async fn home(deps: HomeDeps, caller: AuthUser) -> anyhow::Result<HomeResponse> {
    let user_id = caller.user_id()?;
    let config = deps.config.current().await?;
    let user = match deps.users.get_user(user_id).await? {
        Some(user) => user,
        None => status_bail!(StatusCode::NOT_FOUND, "No such user"),
    };
    // The caller's token already carries a resolved locale — profile preference first, else the
    // browser language it was minted with, else the default. Reading it (rather than re-resolving
    // from the profile field, which is often empty) keeps this page in the same language as every
    // other resolved endpoint, `/config/catalogue` included.
    let locale = caller.locale();

    let features = deps
        .tenants
        .get_tenant(&user.tenant_id)
        .await?
        .map(|tenant| tenant.features)
        .unwrap_or_default();
    let apps = resolve_apps(
        &config,
        &user,
        &features,
        deps.system_tenant_id.as_deref(),
        locale,
    );

    let contacts = deps.contacts.list_contacts(user_id).await?;
    let ctx = HomeContext::new(&user, &contacts);
    let tasks = evaluate(&ctx)
        .into_iter()
        .map(|task| TaskCard {
            label: crate::i18n::message(locale, &format!("home.task.{}.label", task.code)),
            description: crate::i18n::message(
                locale,
                &format!("home.task.{}.description", task.code),
            ),
            url: task.url.to_owned(),
            important: task.important,
        })
        .collect();

    Ok(HomeResponse { apps, tasks })
}

/// The apps this user may see, in config order, labels resolved.
fn resolve_apps(
    config: &Config,
    user: &crate::users::User,
    tenant_features: &[String],
    system_tenant_id: Option<&str>,
    locale: &str,
) -> Vec<AppCard> {
    let subjects = subjects(user, tenant_features, system_tenant_id);
    let view: BTreeSet<&str> = subjects.iter().map(String::as_str).collect();
    config
        .apps
        .iter()
        .filter(|app| match app.enabled_if.as_deref() {
            None => true,
            Some(expression) => eval_expression(expression, &view),
        })
        .map(|app| AppCard {
            label: app.label.resolve(locale, &config.default_locale).to_owned(),
            description: app
                .description
                .as_ref()
                .map(|text| text.resolve(locale, &config.default_locale).to_owned()),
            url: app.url.clone(),
        })
        .collect()
}

/// The subject set an app's `enabledIf` is checked against: the user's roles, their tenant's
/// features, and the `is:system-tenant*` markers when they belong to it.
///
/// The **offline** set — no session markers (`is:2fa`, `is:passkey`): an app card is a persistent
/// property of who the user is, not of how this one session authenticated. Same shape as the
/// notification eligibility set, for the same reason.
fn subjects(
    user: &crate::users::User,
    tenant_features: &[String],
    system_tenant_id: Option<&str>,
) -> BTreeSet<String> {
    let mut set: BTreeSet<String> = user.roles.iter().cloned().collect();
    set.extend(tenant_features.iter().cloned());
    if system_tenant_id.is_some_and(|id| id == user.tenant_id) {
        let _ = set.insert(crate::constants::SYSTEM_TENANT_MARKER.to_owned());
        let _ = set.insert(crate::constants::SYSTEM_TENANT_MEMBER_MARKER.to_owned());
    }
    set
}
