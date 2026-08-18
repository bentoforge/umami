//! `GET /auth/me` (current profile) and `POST /auth/logout-all` (global revocation).
//!
//! Both are authenticated by a valid access token; a user may always inspect themselves and revoke
//! all of their own sessions. `logout-all` bumps `tokenVersion`, invalidating every session at its
//! next refresh.

use crate::audit::repository::{AuditRepository, record_best_effort};
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::password;
use crate::config::Config;
use crate::config::repository::ConfigRepository;
use crate::constants::MAX_TEXT_BODY_SIZE;
use crate::tenants::Tenant;
use crate::tenants::repository::TenantRepository;
use crate::users::repository::UserRepository;
use crate::users::{DisplayNames, Salutation, User, normalize_name};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::{with_user, with_user_with};
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};
use wasabi::{client_bail, status_bail};

/// Current user, without the password hash.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MeUser {
    user_id: String,
    tenant_id: String,
    roles: Vec<String>,
    username: String,
    email: Option<String>,
    title: Option<String>,
    salutation: Salutation,
    firstname: Option<String>,
    lastname: Option<String>,
    /// Server-composed display names (`name` / `fullName` / `addressableName`), flattened in.
    #[serde(flatten)]
    names: DisplayNames,
    locked: bool,
    custom_fields: BTreeMap<String, Value>,
}

impl MeUser {
    fn build(user: User, salutations: &BTreeMap<String, String>) -> Self {
        let names = user.display_names(salutations);
        MeUser {
            user_id: user.user_id,
            tenant_id: user.tenant_id,
            roles: user.roles,
            username: user.username,
            email: user.email,
            title: user.title,
            salutation: user.salutation,
            firstname: user.firstname,
            lastname: user.lastname,
            names,
            locked: user.locked,
            custom_fields: user.custom_fields,
        }
    }
}

/// `GET /auth/me` response: the fresh user record plus their tenant.
#[derive(Serialize, Debug)]
struct MeResponse {
    user: MeUser,
    tenant: Option<Tenant>,
}

/// `GET /auth/me` — profile (user + tenant) resolved fresh from the store.
pub fn me_route(
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me")
        .and(warp::get())
        .and(with_cloneable(users))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user(authenticator))
        .and_then(handle_me_route)
        .boxed()
}

/// `POST /auth/logout-all` — bump `tokenVersion`, revoking all of the caller's sessions.
pub fn logout_all_route(
    users: Arc<dyn UserRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "logout-all")
        .and(warp::post())
        .and(with_cloneable(users))
        .and(with_user(authenticator))
        .and_then(handle_logout_all_route)
        .boxed()
}

/// Guard expression for self-service mutations: blocked when the caller has `self:readonly`.
const DENY_READONLY: &str = "!self:readonly";

/// Request body for a self-service password change.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

/// Request body for a self-service profile update. The structured name parts are always self-
/// editable; custom fields may be set only when the config marks them `selfEditable`. Absent fields
/// are left unchanged; an empty string clears a name part.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PatchMeRequest {
    title: Option<String>,
    salutation: Option<Salutation>,
    firstname: Option<String>,
    lastname: Option<String>,
    #[serde(default)]
    custom_fields: BTreeMap<String, Value>,
}

/// `POST /auth/me/password` — change the caller's own password (verifies the current one, then
/// bumps `tokenVersion` so other sessions are logged out).
pub fn change_password_route(
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "password")
        .and(warp::post())
        .and(with_body_as_json::<ChangePasswordRequest>(
            MAX_TEXT_BODY_SIZE,
        ))
        .and(with_cloneable(users))
        .and(with_cloneable(config))
        .and(with_cloneable(audit))
        .and(with_user_with(authenticator, DENY_READONLY))
        .and_then(handle_change_password_route)
        .boxed()
}

/// `PATCH /auth/me` — self-service profile edit: the caller's structured name parts (always) plus
/// any custom fields the config marks `selfEditable`. Blocked for `self:readonly`.
pub fn patch_me_route(
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me")
        .and(warp::patch())
        .and(with_body_as_json::<PatchMeRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(users))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with(authenticator, DENY_READONLY))
        .and_then(handle_patch_me_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /auth/me", skip_all)]
async fn handle_me_route(
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(me(users, tenants, config, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /auth/logout-all", skip_all)]
async fn handle_logout_all_route(
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(logout_all(users, caller).await)
}

async fn me(
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<MeResponse> {
    let user_id = caller.user_id()?;

    let user = match users.get_user(user_id).await? {
        Some(user) => user,
        None => status_bail!(StatusCode::UNAUTHORIZED, "User no longer exists"),
    };

    let salutations = config.current().await?.salutations.clone();
    let tenant = tenants.get_tenant(&user.tenant_id).await?;

    Ok(MeResponse {
        user: MeUser::build(user, &salutations),
        tenant,
    })
}

#[tracing::instrument(level = "debug", name = "PATCH /auth/me", skip_all)]
async fn handle_patch_me_route(
    request: PatchMeRequest,
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(patch_me(request, users, tenants, config, caller).await)
}

async fn patch_me(
    request: PatchMeRequest,
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<MeResponse> {
    let user_id = caller.user_id()?;
    let mut user = match users.get_user(user_id).await? {
        Some(user) => user,
        None => status_bail!(StatusCode::UNAUTHORIZED, "User no longer exists"),
    };

    let config = config.current().await?;
    // A user may only touch fields the config explicitly marks self-editable; everything else is
    // admin-managed and rejected outright.
    for key in request.custom_fields.keys() {
        match config.custom_user_fields.iter().find(|def| &def.key == key) {
            Some(def) if def.self_editable => {}
            Some(_) => client_bail!("Custom field '{key}' is not self-editable"),
            None => client_bail!("Unknown custom field '{key}'"),
        }
    }

    // Merge the allowed changes onto the existing set, then validate the whole set (types + the
    // required-field rule) so a self-edit can't leave the record invalid.
    user.custom_fields.extend(request.custom_fields);
    Config::validate_custom_fields(&config.custom_user_fields, &user.custom_fields)?;

    // Structured name parts are always the user's own to edit.
    if let Some(title) = request.title {
        user.title = normalize_name(Some(title));
    }
    if let Some(salutation) = request.salutation {
        user.salutation = salutation;
    }
    if let Some(firstname) = request.firstname {
        user.firstname = normalize_name(Some(firstname));
    }
    if let Some(lastname) = request.lastname {
        user.lastname = normalize_name(Some(lastname));
    }

    let updated = users.put_user(user).await?;
    let tenant = tenants.get_tenant(&updated.tenant_id).await?;
    Ok(MeResponse {
        user: MeUser::build(updated, &config.salutations),
        tenant,
    })
}

async fn logout_all(
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> anyhow::Result<serde_json::Value> {
    users.bump_token_version(caller.user_id()?).await?;
    Ok(json!({ "status": "ok" }))
}

#[tracing::instrument(level = "debug", name = "POST /auth/me/password", skip_all)]
async fn handle_change_password_route(
    request: ChangePasswordRequest,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(change_password(request, users, config, audit, caller).await)
}

async fn change_password(
    request: ChangePasswordRequest,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<serde_json::Value> {
    let mut user = match users.get_user(caller.user_id()?).await? {
        Some(user) => user,
        None => status_bail!(StatusCode::UNAUTHORIZED, "User no longer exists"),
    };

    let current_hash = match user.password_hash.as_deref() {
        Some(hash) => hash,
        None => status_bail!(
            StatusCode::BAD_REQUEST,
            "This account has no password set — ask an admin to set one"
        ),
    };

    if !password::verify(&request.current_password, current_hash)? {
        record_best_effort(
            &audit,
            NewAuditEntry::new(
                AuditSeverity::Bad,
                Some(user.tenant_id.clone()),
                Some(user.user_id.clone()),
                "Password change failed: wrong current password".to_owned(),
            ),
        )
        .await;
        status_bail!(StatusCode::UNAUTHORIZED, "Current password is incorrect");
    }

    config
        .current()
        .await?
        .validate_password(&request.new_password)?;

    // Set the new hash and bump the revocation counter so every other session is invalidated.
    user.password_hash = Some(password::hash(&request.new_password)?);
    user.token_version = user.token_version.saturating_add(1);
    let _ = users.put_user(user.clone()).await?;

    record_best_effort(
        &audit,
        NewAuditEntry::new(
            AuditSeverity::Good,
            Some(user.tenant_id.clone()),
            Some(user.user_id.clone()),
            "Password changed".to_owned(),
        ),
    )
    .await;

    Ok(json!({ "status": "ok" }))
}
