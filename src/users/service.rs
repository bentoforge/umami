//! User administration routes (within the caller's tenant).
//!
//! All routes require `manage:users` and operate strictly on the caller's own tenant (resolved
//! from the caller's token), so an admin can never see or touch another tenant's users. The first
//! user of a tenant is created by `POST /tenants` (see `tenants::service`), not here.

use crate::audit::AuditEntry;
use crate::audit::repository::{AuditRepository, record_best_effort};
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::apikeys::repository::ApiKeyRepository;
use crate::auth::session::repository::SessionRepository;
use crate::auth::webauthn::repository::WebauthnRepository;
use crate::bail_i18n;
use crate::config::Config;
use crate::config::repository::ConfigRepository;
use crate::constants::{
    MANAGE_USERS_PERMISSION, MAX_LIST_RESULTS, MAX_TEXT_BODY_SIZE, ROLE_MEMBER,
};
use crate::contacts::repository::ContactRepository;
use crate::messaging::repository::MessagingRepository;
use crate::tenants::repository::TenantRepository;
use crate::users::repository::{NewUser, UserRepository};
use crate::users::{DisplayNames, Salutation, User, normalize_name};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::aws::dynamodb::generate_id;
use wasabi::client_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{client_ip, into_response, with_body_as_json, with_cloneable};

/// Permission required to administer a tenant's users.
const REQUIRE_MANAGE_USERS: &[&str] = &[MANAGE_USERS_PERMISSION];

/// Request body for creating a user.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateUserRequest {
    /// Login username — required and globally unique.
    username: Option<String>,
    /// Optional initial password. Omitted (the normal case) → a temporary one is generated and
    /// returned once, flagged as a still-unchanged reset password.
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    salutation: Option<Salutation>,
    #[serde(default)]
    firstname: Option<String>,
    #[serde(default)]
    lastname: Option<String>,
    roles: Option<Vec<String>>,
    custom_fields: Option<BTreeMap<String, Value>>,
}

/// Request body for patching a user. Absent fields are left unchanged; an empty string clears a
/// name part.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PatchUserRequest {
    /// New login username (globally unique). Absent = unchanged; must not be empty.
    username: Option<String>,
    roles: Option<Vec<String>>,
    locked: Option<bool>,
    /// BCP-47 language tag; empty string clears it back to the deployment default.
    locale: Option<String>,
    title: Option<String>,
    salutation: Option<Salutation>,
    firstname: Option<String>,
    lastname: Option<String>,
    custom_fields: Option<BTreeMap<String, Value>>,
}

/// Request body for an admin password reset. Omit `newPassword` to have one generated.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ResetPasswordRequest {
    new_password: Option<String>,
}

/// Response for an admin password reset. `temporaryPassword` is set (once) only when generated.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ResetPasswordResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    temporary_password: Option<String>,
}

/// Public view of a user — **never** includes the password hash.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct UserView {
    user_id: String,
    tenant_id: String,
    roles: Vec<String>,
    username: String,
    /// Structured name parts (the editable source of truth).
    title: Option<String>,
    salutation: Salutation,
    firstname: Option<String>,
    lastname: Option<String>,
    /// Server-composed display names (`name` / `fullName` / `addressableName`), flattened in.
    #[serde(flatten)]
    names: DisplayNames,
    locked: bool,
    custom_fields: BTreeMap<String, Value>,
    created: DateTime<Utc>,
    last_updated: DateTime<Utc>,
    last_seen: Option<DateTime<Utc>>,
    /// User id that created / last changed this user (audit; not surfaced in the UI yet).
    created_by: Option<String>,
    last_changed_by: Option<String>,
    /// Whether TOTP MFA is configured (secret confirmed) — never exposes the secret.
    mfa_enabled: bool,
    /// Whether the current password came from an admin reset and the user has not changed it since.
    password_generated: bool,
    /// Whether the user has at least one registered passkey.
    has_passkey: bool,
}

impl UserView {
    /// Builds a view, composing the derived display names with the config salutation labels.
    fn build(user: User, default_locale: &str) -> Self {
        let names = user.display_names(default_locale);
        let password_generated = user.password_generated();
        UserView {
            mfa_enabled: user.totp_secret.is_some(),
            password_generated,
            has_passkey: user.has_passkey,
            user_id: user.user_id,
            tenant_id: user.tenant_id,
            roles: user.roles,
            username: user.username,
            title: user.title,
            salutation: user.salutation,
            firstname: user.firstname,
            lastname: user.lastname,
            names,
            locked: user.locked,
            custom_fields: user.custom_fields,
            created: user.created,
            last_updated: user.last_updated,
            last_seen: user.last_seen,
            created_by: user.created_by,
            last_changed_by: user.last_changed_by,
        }
    }
}

/// Create response: the new user plus, when generated, the one-time temporary password.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CreateUserResponse {
    #[serde(flatten)]
    user: UserView,
    #[serde(skip_serializing_if = "Option::is_none")]
    temporary_password: Option<String>,
}

/// Optional search + page cap for the list endpoint (`?q=&limit=`).
#[derive(Deserialize, Debug)]
struct ListQuery {
    q: Option<String>,
    limit: Option<usize>,
}

/// List response. `truncated` is true when more than [`MAX_LIST_RESULTS`] matched and the list was
/// capped (refine the search).
#[derive(Serialize, Debug)]
struct UserListResponse {
    users: Vec<UserView>,
    truncated: bool,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `POST /users` — create a user in the caller's tenant (requires `manage:users`).
pub fn create_user_route(
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users")
        .and(warp::post())
        .and(with_body_as_json::<CreateUserRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(users))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(system_tenant_id))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_create_user_route)
        .boxed()
}

/// `GET /users[?q=…]` — list the caller's tenant's users (requires `manage:users`). Sorted by
/// recent activity, capped, with optional case-insensitive multi-term search over
/// username/name/custom fields.
pub fn list_users_route(
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users")
        .and(warp::get())
        .and(warp::query::<ListQuery>())
        .and(with_cloneable(users))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_list_users_route)
        .boxed()
}

/// `GET /users/{id}` — read one user in the caller's tenant (requires `manage:users`).
pub fn get_user_route(
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String)
        .and(warp::get())
        .and(with_cloneable(users))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_get_user_route)
        .boxed()
}

/// `PATCH /users/{id}` — update a user's roles/lock/name/custom fields within the caller's tenant.
pub fn patch_user_route(
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    system_tenant_id: Option<String>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String)
        .and(warp::patch())
        .and(with_body_as_json::<PatchUserRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(users))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(system_tenant_id))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and(client_ip())
        .and_then(handle_patch_user_route)
        .boxed()
}

/// `DELETE /users/{id}` — hard-delete a user within the caller's tenant (requires `manage:users`).
pub fn delete_user_route(
    deps: DeleteUserDeps,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String)
        .and(warp::delete())
        .and(with_cloneable(deps))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_delete_user_route)
        .boxed()
}

/// Everything a user delete has to clear out.
///
/// A bundle rather than five parameters, because the list is the point: each entry is a table whose
/// rows nothing can reach once the user is gone, and adding one here is how a future table joins the
/// cascade instead of being forgotten.
#[derive(Clone)]
pub struct DeleteUserDeps {
    /// The user record and its username guard.
    pub users: Arc<dyn UserRepository>,
    /// Their email addresses.
    pub contacts: Arc<dyn ContactRepository>,
    /// Their chat identity links and pending link code.
    pub messaging: Arc<dyn MessagingRepository>,
    /// Their refresh sessions.
    pub sessions: Arc<dyn SessionRepository>,
    /// Their registered passkeys.
    pub webauthn: Arc<dyn WebauthnRepository>,
    /// Their personal access tokens — never the tenant's service keys.
    pub api_keys: Arc<dyn ApiKeyRepository>,
}

/// `POST /users/{id}/password` — admin password reset within the caller's tenant. Sets the given
/// `newPassword`, or generates a temporary one (returned once) when omitted. Bumps `tokenVersion`
/// so the target user's existing sessions/PATs stop working. Requires `manage:users`.
pub fn reset_password_route(
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String / "password")
        .and(warp::post())
        .and(with_body_as_json::<ResetPasswordRequest>(
            MAX_TEXT_BODY_SIZE,
        ))
        .and(with_cloneable(users))
        .and(with_cloneable(config))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and(client_ip())
        .and_then(handle_reset_password_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "POST /users", skip_all)]
async fn handle_create_user_route(
    request: CreateUserRequest,
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(create_user(request, users, tenants, config, system_tenant_id, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /users", skip_all)]
async fn handle_list_users_route(
    query: ListQuery,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_users(query, users, config, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /users/{id}", skip_all)]
async fn handle_get_user_route(
    user_id: String,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(get_user(user_id, users, config, caller).await)
}

async fn get_user(
    user_id: String,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<UserView> {
    let user = scoped_user(&users, &user_id, &caller).await?;
    let default_locale = config.current().await?.default_locale.clone();
    Ok(UserView::build(user, &default_locale))
}

#[tracing::instrument(level = "debug", name = "PATCH /users/{id}", skip_all)]
#[allow(clippy::too_many_arguments)]
async fn handle_patch_user_route(
    user_id: String,
    request: PatchUserRequest,
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
    ip: Option<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(
        patch_user(
            user_id,
            request,
            users,
            tenants,
            config,
            system_tenant_id,
            audit,
            caller,
            ip,
        )
        .await,
    )
}

#[tracing::instrument(level = "debug", name = "DELETE /users/{id}", skip_all)]
async fn handle_delete_user_route(
    user_id: String,
    deps: DeleteUserDeps,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(delete_user(user_id, deps, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /users/{id}/password", skip_all)]
async fn handle_reset_password_route(
    user_id: String,
    request: ResetPasswordRequest,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
    ip: Option<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(reset_password(user_id, request, users, config, audit, caller, ip).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

async fn create_user(
    request: CreateUserRequest,
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    caller: AuthUser,
) -> anyhow::Result<CreateUserResponse> {
    let tenant_id = caller.tenant_id()?.to_owned();

    // The username is the login identifier and the only thing that can serve as one, so it is
    // required outright. It used to fall back to the email; an address is now a contact, and a
    // contact is not an identity.
    let username = request
        .username
        .map(|username| username.trim().to_owned())
        .filter(|username| !username.is_empty());
    let username = match username {
        Some(username) => username,
        None => client_bail!("A 'username' is required"),
    };

    let config = config.current().await?;
    // Normal case: no password supplied → generate a temporary one, returned once and flagged as a
    // still-unchanged reset password (so the user must change it and the admin sees the tag).
    let (password, generated) = match request.password {
        Some(pw) if !pw.trim().is_empty() => (pw, false),
        _ => (generate_id(), true),
    };
    config.validate_password(&password)?;
    let custom_fields = request.custom_fields.unwrap_or_default();
    Config::validate_custom_fields(&config.custom_user_fields, &custom_fields)?;

    let password_hash = crate::auth::password::hash(&password)?;
    let roles = request
        .roles
        .filter(|roles| !roles.is_empty())
        .unwrap_or_else(|| vec![ROLE_MEMBER.to_owned()]);
    // A new user holds nothing yet, so every requested role is an addition.
    validate_roles(
        &config,
        &tenants,
        &tenant_id,
        system_tenant_id.as_deref(),
        &[],
        &roles,
    )
    .await?;
    let user = users
        .create_user(NewUser {
            tenant_id,
            roles,
            username,
            title: request.title,
            salutation: request.salutation.unwrap_or_default(),
            firstname: request.firstname,
            lastname: request.lastname,
            password_hash: Some(password_hash),
            custom_fields,
            created_by: Some(caller.user_id()?.to_owned()),
            password_generated: generated,
        })
        .await?;

    Ok(CreateUserResponse {
        user: UserView::build(user, &config.default_locale),
        temporary_password: generated.then_some(password),
    })
}

/// Rejects any requested role that isn't assignable given the tenant's authorization features (or
/// isn't a defined `role:*`). Keeps admins from granting roles the tenant's features don't allow.
async fn validate_roles(
    config: &Config,
    tenants: &Arc<dyn TenantRepository>,
    tenant_id: &str,
    system_tenant_id: Option<&str>,
    current: &[String],
    roles: &[String],
) -> anyhow::Result<()> {
    // Only newly added roles are checked: granting one is an escalation, keeping or dropping one
    // is not.
    //
    // Checking the whole list would strand roles the catalogue no longer defines. Callers send the
    // complete set on every change — the admin UI does — so a stale code rides along in each
    // request and would make every one of them fail, including the request that removes it.
    let added: Vec<&String> = roles
        .iter()
        .filter(|role| !current.contains(role))
        .collect();
    if added.is_empty() {
        return Ok(());
    }
    let features = tenants
        .get_tenant(tenant_id)
        .await?
        .map(|tenant| tenant.features)
        .unwrap_or_default();
    // Synthetic markers included, or every `is:system-tenant`-gated role would read as
    // unassignable — even inside the system tenant.
    let features = config.eval_feature_set(&features, system_tenant_id == Some(tenant_id));
    for role in added {
        if !config.can_assign_role(role, &features) {
            client_bail!("Role '{role}' is not assignable in this tenant");
        }
    }
    Ok(())
}

async fn list_users(
    query: ListQuery,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<UserListResponse> {
    let tenant_id = caller.tenant_id()?;
    let search = query.q.unwrap_or_default();
    let limit = query
        .limit
        .unwrap_or(MAX_LIST_RESULTS)
        .clamp(1, MAX_LIST_RESULTS);
    let default_locale = config.current().await?.default_locale.clone();

    let (users, truncated) = users.find_users(tenant_id, &search, limit).await?;
    let users = users
        .into_iter()
        .map(|user| UserView::build(user, &default_locale))
        .collect();
    Ok(UserListResponse { users, truncated })
}

#[allow(clippy::too_many_arguments)]
async fn patch_user(
    user_id: String,
    request: PatchUserRequest,
    users: Arc<dyn UserRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
    ip: Option<String>,
) -> anyhow::Result<UserView> {
    let tenant_id = caller.tenant_id()?;

    let mut user = match users.get_user(&user_id).await? {
        // Scope strictly to the caller's tenant — a foreign user reads as "not found".
        Some(user) if user.tenant_id == tenant_id => user,
        _ => client_bail!("No such user in this tenant"),
    };
    // Remember whether this request flips the lock state — a security event worth auditing.
    let lock_event = request.locked.filter(|&locked| locked != user.locked);

    let config = config.current().await?;
    if let Some(username) = request.username {
        let username = username.trim().to_owned();
        if username.is_empty() {
            client_bail!("Username must not be empty");
        }
        // Move the uniqueness guard (fails if taken), then record the new login name.
        users
            .rename_username(&user.user_id, &user.username, &username)
            .await?;
        user.username = username;
    }
    if let Some(roles) = request.roles {
        validate_roles(
            &config,
            &tenants,
            tenant_id,
            system_tenant_id.as_deref(),
            &user.roles,
            &roles,
        )
        .await?;
        user.roles = roles;
    }
    if let Some(locked) = request.locked {
        user.locked = locked;
    }
    if let Some(locale) = request.locale {
        // Empty string clears it, so a user can go back to the deployment default without an
        // extra endpoint — same shape as `email` on the admin patch.
        let locale = locale.trim();
        user.locale = if locale.is_empty() {
            None
        } else {
            Some(locale.to_owned())
        };
    }
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
    if let Some(custom_fields) = request.custom_fields {
        Config::validate_custom_fields(&config.custom_user_fields, &custom_fields)?;
        user.custom_fields = custom_fields;
    }
    user.last_changed_by = Some(caller.user_id()?.to_owned());

    let updated = users.put_user(user).await?;

    // Audit a lock/unlock (best-effort). Locking reads as "bad" (access removed), unlocking "good".
    if let Some(locked) = lock_event {
        let action = if locked { "locked" } else { "unlocked" };
        record_best_effort(
            &audit,
            NewAuditEntry::new(
                if locked {
                    AuditSeverity::Bad
                } else {
                    AuditSeverity::Good
                },
                Some(updated.tenant_id.clone()),
                Some(updated.user_id.clone()),
                format!(
                    "User '{}' {action} by admin {}",
                    updated.username,
                    caller.user_id()?,
                ),
            )
            .with_ip(ip),
        )
        .await;
    }

    Ok(UserView::build(updated, &config.default_locale))
}

async fn delete_user(
    user_id: String,
    deps: DeleteUserDeps,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    let tenant_id = caller.tenant_id()?;

    let user = match deps.users.get_user(&user_id).await? {
        // Scope strictly to the caller's tenant — a foreign user reads as "not found".
        Some(user) if user.tenant_id == tenant_id => user,
        _ => client_bail!("No such user in this tenant"),
    };

    // An admin must not delete their own account (would strand their session and risk locking the
    // tenant out of member administration).
    if user.user_id == caller.user_id()? {
        bail_i18n!(
            StatusCode::FORBIDDEN,
            caller.locale(),
            "user.self_undeletable"
        );
    }

    // Everything reachable only through this user goes first, and a failure here stops the whole
    // delete. The two orders fail differently: rows left behind a *live* user are visible and the
    // retry converges, while a deleted user leaves rows nothing can ever reach again — every read
    // on them is keyed on a `userId` that no longer resolves. Addresses of somebody who asked to be
    // removed, and credentials that outlive the account they authenticated, are the wrong things to
    // strand.
    //
    // Not here: in-flight WebAuthn ceremonies and pending challenges. Both are keyed on their own id
    // with a TTL of minutes, neither can be found by user without an index nothing else reads, and
    // one that outlives its user resolves into a `get_user` that returns nothing.
    let contacts = deps.contacts.delete_all_for_user(&user.user_id).await?;
    let links = deps.messaging.delete_all_for_user(&user.user_id).await?;
    let sessions = deps.sessions.delete_all_for_user(&user.user_id).await?;
    let passkeys = deps.webauthn.delete_all_for_user(&user.user_id).await?;
    let tokens = deps
        .api_keys
        .delete_all_for_user(&user.tenant_id, &user.user_id)
        .await?;

    deps.users
        .delete_user(&user.user_id, &user.username)
        .await?;
    Ok(json!({
        "status": "deleted",
        "deleted": {
            "contacts": contacts,
            "messagingLinks": links,
            "sessions": sessions,
            "passkeys": passkeys,
            "personalAccessTokens": tokens
        }
    }))
}

async fn reset_password(
    user_id: String,
    request: ResetPasswordRequest,
    users: Arc<dyn UserRepository>,
    config: Arc<dyn ConfigRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
    ip: Option<String>,
) -> anyhow::Result<ResetPasswordResponse> {
    let tenant_id = caller.tenant_id()?;

    let mut user = match users.get_user(&user_id).await? {
        // Scope strictly to the caller's tenant — a foreign user reads as "not found".
        Some(user) if user.tenant_id == tenant_id => user,
        _ => client_bail!("No such user in this tenant"),
    };

    // Use the supplied password, or generate a temporary one to hand back once.
    let (password, generated) = match request.new_password {
        Some(pw) if !pw.trim().is_empty() => (pw, false),
        _ => (generate_id(), true),
    };
    config.current().await?.validate_password(&password)?;

    user.password_hash = Some(crate::auth::password::hash(&password)?);
    user.token_version = user.token_version.saturating_add(1);
    // Mark this as an admin-set password the user has not changed yet (drives the "generated
    // password" flag in the admin list until the user changes it themselves).
    user.last_password_reset = Some(Utc::now());
    let _ = users.put_user(user.clone()).await?;

    record_best_effort(
        &audit,
        NewAuditEntry::new(
            AuditSeverity::Good,
            Some(user.tenant_id.clone()),
            Some(user.user_id.clone()),
            format!("Password reset by admin {}", caller.user_id()?),
        )
        .with_ip(ip),
    )
    .await;

    Ok(ResetPasswordResponse {
        status: "ok".to_owned(),
        temporary_password: generated.then_some(password),
    })
}

// ── Admin views of a user's activity (audit / sessions / logout) ────────────────────

/// Optional `?limit=` (clamped to `1..=MAX_LIST_RESULTS`) + `?cursor=` for the per-user audit list.
#[derive(Deserialize, Debug)]
struct LimitQuery {
    limit: Option<i32>,
    cursor: Option<String>,
}

/// One page of a user's audit trail + the cursor for the next (absent when exhausted).
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AuditListResponse {
    entries: Vec<AuditEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

/// A user's login session as seen by an admin — never exposes the refresh secret/hash. `current`
/// is always `false` (an admin views someone else's sessions).
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AdminSessionView {
    session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    created: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    current: bool,
}

/// Loads a user, scoping strictly to the caller's tenant — a foreign user reads as "not found".
async fn scoped_user(
    users: &Arc<dyn UserRepository>,
    user_id: &str,
    caller: &AuthUser,
) -> anyhow::Result<User> {
    let tenant_id = caller.tenant_id()?;
    match users.get_user(user_id).await? {
        Some(user) if user.tenant_id == tenant_id => Ok(user),
        _ => client_bail!("No such user in this tenant"),
    }
}

/// `GET /users/{id}/audit[?limit=]` — a tenant user's audit trail (requires `manage:users`).
pub fn user_audit_route(
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String / "audit")
        .and(warp::get())
        .and(warp::query::<LimitQuery>())
        .and(with_cloneable(users))
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_user_audit_route)
        .boxed()
}

/// `GET /users/{id}/sessions` — a tenant user's active login sessions (requires `manage:users`).
pub fn user_sessions_route(
    users: Arc<dyn UserRepository>,
    sessions: Arc<dyn SessionRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String / "sessions")
        .and(warp::get())
        .and(with_cloneable(users))
        .and(with_cloneable(sessions))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_user_sessions_route)
        .boxed()
}

/// `POST /users/{id}/logout-all` — revoke all of a tenant user's sessions by bumping their
/// `tokenVersion` (requires `manage:users`).
pub fn logout_user_route(
    users: Arc<dyn UserRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("users" / String / "logout-all")
        .and(warp::post())
        .and(with_cloneable(users))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_USERS,
        ))
        .and_then(handle_logout_user_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /users/{id}/audit", skip_all)]
async fn handle_user_audit_route(
    user_id: String,
    query: LimitQuery,
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(user_audit(user_id, query, users, audit, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /users/{id}/sessions", skip_all)]
async fn handle_user_sessions_route(
    user_id: String,
    users: Arc<dyn UserRepository>,
    sessions: Arc<dyn SessionRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(user_sessions(user_id, users, sessions, caller).await)
}

#[tracing::instrument(level = "debug", name = "POST /users/{id}/logout-all", skip_all)]
async fn handle_logout_user_route(
    user_id: String,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(logout_user(user_id, users, caller).await)
}

async fn user_audit(
    user_id: String,
    query: LimitQuery,
    users: Arc<dyn UserRepository>,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<AuditListResponse> {
    let user = scoped_user(&users, &user_id, &caller).await?;
    let limit = query.limit.unwrap_or(100).clamp(1, MAX_LIST_RESULTS as i32);
    let (entries, next_cursor) = audit
        .list_by_user(&user.user_id, limit, query.cursor.as_deref())
        .await?;
    Ok(AuditListResponse {
        entries,
        next_cursor,
    })
}

async fn user_sessions(
    user_id: String,
    users: Arc<dyn UserRepository>,
    sessions: Arc<dyn SessionRepository>,
    caller: AuthUser,
) -> anyhow::Result<Vec<AdminSessionView>> {
    let user = scoped_user(&users, &user_id, &caller).await?;
    let views = sessions
        .list_by_user(&user.user_id)
        .await?
        .into_iter()
        .map(|session| AdminSessionView {
            session_id: session.session_id,
            user_agent: session.user_agent,
            ip: session.ip,
            created: session.created,
            last_seen: session.last_seen,
            expires_at: session.expires_at,
            current: false,
        })
        .collect();
    Ok(views)
}

async fn logout_user(
    user_id: String,
    users: Arc<dyn UserRepository>,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    let user = scoped_user(&users, &user_id, &caller).await?;
    users.bump_token_version(&user.user_id).await?;
    Ok(json!({ "status": "ok" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::apikeys::repository::MockApiKeyRepository;
    use crate::auth::session::repository::MockSessionRepository;
    use crate::auth::webauthn::repository::MockWebauthnRepository;
    use crate::contacts::repository::MockContactRepository;
    use crate::messaging::repository::MockMessagingRepository;
    use crate::users::repository::MockUserRepository;
    use chrono::Utc;
    use wasabi::web::auth::user::User as WasabiUser;
    use wasabi::web::auth::{CLAIM_SUB, CLAIM_TENANT};

    /// An admin acting in `tenant-1`.
    fn an_admin() -> AuthUser {
        WasabiUser::builder()
            .with_string(CLAIM_SUB, "admin-1")
            .with_string(CLAIM_TENANT, "tenant-1")
            .build()
    }

    /// The user being deleted, in the admin's own tenant.
    fn a_user() -> User {
        let now = Utc::now();
        User {
            user_id: "user-1".to_owned(),
            tenant_id: "tenant-1".to_owned(),
            roles: Vec::new(),
            username: "jane".to_owned(),
            title: None,
            locale: None,
            salutation: crate::users::Salutation::Unspecified,
            firstname: None,
            lastname: None,
            password_hash: None,
            locked: false,
            token_version: 1,
            totp_secret: None,
            totp_pending: None,
            custom_fields: Default::default(),
            created: now,
            last_updated: now,
            last_seen: None,
            last_active_or_created: now,
            last_password_reset: None,
            last_password_change: None,
            has_passkey: false,
            created_by: None,
            last_changed_by: None,
            preferred_contact: None,
            notification_choices: Default::default(),
        }
    }

    /// The three repositories a test does not vary: they always report a fixed count, so an
    /// assertion on the response proves the cascade reached them.
    fn deps(
        users: MockUserRepository,
        contacts: MockContactRepository,
        messaging: MockMessagingRepository,
    ) -> DeleteUserDeps {
        let mut sessions = MockSessionRepository::new();
        let _ = sessions
            .expect_delete_all_for_user()
            .returning(|_| Box::pin(async { Ok(3) }));
        let mut webauthn = MockWebauthnRepository::new();
        let _ = webauthn
            .expect_delete_all_for_user()
            .returning(|_| Box::pin(async { Ok(1) }));
        let mut api_keys = MockApiKeyRepository::new();
        let _ = api_keys
            .expect_delete_all_for_user()
            .returning(|_, _| Box::pin(async { Ok(2) }));

        DeleteUserDeps {
            users: Arc::new(users),
            contacts: Arc::new(contacts),
            messaging: Arc::new(messaging),
            sessions: Arc::new(sessions),
            webauthn: Arc::new(webauthn),
            api_keys: Arc::new(api_keys),
        }
    }

    /// Everything reachable only through the user goes with them. Nothing else can reach these rows
    /// afterwards — every read on them is keyed on a `userId` that no longer resolves.
    #[tokio::test]
    async fn deleting_a_user_takes_their_contacts_and_messaging_links() {
        let mut users = MockUserRepository::new();
        let _ = users
            .expect_get_user()
            .returning(|_| Box::pin(async { Ok(Some(a_user())) }));
        let _ = users
            .expect_delete_user()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(()) }));

        let mut contacts = MockContactRepository::new();
        let _ = contacts
            .expect_delete_all_for_user()
            .times(1)
            .returning(|_| Box::pin(async { Ok(2) }));

        let mut messaging = MockMessagingRepository::new();
        let _ = messaging
            .expect_delete_all_for_user()
            .times(1)
            .returning(|_| Box::pin(async { Ok(1) }));

        let result = delete_user(
            "user-1".to_owned(),
            deps(users, contacts, messaging),
            an_admin(),
        )
        .await
        .unwrap();

        assert_eq!(result["deleted"]["contacts"], 2);
        assert_eq!(result["deleted"]["messagingLinks"], 1);
        assert_eq!(result["deleted"]["sessions"], 3);
        assert_eq!(result["deleted"]["passkeys"], 1);
        assert_eq!(result["deleted"]["personalAccessTokens"], 2);
    }

    /// The order is load-bearing. A failure while clearing the dependents must leave the user
    /// standing: rows behind a live user are visible and the retry converges, while a deleted user
    /// strands rows nothing can ever reach again.
    #[tokio::test]
    async fn a_failed_cascade_leaves_the_user_alone() {
        let mut users = MockUserRepository::new();
        let _ = users
            .expect_get_user()
            .returning(|_| Box::pin(async { Ok(Some(a_user())) }));
        let _ = users.expect_delete_user().never();

        let mut contacts = MockContactRepository::new();
        let _ = contacts
            .expect_delete_all_for_user()
            .returning(|_| Box::pin(async { Err(anyhow::anyhow!("DynamoDB is having a day")) }));

        let mut messaging = MockMessagingRepository::new();
        let _ = messaging.expect_delete_all_for_user().never();

        assert!(
            delete_user(
                "user-1".to_owned(),
                deps(users, contacts, messaging),
                an_admin()
            )
            .await
            .is_err()
        );
    }
}
