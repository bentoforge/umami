//! umami: micro-IAM — identity, tenant/membership authority, and JWT issuer for a fleet of
//! wasabi-based B2B services.
//!
//! This binary boots a warp web server (via wasabi's `run_webserver`) and wires the auth, tenant,
//! user, API-key, config, audit and messaging routes.

// The `routes![…]` macro builds one deeply-nested `Or<…>` filter type; warp 0.4's layout query
// needs more headroom than the default.
#![recursion_limit = "512"]
#![deny(
    // Code Quality
    warnings,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_results,
    // Safety
    unsafe_code,
    // Robustness
    rust_2018_idioms,
    nonstandard_style,
    future_incompatible,
    // Clippy - Panic Prevention
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
// Relax some lints for test code.
#![cfg_attr(
    test,
    allow(
        unused_results,
        missing_docs,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

mod audit;
mod auth;
mod authz;
mod config;
mod constants;
mod messaging;
mod search;
mod tenants;
mod users;
mod web_ui;

use crate::audit::repository::{AuditRepository, DynamoAuditRepository};
use crate::audit::service::{my_audit_route, tenant_audit_route};
use crate::auth::apikeys::repository::{ApiKeyRepository, DynamoApiKeyRepository};
use crate::auth::apikeys::{
    create_api_key_route, create_my_pat_route, delete_api_key_route, delete_my_pat_route,
    exchange_route, list_api_keys_route, list_my_pats_route, list_user_pats_route,
};
use crate::auth::login::{login_route, logout_route, refresh_route};
use crate::auth::me::{
    change_password_route, delete_session_route, logout_all_route, me_route, patch_me_route,
    sessions_route,
};
use crate::auth::secretbox::SecretBox;
use crate::auth::session::repository::DynamoSessionRepository;
use crate::auth::switch_tenant::switch_tenant_route;
use crate::auth::tokens::{EnvKeyRepository, KeyRepository, TokenIssuer, jwks_route};
use crate::auth::totp::{totp_disable_route, totp_setup_route, totp_verify_route};
use crate::auth::webauthn::WebauthnService;
use crate::auth::webauthn::repository::{DynamoWebauthnRepository, WebauthnRepository};
use crate::auth::webauthn::{
    webauthn_login_finish_route, webauthn_login_start_route, webauthn_register_finish_route,
    webauthn_register_start_route,
};
use crate::auth::{AuthContext, session::repository::SessionRepository};
use crate::authz::{
    assignable_features_route, assignable_roles_route, assignable_scopes_route,
    grant_feature_route, revoke_feature_route,
};
use crate::config::repository::{ConfigRepository, S3ConfigRepository, StaticConfigRepository};
use crate::config::service::{custom_fields_route, get_config_route, put_config_route};
use crate::constants::ROLE_OWNER;
use crate::messaging::repository::{DynamoMessagingRepository, MessagingRepository};
use crate::messaging::service::{
    ResolveDeps, create_link_route, delete_my_link_route, my_code_route, my_links_route,
    regenerate_code_route, resolve_route, user_links_route,
};
use crate::tenants::repository::{DynamoTenantRepository, TenantRepository};
use crate::tenants::service::{
    create_tenant_route, delete_tenant_route, get_tenant_route, list_tenants_route,
    patch_tenant_route,
};
use crate::users::repository::{DynamoUserRepository, NewUser, UserRepository};
use crate::users::service::{
    create_user_route, delete_user_route, get_user_route, list_users_route, logout_user_route,
    patch_user_route, reset_password_route, user_audit_route, user_sessions_route,
};
use crate::web_ui::ui_routes;
use std::env;
use std::sync::Arc;
use warp::Filter;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::generate_id;
use wasabi::aws::s3::S3Client;
use wasabi::tools::system::install_termination_listener;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::info_service::get_info_route;
use wasabi::web::user_info_service::get_user_info_route;
use wasabi::web::warp::run_webserver;
use wasabi::{APP_NAME, APP_VERSION, CLUSTER_ID, TASK_ID, routes};

#[tokio::main]
async fn main() {
    // Load .env before anything else so the logging/config readers see it.
    let dotenv_result = dotenvy::dotenv();

    // Initialize tracing (requires the Tokio runtime for OpenTelemetry gRPC).
    wasabi::logging::init_tracing().await;

    match dotenv_result {
        Ok(path) => tracing::info!(
            "Loaded environment variables from: {}",
            &path.as_path().display()
        ),
        Err(err) => tracing::info!("Skipped loading environment variables from .env: {}", err),
    }

    if let Err(err) = app().await {
        tracing::error!("Main app crashed: {:#}", err);
    }
}

/// Wires dependencies and routes, then runs the web server until shutdown.
async fn app() -> anyhow::Result<()> {
    install_termination_listener();

    tracing::info!(
        "Starting: {} ({}) for {} on {}",
        *APP_NAME,
        *APP_VERSION,
        *CLUSTER_ID,
        *TASK_ID,
    );

    tracing::info!(
        "Environment Variables: {}",
        env::vars()
            .map(|(name, _)| name)
            .collect::<Vec<String>>()
            .join(", ")
    );

    // umami guards its own admin routes with a trusted issuer (for local dev it can trust
    // itself via the JWKS endpoint below — see AUTH_ISSUER in .env.example).
    let authenticator = Arc::new(Authenticator::from_env()?);

    let dynamo_client = DynamoClient::from_env().await?;

    let user_repository: Arc<dyn UserRepository> =
        Arc::new(DynamoUserRepository::with_client(&dynamo_client).await?);
    let session_repository: Arc<dyn SessionRepository> =
        Arc::new(DynamoSessionRepository::with_client(&dynamo_client).await?);
    let tenant_repository: Arc<dyn TenantRepository> =
        Arc::new(DynamoTenantRepository::with_client(&dynamo_client).await?);
    let api_key_repository: Arc<dyn ApiKeyRepository> =
        Arc::new(DynamoApiKeyRepository::with_client(&dynamo_client).await?);
    let audit_repository: Arc<dyn AuditRepository> =
        Arc::new(DynamoAuditRepository::with_client(&dynamo_client).await?);
    let messaging_repository: Arc<dyn MessagingRepository> =
        Arc::new(DynamoMessagingRepository::with_client(&dynamo_client).await?);

    // Signing keys behind a repository trait so the issuer and JWKS route depend only on the trait,
    // not on where keys come from. Currently env-backed (`EnvKeyRepository`).
    let key_repository: Arc<dyn KeyRepository> = Arc::new(EnvKeyRepository::from_env()?);
    let token_issuer = Arc::new(TokenIssuer::from_env(key_repository.clone())?);

    // Config catalog behind a repository: S3 (whole-document, cached) when a bucket is configured,
    // otherwise a built-in default (dev/tests/no-S3).
    // Persist config in S3 whenever an S3 client is available the wasabi way (i.e. S3_BUCKET_SUFFIX
    // is set); the bucket is the fixed "config.<S3_BUCKET_SUFFIX>", auto-created on first boot.
    // Otherwise fall back to the in-memory repo — non-persistent, for local dev without S3.
    let config_repository: Arc<dyn ConfigRepository> = match S3Client::from_env().await {
        Ok(s3_client) => Arc::new(S3ConfigRepository::from_env(s3_client).await?),
        Err(err) => {
            tracing::warn!(
                "S3 not available ({err:#}) — using the in-memory config repository. Config edits \
                 (features, custom fields, PUT /config) are NOT persisted and are lost on restart \
                 (reset to the built-in default). Set S3_BUCKET_SUFFIX (wasabi S3 naming) to \
                 persist config in S3."
            );
            Arc::new(StaticConfigRepository::with_default())
        }
    };

    // Symmetric key for encrypting MFA secrets at rest.
    let mfa = Arc::new(SecretBox::from_env()?);

    // WebAuthn relying party + passkey/ceremony storage.
    let webauthn_service = Arc::new(WebauthnService::from_env()?);
    let webauthn_repository: Arc<dyn WebauthnRepository> =
        Arc::new(DynamoWebauthnRepository::with_client(&dynamo_client).await?);

    let auth_context = AuthContext::from_env(
        user_repository.clone(),
        tenant_repository.clone(),
        session_repository.clone(),
        token_issuer.clone(),
        config_repository.clone(),
        mfa.clone(),
        audit_repository.clone(),
    )?;

    // The system tenant whose members may administer all tenants (they get the `is:system-tenant`
    // marker → `manage:tenants` + `switch:tenant`).
    let system_tenant_id: Option<String> = env::var("UMAMI_SYSTEM_TENANT_ID")
        .ok()
        .filter(|id| !id.is_empty());

    // Optionally bootstrap the very first tenant + owner on an empty deployment.
    maybe_auto_init(
        &tenant_repository,
        &user_repository,
        system_tenant_id.as_deref(),
    )
    .await?;

    let api = routes![
        get_info_route(),
        get_user_info_route(authenticator.clone()),
        jwks_route(key_repository),
        // auth
        login_route(auth_context.clone()),
        refresh_route(auth_context.clone()),
        logout_route(auth_context.clone()),
        me_route(
            user_repository.clone(),
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        logout_all_route(user_repository.clone(), authenticator.clone()),
        sessions_route(session_repository.clone(), authenticator.clone()),
        delete_session_route(session_repository.clone(), authenticator.clone()),
        patch_me_route(
            user_repository.clone(),
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        switch_tenant_route(auth_context.clone(), authenticator.clone()),
        change_password_route(
            user_repository.clone(),
            config_repository.clone(),
            audit_repository.clone(),
            authenticator.clone()
        ),
        // MFA (TOTP)
        totp_setup_route(user_repository.clone(), mfa.clone(), authenticator.clone()),
        totp_verify_route(
            user_repository.clone(),
            mfa.clone(),
            audit_repository.clone(),
            authenticator.clone()
        ),
        totp_disable_route(
            user_repository.clone(),
            mfa,
            audit_repository.clone(),
            authenticator.clone()
        ),
        // MFA (WebAuthn passkeys)
        webauthn_register_start_route(
            webauthn_service.clone(),
            webauthn_repository.clone(),
            user_repository.clone(),
            authenticator.clone()
        ),
        webauthn_register_finish_route(
            webauthn_service.clone(),
            webauthn_repository.clone(),
            user_repository.clone(),
            audit_repository.clone(),
            authenticator.clone()
        ),
        webauthn_login_start_route(
            auth_context.clone(),
            webauthn_service.clone(),
            webauthn_repository.clone()
        ),
        webauthn_login_finish_route(auth_context.clone(), webauthn_service, webauthn_repository),
        // API keys — exchange (service keys + personal access tokens)
        exchange_route(
            api_key_repository.clone(),
            user_repository.clone(),
            tenant_repository.clone(),
            config_repository.clone(),
            token_issuer.clone(),
            audit_repository.clone(),
            system_tenant_id.clone()
        ),
        // tenant service keys (manage:service-keys)
        create_api_key_route(
            api_key_repository.clone(),
            tenant_repository.clone(),
            config_repository.clone(),
            system_tenant_id.clone(),
            authenticator.clone()
        ),
        list_api_keys_route(api_key_repository.clone(), authenticator.clone()),
        list_user_pats_route(api_key_repository.clone(), authenticator.clone()),
        delete_api_key_route(api_key_repository.clone(), authenticator.clone()),
        // personal access tokens (self-service)
        create_my_pat_route(api_key_repository.clone(), authenticator.clone()),
        list_my_pats_route(api_key_repository.clone(), authenticator.clone()),
        delete_my_pat_route(api_key_repository.clone(), authenticator.clone()),
        // messaging links (self-service code + own links)
        my_code_route(
            messaging_repository.clone(),
            config_repository.clone(),
            audit_repository.clone(),
            authenticator.clone()
        ),
        regenerate_code_route(
            messaging_repository.clone(),
            config_repository.clone(),
            audit_repository.clone(),
            authenticator.clone()
        ),
        my_links_route(messaging_repository.clone(), authenticator.clone()),
        delete_my_link_route(messaging_repository.clone(), authenticator.clone()),
        // messaging links (admin: read a tenant user's links)
        user_links_route(messaging_repository.clone(), authenticator.clone()),
        // messaging links (machine: link via code + resolve identity)
        create_link_route(
            messaging_repository.clone(),
            config_repository.clone(),
            audit_repository.clone(),
            authenticator.clone()
        ),
        resolve_route(
            ResolveDeps {
                messaging: messaging_repository,
                users: user_repository.clone(),
                tenants: tenant_repository.clone(),
                config: config_repository.clone(),
                tokens: token_issuer.clone(),
            },
            authenticator.clone()
        ),
        // tenants (cross-tenant admin: create/list/delete require manage:tenants)
        create_tenant_route(
            tenant_repository.clone(),
            user_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        list_tenants_route(tenant_repository.clone(), authenticator.clone()),
        delete_tenant_route(
            tenant_repository.clone(),
            user_repository.clone(),
            api_key_repository.clone(),
            system_tenant_id.clone(),
            authenticator.clone()
        ),
        get_tenant_route(tenant_repository.clone(), authenticator.clone()),
        patch_tenant_route(
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        // users (admin, within own tenant)
        create_user_route(
            user_repository.clone(),
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        list_users_route(
            user_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        get_user_route(
            user_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        patch_user_route(
            user_repository.clone(),
            tenant_repository.clone(),
            config_repository.clone(),
            audit_repository.clone(),
            authenticator.clone()
        ),
        delete_user_route(user_repository.clone(), authenticator.clone()),
        reset_password_route(
            user_repository.clone(),
            config_repository.clone(),
            audit_repository.clone(),
            authenticator.clone()
        ),
        user_audit_route(
            user_repository.clone(),
            audit_repository.clone(),
            authenticator.clone()
        ),
        user_sessions_route(
            user_repository.clone(),
            session_repository.clone(),
            authenticator.clone()
        ),
        logout_user_route(user_repository.clone(), authenticator.clone()),
        // authorization management (assignable roles/scopes/features + feature grant/revoke)
        assignable_roles_route(
            user_repository,
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        assignable_scopes_route(
            tenant_repository.clone(),
            config_repository.clone(),
            system_tenant_id.clone(),
            authenticator.clone()
        ),
        assignable_features_route(
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        grant_feature_route(
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        revoke_feature_route(
            tenant_repository,
            config_repository.clone(),
            authenticator.clone()
        ),
        // config (global catalog + settings)
        get_config_route(config_repository.clone(), authenticator.clone()),
        custom_fields_route(config_repository.clone(), authenticator.clone()),
        put_config_route(config_repository.clone(), authenticator.clone()),
        // audit log (read)
        tenant_audit_route(audit_repository.clone(), authenticator.clone()),
        my_audit_route(audit_repository, authenticator)
    ];

    // Optionally serve the built management UI (SPA) under /app from the same origin. Mounted only
    // when UMAMI_UI_DIR contains a built index.html; otherwise umami runs API-only. Optional CORS
    // (from CORS_ALLOWED_ORIGINS) is applied for cross-origin — typically same-site subdomain — SPAs.
    let ui_dir = env::var("UMAMI_UI_DIR").unwrap_or_else(|_| "clients/ui/dist".to_owned());
    let cors = cors_from_env();
    match ui_routes(&ui_dir, config_repository.clone()) {
        Some(ui) => {
            tracing::info!("Serving management UI from '{ui_dir}' under /app");
            serve(api.or(ui), cors).await
        }
        None => serve(api, cors).await,
    }
}

/// Runs the web server, wrapping the routes in the optional credentialed CORS layer when present.
/// Generic over the route filter so the UI / API-only branches don't need a unified filter type.
async fn serve<F>(routes: F, cors: Option<warp::filters::cors::Cors>) -> anyhow::Result<()>
where
    F: warp::Filter<Error = warp::Rejection> + Clone + Send + Sync + 'static,
    F::Extract: warp::Reply,
{
    match cors {
        Some(cors) => run_webserver(routes.with(cors)).await,
        None => run_webserver(routes).await,
    }
}

/// Builds a credentialed CORS layer from `CORS_ALLOWED_ORIGINS` (comma-separated exact origins, e.g.
/// `https://spa.myapp.com,https://admin.myapp.com`). Returns `None` when the var is unset/empty, so
/// umami stays CORS-free by default. Credentialed CORS forbids `*`, so origins are an explicit
/// allow-list; the browser must also send `credentials: "include"` for the cookie to travel.
fn cors_from_env() -> Option<warp::filters::cors::Cors> {
    let raw = env::var("CORS_ALLOWED_ORIGINS").ok()?;
    let origins: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    if origins.is_empty() {
        return None;
    }
    tracing::info!("CORS enabled for origins: {}", origins.join(", "));
    Some(
        warp::cors()
            .allow_origins(origins.iter().map(String::as_str))
            .allow_credentials(true)
            .allow_methods(["GET", "POST", "PATCH", "DELETE", "OPTIONS"])
            .allow_headers(["content-type", "authorization"])
            .max_age(600)
            .build(),
    )
}

/// Bootstraps the first tenant + owner on an empty deployment when `UMAMI_AUTO_INIT=true`.
///
/// No-op unless auto-init is enabled and **zero** tenants exist. Creates the system tenant — with a
/// caller-supplied `UMAMI_SYSTEM_TENANT_ID` when set (so the owner is immediately a system admin),
/// otherwise a freshly generated id — and an owner user (`UMAMI_ROOT_USERNAME`, default `root`) with
/// a **randomly generated** one-time password. The tenant id, username and password are logged once,
/// prominently; no credentials are hard-coded. Intended for first-run/dev, not steady-state
/// provisioning.
#[tracing::instrument(skip_all, err(Display))]
async fn maybe_auto_init(
    tenants: &Arc<dyn TenantRepository>,
    users: &Arc<dyn UserRepository>,
    system_tenant_id: Option<&str>,
) -> anyhow::Result<()> {
    if env::var("UMAMI_AUTO_INIT").as_deref() != Ok("true") {
        return Ok(());
    }
    if !tenants.find_tenants("", 1).await?.0.is_empty() {
        return Ok(());
    }

    let tenant = match system_tenant_id {
        Some(id) => {
            tenants
                .create_tenant_with_id(id, "System", "system", None)
                .await?
        }
        None => tenants.create_tenant("System", "system", None).await?,
    };

    // Generated, single-use bootstrap credentials — never hard-coded. Logged once below; the
    // operator must sign in and change the password immediately.
    let username = env::var("UMAMI_ROOT_USERNAME")
        .ok()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "root".to_owned());
    let password = generate_id();
    let password_hash = auth::password::hash(&password)?;
    let owner = users
        .create_user(NewUser {
            tenant_id: tenant.tenant_id.clone(),
            roles: vec![ROLE_OWNER.to_owned()],
            username: username.clone(),
            email: None,
            title: None,
            salutation: users::Salutation::default(),
            firstname: None,
            lastname: Some("Root Admin".to_owned()),
            password_hash: Some(password_hash),
            custom_fields: std::collections::BTreeMap::new(),
            created_by: None,
            password_generated: false,
        })
        .await?;

    // One-time, prominent credential dump. The password is only ever shown here.
    let system_hint = if system_tenant_id.is_some() {
        String::new()
    } else {
        format!(
            "\n  ⚠ set UMAMI_SYSTEM_TENANT_ID={} (and restart) to grant cross-tenant/system admin",
            tenant.tenant_id
        )
    };
    tracing::warn!(
        "\n================= UMAMI AUTO-INIT =================\n\
         Bootstrapped an empty deployment. These credentials are shown ONCE:\n\
         \x20 tenant id : {}\n\
         \x20 username  : {}\n\
         \x20 password  : {}\n\
         \x20 user id   : {}\n\
         ⚠ CHANGE THE PASSWORD IMMEDIATELY.{}\n\
         ==================================================",
        tenant.tenant_id,
        username,
        password,
        owner.user_id,
        system_hint
    );

    Ok(())
}
