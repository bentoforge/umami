//! umami: micro-IAM — identity, tenant/membership authority, and JWT issuer for a fleet of
//! wasabi-based B2B services.
//!
//! This binary boots a warp web server (via wasabi's `run_webserver`) and wires the auth, tenant,
//! team, user and membership routes. See `docs/ROADMAP.md` for the phased build plan.

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

mod auth;
mod config;
mod constants;
mod tenants;
mod users;

use crate::auth::apikeys::repository::{ApiKeyRepository, DynamoApiKeyRepository};
use crate::auth::apikeys::{
    create_api_key_route, delete_api_key_route, exchange_route, list_api_keys_route,
};
use crate::auth::exchange::{ExchangeDeps, exchange_route as user_exchange_route};
use crate::auth::login::{login_route, logout_route, refresh_route};
use crate::auth::me::{logout_all_route, me_route};
use crate::auth::secretbox::SecretBox;
use crate::auth::session::DynamoSessionRepository;
use crate::auth::tokens::{EnvKeyRepository, KeyRepository, TokenIssuer, jwks_route};
use crate::auth::totp::{totp_disable_route, totp_setup_route, totp_verify_route};
use crate::auth::webauthn::WebauthnService;
use crate::auth::webauthn::repository::{DynamoWebauthnRepository, WebauthnRepository};
use crate::auth::webauthn::{
    webauthn_login_finish_route, webauthn_login_start_route, webauthn_register_finish_route,
    webauthn_register_start_route,
};
use crate::auth::{AuthContext, session::SessionRepository};
use crate::config::repository::{ConfigRepository, S3ConfigRepository, StaticConfigRepository};
use crate::config::service::{get_config_route, put_config_route};
use crate::tenants::packages::{
    assign_package_route, entitlements_route, remove_package_route, set_feature_route,
};
use crate::tenants::repository::{DynamoTenantRepository, TenantRepository};
use crate::tenants::service::{
    create_tenant_route, delete_tenant_route, get_tenant_route, list_tenants_route,
    patch_license_route, patch_status_route, patch_tenant_route,
};
use crate::tenants::usage::{
    DynamoUsageRepository, UsageRepository, get_usage_route, increment_usage_route,
};
use crate::users::repository::{DynamoUserRepository, NewUser, UserRepository};
use crate::users::service::{
    create_user_route, delete_user_route, list_users_route, patch_user_route,
};
use crate::constants::{DEFAULT_LOCALE, ROLE_OWNER};
use std::env;
use std::sync::Arc;
use wasabi::aws::dynamodb::client::DynamoClient;
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
    let usage_repository: Arc<dyn UsageRepository> =
        Arc::new(DynamoUsageRepository::with_client(&dynamo_client).await?);
    let api_key_repository: Arc<dyn ApiKeyRepository> =
        Arc::new(DynamoApiKeyRepository::with_client(&dynamo_client).await?);

    // Signing keys behind a repository: env-backed for now, AWS-backed (with periodic refresh for
    // rotation) later — the issuer and JWKS route depend only on the trait.
    let key_repository: Arc<dyn KeyRepository> = Arc::new(EnvKeyRepository::from_env()?);
    let token_issuer = Arc::new(TokenIssuer::from_env(key_repository.clone())?);

    // Config catalog behind a repository: S3 (whole-document, cached) when a bucket is configured,
    // otherwise a built-in default (dev/tests/no-S3).
    let config_repository: Arc<dyn ConfigRepository> = if env::var("UMAMI_CONFIG_BUCKET").is_ok() {
        let s3_client = S3Client::from_env().await?;
        Arc::new(S3ConfigRepository::from_env(s3_client).await?)
    } else {
        tracing::info!("UMAMI_CONFIG_BUCKET not set — using the built-in default config");
        Arc::new(StaticConfigRepository::with_default())
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
        session_repository,
        token_issuer.clone(),
        config_repository.clone(),
        mfa.clone(),
    )?;

    // The system tenant whose members may administer all tenants (interim cross-tenant guard).
    let system_tenant_id: Option<String> =
        env::var("UMAMI_SYSTEM_TENANT_ID").ok().filter(|id| !id.is_empty());

    // Optionally bootstrap the very first tenant + owner on an empty deployment.
    maybe_auto_init(&tenant_repository, &user_repository, system_tenant_id.as_deref()).await?;

    run_webserver(routes![
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
            authenticator.clone()
        ),
        logout_all_route(user_repository.clone(), authenticator.clone()),
        // MFA (TOTP)
        totp_setup_route(user_repository.clone(), mfa.clone(), authenticator.clone()),
        totp_verify_route(user_repository.clone(), mfa.clone(), authenticator.clone()),
        totp_disable_route(user_repository.clone(), mfa, authenticator.clone()),
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
            authenticator.clone()
        ),
        webauthn_login_start_route(
            auth_context.clone(),
            webauthn_service.clone(),
            webauthn_repository.clone()
        ),
        webauthn_login_finish_route(auth_context.clone(), webauthn_service, webauthn_repository),
        // API keys (machine-to-machine)
        exchange_route(
            api_key_repository.clone(),
            tenant_repository.clone(),
            config_repository.clone(),
            token_issuer.clone()
        ),
        create_api_key_route(api_key_repository.clone(), authenticator.clone()),
        list_api_keys_route(api_key_repository.clone(), authenticator.clone()),
        delete_api_key_route(api_key_repository, authenticator.clone()),
        // downstream token exchange (authenticated user → product API)
        user_exchange_route(
            ExchangeDeps {
                users: user_repository.clone(),
                tenants: tenant_repository.clone(),
                config: config_repository.clone(),
                tokens: token_issuer,
            },
            authenticator.clone()
        ),
        // tenants (cross-tenant admin: create/list/delete restricted to the system tenant)
        create_tenant_route(
            tenant_repository.clone(),
            user_repository.clone(),
            config_repository.clone(),
            authenticator.clone(),
            system_tenant_id.clone()
        ),
        list_tenants_route(
            tenant_repository.clone(),
            authenticator.clone(),
            system_tenant_id.clone()
        ),
        delete_tenant_route(
            tenant_repository.clone(),
            user_repository.clone(),
            authenticator.clone(),
            system_tenant_id.clone()
        ),
        get_tenant_route(tenant_repository.clone(), authenticator.clone()),
        patch_tenant_route(
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        // tenant CRM/licensing + usage metering
        patch_status_route(tenant_repository.clone(), authenticator.clone()),
        patch_license_route(tenant_repository.clone(), authenticator.clone()),
        increment_usage_route(
            usage_repository.clone(),
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        get_usage_route(
            usage_repository,
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        // tenant packages, features + entitlements (accounting)
        assign_package_route(
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        remove_package_route(tenant_repository.clone(), authenticator.clone()),
        set_feature_route(
            tenant_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        entitlements_route(
            tenant_repository,
            config_repository.clone(),
            authenticator.clone()
        ),
        // users (admin, within own tenant)
        create_user_route(
            user_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        list_users_route(user_repository.clone(), authenticator.clone()),
        patch_user_route(
            user_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        delete_user_route(user_repository, authenticator.clone()),
        // config (global catalog + settings)
        get_config_route(config_repository.clone(), authenticator.clone()),
        put_config_route(config_repository, authenticator)
    ])
    .await
}

/// Bootstraps the first tenant + owner on an empty deployment when `UMAMI_AUTO_INIT=true`.
///
/// No-op unless auto-init is enabled and **zero** tenants exist. Creates a tenant (with the
/// configured `UMAMI_SYSTEM_TENANT_ID` when set, so the owner is immediately a system admin) and an
/// owner user with the well-known bootstrap credentials `UMAMI` / `UMAMI` — which MUST be changed
/// immediately. Intended for first-run/dev, not steady-state provisioning.
#[tracing::instrument(skip_all, err(Display))]
async fn maybe_auto_init(
    tenants: &Arc<dyn TenantRepository>,
    users: &Arc<dyn UserRepository>,
    system_tenant_id: Option<&str>,
) -> anyhow::Result<()> {
    if env::var("UMAMI_AUTO_INIT").as_deref() != Ok("true") {
        return Ok(());
    }
    if !tenants.list_all().await?.is_empty() {
        return Ok(());
    }

    let tenant = match system_tenant_id {
        Some(id) => tenants.create_tenant_with_id(id, "System", "system").await?,
        None => tenants.create_tenant("System", "system").await?,
    };

    // Bootstrap credentials: username `UMAMI`, password `UMAMI`, no email — CHANGE THE PASSWORD.
    let password_hash = auth::password::hash("UMAMI")?;
    let owner = users
        .create_user(NewUser {
            tenant_id: tenant.tenant_id.clone(),
            roles: vec![ROLE_OWNER.to_owned()],
            username: "UMAMI".to_owned(),
            email: None,
            name: "Umami Admin".to_owned(),
            locale: DEFAULT_LOCALE.to_owned(),
            password_hash: Some(password_hash),
            custom_fields: std::collections::BTreeMap::new(),
        })
        .await?;

    tracing::warn!(
        "AUTO-INIT: created bootstrap tenant '{}' and owner '{}' — login UMAMI / UMAMI. \
         CHANGE THIS PASSWORD IMMEDIATELY. Set UMAMI_SYSTEM_TENANT_ID={} to grant system-admin.",
        tenant.tenant_id,
        owner.user_id,
        tenant.tenant_id
    );

    Ok(())
}
