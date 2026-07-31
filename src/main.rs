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

use crate::auth::login::{login_route, logout_route, refresh_route};
use crate::auth::me::{logout_all_route, me_route};
use crate::auth::session::DynamoSessionRepository;
use crate::auth::tokens::{EnvKeyRepository, KeyRepository, TokenIssuer, jwks_route};
use crate::auth::{AuthContext, session::SessionRepository};
use crate::config::repository::{ConfigRepository, S3ConfigRepository, StaticConfigRepository};
use crate::config::service::{get_config_route, put_config_route};
use crate::tenants::repository::{DynamoTenantRepository, TenantRepository};
use crate::tenants::service::{create_tenant_route, get_tenant_route, patch_tenant_route};
use crate::users::repository::{DynamoUserRepository, UserRepository};
use crate::users::service::{create_user_route, list_users_route, patch_user_route};
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

    let auth_context = AuthContext::from_env(
        user_repository.clone(),
        session_repository,
        token_issuer,
        config_repository.clone(),
    )?;

    run_webserver(routes![
        get_info_route(),
        get_user_info_route(authenticator.clone()),
        jwks_route(key_repository),
        // auth
        login_route(auth_context.clone()),
        refresh_route(auth_context.clone()),
        logout_route(auth_context),
        me_route(
            user_repository.clone(),
            tenant_repository.clone(),
            authenticator.clone()
        ),
        logout_all_route(user_repository.clone(), authenticator.clone()),
        // tenants
        create_tenant_route(
            tenant_repository.clone(),
            user_repository.clone(),
            config_repository.clone()
        ),
        get_tenant_route(tenant_repository.clone(), authenticator.clone()),
        patch_tenant_route(tenant_repository, authenticator.clone()),
        // users (admin, within own tenant)
        create_user_route(
            user_repository.clone(),
            config_repository.clone(),
            authenticator.clone()
        ),
        list_users_route(user_repository.clone(), authenticator.clone()),
        patch_user_route(user_repository, authenticator.clone()),
        // config (global catalog + settings)
        get_config_route(config_repository.clone(), authenticator.clone()),
        put_config_route(config_repository, authenticator)
    ])
    .await
}
