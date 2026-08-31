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
mod i18n;

// Message catalogue for localized API errors; must live at the crate root because `t!` resolves
// the generated items against `crate::`. See `i18n.rs` for what is translated and what is not.
rust_i18n::i18n!("locales", fallback = "en");
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
use crate::auth::authorize::authorize_route;
use crate::auth::login::{login_route, logout_route, refresh_route};
use crate::auth::me::{
    change_password_route, delete_session_route, logout_all_route, me_route, patch_me_route,
    sessions_route,
};
use crate::auth::ratelimit::RateLimiter;
use crate::auth::ratelimit::repository::{DynamoRateLimitRepository, RateLimitRepository};
use crate::auth::ratelimit::service::{
    api_key_rate_limit_route, my_pat_rate_limit_route, my_rate_limit_route,
    rate_limit_blocks_route, user_pat_rate_limit_route, user_rate_limit_route,
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
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::generate_id;
use wasabi::aws::s3::S3Client;
use wasabi::tools::system::install_termination_listener;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::info_service::get_info_route;
use wasabi::web::user_info_service::get_user_info_route;
use wasabi::web::warp::{recover_api_errors, run_webserver};
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
    let rate_limit_repository: Arc<dyn RateLimitRepository> =
        Arc::new(DynamoRateLimitRepository::with_client(&dynamo_client).await?);
    // Rate limiter (per-node LRU block cache in front of the store) guarding /auth/login and
    // /auth/token; the LRU size is `UMAMI_RATELIMIT_CACHE_CAP`, thresholds live in the config.
    let rate_limiter = Arc::new(RateLimiter::from_env(rate_limit_repository));

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
        rate_limiter.clone(),
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

    // `POST /auth/token` is the one endpoint arbitrary third-party pages must reach, so it gets its
    // own public CORS policy and is mounted outside the credentialed layer (see `serve`).
    let token_exchange = with_public_exchange_cors(exchange_route(
        api_key_repository.clone(),
        user_repository.clone(),
        tenant_repository.clone(),
        config_repository.clone(),
        token_issuer.clone(),
        audit_repository.clone(),
        rate_limiter.clone(),
        system_tenant_id.clone(),
    ));

    let api = routes![
        get_info_route(),
        get_user_info_route(authenticator.clone()),
        jwks_route(key_repository),
        // auth
        login_route(auth_context.clone()),
        refresh_route(auth_context.clone()),
        // Hosted-login redirect: an app bounces the browser here, umami ensures a session
        // exists, the browser comes back. No code, no token in the response — same-site apps
        // then just call /auth/refresh with the cookie the browser already carries.
        authorize_route(auth_context.clone()),
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
        // API keys — the exchange itself is mounted separately (see `token_exchange` below), because
        // it needs a *public* CORS policy the credentialed one cannot express.
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
            system_tenant_id.clone(),
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
            system_tenant_id.clone(),
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
            user_repository.clone(),
            tenant_repository.clone(),
            config_repository.clone(),
            system_tenant_id.clone(),
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
            system_tenant_id.clone(),
            authenticator.clone()
        ),
        grant_feature_route(
            tenant_repository.clone(),
            config_repository.clone(),
            system_tenant_id.clone(),
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
        my_audit_route(audit_repository, authenticator.clone()),
        // rate limits (read-only inspection + the deployment-wide overview)
        my_rate_limit_route(
            config_repository.clone(),
            rate_limiter.clone(),
            authenticator.clone()
        ),
        user_rate_limit_route(
            user_repository.clone(),
            config_repository.clone(),
            rate_limiter.clone(),
            authenticator.clone()
        ),
        api_key_rate_limit_route(
            api_key_repository.clone(),
            config_repository.clone(),
            rate_limiter.clone(),
            authenticator.clone()
        ),
        my_pat_rate_limit_route(
            api_key_repository.clone(),
            config_repository.clone(),
            rate_limiter.clone(),
            authenticator.clone()
        ),
        user_pat_rate_limit_route(
            api_key_repository.clone(),
            user_repository.clone(),
            config_repository.clone(),
            rate_limiter.clone(),
            authenticator.clone()
        ),
        rate_limit_blocks_route(rate_limiter.clone(), authenticator)
    ];

    // Optionally serve the built management UI (SPA) under /app from the same origin. Mounted only
    // when UMAMI_UI_DIR contains a built index.html; otherwise umami runs API-only. Optional CORS
    // (from CORS_ALLOWED_ORIGINS) is applied for cross-origin — typically same-site subdomain — SPAs.
    let ui_dir = env::var("UMAMI_UI_DIR").unwrap_or_else(|_| "clients/ui/dist".to_owned());
    let cors = cors_from_env();
    match ui_routes(&ui_dir, config_repository.clone()) {
        Some(ui) => {
            tracing::info!("Serving management UI from '{ui_dir}' under /app");
            serve(token_exchange, api.or(ui), cors).await
        }
        None => serve(token_exchange, api, cors).await,
    }
}

/// Runs the web server: `public` is served as-is, `routes` gets the optional credentialed CORS layer.
///
/// The split matters. Two CORS layers over one route would emit **two**
/// `Access-Control-Allow-Origin` headers, which every browser rejects — so anything carrying its own
/// policy (today: the token exchange) must be mounted outside the global one, not merely before it.
/// Generic over both filters so the UI / API-only branches don't need a unified filter type.
async fn serve<P, F>(
    public: P,
    routes: F,
    cors: Option<warp::filters::cors::Cors>,
) -> anyhow::Result<()>
where
    P: warp::Filter<Error = warp::Rejection> + Clone + Send + Sync + 'static,
    P::Extract: warp::Reply,
    F: warp::Filter<Error = warp::Rejection> + Clone + Send + Sync + 'static,
    F::Extract: warp::Reply,
{
    match cors {
        // Recover *before* wrapping in CORS. A rejection turned into a response
        // outside the CORS layer carries no `Access-Control-Allow-Origin`, so the
        // browser blocks it — and the caller sees a network error instead of the
        // 401 that told it there is no session yet. `run_webserver` recovers again
        // on the outside, which finds nothing left to do.
        Some(cors) => run_webserver(public.or(recover_api_errors(routes).with(cors))).await,
        None => run_webserver(public.or(routes)).await,
    }
}

/// Mounts `route` (the token exchange) with a public, credential-free CORS policy: it answers the
/// preflight itself and sends a **literal** `Access-Control-Allow-Origin: *`.
///
/// Why this endpoint is open to every origin, and why that is not the hole it looks like:
///
/// - The exchange is deliberately cookie- and bearer-free — the API key (or its HMAC proof) *is* the
///   credential — so there is no session for a foreign origin to ride on.
/// - **CORS is not authorization.** What restricts a key to a site is `allowedOrigins` on the key,
///   checked against the request's `Origin` header, which the browser sets and a page cannot forge.
///   That check is untouched by this policy and runs on every exchange.
/// - The cost cap is the rate limit (per IP and per key), which also runs regardless.
///
/// The alternative — every partner's origin in `CORS_ALLOWED_ORIGINS` — would make each new customer
/// a redeploy while adding no security, since the per-key origin list already exists and is editable
/// through the API.
///
/// Two implementation details are deliberate:
///
/// - **A literal `*`, not warp's `allow_any_origin()`.** That helper *reflects* the request's
///   `Origin` back, which (a) would permit credentialed requests the moment someone adds
///   `allow_credentials(true)`, and (b) makes the response origin-dependent without emitting
///   `Vary: Origin` — behind a shared cache such as CloudFront one origin's header could be served to
///   another. A wildcard is credential-proof *by spec* and identical for every caller, so it is both
///   safer and cache-safe.
/// - **Mounted outside the credentialed layer** (see [`serve`]), because two CORS layers over one
///   route emit two `Access-Control-Allow-Origin` headers, which browsers reject.
fn with_public_exchange_cors<R>(route: BoxedFilter<(R,)>) -> BoxedFilter<(impl warp::Reply,)>
where
    R: warp::Reply + 'static,
{
    let preflight = warp::path!("auth" / "token")
        .and(warp::options())
        .map(exchange_preflight_reply);

    preflight.or(route.map(with_wildcard_origin)).boxed()
}

/// The preflight answer for the token exchange: what a browser must see before it sends the POST.
fn exchange_preflight_reply() -> impl warp::Reply {
    let reply = warp::reply::with_status(warp::reply::reply(), StatusCode::NO_CONTENT);
    let reply = with_wildcard_origin(reply);
    let reply = warp::reply::with_header(reply, "access-control-allow-methods", "POST, OPTIONS");
    let reply = warp::reply::with_header(reply, "access-control-allow-headers", "content-type");
    warp::reply::with_header(reply, "access-control-max-age", "600")
}

/// Adds the literal wildcard origin. Separate so the POST and the preflight cannot drift apart.
fn with_wildcard_origin<R: warp::Reply>(reply: R) -> impl warp::Reply {
    warp::reply::with_header(reply, "access-control-allow-origin", "*")
}

/// Builds a credentialed CORS layer from `CORS_ALLOWED_ORIGINS` (comma-separated exact origins, e.g.
/// `https://spa.myapp.com,https://admin.myapp.com`). Returns `None` when the var is unset/empty, so
/// umami stays CORS-free by default. Credentialed CORS forbids `*`, so origins are an explicit
/// allow-list; the browser must also send `credentials: "include"` for the cookie to travel.
fn cors_from_env() -> Option<warp::filters::cors::Cors> {
    let raw = env::var("CORS_ALLOWED_ORIGINS").ok()?;
    let origins = allowed_origins(&raw, env::var("UMAMI_ISSUER").ok().as_deref());
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

/// Assembles the allow-list from the raw `CORS_ALLOWED_ORIGINS` value plus the deployment's
/// own issuer. Empty result means "no CORS layer at all", which is umami's default.
fn allowed_origins(raw: &str, issuer: Option<&str>) -> Vec<String> {
    let mut origins: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| match origin_of(s) {
            Some(origin) => Some(origin),
            // warp's `allow_origins` *panics* on an entry without scheme+host, which
            // would take the whole IAM — and every product's login with it — down over
            // a config typo. Dropping the entry degrades one SPA instead.
            None => {
                tracing::warn!("Ignoring unparsable CORS_ALLOWED_ORIGINS entry '{s}'");
                None
            }
        })
        .collect();
    if origins.is_empty() {
        return origins;
    }

    // The layer wraps *every* API route and warp refuses any `Origin` outside the
    // allow-list — including umami's own. Without this, configuring CORS for an
    // external SPA locks the bundled management UI under /app out of `/auth/login`
    // with a 403, because a same-origin POST carrying JSON still sends `Origin`.
    if let Some(own) = issuer.and_then(origin_of)
        && !origins.contains(&own)
    {
        origins.push(own);
    }
    origins
}

/// Reduces a URL to its CORS origin: scheme + host + port, no path, no trailing slash.
/// `https://iam.example.com/` becomes `https://iam.example.com`. Returns `None` when the
/// input has no scheme or no host — the two things warp requires of an origin.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use warp::Filter;
    use warp::http::{HeaderValue, StatusCode};

    /// Stand-in for the real exchange route: same path and method, no dependencies.
    fn stub_exchange() -> BoxedFilter<(&'static str,)> {
        warp::path!("auth" / "token")
            .and(warp::post())
            .map(|| "token")
            .boxed()
    }

    #[test]
    fn origin_of_strips_path_and_trailing_slash() {
        assert_eq!(
            origin_of("https://iam.example.com/").as_deref(),
            Some("https://iam.example.com")
        );
        assert_eq!(
            origin_of("http://localhost:8080/.well-known/jwks.json").as_deref(),
            Some("http://localhost:8080")
        );
        assert_eq!(
            origin_of("http://localhost:8080").as_deref(),
            Some("http://localhost:8080")
        );
    }

    #[test]
    fn origin_of_rejects_input_without_scheme_or_host() {
        assert_eq!(origin_of("iam.example.com"), None);
        assert_eq!(origin_of("https://"), None);
        assert_eq!(origin_of("://iam.example.com"), None);
    }

    /// The regression: a CORS config for an external SPA must not lock umami's own
    /// management UI out of its own login.
    #[test]
    fn own_issuer_origin_is_always_allowed() {
        let origins = allowed_origins("https://app.example.com", Some("https://iam.example.com/"));
        assert_eq!(
            origins,
            vec!["https://app.example.com", "https://iam.example.com"]
        );
    }

    #[test]
    fn own_origin_is_not_duplicated() {
        let origins = allowed_origins("https://iam.example.com/", Some("https://iam.example.com/"));
        assert_eq!(origins, vec!["https://iam.example.com"]);
    }

    /// No configured origin means no layer, and no layer means no CORS check — so the
    /// issuer must not single-handedly switch CORS on.
    #[test]
    fn issuer_alone_does_not_enable_cors() {
        assert!(allowed_origins("", Some("https://iam.example.com/")).is_empty());
        assert!(allowed_origins("  , ", Some("https://iam.example.com/")).is_empty());
    }

    /// A typo'd entry is dropped rather than panicking warp at boot.
    #[test]
    fn unparsable_entries_are_dropped_not_fatal() {
        let origins = allowed_origins(
            "not-a-url, https://app.example.com",
            Some("https://iam.example.com/"),
        );
        assert_eq!(
            origins,
            vec!["https://app.example.com", "https://iam.example.com"]
        );
    }

    /// A credentialed layer like `cors_from_env` builds for our own SPAs.
    fn credentialed_cors() -> warp::filters::cors::Cors {
        warp::cors()
            .allow_origins(["https://app.example.com"])
            .allow_credentials(true)
            .allow_methods(["GET", "POST", "OPTIONS"])
            .allow_headers(["content-type", "authorization"])
            .build()
    }

    /// A partner page on an origin nobody configured must still be able to exchange a key.
    #[tokio::test]
    async fn exchange_allows_an_arbitrary_origin() {
        let route = with_public_exchange_cors(stub_exchange());

        let response = warp::test::request()
            .method("POST")
            .path("/auth/token")
            .header("origin", "https://some-shop-we-never-heard-of.example")
            .header("content-type", "application/json")
            .reply(&route)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("access-control-allow-origin"),
            Some(&HeaderValue::from_static("*"))
        );
    }

    /// The wildcard must stay credential-free. `*` plus `Allow-Credentials: true` is both invalid per
    /// spec and the one change that would turn this open endpoint into a session-leak — so it is
    /// asserted rather than left to review.
    #[tokio::test]
    async fn exchange_never_allows_credentials() {
        let route = with_public_exchange_cors(stub_exchange());

        let response = warp::test::request()
            .method("POST")
            .path("/auth/token")
            .header("origin", "https://attacker.example")
            .reply(&route)
            .await;

        assert!(
            response
                .headers()
                .get("access-control-allow-credentials")
                .is_none(),
            "the public exchange policy must never allow credentials"
        );
    }

    /// The browser's preflight has to be answered by the public layer, or the POST never happens.
    #[tokio::test]
    async fn exchange_answers_the_preflight() {
        let route = with_public_exchange_cors(stub_exchange());

        let response = warp::test::request()
            .method("OPTIONS")
            .path("/auth/token")
            .header("origin", "https://some-shop.example")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .reply(&route)
            .await;

        assert!(
            response.status().is_success(),
            "preflight was {}",
            response.status()
        );
        assert_eq!(
            response.headers().get("access-control-allow-origin"),
            Some(&HeaderValue::from_static("*"))
        );
    }

    /// An error response has to carry the CORS headers too.
    ///
    /// A browser that cannot read a 401 reports a network error, not a 401 — so an app asking
    /// "do I have a session?" cannot tell "no" from "unreachable". The recover layer therefore has
    /// to sit *inside* the CORS wrapper, which is what `serve` composes.
    #[tokio::test]
    async fn rejections_carry_the_allow_origin_header() {
        // A route that always rejects, standing in for "no session".
        let failing = warp::path!("auth" / "refresh")
            .and(warp::post())
            .and_then(|| async {
                Err::<&str, warp::Rejection>(warp::reject::custom(
                    wasabi::web::error::ApiError::new(StatusCode::UNAUTHORIZED, "no session"),
                ))
            });
        let route = recover_api_errors(failing).with(credentialed_cors());

        let response = warp::test::request()
            .method("POST")
            .path("/auth/refresh")
            .header("origin", "https://app.example.com")
            .reply(&route)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("access-control-allow-origin"),
            Some(&HeaderValue::from_static("https://app.example.com")),
            "a 401 the browser cannot read is indistinguishable from an outage"
        );
    }

    /// Mounting order is the whole point: composed the way `serve` does it, the exchange must carry
    /// **exactly one** `Access-Control-Allow-Origin` header. Two layers over one route emit two, and
    /// browsers reject that — which would look like "CORS is broken" with a correct-looking config.
    #[tokio::test]
    async fn exchange_carries_exactly_one_allow_origin_header() {
        let others = warp::path!("tenants").map(|| "tenants");
        let route = with_public_exchange_cors(stub_exchange()).or(others.with(credentialed_cors()));

        let response = warp::test::request()
            .method("POST")
            .path("/auth/token")
            .header("origin", "https://some-shop.example")
            .reply(&route)
            .await;

        let allow_origin: Vec<_> = response
            .headers()
            .get_all("access-control-allow-origin")
            .iter()
            .collect();

        assert_eq!(allow_origin.len(), 1, "headers: {:?}", response.headers());
        assert_eq!(
            allow_origin.first().copied(),
            Some(&HeaderValue::from_static("*"))
        );
    }
}
