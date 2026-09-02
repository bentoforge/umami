//! umami's HTTP surface: which routes exist, and how they are served.
//!
//! One submodule per domain, each exposing `routes(&Platform)`. [`serve`] composes them, mounts the
//! token exchange under its own CORS policy, optionally mounts the management UI, and runs the
//! server. Splitting the table this way is not only about file size: `routes![…]` builds one
//! right-nested `Or<…>` type, and a single 81-deep one needed `#![recursion_limit = "512"]` to
//! type-check at all. A dozen shallow trees fit under the default limit, which is why that
//! attribute is no longer in `main.rs` — keep the groups small enough that it stays gone.
//!
//! This module is wiring, so it is allowed to take a `&Platform`; the domain modules it calls are
//! not. Their route builders keep explicit parameters — that is what lets them be tested with
//! `warp::test` and `mockall` doubles, without a container in sight.
//!
//! Each group has the same signature: `routes(&Platform) -> BoxedFilter<(impl Reply + use<>,)>`.
//! The `use<>` is load-bearing — under edition 2024's capture rules an `impl Trait` return
//! implicitly captures the `&Platform` lifetime, and a filter that borrows the platform cannot
//! escape the function that built it. Capturing nothing is correct here: the filters hold owned
//! `Arc` clones, never a reference to the platform.
//!
//! Route order carries no meaning here. Every path is built with `warp::path!`, which matches the
//! full path exactly, so no route can shadow another and groups may be reordered freely.

pub mod apikeys;
pub mod audit;
pub mod auth;
pub mod authz;
pub mod config;
pub mod contacts;
pub mod cors;
pub mod messaging;
pub mod notify;
pub mod ratelimit;
pub mod tenants;
pub mod users;

use crate::api::cors::{cors_from_env, with_public_exchange_cors};
use crate::auth::tokens::jwks_route;
use crate::boot::Platform;
use crate::web_ui::ui_routes;
use std::env;
use warp::Filter;
use wasabi::routes;
use wasabi::web::info_service::get_info_route;
use wasabi::web::user_info_service::get_user_info_route;
use wasabi::web::warp::{recover_api_errors, run_webserver};

/// Mounts every route on the booted platform and serves until shutdown.
pub async fn serve(platform: &Platform) -> anyhow::Result<()> {
    let token_exchange = with_public_exchange_cors(apikeys::exchange(platform));

    let api = routes![
        // service metadata + the public key set
        get_info_route(),
        get_user_info_route(platform.authenticator.clone()),
        jwks_route(platform.keys.clone()),
        auth::routes(platform),
        apikeys::routes(platform),
        contacts::routes(platform),
        notify::routes(platform),
        messaging::routes(platform),
        tenants::routes(platform),
        users::routes(platform),
        authz::routes(platform),
        config::routes(platform),
        audit::routes(platform),
        ratelimit::routes(platform)
    ];

    // Optionally serve the built management UI (SPA) under /app from the same origin. Mounted only
    // when UMAMI_UI_DIR contains a built index.html; otherwise umami runs API-only. Optional CORS
    // (from CORS_ALLOWED_ORIGINS) is applied for cross-origin — typically same-site subdomain — SPAs.
    let ui_dir = env::var("UMAMI_UI_DIR").unwrap_or_else(|_| "clients/ui/dist".to_owned());
    let cors = cors_from_env();
    match ui_routes(&ui_dir, platform.config.clone()) {
        Some(ui) => {
            tracing::info!("Serving management UI from '{ui_dir}' under /app");
            run(token_exchange, api.or(ui), cors).await
        }
        None => run(token_exchange, api, cors).await,
    }
}

/// Runs the web server: `public` is served as-is, `routes` gets the optional credentialed CORS layer.
///
/// The split matters. Two CORS layers over one route would emit **two**
/// `Access-Control-Allow-Origin` headers, which every browser rejects — so anything carrying its own
/// policy (today: the token exchange) must be mounted outside the global one, not merely before it.
/// Generic over both filters so the UI / API-only branches don't need a unified filter type.
async fn run<P, F>(
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
