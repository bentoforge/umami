//! umami: micro-IAM — identity, tenant/membership authority, and JWT issuer for a fleet of
//! wasabi-based B2B services.
//!
//! This binary is the entry point only: [`boot::Platform`] resolves every dependency from the
//! environment, [`api::serve`] mounts the routes and runs the warp server (via wasabi's
//! `run_webserver`) until shutdown.

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

mod api;
mod audit;
mod auth;
mod authz;
mod boot;
mod i18n;

// Message catalogue for localized API errors; must live at the crate root because `t!` resolves
// the generated items against `crate::`. See `i18n.rs` for what is translated and what is not.
rust_i18n::i18n!("locales", fallback = "en");
mod config;
mod constants;
mod contacts;
mod messaging;
mod notify;
mod search;
mod storage;
mod tenants;
mod users;
mod web_ui;

use crate::boot::Platform;
use crate::boot::auto_init::maybe_auto_init;
use std::env;
use wasabi::tools::system::install_termination_listener;
use wasabi::{APP_NAME, APP_VERSION, CLUSTER_ID, TASK_ID};

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

        // A failed boot must not look like a clean shutdown. An orchestrator restarting on
        // non-zero, a `docker run` in a deploy script and CI all read the exit code, not the log —
        // and umami failing to start is the one event the fleet cannot work around.
        #[cfg(feature = "open_telemetry")]
        // The OTLP exporter batches, so exiting immediately drops the line explaining why. Console
        // output is synchronous and already written by now.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        std::process::exit(1);
    }
}

/// Boots the platform, then serves the API until shutdown.
///
/// The three steps are deliberately all this function does: what gets built lives in
/// [`boot::Platform::boot`], what gets mounted lives in [`api::serve`].
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

    let platform = Platform::boot().await?;

    // Optionally bootstrap the very first tenant + owner on an empty deployment.
    maybe_auto_init(&platform).await?;

    api::serve(&platform).await
}
