//! Authentication: token issuance (JWKS), sessions, password login, and the login/refresh flows.
//!
//! Later phases add `/auth/me`, tenant switching and MFA. Shared dependencies for the auth routes
//! are bundled in [`AuthContext`].

pub mod cookies;
pub mod login;
pub mod me;
pub mod password;
pub mod session;
pub mod tokens;

use crate::auth::session::SessionRepository;
use crate::auth::tokens::TokenIssuer;
use crate::config::repository::ConfigRepository;
use crate::constants::DEFAULT_REFRESH_TTL_SECS;
use crate::users::repository::UserRepository;
use anyhow::Context;
use std::env;
use std::sync::Arc;

/// Shared dependencies and config for the auth routes (login, refresh, logout).
#[derive(Clone)]
pub struct AuthContext {
    /// User identity persistence.
    pub users: Arc<dyn UserRepository>,
    /// Session persistence backing the refresh flow.
    pub sessions: Arc<dyn SessionRepository>,
    /// ES256 access-token issuer.
    pub tokens: Arc<TokenIssuer>,
    /// Config source — resolves role codes to permissions at token-issue time.
    pub config: Arc<dyn ConfigRepository>,
    /// Refresh/session lifetime in seconds (`UMAMI_REFRESH_TTL_SECS`).
    pub refresh_ttl_secs: i64,
    /// Optional `Domain` attribute for the refresh cookie (`UMAMI_COOKIE_DOMAIN`).
    pub cookie_domain: Option<String>,
}

impl AuthContext {
    /// Assembles the context from its repositories/issuer/config plus `UMAMI_REFRESH_TTL_SECS` and
    /// `UMAMI_COOKIE_DOMAIN`.
    pub fn from_env(
        users: Arc<dyn UserRepository>,
        sessions: Arc<dyn SessionRepository>,
        tokens: Arc<TokenIssuer>,
        config: Arc<dyn ConfigRepository>,
    ) -> anyhow::Result<Self> {
        let refresh_ttl_secs = match env::var("UMAMI_REFRESH_TTL_SECS") {
            Ok(raw) => raw
                .parse::<i64>()
                .context("UMAMI_REFRESH_TTL_SECS must be an integer number of seconds")?,
            Err(_) => DEFAULT_REFRESH_TTL_SECS as i64,
        };
        let cookie_domain = env::var("UMAMI_COOKIE_DOMAIN")
            .ok()
            .filter(|d| !d.is_empty());

        Ok(Self {
            users,
            sessions,
            tokens,
            config,
            refresh_ttl_secs,
            cookie_domain,
        })
    }
}
