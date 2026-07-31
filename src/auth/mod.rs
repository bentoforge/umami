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
use crate::users::repository::UserRepository;
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
    /// Config source — resolves role permissions and the access/refresh TTLs at token-issue time.
    pub config: Arc<dyn ConfigRepository>,
    /// Optional `Domain` attribute for the refresh cookie (`UMAMI_COOKIE_DOMAIN`).
    pub cookie_domain: Option<String>,
}

impl AuthContext {
    /// Assembles the context from its repositories/issuer/config plus `UMAMI_COOKIE_DOMAIN`.
    /// Access/refresh lifetimes come from the config `security` settings, not env.
    pub fn from_env(
        users: Arc<dyn UserRepository>,
        sessions: Arc<dyn SessionRepository>,
        tokens: Arc<TokenIssuer>,
        config: Arc<dyn ConfigRepository>,
    ) -> anyhow::Result<Self> {
        let cookie_domain = env::var("UMAMI_COOKIE_DOMAIN")
            .ok()
            .filter(|d| !d.is_empty());

        Ok(Self {
            users,
            sessions,
            tokens,
            config,
            cookie_domain,
        })
    }
}
