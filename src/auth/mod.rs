//! Authentication: token issuance (JWKS), sessions, password login, and the login/refresh flows.
//!
//! Later phases add `/auth/me`, tenant switching and MFA. Shared dependencies for the auth routes
//! are bundled in [`AuthContext`].

pub mod cookies;
pub mod login;
pub mod me;
pub mod password;
pub mod secretbox;
pub mod session;
pub mod tokens;
pub mod totp;
pub mod webauthn;

use crate::auth::secretbox::SecretBox;
use crate::auth::session::SessionRepository;
use crate::auth::tokens::TokenIssuer;
use crate::config::repository::ConfigRepository;
use crate::tenants::repository::TenantRepository;
use crate::users::repository::UserRepository;
use std::env;
use std::sync::Arc;

/// Shared dependencies and config for the auth routes (login, refresh, logout).
#[derive(Clone)]
pub struct AuthContext {
    /// User identity persistence.
    pub users: Arc<dyn UserRepository>,
    /// Tenant persistence — used to resolve config-driven token claims (e.g. `features`).
    pub tenants: Arc<dyn TenantRepository>,
    /// Session persistence backing the refresh flow.
    pub sessions: Arc<dyn SessionRepository>,
    /// ES256 access-token issuer.
    pub tokens: Arc<TokenIssuer>,
    /// Config source — resolves role permissions and the access/refresh TTLs at token-issue time.
    pub config: Arc<dyn ConfigRepository>,
    /// Decrypts the TOTP secret to verify the MFA code during login.
    pub mfa: Arc<SecretBox>,
    /// Optional `Domain` attribute for the refresh cookie (`UMAMI_COOKIE_DOMAIN`).
    pub cookie_domain: Option<String>,
}

impl AuthContext {
    /// Assembles the context from its repositories/issuer/config/mfa plus `UMAMI_COOKIE_DOMAIN`.
    /// Access/refresh lifetimes come from the config `security` settings, not env.
    pub fn from_env(
        users: Arc<dyn UserRepository>,
        tenants: Arc<dyn TenantRepository>,
        sessions: Arc<dyn SessionRepository>,
        tokens: Arc<TokenIssuer>,
        config: Arc<dyn ConfigRepository>,
        mfa: Arc<SecretBox>,
    ) -> anyhow::Result<Self> {
        let cookie_domain = env::var("UMAMI_COOKIE_DOMAIN")
            .ok()
            .filter(|d| !d.is_empty());

        Ok(Self {
            users,
            tenants,
            sessions,
            tokens,
            config,
            mfa,
            cookie_domain,
        })
    }
}
