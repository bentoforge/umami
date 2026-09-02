//! Authentication: token issuance (JWKS), sessions, password + passkey login, refresh/logout, the
//! `/auth/me` profile, tenant switching, MFA (TOTP + WebAuthn), and API-key/PAT exchange. Shared
//! dependencies for the auth routes are bundled in [`AuthContext`].

pub mod apikeys;
pub mod authorize;
pub mod broker;
pub mod capabilities;
pub mod challenge;
pub mod cookies;
pub mod login;
pub mod me;
pub mod password;
pub mod ratelimit;
pub mod recovery;
pub mod secretbox;
pub mod session;
pub mod switch_tenant;
pub mod tokens;
pub mod totp;
pub mod webauthn;

use crate::audit::repository::AuditRepository;
use crate::auth::ratelimit::RateLimiter;
use crate::auth::secretbox::SecretBox;
use crate::auth::session::repository::SessionRepository;
use crate::auth::tokens::TokenIssuer;
use crate::config::repository::ConfigRepository;
use crate::storage::Repositories;
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
    /// Contact store, read at mint time **only** when the target API asks for `$user.email`.
    pub contacts: Arc<dyn crate::contacts::repository::ContactRepository>,
    /// Session persistence backing the refresh flow.
    pub sessions: Arc<dyn SessionRepository>,
    /// ES256 access-token issuer.
    pub tokens: Arc<TokenIssuer>,
    /// Config source — resolves role permissions and the access/refresh TTLs at token-issue time.
    pub config: Arc<dyn ConfigRepository>,
    /// Decrypts the TOTP secret to verify the MFA code during login.
    pub mfa: Arc<SecretBox>,
    /// Append-only security audit trail (login success/failure, refresh reuse, …).
    pub audit: Arc<dyn AuditRepository>,
    /// Rate limiter guarding `POST /auth/login` (per-IP volume + per-account brute-force).
    pub rate_limiter: Arc<RateLimiter>,
    /// The configured system tenant (`UMAMI_SYSTEM_TENANT_ID`); a token minted for this tenant gets
    /// the `is:system-tenant` synthetic marker.
    pub system_tenant_id: Option<String>,
    /// Optional `Domain` attribute for the refresh cookie (`UMAMI_COOKIE_DOMAIN`).
    pub cookie_domain: Option<String>,
    /// `Secure`/`SameSite` for the refresh cookie (`UMAMI_COOKIE_SECURE`/`_SAMESITE`).
    pub cookie_policy: crate::auth::cookies::CookiePolicy,
}

impl AuthContext {
    /// Assembles the context from the storage bundle plus the services and policy the auth routes
    /// need. Takes all of [`Repositories`] rather than the five ports it uses: the alternative is
    /// five more positional arguments of near-identical shape at the one call site that must get
    /// them right. Access/refresh lifetimes come from the config `security` settings, not env; the
    /// cookie attributes come from `UMAMI_COOKIE_DOMAIN`/`_SECURE`/`_SAMESITE`.
    pub fn from_env(
        repos: &Repositories,
        tokens: Arc<TokenIssuer>,
        config: Arc<dyn ConfigRepository>,
        mfa: Arc<SecretBox>,
        rate_limiter: Arc<RateLimiter>,
        system_tenant_id: Option<String>,
    ) -> anyhow::Result<Self> {
        let cookie_domain = env::var("UMAMI_COOKIE_DOMAIN")
            .ok()
            .filter(|d| !d.is_empty());
        let cookie_policy = crate::auth::cookies::CookiePolicy::from_env()?;

        Ok(Self {
            users: repos.users.clone(),
            tenants: repos.tenants.clone(),
            contacts: repos.contacts.clone(),
            sessions: repos.sessions.clone(),
            tokens,
            config,
            mfa,
            audit: repos.audit.clone(),
            rate_limiter,
            system_tenant_id,
            cookie_domain,
            cookie_policy,
        })
    }
}
