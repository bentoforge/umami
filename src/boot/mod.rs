//! Boot-time wiring: everything umami needs, built once, in one place.
//!
//! ## Why a plain struct and not a service registry
//!
//! [`Platform`] is a struct with typed fields, not a `TypeId → Arc<dyn Any>` map. A dynamic
//! registry cannot hold umami's services at all: they are trait objects, and `Any` downcasting
//! requires `Sized`, so `Arc<dyn UserRepository>` can only go into such a map wrapped in a newtype
//! per port — which is the typed struct again, plus a mutex and a panic on a missing entry. A
//! forgotten dependency should be a compile error in the one service the whole fleet signs in
//! through, not a boot-time panic.
//!
//! ## The rule that keeps this from becoming a service locator
//!
//! **`&Platform` appears in `boot` and `api` only.** Those two are the wiring layer. Nothing in a
//! domain module takes it: the route builders there keep explicit parameters, which is what keeps
//! them independent of the HTTP stack and mockable with `mockall` doubles. That is worth more than
//! the boilerplate it costs.

pub mod auto_init;
pub mod aws;
pub mod seam;

use crate::auth::AuthContext;
use crate::auth::ratelimit::RateLimiter;
use crate::auth::recovery::RecoveryDeps;
use crate::auth::secretbox::SecretBox;
use crate::auth::tokens::{KeyRepository, TokenIssuer, key_repository_from_env};
use crate::auth::webauthn::WebauthnService;
use crate::boot::aws::Aws;
use crate::config::repository::{self, ConfigRepository};
use crate::contacts::service::VerifyDeps;
use crate::messaging::service::ResolveDeps;
use crate::notify;
use crate::notify::Notifier;
use crate::notify::service::NotifyDeps;
use crate::storage::{self, Repositories};
use crate::users::service::DeleteUserDeps;
use std::env;
use std::sync::Arc;
use wasabi::web::auth::authenticator::Authenticator;

/// Every dependency the route table needs, resolved from the environment at startup.
pub struct Platform {
    /// Persistence, from whichever backend answered (today: DynamoDB).
    pub repos: Repositories,
    /// Validates the JWTs on umami's own admin routes.
    pub authenticator: Arc<Authenticator>,
    /// Signing keys, behind the trait so the issuer and JWKS route stay unaware of their source.
    pub keys: Arc<dyn KeyRepository>,
    /// ES256 access-token issuer.
    pub tokens: Arc<TokenIssuer>,
    /// The config catalog (roles, features, TTLs, custom fields).
    pub config: Arc<dyn ConfigRepository>,
    /// The one outbound seam: how a transactional mail leaves umami.
    pub notifier: Arc<dyn Notifier>,
    /// Symmetric key for encrypting MFA secrets at rest.
    pub mfa: Arc<SecretBox>,
    /// WebAuthn relying party.
    pub webauthn: Arc<WebauthnService>,
    /// Rate limiter guarding `/auth/login` and `/auth/token`.
    pub rate_limiter: Arc<RateLimiter>,
    /// Shared dependencies of the auth routes.
    pub auth: AuthContext,
    /// The system tenant (`UMAMI_SYSTEM_TENANT_ID`) whose members may administer all tenants.
    pub system_tenant_id: Option<String>,
    /// umami's public base URL, for the links in outbound mail.
    pub public_base_url: String,
}

impl Platform {
    /// Resolves every dependency from the environment, provisioning storage on the way.
    ///
    /// Each configurable seam is resolved by its own module (`storage`, `config::repository`,
    /// `auth::tokens`, `notify`) under the rules in [`seam`], and the set of choices is logged as
    /// one block at the end. What a seam does when its prerequisite is missing depends on whether
    /// the operator named it: explicit is strict, unset auto-detects.
    pub async fn boot() -> anyhow::Result<Self> {
        // umami guards its own admin routes with a trusted issuer (for local dev it can trust
        // itself via the JWKS endpoint — see AUTH_ISSUER in .env.example).
        let authenticator = Arc::new(Authenticator::from_env()?);

        // "Is AWS usable here?" — asked at most once, and only if some seam might pick an AWS
        // provider. Every such seam takes it, so the precondition they share is visible rather
        // than rediscovered as a failure on the first call to each service.
        let aws = Aws::new();

        let (repos, storage_seam) = storage::from_env(&aws).await?;

        // Rate limiter (per-node LRU block cache in front of the store) guarding /auth/login and
        // /auth/token; the LRU size is `UMAMI_RATELIMIT_CACHE_CAP`, thresholds live in the config.
        let rate_limiter = Arc::new(RateLimiter::from_env(repos.rate_limits.clone()));

        let (keys, keys_seam) = key_repository_from_env()?;
        let tokens = Arc::new(TokenIssuer::from_env(keys.clone())?);

        let (config, config_seam) = repository::from_env(&aws).await?;

        // The one outbound seam. Without a transport this is a noop that says so, and the routes
        // needing mail refuse rather than accepting a request that goes nowhere.
        let (notifier, mail_seam) = notify::from_env(&aws).await?;

        // Symmetric key for encrypting MFA secrets at rest.
        let mfa = Arc::new(SecretBox::from_env()?);

        // WebAuthn relying party; the passkeys and ceremonies themselves live in `repos.webauthn`.
        let webauthn = Arc::new(WebauthnService::from_env()?);

        // The system tenant whose members may administer all tenants (they get the
        // `is:system-tenant` marker → `manage:tenants` + `switch:tenant`). Read once, here, and
        // handed out from the platform — two readers of this variable can disagree about who the
        // system tenant is, and the disagreement is a silent privilege bug.
        let system_tenant_id = env::var("UMAMI_SYSTEM_TENANT_ID")
            .ok()
            .filter(|id| !id.is_empty());

        let auth = AuthContext::from_env(
            &repos,
            tokens.clone(),
            config.clone(),
            mfa.clone(),
            rate_limiter.clone(),
            system_tenant_id.clone(),
        )?;

        // One block, after every seam has answered: what an operator checks after a deploy is the
        // whole set at once, not four lines interleaved with table provisioning.
        seam::report(&[storage_seam, config_seam, keys_seam, mail_seam]);

        Ok(Platform {
            system_tenant_id,
            // Read once at boot rather than per request, and once rather than per mailing route:
            // every link in every mail has to point at the same host.
            public_base_url: notify::public_base_url()?,
            repos,
            authenticator,
            keys,
            tokens,
            config,
            notifier,
            mfa,
            webauthn,
            rate_limiter,
            auth,
        })
    }

    /// Everything `DELETE /users/{id}` has to clear out along with the user.
    pub fn delete_user_deps(&self) -> DeleteUserDeps {
        DeleteUserDeps {
            users: self.repos.users.clone(),
            contacts: self.repos.contacts.clone(),
            messaging: self.repos.messaging.clone(),
            sessions: self.repos.sessions.clone(),
            webauthn: self.repos.webauthn.clone(),
            api_keys: self.repos.api_keys.clone(),
        }
    }

    /// Dependencies of the notification routes.
    pub fn notify_deps(&self) -> NotifyDeps {
        NotifyDeps {
            users: self.repos.users.clone(),
            tenants: self.repos.tenants.clone(),
            contacts: self.repos.contacts.clone(),
            config: self.config.clone(),
            notifier: self.notifier.clone(),
            system_tenant_id: self.system_tenant_id.clone(),
            public_base_url: self.public_base_url.clone(),
        }
    }

    /// Dependencies of the two password-recovery routes.
    pub fn recovery_deps(&self) -> RecoveryDeps {
        RecoveryDeps {
            users: self.repos.users.clone(),
            contacts: self.repos.contacts.clone(),
            challenges: self.repos.challenges.clone(),
            config: self.config.clone(),
            notifier: self.notifier.clone(),
            rate_limiter: self.rate_limiter.clone(),
            public_base_url: self.public_base_url.clone(),
        }
    }

    /// Dependencies of the contact-verification route that mails the challenge.
    pub fn verify_deps(&self) -> VerifyDeps {
        VerifyDeps {
            contacts: self.repos.contacts.clone(),
            challenges: self.repos.challenges.clone(),
            users: self.repos.users.clone(),
            config: self.config.clone(),
            notifier: self.notifier.clone(),
            rate_limiter: self.rate_limiter.clone(),
            public_base_url: self.public_base_url.clone(),
        }
    }

    /// Dependencies of the messaging identity-resolution route.
    pub fn resolve_deps(&self) -> ResolveDeps {
        ResolveDeps {
            messaging: self.repos.messaging.clone(),
            contacts: self.repos.contacts.clone(),
            users: self.repos.users.clone(),
            tenants: self.repos.tenants.clone(),
            config: self.config.clone(),
            tokens: self.tokens.clone(),
        }
    }
}
