//! Sign-in, session and profile routes: password and passkey login, refresh, logout, the
//! `/auth/me` profile, tenant switching, MFA enrolment and password recovery.

use crate::auth::authorize::authorize_route;
use crate::auth::capabilities::capabilities_route;
use crate::auth::login::{login_route, logout_route, refresh_route};
use crate::auth::me::{
    change_password_route, delete_session_route, logout_all_route, me_route, patch_me_route,
    sessions_route,
};
use crate::auth::recovery::{complete_recovery_route, forgot_password_route};
use crate::auth::switch_tenant::switch_tenant_route;
use crate::auth::totp::{totp_disable_route, totp_setup_route, totp_verify_route};
use crate::auth::webauthn::{
    webauthn_login_finish_route, webauthn_login_start_route, webauthn_register_finish_route,
    webauthn_register_start_route,
};
use crate::boot::Platform;
use crate::home::service::home_route;
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    let recovery_deps = platform.recovery_deps();

    routes![
        // auth
        login_route(platform.auth.clone()),
        refresh_route(platform.auth.clone()),
        // Hosted-login redirect: an app bounces the browser here, umami ensures a session
        // exists, the browser comes back. No code, no token in the response — same-site apps
        // then just call /auth/refresh with the cookie the browser already carries.
        authorize_route(platform.auth.clone()),
        logout_route(platform.auth.clone()),
        me_route(
            platform.repos.users.clone(),
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.authenticator.clone()
        ),
        logout_all_route(platform.repos.users.clone(), platform.authenticator.clone()),
        sessions_route(
            platform.repos.sessions.clone(),
            platform.authenticator.clone()
        ),
        delete_session_route(
            platform.repos.sessions.clone(),
            platform.authenticator.clone()
        ),
        patch_me_route(
            platform.repos.users.clone(),
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.authenticator.clone()
        ),
        home_route(platform.home_deps(), platform.authenticator.clone()),
        switch_tenant_route(platform.auth.clone(), platform.authenticator.clone()),
        change_password_route(
            platform.repos.users.clone(),
            platform.config.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        // MFA (TOTP)
        totp_setup_route(
            platform.repos.users.clone(),
            platform.mfa.clone(),
            platform.authenticator.clone()
        ),
        totp_verify_route(
            platform.repos.users.clone(),
            platform.mfa.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        totp_disable_route(
            platform.repos.users.clone(),
            platform.mfa.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        // MFA (WebAuthn passkeys)
        webauthn_register_start_route(
            platform.webauthn.clone(),
            platform.repos.webauthn.clone(),
            platform.repos.users.clone(),
            platform.authenticator.clone()
        ),
        webauthn_register_finish_route(
            platform.webauthn.clone(),
            platform.repos.webauthn.clone(),
            platform.repos.users.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        webauthn_login_start_route(
            platform.auth.clone(),
            platform.webauthn.clone(),
            platform.repos.webauthn.clone()
        ),
        webauthn_login_finish_route(
            platform.auth.clone(),
            platform.webauthn.clone(),
            platform.repos.webauthn.clone()
        ),
        // password recovery (both unauthenticated: the link is opened from a mail client)
        forgot_password_route(recovery_deps.clone(), platform.repos.audit.clone()),
        complete_recovery_route(recovery_deps, platform.repos.audit.clone()),
        // what the sign-in screen may offer, before anyone has signed in
        capabilities_route(platform.notifier.clone())
    ]
    .boxed()
}
