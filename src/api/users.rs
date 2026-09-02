//! User administration within the caller's own tenant.

use crate::boot::Platform;
use crate::users::service::{
    create_user_route, delete_user_route, get_user_route, list_users_route, logout_user_route,
    patch_user_route, reset_password_route, user_audit_route, user_sessions_route,
};
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    routes![
        // users (admin, within own tenant)
        create_user_route(
            platform.repos.users.clone(),
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.system_tenant_id.clone(),
            platform.authenticator.clone()
        ),
        list_users_route(
            platform.repos.users.clone(),
            platform.config.clone(),
            platform.authenticator.clone()
        ),
        get_user_route(
            platform.repos.users.clone(),
            platform.config.clone(),
            platform.authenticator.clone()
        ),
        patch_user_route(
            platform.repos.users.clone(),
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.repos.audit.clone(),
            platform.system_tenant_id.clone(),
            platform.authenticator.clone()
        ),
        delete_user_route(platform.repos.users.clone(), platform.authenticator.clone()),
        reset_password_route(
            platform.repos.users.clone(),
            platform.config.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        user_audit_route(
            platform.repos.users.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        user_sessions_route(
            platform.repos.users.clone(),
            platform.repos.sessions.clone(),
            platform.authenticator.clone()
        ),
        logout_user_route(platform.repos.users.clone(), platform.authenticator.clone())
    ]
    .boxed()
}
