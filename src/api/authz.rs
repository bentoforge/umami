//! Authorization management: what a caller may assign, and feature grants.

use crate::authz::{
    assignable_features_route, assignable_roles_route, assignable_scopes_route,
    grant_feature_route, revoke_feature_route,
};
use crate::boot::Platform;
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    routes![
        // authorization management (assignable roles/scopes/features + feature grant/revoke)
        assignable_roles_route(
            platform.repos.users.clone(),
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.system_tenant_id.clone(),
            platform.authenticator.clone()
        ),
        assignable_scopes_route(
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.system_tenant_id.clone(),
            platform.authenticator.clone()
        ),
        assignable_features_route(
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.system_tenant_id.clone(),
            platform.authenticator.clone()
        ),
        grant_feature_route(
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.system_tenant_id.clone(),
            platform.authenticator.clone()
        ),
        revoke_feature_route(
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.authenticator.clone()
        )
    ]
    .boxed()
}
