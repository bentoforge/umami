//! Tenant administration. Create/list/delete are cross-tenant and need `manage:tenants`.

use crate::boot::Platform;
use crate::tenants::service::{
    create_tenant_route, delete_tenant_route, get_tenant_route, list_tenants_route,
    patch_tenant_route,
};
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    routes![
        // tenants (cross-tenant admin: create/list/delete require manage:tenants)
        create_tenant_route(
            platform.repos.tenants.clone(),
            platform.repos.users.clone(),
            platform.config.clone(),
            platform.authenticator.clone()
        ),
        list_tenants_route(
            platform.repos.tenants.clone(),
            platform.authenticator.clone()
        ),
        delete_tenant_route(
            platform.repos.tenants.clone(),
            platform.repos.users.clone(),
            platform.repos.api_keys.clone(),
            platform.system_tenant_id.clone(),
            platform.authenticator.clone()
        ),
        get_tenant_route(
            platform.repos.tenants.clone(),
            platform.authenticator.clone()
        ),
        patch_tenant_route(
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.authenticator.clone()
        )
    ]
    .boxed()
}
