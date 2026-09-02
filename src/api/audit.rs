//! Reading the security audit trail.

use crate::audit::service::{my_audit_route, tenant_audit_route};
use crate::boot::Platform;
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    routes![
        // audit log (read)
        tenant_audit_route(platform.repos.audit.clone(), platform.authenticator.clone()),
        my_audit_route(platform.repos.audit.clone(), platform.authenticator.clone())
    ]
    .boxed()
}
