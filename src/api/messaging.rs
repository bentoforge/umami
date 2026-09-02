//! Messaging links: the caller's code and links, the admin read, and the machine routes.

use crate::boot::Platform;
use crate::messaging::service::{
    create_link_route, delete_my_link_route, my_code_route, my_links_route, regenerate_code_route,
    resolve_route, user_links_route,
};
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    routes![
        // messaging links (self-service code + own links)
        my_code_route(
            platform.repos.messaging.clone(),
            platform.config.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        regenerate_code_route(
            platform.repos.messaging.clone(),
            platform.config.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        my_links_route(
            platform.repos.messaging.clone(),
            platform.authenticator.clone()
        ),
        delete_my_link_route(
            platform.repos.messaging.clone(),
            platform.authenticator.clone()
        ),
        // messaging links (admin: read a tenant user's links)
        user_links_route(
            platform.repos.messaging.clone(),
            platform.authenticator.clone()
        ),
        // messaging links (machine: link via code + resolve identity)
        create_link_route(
            platform.repos.messaging.clone(),
            platform.config.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        resolve_route(platform.resolve_deps(), platform.authenticator.clone())
    ]
    .boxed()
}
