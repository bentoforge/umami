//! The global config catalog and its settings.

use crate::boot::Platform;
use crate::config::service::{custom_fields_route, get_config_route, put_config_route};
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    routes![
        // config (global catalog + settings)
        get_config_route(platform.config.clone(), platform.authenticator.clone()),
        custom_fields_route(platform.config.clone(), platform.authenticator.clone()),
        put_config_route(platform.config.clone(), platform.authenticator.clone())
    ]
    .boxed()
}
