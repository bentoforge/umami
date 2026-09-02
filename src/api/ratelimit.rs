//! Read-only inspection of the rate limiter, plus the deployment-wide block overview.

use crate::auth::ratelimit::service::{
    api_key_rate_limit_route, my_pat_rate_limit_route, my_rate_limit_route,
    rate_limit_blocks_route, user_pat_rate_limit_route, user_rate_limit_route,
};
use crate::boot::Platform;
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    routes![
        // rate limits (read-only inspection + the deployment-wide overview)
        my_rate_limit_route(
            platform.config.clone(),
            platform.rate_limiter.clone(),
            platform.authenticator.clone()
        ),
        user_rate_limit_route(
            platform.repos.users.clone(),
            platform.config.clone(),
            platform.rate_limiter.clone(),
            platform.authenticator.clone()
        ),
        api_key_rate_limit_route(
            platform.repos.api_keys.clone(),
            platform.config.clone(),
            platform.rate_limiter.clone(),
            platform.authenticator.clone()
        ),
        my_pat_rate_limit_route(
            platform.repos.api_keys.clone(),
            platform.config.clone(),
            platform.rate_limiter.clone(),
            platform.authenticator.clone()
        ),
        user_pat_rate_limit_route(
            platform.repos.api_keys.clone(),
            platform.repos.users.clone(),
            platform.config.clone(),
            platform.rate_limiter.clone(),
            platform.authenticator.clone()
        ),
        rate_limit_blocks_route(
            platform.rate_limiter.clone(),
            platform.authenticator.clone()
        )
    ]
    .boxed()
}
