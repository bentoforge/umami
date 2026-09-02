//! Tenant service keys and personal access tokens.
//!
//! The exchange lives here too, as [`exchange`], but is mounted separately by
//! [`crate::api::serve`]: it is the one endpoint arbitrary third-party pages must reach, so it
//! carries its own public CORS policy and cannot sit under the credentialed layer.

use crate::auth::apikeys::{
    create_api_key_route, create_my_pat_route, delete_api_key_route, delete_my_pat_route,
    exchange_route, list_api_keys_route, list_my_pats_route, list_user_pats_route,
};
use crate::boot::Platform;
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    routes![
        // tenant service keys (manage:service-keys)
        create_api_key_route(
            platform.repos.api_keys.clone(),
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.system_tenant_id.clone(),
            platform.authenticator.clone()
        ),
        list_api_keys_route(
            platform.repos.api_keys.clone(),
            platform.authenticator.clone()
        ),
        list_user_pats_route(
            platform.repos.api_keys.clone(),
            platform.authenticator.clone()
        ),
        delete_api_key_route(
            platform.repos.api_keys.clone(),
            platform.authenticator.clone()
        ),
        // personal access tokens (self-service)
        create_my_pat_route(
            platform.repos.api_keys.clone(),
            platform.authenticator.clone()
        ),
        list_my_pats_route(
            platform.repos.api_keys.clone(),
            platform.authenticator.clone()
        ),
        delete_my_pat_route(
            platform.repos.api_keys.clone(),
            platform.authenticator.clone()
        )
    ]
    .boxed()
}

/// `POST /auth/token` — the API-key exchange, mounted on its own by [`crate::api::serve`].
///
/// Kept out of [`routes`] because it needs a public, credential-free CORS policy: it is the one
/// endpoint arbitrary third-party pages call, and two CORS layers over one route emit two
/// `Access-Control-Allow-Origin` headers, which browsers reject.
pub fn exchange(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    exchange_route(
        platform.repos.api_keys.clone(),
        platform.repos.users.clone(),
        platform.repos.tenants.clone(),
        platform.config.clone(),
        platform.tokens.clone(),
        platform.repos.audit.clone(),
        platform.rate_limiter.clone(),
        platform.system_tenant_id.clone(),
        platform.repos.contacts.clone(),
    )
}
