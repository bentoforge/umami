//! Limits: per-tenant quota settings, and the booking surface (check/consume/report/top-up).
//! Ledger and history routes land with those stores.

use crate::boot::Platform;
use crate::limits::service::{
    check_limit_route, consume_limit_route, history_route, ledger_route, list_limits_route,
    report_gauge_route, set_limit_settings_route, topup_limit_route,
};
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    routes![
        list_limits_route(
            platform.repos.tenants.clone(),
            platform.repos.limits.clone(),
            platform.authenticator.clone()
        ),
        set_limit_settings_route(
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.repos.limits.clone(),
            platform.authenticator.clone()
        ),
        check_limit_route(
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.repos.limits.clone(),
            platform.authenticator.clone()
        ),
        consume_limit_route(
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.repos.limits.clone(),
            platform.authenticator.clone()
        ),
        report_gauge_route(
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.repos.limits.clone(),
            platform.authenticator.clone()
        ),
        topup_limit_route(
            platform.repos.tenants.clone(),
            platform.config.clone(),
            platform.repos.limits.clone(),
            platform.authenticator.clone()
        ),
        ledger_route(
            platform.repos.limits.clone(),
            platform.authenticator.clone()
        ),
        history_route(
            platform.repos.limits.clone(),
            platform.authenticator.clone()
        )
    ]
    .boxed()
}
