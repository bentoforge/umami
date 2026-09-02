//! Notifications: what a user subscribes to, and who a firing reaches.

use crate::boot::Platform;
use crate::notify::service::{
    audience_route, clear_choice_route, my_notifications_route, report_undeliverable_route,
    send_route, set_choice_route,
};
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    let notify_deps = platform.notify_deps();

    routes![
        // notifications (self-service: what I subscribe to)
        my_notifications_route(notify_deps.clone(), platform.authenticator.clone()),
        set_choice_route(
            notify_deps.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        clear_choice_route(
            notify_deps.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        // notifications (machine: who hears about a firing, then hand the messages over)
        audience_route(
            notify_deps.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        send_route(
            notify_deps,
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        // the mail worker's one endpoint: what it could not deliver
        report_undeliverable_route(
            platform.repos.contacts.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        )
    ]
    .boxed()
}
