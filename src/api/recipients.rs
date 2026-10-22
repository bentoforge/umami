//! External recipients (ADR 0021): the tenant admin's list, and the recipient's own side behind
//! the links in its mails.

use crate::boot::Platform;
use crate::recipients::service::{
    confirm_recipient_route, create_recipient_route, delete_recipient_route, list_recipients_route,
    manage_choices_route, manage_view_route, patch_recipient_route, resend_confirmation_route,
    unsubscribe_route,
};
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    let deps = platform.recipient_deps();

    routes![
        // external recipients (admin: a tenant's addresses with no login)
        list_recipients_route(deps.clone(), platform.authenticator.clone()),
        create_recipient_route(
            deps.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        patch_recipient_route(
            deps.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        delete_recipient_route(
            deps.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        resend_confirmation_route(
            deps.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        // external recipients (the mailbox itself, behind a mailed token)
        confirm_recipient_route(deps.clone(), platform.repos.audit.clone()),
        manage_view_route(deps.clone()),
        manage_choices_route(deps.clone(), platform.repos.audit.clone()),
        unsubscribe_route(deps, platform.repos.audit.clone())
    ]
    .boxed()
}
