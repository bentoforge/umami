//! Email contacts: the caller's own addresses, the verification ceremony, and the admin read.

use crate::boot::Platform;
use crate::contacts::service::{
    add_my_contact_route, delete_my_contact_route, finish_verification_route, my_contacts_route,
    preferred_contact_route, start_verification_route, user_contacts_route,
};
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::routes;

/// Mounts this group on the booted platform.
pub fn routes(platform: &Platform) -> BoxedFilter<(impl warp::Reply + use<>,)> {
    routes![
        // email contacts (self-service)
        my_contacts_route(
            platform.repos.contacts.clone(),
            platform.repos.users.clone(),
            platform.notifier.clone(),
            platform.authenticator.clone()
        ),
        add_my_contact_route(
            platform.repos.contacts.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        delete_my_contact_route(
            platform.repos.contacts.clone(),
            platform.repos.users.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        preferred_contact_route(
            platform.repos.contacts.clone(),
            platform.repos.users.clone(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        // email contacts (verification: mail a challenge, then take the secret back)
        start_verification_route(
            platform.verify_deps(),
            platform.repos.audit.clone(),
            platform.authenticator.clone()
        ),
        finish_verification_route(
            platform.repos.contacts.clone(),
            platform.repos.challenges.clone(),
            platform.repos.audit.clone()
        ),
        // email contacts (admin: read a tenant user's addresses)
        user_contacts_route(
            platform.repos.contacts.clone(),
            platform.authenticator.clone()
        )
    ]
    .boxed()
}
