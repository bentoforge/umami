//! `GET /auth/capabilities` — what the sign-in screen may offer, before anyone has signed in.
//!
//! The login page is unauthenticated, so it cannot read the config. Without this it would either
//! show a "forgot password?" link that leads to a dead end on a deployment with no mail path, or
//! never show one at all. Neither is acceptable, so umami states the one fact the screen needs.
//!
//! **Deliberately not a general config peephole.** Every field here is readable by anyone who can
//! reach the login page, so the bar is: does the sign-in screen have to change its own shape because
//! of it? Password recovery does. Anything that merely *interests* an unauthenticated caller does
//! not belong, and neither does anything that says something about a specific account.

use crate::notify::Notifier;
use serde::Serialize;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::web::warp::{into_response, with_cloneable};

/// What the sign-in screen can offer.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Capabilities {
    /// Whether `POST /auth/forgot-password` can actually mail anybody — i.e. whether a mail queue is
    /// configured. `false` ⇒ the screen hides the recovery link rather than offering a dead end.
    password_recovery: bool,
}

/// `GET /auth/capabilities` — public, cacheable, account-independent.
pub fn capabilities_route(notifier: Arc<dyn Notifier>) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "capabilities")
        .and(warp::get())
        .and(with_cloneable(notifier))
        .and_then(handle_capabilities_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /auth/capabilities", skip_all)]
async fn handle_capabilities_route(
    notifier: Arc<dyn Notifier>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(Ok(Capabilities {
        password_recovery: notifier.is_configured(),
    }))
}
