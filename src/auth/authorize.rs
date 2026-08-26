//! `GET /auth/authorize` — the hosted-login redirect.
//!
//! An app sends the browser here, umami makes sure a session exists, and the browser comes back.
//! That is the whole flow: **there is no authorization code and no token in the response.**
//!
//! ## Why no code
//!
//! An OAuth authorization code exists to carry a credential across a boundary the browser will not
//! carry it over. umami is deployed *per environment*, next to the apps it serves (see the README),
//! so umami and the app are normally **same-site** — and the browser carries the refresh cookie for
//! them itself. The app returns from the redirect and calls `POST /auth/refresh?api=…` with
//! `credentials: "include"`, exactly as it would have anyway. A code would be a second credential
//! handing over what the first one already delivered, plus a table, a TTL, single-use enforcement,
//! reuse detection and PKCE to protect it.
//!
//! If a deployment ever puts umami on a *different registrable domain* than the app, the cookie
//! stops working cross-site and a code exchange becomes necessary. That is the point to add one —
//! not before.
//!
//! ## What `state` is for
//!
//! Round-trip integrity, not authentication: the app generates it, umami echoes it back verbatim,
//! and the app checks it recognises the value. That is what tells the app *it* started this
//! redirect, and it is where the app stashes which page to return to.
//!
//! ## Why `redirect_uri` must be allow-listed
//!
//! Without the allow-list this endpoint is an open redirector, and the IAM domain lends
//! credibility to whatever it points at. Matching is **exact** — prefix matching is the classic
//! hole (`https://app.example.com.evil.test` prefix-matches `https://app.example.com`).

use crate::auth::AuthContext;
use crate::auth::cookies::parse_refresh_cookie;
use crate::config::Config;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::Uri;
use warp::http::status::StatusCode;
use warp::reply::Reply;
use wasabi::web::warp::with_cloneable;

/// Query for `GET /auth/authorize`.
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AuthorizeQuery {
    /// Where to send the browser back to. Must match `security.redirectUris` exactly.
    redirect_uri: String,
    /// Opaque value echoed back unchanged, for the app's own round-trip check.
    #[serde(default)]
    state: Option<String>,
}

/// `GET /auth/authorize?redirectUri=…&state=…` — ensure a session, then bounce back.
///
/// Deliberately not guarded by a bearer: the caller is a browser mid-navigation that has no token
/// yet. The refresh cookie is the only credential in play, and `SameSite=Lax` does travel with a
/// top-level navigation like this one (unlike a background `fetch`).
pub fn authorize_route(context: AuthContext) -> BoxedFilter<(impl Reply,)> {
    warp::path!("auth" / "authorize")
        .and(warp::get())
        .and(with_cloneable(Arc::new(context)))
        .and(warp::query::<AuthorizeQuery>())
        .and(warp::header::optional::<String>("cookie"))
        .then(handle_authorize)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /auth/authorize", skip_all)]
async fn handle_authorize(
    context: Arc<AuthContext>,
    query: AuthorizeQuery,
    cookie_header: Option<String>,
) -> Box<dyn Reply> {
    let config = match context.config.current().await {
        Ok(config) => config,
        Err(err) => {
            tracing::error!("authorize could not read the config: {err:#}");
            return bad_request("Configuration unavailable");
        }
    };

    if !is_allowed_redirect(&config, &query.redirect_uri) {
        // Deliberately terse and identical for "not configured" and "not on the list": the caller
        // is an unauthenticated browser, and telling it which URLs *are* allowed helps nobody but
        // someone probing.
        tracing::warn!(
            "authorize refused redirect_uri '{}' — not in security.redirectUris",
            query.redirect_uri
        );
        return bad_request("redirect_uri is not allowed");
    }

    if has_live_session(&context, cookie_header.as_deref()).await {
        redirect_to(&build_return_url(
            &query.redirect_uri,
            query.state.as_deref(),
        ))
    } else {
        // No session: hand off to the hosted login page, which returns here once it has one. The
        // `next` target is this very request, so the decision above is re-made with a cookie in
        // hand — the login page never has to understand redirect_uri or state.
        redirect_to(&login_url(&query))
    }
}

/// Exact-match check against `security.redirectUris`. An empty list disables the flow.
fn is_allowed_redirect(config: &Config, candidate: &str) -> bool {
    config
        .security
        .redirect_uris
        .iter()
        .any(|allowed| allowed == candidate)
}

/// Whether the cookie names a session that is still usable.
///
/// Only presence and expiry are checked, not the refresh secret: this endpoint issues nothing, it
/// only decides "does this browser need to see the login page". The secret is verified where it
/// matters, on `POST /auth/refresh`. A revoked-but-unexpired session therefore gets bounced back
/// and fails at the refresh — one extra round trip, no false authentication.
async fn has_live_session(context: &AuthContext, cookie_header: Option<&str>) -> bool {
    let Some((session_id, _secret)) = parse_refresh_cookie(cookie_header) else {
        return false;
    };
    match context.sessions.get_session(&session_id).await {
        Ok(Some(session)) => !session.is_expired(chrono::Utc::now()),
        Ok(None) => false,
        Err(err) => {
            tracing::warn!("authorize could not load session '{session_id}': {err:#}");
            false
        }
    }
}

/// `redirect_uri` with `state` appended, preserving any query string it already had.
fn build_return_url(redirect_uri: &str, state: Option<&str>) -> String {
    match state {
        Some(state) => {
            let separator = if redirect_uri.contains('?') { '&' } else { '?' };
            format!(
                "{redirect_uri}{separator}state={}",
                utf8_percent_encode(state, NON_ALPHANUMERIC)
            )
        }
        None => redirect_uri.to_owned(),
    }
}

/// The hosted login page, told where to come back to.
fn login_url(query: &AuthorizeQuery) -> String {
    let mut next = format!(
        "/auth/authorize?redirectUri={}",
        utf8_percent_encode(&query.redirect_uri, NON_ALPHANUMERIC)
    );
    if let Some(state) = &query.state {
        next.push_str(&format!(
            "&state={}",
            utf8_percent_encode(state, NON_ALPHANUMERIC)
        ));
    }
    format!(
        "/app/login?next={}",
        utf8_percent_encode(&next, NON_ALPHANUMERIC)
    )
}

fn redirect_to(location: &str) -> Box<dyn Reply> {
    match location.parse::<Uri>() {
        Ok(uri) => Box::new(warp::redirect::found(uri)),
        Err(err) => {
            tracing::warn!("authorize built an unparseable redirect '{location}': {err}");
            bad_request("redirect_uri is not a valid URL")
        }
    }
}

fn bad_request(message: &'static str) -> Box<dyn Reply> {
    Box::new(warp::reply::with_status(message, StatusCode::BAD_REQUEST))
}

#[cfg(test)]
mod tests {
    use super::*;
    use percent_encoding::percent_decode_str;

    fn config_with(uris: &[&str]) -> Config {
        let mut config = Config::default();
        config.security.redirect_uris = uris.iter().map(|s| (*s).to_owned()).collect();
        config
    }

    #[test]
    fn empty_allowlist_disables_the_flow() {
        let config = config_with(&[]);
        assert!(!is_allowed_redirect(&config, "https://app.example.com/cb"));
    }

    #[test]
    fn matching_is_exact() {
        let config = config_with(&["https://app.example.com/cb"]);
        assert!(is_allowed_redirect(&config, "https://app.example.com/cb"));

        // The prefix-matching trap: a hostile host that *starts with* an allowed one.
        assert!(!is_allowed_redirect(
            &config,
            "https://app.example.com.evil.test/cb"
        ));
        // Nor is a deeper path on an allowed origin allowed.
        assert!(!is_allowed_redirect(
            &config,
            "https://app.example.com/cb/../elsewhere"
        ));
        // Scheme and trailing slash are part of the value.
        assert!(!is_allowed_redirect(&config, "http://app.example.com/cb"));
        assert!(!is_allowed_redirect(&config, "https://app.example.com/cb/"));
    }

    #[test]
    fn state_is_appended_and_encoded() {
        assert_eq!(
            build_return_url("https://app.example.com/cb", Some("a b&c")),
            "https://app.example.com/cb?state=a%20b%26c"
        );
        // An existing query string is kept.
        assert_eq!(
            build_return_url("https://app.example.com/cb?x=1", Some("s")),
            "https://app.example.com/cb?x=1&state=s"
        );
        assert_eq!(
            build_return_url("https://app.example.com/cb", None),
            "https://app.example.com/cb"
        );
    }

    #[test]
    fn login_url_round_trips_through_next() {
        let query = AuthorizeQuery {
            redirect_uri: "https://app.example.com/cb".to_owned(),
            state: Some("xyz".to_owned()),
        };
        let url = login_url(&query);
        assert!(url.starts_with("/app/login?next="));
        // The login page must be able to hand control straight back to authorize, so the whole
        // authorize URL — redirect_uri and state included — has to survive the encoding.
        let next = url.trim_start_matches("/app/login?next=");
        let decoded = percent_decode_str(next).decode_utf8().unwrap();
        assert!(decoded.starts_with("/auth/authorize?redirectUri="));
        assert!(decoded.contains("state=xyz"));
    }
}
