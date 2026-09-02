//! CORS policies for umami's HTTP surface.
//!
//! Two of them, and they cannot be one: a credentialed allow-list for umami's own SPAs, and a
//! credential-free wildcard for the token exchange that arbitrary partner pages must reach. See
//! [`crate::api::serve`] for why they have to be mounted as separate layers.

use std::env;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;

/// Mounts `route` (the token exchange) with a public, credential-free CORS policy: it answers the
/// preflight itself and sends a **literal** `Access-Control-Allow-Origin: *`.
///
/// Why this endpoint is open to every origin, and why that is not the hole it looks like:
///
/// - The exchange is deliberately cookie- and bearer-free — the API key (or its HMAC proof) *is* the
///   credential — so there is no session for a foreign origin to ride on.
/// - **CORS is not authorization.** What restricts a key to a site is `allowedOrigins` on the key,
///   checked against the request's `Origin` header, which the browser sets and a page cannot forge.
///   That check is untouched by this policy and runs on every exchange.
/// - The cost cap is the rate limit (per IP and per key), which also runs regardless.
///
/// The alternative — every partner's origin in `CORS_ALLOWED_ORIGINS` — would make each new customer
/// a redeploy while adding no security, since the per-key origin list already exists and is editable
/// through the API.
///
/// Two implementation details are deliberate:
///
/// - **A literal `*`, not warp's `allow_any_origin()`.** That helper *reflects* the request's
///   `Origin` back, which (a) would permit credentialed requests the moment someone adds
///   `allow_credentials(true)`, and (b) makes the response origin-dependent without emitting
///   `Vary: Origin` — behind a shared cache such as CloudFront one origin's header could be served to
///   another. A wildcard is credential-proof *by spec* and identical for every caller, so it is both
///   safer and cache-safe.
/// - **Mounted outside the credentialed layer** (see [`crate::api::serve`]), because two CORS
///   layers over one route emit two `Access-Control-Allow-Origin` headers, which browsers reject.
pub fn with_public_exchange_cors<R>(route: BoxedFilter<(R,)>) -> BoxedFilter<(impl warp::Reply,)>
where
    R: warp::Reply + 'static,
{
    let preflight = warp::path!("auth" / "token")
        .and(warp::options())
        .map(exchange_preflight_reply);

    preflight.or(route.map(with_wildcard_origin)).boxed()
}

/// The preflight answer for the token exchange: what a browser must see before it sends the POST.
fn exchange_preflight_reply() -> impl warp::Reply {
    let reply = warp::reply::with_status(warp::reply::reply(), StatusCode::NO_CONTENT);
    let reply = with_wildcard_origin(reply);
    let reply = warp::reply::with_header(reply, "access-control-allow-methods", "POST, OPTIONS");
    let reply = warp::reply::with_header(reply, "access-control-allow-headers", "content-type");
    warp::reply::with_header(reply, "access-control-max-age", "600")
}

/// Adds the literal wildcard origin. Separate so the POST and the preflight cannot drift apart.
fn with_wildcard_origin<R: warp::Reply>(reply: R) -> impl warp::Reply {
    warp::reply::with_header(reply, "access-control-allow-origin", "*")
}

/// Builds a credentialed CORS layer from `CORS_ALLOWED_ORIGINS` (comma-separated exact origins, e.g.
/// `https://spa.myapp.com,https://admin.myapp.com`). Returns `None` when the var is unset/empty, so
/// umami stays CORS-free by default. Credentialed CORS forbids `*`, so origins are an explicit
/// allow-list; the browser must also send `credentials: "include"` for the cookie to travel.
pub fn cors_from_env() -> Option<warp::filters::cors::Cors> {
    let raw = env::var("CORS_ALLOWED_ORIGINS").ok()?;
    let origins = allowed_origins(&raw, env::var("UMAMI_ISSUER").ok().as_deref());
    if origins.is_empty() {
        return None;
    }
    tracing::info!("CORS enabled for origins: {}", origins.join(", "));
    Some(
        warp::cors()
            .allow_origins(origins.iter().map(String::as_str))
            .allow_credentials(true)
            .allow_methods(["GET", "POST", "PATCH", "DELETE", "OPTIONS"])
            .allow_headers(["content-type", "authorization"])
            .max_age(600)
            .build(),
    )
}

/// Assembles the allow-list from the raw `CORS_ALLOWED_ORIGINS` value plus the deployment's
/// own issuer. Empty result means "no CORS layer at all", which is umami's default.
fn allowed_origins(raw: &str, issuer: Option<&str>) -> Vec<String> {
    let mut origins: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| match origin_of(s) {
            Some(origin) => Some(origin),
            // warp's `allow_origins` *panics* on an entry without scheme+host, which
            // would take the whole IAM — and every product's login with it — down over
            // a config typo. Dropping the entry degrades one SPA instead.
            None => {
                tracing::warn!("Ignoring unparsable CORS_ALLOWED_ORIGINS entry '{s}'");
                None
            }
        })
        .collect();
    if origins.is_empty() {
        return origins;
    }

    // The layer wraps *every* API route and warp refuses any `Origin` outside the
    // allow-list — including umami's own. Without this, configuring CORS for an
    // external SPA locks the bundled management UI under /app out of `/auth/login`
    // with a 403, because a same-origin POST carrying JSON still sends `Origin`.
    if let Some(own) = issuer.and_then(origin_of)
        && !origins.contains(&own)
    {
        origins.push(own);
    }
    origins
}

/// Reduces a URL to its CORS origin: scheme + host + port, no path, no trailing slash.
/// `https://iam.example.com/` becomes `https://iam.example.com`. Returns `None` when the
/// input has no scheme or no host — the two things warp requires of an origin.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::http::HeaderValue;
    use wasabi::web::warp::recover_api_errors;

    /// Stand-in for the real exchange route: same path and method, no dependencies.
    fn stub_exchange() -> BoxedFilter<(&'static str,)> {
        warp::path!("auth" / "token")
            .and(warp::post())
            .map(|| "token")
            .boxed()
    }

    #[test]
    fn origin_of_strips_path_and_trailing_slash() {
        assert_eq!(
            origin_of("https://iam.example.com/").as_deref(),
            Some("https://iam.example.com")
        );
        assert_eq!(
            origin_of("http://localhost:8080/.well-known/jwks.json").as_deref(),
            Some("http://localhost:8080")
        );
        assert_eq!(
            origin_of("http://localhost:8080").as_deref(),
            Some("http://localhost:8080")
        );
    }

    #[test]
    fn origin_of_rejects_input_without_scheme_or_host() {
        assert_eq!(origin_of("iam.example.com"), None);
        assert_eq!(origin_of("https://"), None);
        assert_eq!(origin_of("://iam.example.com"), None);
    }

    /// The regression: a CORS config for an external SPA must not lock umami's own
    /// management UI out of its own login.
    #[test]
    fn own_issuer_origin_is_always_allowed() {
        let origins = allowed_origins("https://app.example.com", Some("https://iam.example.com/"));
        assert_eq!(
            origins,
            vec!["https://app.example.com", "https://iam.example.com"]
        );
    }

    #[test]
    fn own_origin_is_not_duplicated() {
        let origins = allowed_origins("https://iam.example.com/", Some("https://iam.example.com/"));
        assert_eq!(origins, vec!["https://iam.example.com"]);
    }

    /// No configured origin means no layer, and no layer means no CORS check — so the
    /// issuer must not single-handedly switch CORS on.
    #[test]
    fn issuer_alone_does_not_enable_cors() {
        assert!(allowed_origins("", Some("https://iam.example.com/")).is_empty());
        assert!(allowed_origins("  , ", Some("https://iam.example.com/")).is_empty());
    }

    /// A typo'd entry is dropped rather than panicking warp at boot.
    #[test]
    fn unparsable_entries_are_dropped_not_fatal() {
        let origins = allowed_origins(
            "not-a-url, https://app.example.com",
            Some("https://iam.example.com/"),
        );
        assert_eq!(
            origins,
            vec!["https://app.example.com", "https://iam.example.com"]
        );
    }

    /// A credentialed layer like `cors_from_env` builds for our own SPAs.
    fn credentialed_cors() -> warp::filters::cors::Cors {
        warp::cors()
            .allow_origins(["https://app.example.com"])
            .allow_credentials(true)
            .allow_methods(["GET", "POST", "OPTIONS"])
            .allow_headers(["content-type", "authorization"])
            .build()
    }

    /// A partner page on an origin nobody configured must still be able to exchange a key.
    #[tokio::test]
    async fn exchange_allows_an_arbitrary_origin() {
        let route = with_public_exchange_cors(stub_exchange());

        let response = warp::test::request()
            .method("POST")
            .path("/auth/token")
            .header("origin", "https://some-shop-we-never-heard-of.example")
            .header("content-type", "application/json")
            .reply(&route)
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("access-control-allow-origin"),
            Some(&HeaderValue::from_static("*"))
        );
    }

    /// The wildcard must stay credential-free. `*` plus `Allow-Credentials: true` is both invalid per
    /// spec and the one change that would turn this open endpoint into a session-leak — so it is
    /// asserted rather than left to review.
    #[tokio::test]
    async fn exchange_never_allows_credentials() {
        let route = with_public_exchange_cors(stub_exchange());

        let response = warp::test::request()
            .method("POST")
            .path("/auth/token")
            .header("origin", "https://attacker.example")
            .reply(&route)
            .await;

        assert!(
            response
                .headers()
                .get("access-control-allow-credentials")
                .is_none(),
            "the public exchange policy must never allow credentials"
        );
    }

    /// The browser's preflight has to be answered by the public layer, or the POST never happens.
    #[tokio::test]
    async fn exchange_answers_the_preflight() {
        let route = with_public_exchange_cors(stub_exchange());

        let response = warp::test::request()
            .method("OPTIONS")
            .path("/auth/token")
            .header("origin", "https://some-shop.example")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .reply(&route)
            .await;

        assert!(
            response.status().is_success(),
            "preflight was {}",
            response.status()
        );
        assert_eq!(
            response.headers().get("access-control-allow-origin"),
            Some(&HeaderValue::from_static("*"))
        );
    }

    /// An error response has to carry the CORS headers too.
    ///
    /// A browser that cannot read a 401 reports a network error, not a 401 — so an app asking
    /// "do I have a session?" cannot tell "no" from "unreachable". The recover layer therefore has
    /// to sit *inside* the CORS wrapper, which is what `serve` composes.
    #[tokio::test]
    async fn rejections_carry_the_allow_origin_header() {
        // A route that always rejects, standing in for "no session".
        let failing = warp::path!("auth" / "refresh")
            .and(warp::post())
            .and_then(|| async {
                Err::<&str, warp::Rejection>(warp::reject::custom(
                    wasabi::web::error::ApiError::new(StatusCode::UNAUTHORIZED, "no session"),
                ))
            });
        let route = recover_api_errors(failing).with(credentialed_cors());

        let response = warp::test::request()
            .method("POST")
            .path("/auth/refresh")
            .header("origin", "https://app.example.com")
            .reply(&route)
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("access-control-allow-origin"),
            Some(&HeaderValue::from_static("https://app.example.com")),
            "a 401 the browser cannot read is indistinguishable from an outage"
        );
    }

    /// Mounting order is the whole point: composed the way `serve` does it, the exchange must carry
    /// **exactly one** `Access-Control-Allow-Origin` header. Two layers over one route emit two, and
    /// browsers reject that — which would look like "CORS is broken" with a correct-looking config.
    #[tokio::test]
    async fn exchange_carries_exactly_one_allow_origin_header() {
        let others = warp::path!("tenants").map(|| "tenants");
        let route = with_public_exchange_cors(stub_exchange()).or(others.with(credentialed_cors()));

        let response = warp::test::request()
            .method("POST")
            .path("/auth/token")
            .header("origin", "https://some-shop.example")
            .reply(&route)
            .await;

        let allow_origin: Vec<_> = response
            .headers()
            .get_all("access-control-allow-origin")
            .iter()
            .collect();

        assert_eq!(allow_origin.len(), 1, "headers: {:?}", response.headers());
        assert_eq!(
            allow_origin.first().copied(),
            Some(&HeaderValue::from_static("*"))
        );
    }
}
