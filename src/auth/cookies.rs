//! Refresh-cookie construction and parsing.
//!
//! The refresh cookie is `HttpOnly; Secure; SameSite=Lax; Path=/auth`, so it is sent only to
//! umami's auth endpoints and is never readable by JavaScript. Its value is
//! `"<sessionId>.<refreshSecret>"`.

use crate::constants::REFRESH_COOKIE_NAME;
use cookie::time::Duration;
use cookie::{Cookie, SameSite};

/// Path the refresh cookie is scoped to — only umami's auth endpoints receive it.
const REFRESH_COOKIE_PATH: &str = "/auth";

/// Builds the `Set-Cookie` header value carrying `"<session_id>.<secret>"`.
///
/// `domain` sets the cookie `Domain` attribute when non-empty (omit for host-only cookies).
pub fn build_refresh_cookie(
    session_id: &str,
    secret: &str,
    domain: Option<&str>,
    max_age_secs: i64,
) -> String {
    let value = format!("{session_id}.{secret}");
    let mut builder = Cookie::build((REFRESH_COOKIE_NAME, value))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path(REFRESH_COOKIE_PATH)
        .max_age(Duration::seconds(max_age_secs));

    if let Some(domain) = domain.filter(|value| !value.is_empty()) {
        builder = builder.domain(domain.to_owned());
    }

    builder.build().to_string()
}

/// Builds the `Set-Cookie` header value that clears the refresh cookie (logout).
pub fn clear_refresh_cookie(domain: Option<&str>) -> String {
    let mut builder = Cookie::build((REFRESH_COOKIE_NAME, ""))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path(REFRESH_COOKIE_PATH)
        .max_age(Duration::seconds(0));

    if let Some(domain) = domain.filter(|value| !value.is_empty()) {
        builder = builder.domain(domain.to_owned());
    }

    builder.build().to_string()
}

/// Extracts `(session_id, secret)` from a raw `Cookie` request header, if the refresh cookie is
/// present and well-formed.
pub fn parse_refresh_cookie(cookie_header: Option<&str>) -> Option<(String, String)> {
    let header = cookie_header?;

    for cookie in Cookie::split_parse(header).flatten() {
        if cookie.name() == REFRESH_COOKIE_NAME {
            let (session_id, secret) = cookie.value().split_once('.')?;
            if session_id.is_empty() || secret.is_empty() {
                return None;
            }
            return Some((session_id.to_owned(), secret.to_owned()));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sets_security_attributes() {
        let header = build_refresh_cookie("sid", "sec", Some("example.com"), 3600);
        assert!(header.contains("umami_refresh=sid.sec"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Path=/auth"));
        assert!(header.contains("Domain=example.com"));
    }

    #[test]
    fn build_omits_domain_when_absent() {
        let header = build_refresh_cookie("sid", "sec", None, 3600);
        assert!(!header.contains("Domain="));
    }

    #[test]
    fn parse_roundtrips_build() {
        let header = build_refresh_cookie("sid123", "secretval", None, 3600);
        // A request Cookie header carries just "name=value".
        let request_cookie = header.split(';').next().unwrap();
        let parsed = parse_refresh_cookie(Some(request_cookie)).unwrap();
        assert_eq!(parsed, ("sid123".to_owned(), "secretval".to_owned()));
    }

    #[test]
    fn parse_returns_none_for_missing_or_malformed() {
        assert!(parse_refresh_cookie(None).is_none());
        assert!(parse_refresh_cookie(Some("other=1")).is_none());
        assert!(parse_refresh_cookie(Some("umami_refresh=nodot")).is_none());
    }
}
