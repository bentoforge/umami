//! Refresh-cookie construction and parsing.
//!
//! The refresh cookie is `HttpOnly; Path=/auth` plus `Secure` and `SameSite` from
//! [`CookiePolicy`], so it is sent only to umami's auth endpoints and is never readable by
//! JavaScript. Its value is `"<sessionId>.<refreshSecret>"`.

use crate::constants::REFRESH_COOKIE_NAME;
use cookie::time::Duration;
use cookie::{Cookie, SameSite};
use std::env;

/// Path the refresh cookie is scoped to — only umami's auth endpoints receive it.
const REFRESH_COOKIE_PATH: &str = "/auth";

/// The two refresh-cookie attributes a deployment may need to change.
///
/// Both default to the strict values and exist for two narrow, real situations:
///
/// - **`secure = false`** — umami served over plain `http://localhost` in local development.
///   Chrome and Firefox accept `Secure` cookies from localhost (it counts as a trustworthy
///   origin), Safari does not, so a local run is browser-dependent without this.
/// - **`same_site = None`** — an app on a genuinely different registrable domain than umami.
///   Note this is *necessary but not sufficient*: such a cookie is third-party, which Safari
///   blocks outright and Chrome restricts. Prefer putting umami and its apps on one site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookiePolicy {
    /// `Secure` attribute. Default `true`.
    pub secure: bool,
    /// `SameSite` attribute. Default `Lax`.
    pub same_site: SameSite,
}

impl Default for CookiePolicy {
    fn default() -> Self {
        Self {
            secure: true,
            same_site: SameSite::Lax,
        }
    }
}

impl CookiePolicy {
    /// Reads `UMAMI_COOKIE_SECURE` and `UMAMI_COOKIE_SAMESITE`, falling back to the strict
    /// defaults. Warns on every loosened value so a relaxed production deployment is visible in
    /// the boot log.
    pub fn from_env() -> anyhow::Result<Self> {
        let policy = Self::parse(
            env::var("UMAMI_COOKIE_SECURE").ok().as_deref(),
            env::var("UMAMI_COOKIE_SAMESITE").ok().as_deref(),
        )?;

        if !policy.secure {
            tracing::warn!(
                "UMAMI_COOKIE_SECURE=false — the refresh cookie is sent over plain HTTP. Intended \
                 for local development only."
            );
        }
        if policy.same_site == SameSite::None {
            tracing::warn!(
                "UMAMI_COOKIE_SAMESITE=none — the refresh cookie becomes a third-party cookie for \
                 cross-site apps. Safari blocks these outright and Chrome restricts them."
            );
        }

        Ok(policy)
    }

    /// The parsing itself, separated from the environment so it is testable without mutating
    /// process-global state (which racing parallel tests cannot do safely). Empty or absent
    /// values keep the default.
    pub fn parse(secure: Option<&str>, same_site: Option<&str>) -> anyhow::Result<Self> {
        let mut policy = Self::default();

        if let Some(value) = secure.map(str::trim).filter(|v| !v.is_empty()) {
            policy.secure = match value.to_ascii_lowercase().as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                other => {
                    anyhow::bail!("UMAMI_COOKIE_SECURE must be true or false, got '{other}'")
                }
            };
        }

        if let Some(value) = same_site.map(str::trim).filter(|v| !v.is_empty()) {
            policy.same_site = match value.to_ascii_lowercase().as_str() {
                "lax" => SameSite::Lax,
                "strict" => SameSite::Strict,
                "none" => SameSite::None,
                other => anyhow::bail!(
                    "UMAMI_COOKIE_SAMESITE must be lax, strict or none, got '{other}'"
                ),
            };
        }

        // Browsers reject `SameSite=None` without `Secure`, so such a cookie is simply dropped.
        // Failing at boot beats a deployment where nobody can stay logged in.
        if policy.same_site == SameSite::None && !policy.secure {
            anyhow::bail!(
                "UMAMI_COOKIE_SAMESITE=none requires UMAMI_COOKIE_SECURE=true — browsers reject \
                 SameSite=None cookies without the Secure attribute"
            );
        }

        Ok(policy)
    }
}

/// Builds the `Set-Cookie` header value carrying `"<session_id>.<secret>"`.
///
/// `domain` sets the cookie `Domain` attribute when non-empty (omit for host-only cookies).
pub fn build_refresh_cookie(
    session_id: &str,
    secret: &str,
    domain: Option<&str>,
    max_age_secs: i64,
    policy: CookiePolicy,
) -> String {
    let value = format!("{session_id}.{secret}");
    let mut builder = Cookie::build((REFRESH_COOKIE_NAME, value))
        .http_only(true)
        .secure(policy.secure)
        .same_site(policy.same_site)
        .path(REFRESH_COOKIE_PATH)
        .max_age(Duration::seconds(max_age_secs));

    if let Some(domain) = domain.filter(|value| !value.is_empty()) {
        builder = builder.domain(domain.to_owned());
    }

    builder.build().to_string()
}

/// Builds the `Set-Cookie` header value that clears the refresh cookie (logout).
pub fn clear_refresh_cookie(domain: Option<&str>, policy: CookiePolicy) -> String {
    let mut builder = Cookie::build((REFRESH_COOKIE_NAME, ""))
        .http_only(true)
        .secure(policy.secure)
        .same_site(policy.same_site)
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
    #[test]
    fn cookie_policy_defaults_to_strict() {
        let policy = CookiePolicy::default();
        assert!(policy.secure);
        assert_eq!(policy.same_site, SameSite::Lax);
        // Absent env vars must not loosen anything.
        assert_eq!(CookiePolicy::parse(None, None).unwrap(), policy);
        // An empty value is "unset", not "false" — a blank env var in a compose file must not
        // silently strip Secure.
        assert_eq!(CookiePolicy::parse(Some(""), Some("  ")).unwrap(), policy);
    }

    #[test]
    fn cookie_policy_parses_both_attributes() {
        let policy = CookiePolicy::parse(Some("false"), Some("strict")).unwrap();
        assert!(!policy.secure);
        assert_eq!(policy.same_site, SameSite::Strict);

        assert!(!CookiePolicy::parse(Some("0"), None).unwrap().secure);
        assert!(CookiePolicy::parse(Some("TRUE"), None).unwrap().secure);
        assert_eq!(
            CookiePolicy::parse(None, Some("None")).unwrap().same_site,
            SameSite::None
        );
    }

    #[test]
    fn cookie_policy_rejects_garbage() {
        assert!(CookiePolicy::parse(Some("yes"), None).is_err());
        assert!(CookiePolicy::parse(None, Some("laxx")).is_err());
    }

    #[test]
    fn cookie_policy_rejects_samesite_none_without_secure() {
        // Browsers drop such a cookie outright; refusing at boot surfaces it immediately.
        let err = CookiePolicy::parse(Some("false"), Some("none")).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires UMAMI_COOKIE_SECURE=true")
        );
    }

    #[test]
    fn built_cookie_reflects_the_policy() {
        let strict = build_refresh_cookie("sid", "sec", None, 60, CookiePolicy::default());
        assert!(strict.contains("Secure"));
        assert!(strict.contains("SameSite=Lax"));
        assert!(strict.contains("HttpOnly"));
        assert!(strict.contains("Path=/auth"));

        let local = build_refresh_cookie(
            "sid",
            "sec",
            None,
            60,
            CookiePolicy::parse(Some("false"), None).unwrap(),
        );
        assert!(!local.contains("Secure"));
        assert!(local.contains("SameSite=Lax"));

        // Clearing must carry the same attributes, or the browser keeps the original cookie.
        let cleared = clear_refresh_cookie(None, CookiePolicy::parse(Some("false"), None).unwrap());
        assert!(!cleared.contains("Secure"));
        assert!(cleared.contains("Max-Age=0"));
    }

    use super::*;

    #[test]
    fn build_sets_security_attributes() {
        let header = build_refresh_cookie(
            "sid",
            "sec",
            Some("example.com"),
            3600,
            CookiePolicy::default(),
        );
        assert!(header.contains("umami_refresh=sid.sec"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Path=/auth"));
        assert!(header.contains("Domain=example.com"));
    }

    #[test]
    fn build_omits_domain_when_absent() {
        let header = build_refresh_cookie("sid", "sec", None, 3600, CookiePolicy::default());
        assert!(!header.contains("Domain="));
    }

    #[test]
    fn parse_roundtrips_build() {
        let header =
            build_refresh_cookie("sid123", "secretval", None, 3600, CookiePolicy::default());
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
