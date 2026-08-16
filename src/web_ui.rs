//! Serves the built management UI (a Vite/React SPA) from the umami server itself.
//!
//! Mounted under `/app` (the UI is built with Vite `base: "/app/"` and a `BrowserRouter` `basename`
//! of `/app`):
//! - `/app/assets/*` — content-hashed build assets, cached immutably for a year.
//! - any other `/app/*` path — falls back to `index.html`, so the client-side router resolves deep
//!   links (a reload of `/app/tenants` still boots the SPA). The HTML shell is revalidated each load.
//! - `/` — redirects to `/app/`.
//!
//! Enabled when `UMAMI_UI_DIR` (default `clients/ui/dist`) contains a built `index.html`; otherwise
//! the routes are not mounted and umami runs API-only.

use std::path::PathBuf;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::filters::fs::File;
use warp::http::Uri;
use warp::reply::Reply;

/// Hashed assets never change under their content-hashed names → cache for a year.
const CACHE_IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// The HTML shell must be revalidated so a new deploy is picked up (fs sets ETag/Last-Modified,
/// so revalidation is a cheap 304 when unchanged).
const CACHE_REVALIDATE: &str = "no-cache";

/// Builds the UI routes serving the SPA from `ui_dir`, or `None` when it has no `index.html`.
/// The `use<>` bound makes the returned reply capture nothing — the routes own their (cloned) paths
/// and are `'static`, independent of the borrowed `ui_dir`.
pub fn ui_routes(ui_dir: &str) -> Option<BoxedFilter<(impl Reply + use<>,)>> {
    let dir = PathBuf::from(ui_dir);
    let index = dir.join("index.html");
    if !index.is_file() {
        return None;
    }

    // /app/assets/* → the content-hashed bundles, cached immutably.
    let assets = warp::path("app")
        .and(warp::path("assets"))
        .and(warp::fs::dir(dir.join("assets")))
        .map(|file: File| warp::reply::with_header(file, "cache-control", CACHE_IMMUTABLE));

    // /app/* that maps to a real file (index.html, favicon, …) → serve it (revalidated).
    let files = warp::path("app")
        .and(warp::fs::dir(dir))
        .map(|file: File| warp::reply::with_header(file, "cache-control", CACHE_REVALIDATE));

    // Any remaining /app/* (a client route like /app/tenants) → the SPA shell. `path::tail` consumes
    // the rest of the path so the route matches; the file served is always index.html.
    let fallback = warp::path("app")
        .and(warp::path::tail())
        .and(warp::fs::file(index))
        .map(|_tail: warp::path::Tail, file: File| {
            warp::reply::with_header(file, "cache-control", CACHE_REVALIDATE)
        });

    // Bare root → the app.
    let root = warp::path::end()
        .and(warp::get())
        .map(|| warp::redirect::found(Uri::from_static("/app/")));

    Some(assets.or(files).or(fallback).or(root).boxed())
}

#[cfg(test)]
mod tests {
    use super::ui_routes;
    use std::fs;
    use std::path::PathBuf;

    /// Materialises a minimal built-SPA layout in a temp dir.
    fn fixture(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("assets")).unwrap();
        fs::write(
            dir.join("index.html"),
            "<!doctype html><div id=\"root\"></div>",
        )
        .unwrap();
        fs::write(dir.join("assets/app.js"), "console.log(1)").unwrap();
        dir
    }

    #[tokio::test]
    async fn serves_assets_spa_fallback_and_root_redirect() {
        let dir = fixture("umami_web_ui_fixture");
        let routes = ui_routes(dir.to_str().unwrap()).expect("index present");

        // Hashed asset → immutable cache.
        let res = warp::test::request()
            .path("/app/assets/app.js")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 200);
        assert_eq!(
            res.headers()["cache-control"],
            "public, max-age=31536000, immutable"
        );

        // Deep client route → index.html shell (SPA), revalidated.
        let res = warp::test::request()
            .path("/app/tenants")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 200);
        assert!(String::from_utf8_lossy(res.body()).contains("id=\"root\""));
        assert_eq!(res.headers()["cache-control"], "no-cache");

        // Bare root → redirect to the app.
        let res = warp::test::request().path("/").reply(&routes).await;
        assert_eq!(res.status(), 302);
        assert_eq!(res.headers()["location"], "/app/");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn absent_dir_is_not_mounted() {
        let dir = std::env::temp_dir().join("umami_web_ui_absent");
        let _ = fs::remove_dir_all(&dir);
        assert!(ui_routes(dir.to_str().unwrap()).is_none());
    }
}
