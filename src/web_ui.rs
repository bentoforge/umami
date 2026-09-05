//! Serves the built management UI (a Vite/React SPA) from the umami server itself, plus runtime
//! white-labeling.
//!
//! Mounted under `/app` (the UI is built with Vite `base: "/app/"` and a `BrowserRouter` `basename`
//! of `/app`):
//! - `/app/assets/*` — content-hashed build assets, cached immutably for a year.
//! - `/app/branding.css`, `/app/logo`, `/app/favicon` — white-labeling served from the config
//!   `branding` block (accent CSS, logo, favicon); empty → built-in defaults. `no-cache`.
//! - any other `/app/*` path — falls back to `index.html`, so the client-side router resolves deep
//!   links (a reload of `/app/tenants` still boots the SPA). The HTML shell is revalidated each load.
//! - `/` — redirects to `/app/`.
//!
//! Enabled when `UMAMI_UI_DIR` (default `clients/ui/dist`) contains a built `index.html`; otherwise
//! the routes are not mounted and umami runs API-only.

use crate::config::repository::ConfigRepository;
use base64::Engine;
use std::path::PathBuf;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::filters::fs::File;
use warp::http::Uri;
use warp::reject::Rejection;
use warp::reply::{Reply, Response};
use wasabi::web::warp::with_cloneable;

/// Hashed assets never change under their content-hashed names → cache for a year.
const CACHE_IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// The HTML shell + branding are config-driven → revalidate so a new deploy/edit is picked up.
const CACHE_REVALIDATE: &str = "no-cache";

/// Built-in default brand assets (the `ci/` corporate-identity SVGs), embedded at compile time and
/// served when the config `branding` block leaves the corresponding field empty.
const DEFAULT_FAVICON_SVG: &str = include_str!("../ci/favicon.svg");
/// Wordmark for light backgrounds.
const DEFAULT_LOGO_LIGHT_SVG: &str = include_str!("../ci/logo_light.svg");
/// Wordmark for dark backgrounds.
const DEFAULT_LOGO_DARK_SVG: &str = include_str!("../ci/logo_dark.svg");

/// Builds the UI routes serving the SPA + branding from `ui_dir`, reading white-labeling from
/// `config`. Returns `None` when `ui_dir` has no `index.html`. The `use<>` bound makes the returned
/// reply capture nothing (the routes own their cloned paths + config and are `'static`).
pub fn ui_routes(
    ui_dir: &str,
    config: Arc<dyn ConfigRepository>,
) -> Option<BoxedFilter<(impl Reply + use<>,)>> {
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

    // Runtime white-labeling from the config `branding` block.
    let branding_css = warp::path!("app" / "branding.css")
        .and(warp::get())
        .and(with_cloneable(config.clone()))
        .and_then(|config: Arc<dyn ConfigRepository>| async move {
            Ok::<_, Rejection>(css_response(config).await)
        });
    // Public branding info the SPA reads at runtime (currently the document title).
    let branding_json = warp::path!("app" / "branding.json")
        .and(warp::get())
        .and(with_cloneable(config.clone()))
        .and_then(|config: Arc<dyn ConfigRepository>| async move {
            Ok::<_, Rejection>(branding_json_response(config).await)
        });
    let favicon = warp::path!("app" / "favicon")
        .and(warp::get())
        .and(with_cloneable(config.clone()))
        .and_then(|config: Arc<dyn ConfigRepository>| async move {
            Ok::<_, Rejection>(asset_response(
                branding(&config).await.favicon,
                DEFAULT_FAVICON_SVG,
            ))
        });
    // Two theme variants; each prefers its own, then the theme-neutral `logo`, then the other
    // variant, then a built-in default. The UI picks via <picture media="(prefers-color-scheme:
    // dark)">. A deployment whose light and dark logos are the same sets only `logo`.
    let logo_light = warp::path!("app" / "logo" / "light")
        .and(warp::get())
        .and(with_cloneable(config.clone()))
        .and_then(|config: Arc<dyn ConfigRepository>| async move {
            let brand = branding(&config).await;
            Ok::<_, Rejection>(asset_response(
                brand.logo_light.or(brand.logo.clone()).or(brand.logo_dark),
                DEFAULT_LOGO_LIGHT_SVG,
            ))
        });
    let logo_dark = warp::path!("app" / "logo" / "dark")
        .and(warp::get())
        .and(with_cloneable(config))
        .and_then(|config: Arc<dyn ConfigRepository>| async move {
            let brand = branding(&config).await;
            Ok::<_, Rejection>(asset_response(
                brand.logo_dark.or(brand.logo.clone()).or(brand.logo_light),
                DEFAULT_LOGO_DARK_SVG,
            ))
        });

    // /app/* that maps to a real file (index.html, …) → serve it (revalidated).
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

    Some(
        assets
            .or(branding_css)
            .or(branding_json)
            .or(favicon)
            .or(logo_light)
            .or(logo_dark)
            .or(files)
            .or(fallback)
            .or(root)
            .boxed(),
    )
}

/// Snapshot of the config `branding` block (defaults on any config-read error).
async fn branding(config: &Arc<dyn ConfigRepository>) -> crate::config::BrandingConfig {
    config
        .current()
        .await
        .map(|c| c.branding.clone())
        .unwrap_or_default()
}

/// `/app/branding.css` — the operator's `customCss`, or empty.
async fn css_response(config: Arc<dyn ConfigRepository>) -> Response {
    let css = branding(&config).await.custom_css.unwrap_or_default();
    let reply = warp::reply::with_header(css, "content-type", "text/css; charset=utf-8");
    warp::reply::with_header(reply, "cache-control", CACHE_REVALIDATE).into_response()
}

/// `/app/branding.json` — public branding the SPA reads at runtime; currently the document title
/// (`branding.title`, defaulting to `"umami"`). No auth: it is read before login.
async fn branding_json_response(config: Arc<dyn ConfigRepository>) -> Response {
    let brand = branding(&config).await;
    let title = brand.title.unwrap_or_else(|| "umami".to_owned());
    // The footer travels as the operator wrote it — a bare string, or a per-locale map — and the
    // SPA resolves it against its own current language, so it follows the in-app switcher without a
    // refetch. Null when empty, so the SPA shows no line rather than an empty one.
    let footer = if brand.footer.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::to_value(&brand.footer).unwrap_or(serde_json::Value::Null)
    };
    // The build this binary is: the tag the image was built from, set as `APP_VERSION` by the
    // release pipeline (see the Dockerfile). Absent for a bare `cargo run`, where there is no
    // build to name.
    let version = std::env::var("APP_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let reply = warp::reply::json(&serde_json::json!({
        "title": title,
        "footer": footer,
        "version": version,
    }));
    warp::reply::with_header(reply, "cache-control", CACHE_REVALIDATE).into_response()
}

/// Serves a branding image from `value` (a `data:` URI or `http(s)` URL), falling back to
/// `default_svg` when empty/invalid.
fn asset_response(value: Option<String>, default_svg: &'static str) -> Response {
    let trimmed = value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let reply: Response = match trimmed {
        Some(url) if url.starts_with("http://") || url.starts_with("https://") => {
            match Uri::try_from(url) {
                Ok(uri) => warp::redirect::found(uri).into_response(),
                Err(_) => svg(default_svg),
            }
        }
        Some(data) if data.starts_with("data:") => match parse_data_uri(data) {
            Some((mime, bytes)) => {
                warp::reply::with_header(bytes, "content-type", mime).into_response()
            }
            None => svg(default_svg),
        },
        _ => svg(default_svg),
    };
    warp::reply::with_header(reply, "cache-control", CACHE_REVALIDATE).into_response()
}

/// A default inline SVG reply.
fn svg(body: &'static str) -> Response {
    warp::reply::with_header(body, "content-type", "image/svg+xml").into_response()
}

/// Parses a `data:<mime>[;base64],<data>` URI into `(mime, bytes)`.
fn parse_data_uri(uri: &str) -> Option<(String, Vec<u8>)> {
    let rest = uri.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    let is_base64 = meta.ends_with(";base64");
    let mime = meta.trim_end_matches(";base64");
    let mime = if mime.is_empty() {
        "application/octet-stream"
    } else {
        mime
    };
    let bytes = if is_base64 {
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .ok()?
    } else {
        data.as_bytes().to_vec()
    };
    Some((mime.to_owned(), bytes))
}

#[cfg(test)]
mod tests {
    use super::{parse_data_uri, ui_routes};
    use crate::config::Config;
    use crate::config::repository::{ConfigRepository, StaticConfigRepository};
    use crate::config::text::LocalizedText;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

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
    async fn serves_assets_branding_spa_and_root_redirect() {
        let dir = fixture("umami_web_ui_fixture");
        let config = Arc::new(StaticConfigRepository::with_default());
        let routes = ui_routes(dir.to_str().unwrap(), config).expect("index present");

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

        // Branding CSS (empty by default) → text/css, no-cache.
        let res = warp::test::request()
            .path("/app/branding.css")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 200);
        assert!(
            res.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/css")
        );

        // branding.json → the deployment name, and no footer by default.
        let res = warp::test::request()
            .path("/app/branding.json")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = serde_json::from_slice(res.body()).unwrap();
        assert_eq!(body["title"], "umami");
        assert!(body["footer"].is_null());

        // Favicon + both logo variants default → an SVG.
        for path in ["/app/favicon", "/app/logo/light", "/app/logo/dark"] {
            let res = warp::test::request().path(path).reply(&routes).await;
            assert_eq!(res.status(), 200, "{path}");
            assert_eq!(res.headers()["content-type"], "image/svg+xml", "{path}");
        }

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

    #[tokio::test]
    async fn branding_json_carries_the_configured_footer() {
        let dir = fixture("umami_web_ui_footer_fixture");

        // A footer set on the branding config, seeded through the repository's own save path.
        let mut cfg = Config::default();
        cfg.branding.footer = LocalizedText::from("© Test GmbH");
        let repo = StaticConfigRepository::with_default();
        repo.save(cfg, 1).await.expect("seed footer");

        let routes = ui_routes(dir.to_str().unwrap(), Arc::new(repo)).expect("index present");

        let res = warp::test::request()
            .path("/app/branding.json")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = serde_json::from_slice(res.body()).unwrap();
        // A single-language footer travels as the bare string the operator wrote.
        assert_eq!(body["footer"], "© Test GmbH");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn absent_dir_is_not_mounted() {
        let dir = std::env::temp_dir().join("umami_web_ui_absent");
        let _ = fs::remove_dir_all(&dir);
        let config = Arc::new(StaticConfigRepository::with_default());
        assert!(ui_routes(dir.to_str().unwrap(), config).is_none());
    }

    #[test]
    fn data_uri_is_parsed() {
        // "PNG" base64 of the bytes 1,2,3.
        let (mime, bytes) = parse_data_uri("data:image/png;base64,AQID").unwrap();
        assert_eq!(mime, "image/png");
        assert_eq!(bytes, vec![1, 2, 3]);
        assert!(parse_data_uri("not-a-data-uri").is_none());
    }
}
