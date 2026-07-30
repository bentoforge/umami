//! Access-token signing and the public JWKS endpoint.
//!
//! umami is the JWT issuer for the fleet: it signs short-lived ES256 access tokens and publishes
//! the matching **public** keys at `/.well-known/jwks.json`, which every wasabi product service
//! fetches to verify tokens offline.
//!
//! Phase 1 exposes a stub JWKS document with an empty key set so the endpoint is already
//! discoverable. Phase 2 replaces this with the real ES256 public key(s), each carrying a `kid`.

use serde::Serialize;
use warp::Filter;
use warp::filters::BoxedFilter;

/// A JSON Web Key Set as published at `/.well-known/jwks.json`.
///
/// Each entry (once populated in Phase 2) is a public JWK for a signing key, identified by its
/// `kid`. Product services select the key matching the token's `kid` header to verify the
/// signature offline.
#[derive(Serialize, Debug, Default)]
struct JwkSet {
    keys: Vec<serde_json::Value>,
}

/// Route serving umami's public signing keys as a JWKS document.
///
/// Phase 1 returns an empty key set; Phase 2 populates it with the active ES256 public key and
/// any previous keys retained during rotation.
pub fn jwks_route() -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!(".well-known" / "jwks.json")
        .and(warp::get())
        .and_then(handle_jwks)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /.well-known/jwks.json", skip_all)]
async fn handle_jwks() -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::json(&JwkSet::default()))
}
