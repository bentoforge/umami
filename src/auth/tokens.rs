//! Access-token signing (ES256) and the public JWKS endpoint.
//!
//! umami is the JWT issuer for the fleet: it signs short-lived ES256 access tokens and publishes
//! the matching **public** keys at `/.well-known/jwks.json`, which every wasabi product service
//! fetches to verify tokens offline.
//!
//! Signing keys sit behind the [`KeyRepository`] trait so the source of key material is pluggable.
//! Phase 2 ships [`EnvKeyRepository`] (key from `UMAMI_SIGNING_KEY`); a future AWS-backed
//! implementation with a periodic refresh (for rotation) drops in without touching the issuer or
//! the JWKS route.

use anyhow::Context;
use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::SecretKey;
use p256::pkcs8::DecodePrivateKey;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use wasabi::web::warp::{into_rejection, with_cloneable};

/// A resolved set of signing keys: the active private key for signing plus the public JWKS
/// document (active key, and any retained previous keys during rotation).
pub struct KeySet {
    /// `kid` of the active signing key, written into the token header so verifiers can select it.
    pub active_kid: String,
    /// Private key material used to sign new access tokens (ES256).
    pub encoding_key: EncodingKey,
    /// The public JWKS document served at `/.well-known/jwks.json` (`{"keys":[...]}`).
    pub jwks: Value,
}

/// Source of signing key material. Pluggable so keys can come from env now and from an
/// AWS secret (with periodic refresh for rotation) later.
#[async_trait]
pub trait KeyRepository: Send + Sync {
    /// Returns the current key set. Implementations may cache and refresh internally.
    async fn current(&self) -> anyhow::Result<Arc<KeySet>>;
}

/// [`KeyRepository`] backed by a single key loaded from the environment (`UMAMI_SIGNING_KEY`,
/// `UMAMI_SIGNING_KID`). Intended for local dev; production loads keys from a secret store.
pub struct EnvKeyRepository {
    key_set: Arc<KeySet>,
}

impl EnvKeyRepository {
    /// Builds the repository from `UMAMI_SIGNING_KEY` (PKCS#8 PEM, P-256) and `UMAMI_SIGNING_KID`.
    pub fn from_env() -> anyhow::Result<Self> {
        let pem = env::var("UMAMI_SIGNING_KEY")
            .context("Please provide UMAMI_SIGNING_KEY (ES256/P-256 private key PEM)")?;
        let kid = env::var("UMAMI_SIGNING_KID")
            .context("Please provide UMAMI_SIGNING_KID (key id published in JWKS)")?;

        Ok(Self {
            key_set: Arc::new(build_key_set(&pem, &kid)?),
        })
    }
}

#[async_trait]
impl KeyRepository for EnvKeyRepository {
    async fn current(&self) -> anyhow::Result<Arc<KeySet>> {
        Ok(self.key_set.clone())
    }
}

/// Builds a [`KeySet`] from a PEM private key and its key id: an [`EncodingKey`] for signing and
/// the public JWK (derived from the key) for the JWKS document.
fn build_key_set(pem: &str, kid: &str) -> anyhow::Result<KeySet> {
    let encoding_key =
        EncodingKey::from_ec_pem(pem.as_bytes()).context("Invalid ES256 private key PEM")?;

    let secret_key =
        SecretKey::from_pkcs8_pem(pem).context("Invalid PKCS#8 P-256 private key PEM")?;
    let jwk = secret_key.public_key().to_jwk();

    let mut jwk_value = serde_json::to_value(&jwk).context("Failed to encode public JWK")?;
    if let Value::Object(map) = &mut jwk_value {
        let _ = map.insert("kid".to_owned(), Value::from(kid));
        let _ = map.insert("alg".to_owned(), Value::from("ES256"));
        let _ = map.insert("use".to_owned(), Value::from("sig"));
    }

    Ok(KeySet {
        active_kid: kid.to_owned(),
        encoding_key,
        jwks: json!({ "keys": [jwk_value] }),
    })
}

/// The wasabi-compatible access-token claim set. Field names match the `CLAIM_*` constants that
/// `wasabi::web::auth::User` reads; `ver` is a custom claim carrying the `tokenVersion` snapshot.
#[derive(Serialize, Debug)]
struct AccessClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<&'a str>,
    name: &'a str,
    email: &'a str,
    locale: &'a str,
    permissions: &'a [String],
    iat: i64,
    exp: i64,
    ver: u32,
    /// Config-driven extra claims (e.g. `features`, selected custom fields), flattened in.
    #[serde(flatten)]
    extra: &'a BTreeMap<String, Value>,
}

/// The inputs needed to mint an access token for a user in a given active tenant.
pub struct AccessTokenClaims<'a> {
    /// User id → `sub`.
    pub subject: &'a str,
    /// Display name → `name`.
    pub name: &'a str,
    /// Email → `email`.
    pub email: &'a str,
    /// BCP-47 locale → `locale`.
    pub locale: &'a str,
    /// Active tenant → `tenant` (omitted when `None`).
    pub tenant: Option<&'a str>,
    /// Target audience → `aud` (falls back to the issuer's default when `None`).
    pub audience: Option<&'a str>,
    /// Effective permissions for the active tenant → `permissions`.
    pub permissions: &'a [String],
    /// `user.tokenVersion` snapshot → `ver`.
    pub token_version: u32,
    /// Config-driven extra claims flattened into the token (e.g. `features`).
    pub extra: &'a BTreeMap<String, Value>,
}

/// Issues signed ES256 access tokens with wasabi-compatible claims.
pub struct TokenIssuer {
    keys: Arc<dyn KeyRepository>,
    issuer: String,
    default_audience: Option<String>,
}

impl TokenIssuer {
    /// Builds the issuer from the environment: `UMAMI_ISSUER` (required, must match the issuer
    /// product services trust) and `UMAMI_DEFAULT_AUDIENCE` (optional). The access-token lifetime
    /// comes from the config `security` settings, passed per call.
    pub fn from_env(keys: Arc<dyn KeyRepository>) -> anyhow::Result<Self> {
        let issuer = env::var("UMAMI_ISSUER")
            .context("Please provide UMAMI_ISSUER (e.g. https://umami.example.com/)")?;
        let default_audience = env::var("UMAMI_DEFAULT_AUDIENCE").ok();

        Ok(Self {
            keys,
            issuer,
            default_audience,
        })
    }

    /// Signs an access token for the given user/tenant with the given lifetime (from config).
    /// Returns the token string and its `exp` (epoch seconds).
    #[tracing::instrument(level = "debug", skip(self, request), err(Display))]
    pub async fn issue_access_token(
        &self,
        request: &AccessTokenClaims<'_>,
        access_ttl_secs: i64,
    ) -> anyhow::Result<(String, i64)> {
        let key_set = self.keys.current().await?;

        let iat = Utc::now().timestamp();
        let exp = iat + access_ttl_secs;

        let claims = AccessClaims {
            iss: &self.issuer,
            sub: request.subject,
            aud: request.audience.or(self.default_audience.as_deref()),
            tenant: request.tenant,
            name: request.name,
            email: request.email,
            locale: request.locale,
            permissions: request.permissions,
            iat,
            exp,
            ver: request.token_version,
            extra: request.extra,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(key_set.active_kid.clone());

        let token = encode(&header, &claims, &key_set.encoding_key)
            .context("Failed to sign access token")?;

        Ok((token, exp))
    }
}

/// Route serving umami's public signing keys as a JWKS document.
pub fn jwks_route(keys: Arc<dyn KeyRepository>) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!(".well-known" / "jwks.json")
        .and(warp::get())
        .and(with_cloneable(keys))
        .and_then(handle_jwks)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /.well-known/jwks.json", skip_all)]
async fn handle_jwks(keys: Arc<dyn KeyRepository>) -> Result<impl warp::Reply, warp::Rejection> {
    match keys.current().await {
        Ok(key_set) => Ok(warp::reply::json(&key_set.jwks)),
        Err(err) => Err(into_rejection(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway P-256 key generated for tests only.
    const TEST_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg61z7vocO8Rp4xh4K\nNDDjbirPq3fNO0fehJ576NWRbWWhRANCAATG1iHEz7UbK3nLIOj3d5mH10dvD8lG\nSOszLsd/jAjXBR/K60sLlqY6FNRjN5u8oWNt2pcRhjKufIbi4WGlVDHk\n-----END PRIVATE KEY-----\n";

    struct StaticKeys(Arc<KeySet>);

    #[async_trait]
    impl KeyRepository for StaticKeys {
        async fn current(&self) -> anyhow::Result<Arc<KeySet>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn build_key_set_produces_ec_jwk_with_kid() {
        let key_set = build_key_set(TEST_PEM, "test-1").unwrap();
        let keys = key_set.jwks.get("keys").and_then(Value::as_array).unwrap();
        let jwk = keys.first().unwrap();
        assert_eq!(jwk.get("kty").and_then(Value::as_str), Some("EC"));
        assert_eq!(jwk.get("crv").and_then(Value::as_str), Some("P-256"));
        assert_eq!(jwk.get("kid").and_then(Value::as_str), Some("test-1"));
        assert!(jwk.get("x").and_then(Value::as_str).is_some());
        assert!(jwk.get("y").and_then(Value::as_str).is_some());
    }

    #[tokio::test]
    async fn issues_a_decodable_es256_token() {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};

        let key_set = Arc::new(build_key_set(TEST_PEM, "test-1").unwrap());
        let keys: Arc<dyn KeyRepository> = Arc::new(StaticKeys(key_set));
        let issuer = TokenIssuer {
            keys,
            issuer: "https://umami.test/".to_owned(),
            default_audience: Some("umami".to_owned()),
        };

        let perms = vec!["write:blocks".to_owned()];
        let extra = BTreeMap::new();
        let (token, exp) = issuer
            .issue_access_token(
                &AccessTokenClaims {
                    subject: "u1",
                    name: "Jane",
                    email: "jane@test",
                    locale: "en-US",
                    tenant: Some("t1"),
                    audience: None,
                    permissions: &perms,
                    token_version: 3,
                    extra: &extra,
                },
                600,
            )
            .await
            .unwrap();
        assert!(exp > Utc::now().timestamp());

        // Verify offline exactly the way a product service would: reconstruct the public key from
        // the JWK's x/y components (what a JWKS consumer does).
        let key_set = build_key_set(TEST_PEM, "test-1").unwrap();
        let jwk = key_set
            .jwks
            .get("keys")
            .and_then(Value::as_array)
            .and_then(|keys| keys.first())
            .unwrap();
        let x = jwk.get("x").and_then(Value::as_str).unwrap();
        let y = jwk.get("y").and_then(Value::as_str).unwrap();
        let decoding = DecodingKey::from_ec_components(x, y).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&["https://umami.test/"]);
        validation.set_audience(&["umami"]);
        let decoded = jsonwebtoken::decode::<Value>(&token, &decoding, &validation).unwrap();

        assert_eq!(
            decoded.claims.get("sub").and_then(Value::as_str),
            Some("u1")
        );
        assert_eq!(
            decoded.claims.get("tenant").and_then(Value::as_str),
            Some("t1")
        );
        assert_eq!(decoded.claims.get("ver").and_then(Value::as_u64), Some(3));
    }
}
