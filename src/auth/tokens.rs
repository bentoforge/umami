//! Access-token signing (ES256) and the public JWKS endpoint.
//!
//! umami is the JWT issuer for the fleet: it signs short-lived ES256 access tokens and publishes
//! the matching **public** keys at `/.well-known/jwks.json`, which every wasabi product service
//! fetches to verify tokens offline.
//!
//! Signing keys sit behind the [`KeyRepository`] trait so the issuer and JWKS route depend only on
//! the trait, not on where key material lives (env, a secret store, …). The bundled
//! [`EnvKeyRepository`] loads the active signing key from `UMAMI_SIGNING_KEY` and, for a rollover,
//! any retired public keys from `UMAMI_PREVIOUS_KEYS` (kept in the JWKS until their tokens expire).

use anyhow::Context;
use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::SecretKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
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

/// Source of signing key material. Pluggable so the key can come from the environment, a secret
/// store, or anywhere else without changing the issuer or JWKS route.
#[async_trait]
pub trait KeyRepository: Send + Sync {
    /// Returns the current key set. Implementations may cache and refresh internally.
    async fn current(&self) -> anyhow::Result<Arc<KeySet>>;
}

/// [`KeyRepository`] backed by keys loaded from the environment: the active signing JWK
/// (`UMAMI_SIGNING_KEY`) plus optional retired public JWKs (`UMAMI_PREVIOUS_KEYS`) for rollover.
/// Intended for local dev; production loads keys from a secret store.
pub struct EnvKeyRepository {
    key_set: Arc<KeySet>,
}

impl EnvKeyRepository {
    /// Builds the repository from `UMAMI_SIGNING_KEY` — the **active** key that signs, as a private
    /// EC P-256 JWK (carrying its own `kid`) — plus the optional `UMAMI_PREVIOUS_KEYS`, a JSON array
    /// of **public** JWKs kept in the JWKS for verification only during a key rollover, so tokens
    /// signed by a just-retired key still verify until they expire.
    pub fn from_env() -> anyhow::Result<Self> {
        let active_jwk = env::var("UMAMI_SIGNING_KEY").context(
            "Please provide UMAMI_SIGNING_KEY (a private EC P-256 JWK, JSON, with a kid)",
        )?;
        let (pem, kid) = active_key_from_jwk(&active_jwk)?;
        let previous = previous_jwks_from_env()?;

        Ok(Self {
            key_set: Arc::new(build_key_set(&pem, &kid, previous)?),
        })
    }
}

/// Parses the active signing key from a **private** EC P-256 JWK (JSON), returning its PKCS#8 PEM
/// (for the signer) and its `kid`. Using one JWK keeps the active-key config consistent with
/// `UMAMI_PREVIOUS_KEYS` (also JWKs) and carries the key id in the same object as the material.
fn active_key_from_jwk(jwk: &str) -> anyhow::Result<(String, String)> {
    let value: Value = serde_json::from_str(jwk)
        .context("UMAMI_SIGNING_KEY is not valid JSON — it must be a private EC P-256 JWK")?;

    let kid = value
        .get("kid")
        .and_then(Value::as_str)
        .filter(|kid| !kid.is_empty())
        .context("UMAMI_SIGNING_KEY JWK must include a non-empty \"kid\"")?
        .to_owned();

    // `elliptic_curve`'s JWK deserializer rejects **any** member outside
    // kty/crv/x/y/d — including the `kid` this function requires, and the
    // `alg`/`use` that every generator emits (`step crypto jwk create`, node's
    // `export({format:"jwk"})`, jose). Hand it only the five it accepts and keep
    // the metadata on the side. `build_key_set` does the mirror image when it
    // publishes the public half.
    let stripped = strip_to_ec_members(&value)?;

    let secret_key = SecretKey::from_jwk_str(&stripped).map_err(|err| {
        // The crate collapses every failure into an opaque "crypto error", which
        // tells an operator nothing. Say what we handed it instead.
        anyhow::anyhow!(
            "UMAMI_SIGNING_KEY is not a valid private EC P-256 JWK ({err}). Checked members: \
             kty/crv/x/y/d — kty must be \"EC\", crv \"P-256\", and x/y/d base64url of 32 bytes each."
        )
    })?;
    let pem = secret_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("Failed to re-encode the signing key")?
        .to_string();

    Ok((pem, kid))
}

/// Reduces a JWK object to exactly the five members `elliptic_curve` accepts.
///
/// Missing members are named individually: the underlying parser reports nothing
/// useful, and "which field is absent" is the whole diagnosis in practice.
fn strip_to_ec_members(value: &Value) -> anyhow::Result<String> {
    let mut out = serde_json::Map::new();
    for member in ["kty", "crv", "x", "y", "d"] {
        let found = value.get(member).and_then(Value::as_str).with_context(|| {
            if member == "d" {
                format!(
                    "UMAMI_SIGNING_KEY is missing \"{member}\" — this looks like a *public* \
                         JWK; the private key is required for signing"
                )
            } else {
                format!("UMAMI_SIGNING_KEY is missing \"{member}\"")
            }
        })?;
        let _ = out.insert(member.to_owned(), Value::from(found));
    }
    Ok(Value::Object(out).to_string())
}

/// Parses `UMAMI_PREVIOUS_KEYS` (optional) as a JSON array of public JWK objects. Unset/empty ⇒ none.
/// These are published in the JWKS alongside the active key so verifiers can still validate tokens
/// signed by a recently-rotated-out key (selected by the token's `kid`).
fn previous_jwks_from_env() -> anyhow::Result<Vec<Value>> {
    let raw = match env::var("UMAMI_PREVIOUS_KEYS") {
        Ok(raw) if !raw.trim().is_empty() => raw,
        _ => return Ok(Vec::new()),
    };
    let keys: Vec<Value> = serde_json::from_str(&raw)
        .context("UMAMI_PREVIOUS_KEYS must be a JSON array of public JWK objects")?;
    if keys.iter().any(|jwk| !jwk.is_object()) {
        anyhow::bail!("UMAMI_PREVIOUS_KEYS entries must be JWK objects");
    }
    Ok(keys)
}

#[async_trait]
impl KeyRepository for EnvKeyRepository {
    async fn current(&self) -> anyhow::Result<Arc<KeySet>> {
        Ok(self.key_set.clone())
    }
}

/// Builds a [`KeySet`] from the active PEM private key + its key id and any previous public JWKs:
/// an [`EncodingKey`] that signs with the active key, and a JWKS document listing the active key's
/// public JWK first, then the previous keys (for verification during rollover). Previous entries
/// carrying the active `kid` are dropped so the active key is never duplicated.
fn build_key_set(pem: &str, kid: &str, previous: Vec<Value>) -> anyhow::Result<KeySet> {
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

    let mut keys = vec![jwk_value];
    keys.extend(
        previous
            .into_iter()
            .filter(|jwk| jwk.get("kid").and_then(Value::as_str) != Some(kid)),
    );

    Ok(KeySet {
        active_kid: kid.to_owned(),
        encoding_key,
        jwks: json!({ "keys": keys }),
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
    permissions: &'a [String],
    iat: i64,
    exp: i64,
    ver: u32,
    /// Config-driven extra claims (e.g. `features`, selected custom fields), flattened in.
    #[serde(flatten)]
    extra: &'a BTreeMap<String, Value>,
}

/// The inputs needed to mint an access token for a user in a given active tenant.
///
/// Profile claims — email, name, locale — are **not** here. They come from the target API's
/// config-driven claim mapping and arrive via `extra`, so umami puts no personal data in every token
/// by default; a deployment that wants an address in its tokens maps one.
pub struct AccessTokenClaims<'a> {
    /// User id → `sub`.
    pub subject: &'a str,
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

    /// A real generated key, with the `kid`/`alg`/`use` that generators emit.
    const TEST_JWK: &str = r#"{"kty":"EC","x":"lb7Cz8dAfAft8gQ9u4x7eBt6pE9dtTxREGfDZORBLZk","y":"gwm95Jds7UGl6EoeCifp8YO9w4vyiJZjSPf1J-Lp9nk","crv":"P-256","d":"0vtvOGS8yU9z1HXHYCE68_AWDN9xR2_ihZCA_keMsxY","kid":"test-1","alg":"ES256","use":"sig"}"#;

    #[test]
    fn active_key_accepts_a_jwk_with_kid_alg_and_use() {
        // The regression this guards: `elliptic_curve`'s deserializer errors on any
        // member outside kty/crv/x/y/d, so passing the JWK through verbatim made
        // every real-world key fail with an opaque "crypto error" — while the kid
        // this function needs is itself one of the rejected members.
        let (pem, kid) = active_key_from_jwk(TEST_JWK).unwrap();
        assert_eq!(kid, "test-1");
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn active_key_requires_a_kid() {
        let without_kid = r#"{"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB","d":"CCCC"}"#;
        let err = active_key_from_jwk(without_kid).unwrap_err().to_string();
        assert!(err.contains("kid"), "{err}");
    }

    #[test]
    fn active_key_names_the_missing_member() {
        let public_only: Value = serde_json::from_str(TEST_JWK).unwrap();
        let mut map = public_only.as_object().unwrap().clone();
        let _ = map.remove("d");
        let err = active_key_from_jwk(&Value::Object(map).to_string())
            .unwrap_err()
            .to_string();
        // A public JWK is the likeliest wrong input, so it gets named as such.
        assert!(err.contains("public"), "{err}");
    }

    #[test]
    fn active_key_rejects_a_wrong_curve() {
        let p384: Value = serde_json::from_str(TEST_JWK).unwrap();
        let mut map = p384.as_object().unwrap().clone();
        let _ = map.insert("crv".to_owned(), Value::from("P-384"));
        assert!(active_key_from_jwk(&Value::Object(map).to_string()).is_err());
    }

    #[test]
    fn build_key_set_produces_ec_jwk_with_kid() {
        let key_set = build_key_set(TEST_PEM, "test-1", Vec::new()).unwrap();
        let keys = key_set.jwks.get("keys").and_then(Value::as_array).unwrap();
        let jwk = keys.first().unwrap();
        assert_eq!(jwk.get("kty").and_then(Value::as_str), Some("EC"));
        assert_eq!(jwk.get("crv").and_then(Value::as_str), Some("P-256"));
        assert_eq!(jwk.get("kid").and_then(Value::as_str), Some("test-1"));
        assert!(jwk.get("x").and_then(Value::as_str).is_some());
        assert!(jwk.get("y").and_then(Value::as_str).is_some());
    }

    #[test]
    fn jwks_publishes_previous_keys_for_rollover() {
        // A retired public JWK is kept in the JWKS so its tokens still verify; the active key stays
        // first. A previous entry re-using the active kid is dropped (no duplicate).
        let previous = vec![
            json!({ "kty": "EC", "crv": "P-256", "kid": "old-1", "x": "AAAA", "y": "BBBB" }),
            json!({ "kty": "EC", "crv": "P-256", "kid": "test-1", "x": "CCCC", "y": "DDDD" }),
        ];
        let key_set = build_key_set(TEST_PEM, "test-1", previous).unwrap();
        let keys = key_set.jwks.get("keys").and_then(Value::as_array).unwrap();
        let kids: Vec<&str> = keys
            .iter()
            .filter_map(|k| k.get("kid").and_then(Value::as_str))
            .collect();
        assert_eq!(kids, vec!["test-1", "old-1"]); // active first, duplicate active kid dropped
    }

    #[tokio::test]
    async fn issues_a_decodable_es256_token() {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};

        let key_set = Arc::new(build_key_set(TEST_PEM, "test-1", Vec::new()).unwrap());
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
        let key_set = build_key_set(TEST_PEM, "test-1", Vec::new()).unwrap();
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
