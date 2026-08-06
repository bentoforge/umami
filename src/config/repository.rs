//! Loading and saving the whole [`Config`] document.
//!
//! [`ConfigRepository`] is the seam (like `KeyRepository`): [`StaticConfigRepository`] serves a
//! built-in default (dev/tests/no-S3), [`S3ConfigRepository`] keeps the document in S3 with a
//! cached, periodically-refreshed read path and a whole-document write path.

use crate::config::Config;
use anyhow::Context;
use async_trait::async_trait;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use wasabi::aws::s3::{BucketName, CachedObject, S3Client, VersionRetention};

/// Minimum time the S3 config bytes stay cached before a refresh is attempted.
const CONFIG_CACHE_TTL: Duration = Duration::from_secs(900);

/// Default S3 object key for the config document.
const DEFAULT_CONFIG_KEY: &str = "umami/config.json";

/// Reads the optional noncurrent-version retention for the config bucket from the environment:
/// `UMAMI_CONFIG_VERSIONS_KEEP` (keep the newest N) and `UMAMI_CONFIG_VERSIONS_EXPIRE_DAYS`
/// (expire noncurrent versions after N days). Both optional; unset → versioning without expiry.
fn version_retention_from_env() -> anyhow::Result<VersionRetention> {
    fn parse_i32(name: &str) -> anyhow::Result<Option<i32>> {
        match env::var(name) {
            Ok(raw) => {
                Ok(Some(raw.trim().parse::<i32>().with_context(|| {
                    format!("{name} must be a positive integer")
                })?))
            }
            Err(_) => Ok(None),
        }
    }

    Ok(VersionRetention {
        keep_newest: parse_i32("UMAMI_CONFIG_VERSIONS_KEEP")?,
        expire_after_days: parse_i32("UMAMI_CONFIG_VERSIONS_EXPIRE_DAYS")?,
    })
}

/// Source of the configuration document. Pluggable so config can come from S3 now and elsewhere
/// later; both implementations expose the whole document.
#[async_trait]
pub trait ConfigRepository: Send + Sync {
    /// Returns the current config (cached; may refresh internally).
    async fn current(&self) -> anyhow::Result<Arc<Config>>;

    /// Persists the whole config document.
    async fn save(&self, config: Config) -> anyhow::Result<()>;
}

/// In-memory [`ConfigRepository`] serving a default (or last-saved) config. Non-persistent —
/// intended for dev/tests or deployments without an S3 config bucket.
pub struct StaticConfigRepository {
    config: RwLock<Arc<Config>>,
}

impl StaticConfigRepository {
    /// Creates a repository seeded with [`Config::default`].
    pub fn with_default() -> Self {
        Self {
            config: RwLock::new(Arc::new(Config::default())),
        }
    }
}

#[async_trait]
impl ConfigRepository for StaticConfigRepository {
    async fn current(&self) -> anyhow::Result<Arc<Config>> {
        Ok(self.config.read().await.clone())
    }

    async fn save(&self, config: Config) -> anyhow::Result<()> {
        *self.config.write().await = Arc::new(config);
        Ok(())
    }
}

/// S3-backed [`ConfigRepository`]: one `config.json` object, cached for reads, overwritten whole on
/// save. Seeds a default document on first boot if the object is absent.
pub struct S3ConfigRepository {
    cached: Arc<dyn CachedObject>,
    client: S3Client,
    /// Bucket-name **prefix**; the effective bucket is `<prefix>.<S3_BUCKET_SUFFIX>` (wasabi's
    /// naming schema). Stored because [`BucketName`] isn't `Clone`, so we rebuild it per use.
    bucket_prefix: String,
    key: String,
}

impl S3ConfigRepository {
    /// Builds the repository from `UMAMI_CONFIG_BUCKET` (the bucket **prefix**; the effective name
    /// is `<prefix>.<S3_BUCKET_SUFFIX>`) plus optional `UMAMI_CONFIG_KEY`. Provisions the bucket if
    /// absent (mirroring how each repository auto-creates its DynamoDB table on boot), enables
    /// versioning so config edits are recoverable, and seeds a default document if none exists yet.
    pub async fn from_env(client: S3Client) -> anyhow::Result<Self> {
        let bucket_prefix = env::var("UMAMI_CONFIG_BUCKET").context(
            "Please provide UMAMI_CONFIG_BUCKET (the bucket-name prefix) for the S3 config repository",
        )?;
        let key = env::var("UMAMI_CONFIG_KEY").unwrap_or_else(|_| DEFAULT_CONFIG_KEY.to_owned());
        let bucket = BucketName::Prefix(bucket_prefix.clone());
        let effective = client.effective_name(&bucket);

        // Provision the bucket if it doesn't exist yet (idempotent).
        client
            .create_bucket(&bucket)
            .await
            .with_context(|| format!("Failed to provision config bucket '{effective}'"))?;

        // Turn on versioning so a bad config edit can be rolled back to a prior object version,
        // with optional noncurrent-version retention (keep-N / expire-after-days) from the env.
        // Best-effort: a missing `s3:PutBucketVersioning`/`s3:PutLifecycleConfiguration` grant must
        // not make the IAM service unbootable — we log and carry on (the store works fine without).
        let retention = version_retention_from_env()?;
        if let Err(err) = client.enable_versioning(&bucket, Some(retention)).await {
            tracing::warn!(
                "could not enable versioning on config bucket '{effective}' — continuing without \
                 it (grant s3:PutBucketVersioning [+ s3:PutLifecycleConfiguration for retention] \
                 to enable config rollback): {err:#}"
            );
        }

        if client.get_object(&bucket, &key).await.is_err() {
            let bytes = serde_json::to_vec_pretty(&Config::default())
                .context("Failed to serialize default config")?;
            client
                .put_object(&bucket, &key, bytes)
                .await
                .context("Failed to seed default config.json in S3")?;
            tracing::warn!("config.json absent — seeded default at s3://{effective}/{key}");
        }

        let cached = client.cached_object(bucket, &key, CONFIG_CACHE_TTL);

        Ok(Self {
            cached,
            client,
            bucket_prefix,
            key,
        })
    }
}

#[async_trait]
impl ConfigRepository for S3ConfigRepository {
    async fn current(&self) -> anyhow::Result<Arc<Config>> {
        let bytes = self
            .cached
            .fetch_cached()
            .await
            .context("Failed to fetch config.json from S3")?;
        let config: Config =
            serde_json::from_slice(&bytes).context("Failed to parse config.json")?;
        Ok(Arc::new(config))
    }

    async fn save(&self, config: Config) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(&config).context("Failed to serialize config")?;
        self.client
            .put_object(
                &BucketName::Prefix(self.bucket_prefix.clone()),
                &self.key,
                bytes,
            )
            .await
            .context("Failed to write config.json to S3")?;
        // Force the cache to reflect the new document on the next read.
        let _ = self
            .cached
            .fetch_with_flush(true)
            .await
            .context("Failed to refresh config cache after save")?;
        Ok(())
    }
}
