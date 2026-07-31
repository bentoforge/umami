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
use wasabi::aws::s3::{BucketName, CachedObject, S3Client};

/// Minimum time the S3 config bytes stay cached before a refresh is attempted.
const CONFIG_CACHE_TTL: Duration = Duration::from_secs(900);

/// Default S3 object key for the config document.
const DEFAULT_CONFIG_KEY: &str = "umami/config.json";

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
    bucket_name: String,
    key: String,
}

impl S3ConfigRepository {
    /// Builds the repository from `UMAMI_CONFIG_BUCKET` (+ optional `UMAMI_CONFIG_KEY`), seeding a
    /// default document if none exists yet.
    pub async fn from_env(client: S3Client) -> anyhow::Result<Self> {
        let bucket_name = env::var("UMAMI_CONFIG_BUCKET")
            .context("Please provide UMAMI_CONFIG_BUCKET for the S3 config repository")?;
        let key = env::var("UMAMI_CONFIG_KEY").unwrap_or_else(|_| DEFAULT_CONFIG_KEY.to_owned());

        if client
            .get_object(&BucketName::FullyQualifiedName(bucket_name.clone()), &key)
            .await
            .is_err()
        {
            let bytes = serde_json::to_vec_pretty(&Config::default())
                .context("Failed to serialize default config")?;
            client
                .put_object(
                    &BucketName::FullyQualifiedName(bucket_name.clone()),
                    &key,
                    bytes,
                )
                .await
                .context("Failed to seed default config.json in S3")?;
            tracing::warn!("config.json absent — seeded default at s3://{bucket_name}/{key}");
        }

        let cached = client.cached_object(
            BucketName::FullyQualifiedName(bucket_name.clone()),
            &key,
            CONFIG_CACHE_TTL,
        );

        Ok(Self {
            cached,
            client,
            bucket_name,
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
                &BucketName::FullyQualifiedName(self.bucket_name.clone()),
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
