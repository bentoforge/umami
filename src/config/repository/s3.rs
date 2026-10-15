//! The config document in S3: one versioned object, cached for reads.

use super::{ConfigRepository, bump, cache_ttl_from_env, log_cache_ttl, parse_or_default};
use crate::config::Config;
use anyhow::Context;
use async_trait::async_trait;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;
use wasabi::aws::s3::{BucketName, CachedObject, S3Client, VersionRetention};

/// Overrides the default cache TTL for this store, in whole seconds.
const CACHE_TTL_VARIABLE: &str = "UMAMI_CONFIG_S3_CACHE_TTL_SECS";

/// Default S3 object key for the config document.
const DEFAULT_CONFIG_KEY: &str = "umami/config.json";

/// Bucket-name **prefix** for the config bucket. The wasabi naming schema appends
/// `.<S3_BUCKET_SUFFIX>` to form the effective bucket, so this is a fixed prefix — never a full
/// bucket name and not separately configurable.
const CONFIG_BUCKET_PREFIX: &str = "config";

/// Reads the optional noncurrent-version retention for the config bucket from the environment:
/// `UMAMI_CONFIG_S3_VERSIONS_KEEP` (keep the newest N) and `UMAMI_CONFIG_S3_VERSIONS_EXPIRE_DAYS`
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
        keep_newest: parse_i32("UMAMI_CONFIG_S3_VERSIONS_KEEP")?,
        expire_after_days: parse_i32("UMAMI_CONFIG_S3_VERSIONS_EXPIRE_DAYS")?,
    })
}

/// S3-backed [`ConfigRepository`]: one `config.json` object, cached for reads, overwritten whole on
/// save. Seeds a default document on first boot if the object is absent.
pub struct S3ConfigRepository {
    cached: Arc<dyn CachedObject>,
    client: S3Client,
    /// Held across the read-compare-write of a save, so two concurrent editors on this instance
    /// cannot both read the same stored version and both write. It does nothing for a *second*
    /// instance — see [`ConfigRepository::save`] and `docs/CONFIG.md`.
    writing: Mutex<()>,
    /// Bucket-name **prefix**; the effective bucket is `<prefix>.<S3_BUCKET_SUFFIX>` (wasabi's
    /// naming schema). Stored because [`BucketName`] isn't `Clone`, so we rebuild it per use.
    bucket_prefix: String,
    key: String,
}

impl S3ConfigRepository {
    /// Builds the repository for the fixed [`CONFIG_BUCKET_PREFIX`] bucket (effective name
    /// `config.<S3_BUCKET_SUFFIX>`, wasabi naming — analogous to how DynamoDB tables get a fixed
    /// name plus the shared deployment prefix) plus optional `UMAMI_CONFIG_S3_KEY`. Provisions the
    /// bucket if absent (mirroring how each repository auto-creates its DynamoDB table on boot),
    /// enables versioning so config edits are recoverable, and seeds a default document if none
    /// exists yet.
    pub async fn from_env(client: S3Client) -> anyhow::Result<Self> {
        let bucket_prefix = CONFIG_BUCKET_PREFIX.to_owned();
        let key = env::var("UMAMI_CONFIG_S3_KEY").unwrap_or_else(|_| DEFAULT_CONFIG_KEY.to_owned());
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

        let cache_ttl = cache_ttl_from_env(CACHE_TTL_VARIABLE)?;
        log_cache_ttl(CACHE_TTL_VARIABLE, cache_ttl);

        let cached = client.cached_object(bucket, &key, cache_ttl);

        Ok(Self {
            cached,
            client,
            bucket_prefix,
            key,
            writing: Mutex::new(()),
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
        Ok(Arc::new(parse_or_default(&bytes)))
    }

    /// Same fallback as [`ConfigRepository::current`] — deliberately, because a save has to be
    /// checked against the version an editor was shown, and an unparseable document is shown as the
    /// built-in default. Refusing instead would look safer and would lock out the very repair the
    /// fallback exists to allow.
    ///
    /// Refreshes this instance's cache on the way, so the editor's own load is also what unsticks
    /// the instance it happened to reach.
    async fn authoritative(&self) -> anyhow::Result<Config> {
        let bytes = self
            .cached
            .fetch()
            .await
            .context("Failed to fetch config.json from S3")?;
        Ok(parse_or_default(&bytes))
    }

    async fn save(&self, config: Config, expected_version: u64) -> anyhow::Result<Config> {
        let _writing = self.writing.lock().await;

        // Uncached, every time. `current()` may be serving a document up to the cache TTL old,
        // and a guard that compares against that lets a second editor pass it with a version that
        // was already superseded — overwriting the first edit with no error anywhere.
        let stored = self.authoritative().await?;
        let next = bump(config, stored.version, expected_version)?;

        let bytes = serde_json::to_vec_pretty(&next).context("Failed to serialize config")?;
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
        Ok(next)
    }
}
