//! The built-in config, in memory and lost on restart.

use super::{ConfigRepository, bump};
use crate::config::Config;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

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

    /// The same read — this store *is* the stored document, so there is no cache to look past.
    async fn authoritative(&self) -> anyhow::Result<Config> {
        Ok((**self.config.read().await).clone())
    }

    async fn save(&self, config: Config, expected_version: u64) -> anyhow::Result<Config> {
        // The write lock spans the comparison and the swap, which is the whole compare-and-swap.
        let mut stored = self.config.write().await;
        let next = bump(config, stored.version, expected_version)?;
        *stored = Arc::new(next.clone());
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_in_memory_store_enforces_the_same_rule() {
        let store = StaticConfigRepository::with_default();
        let seeded = store.current().await.expect("seeded").version;

        let saved = store
            .save(Config::default(), seeded)
            .await
            .expect("should save");
        assert_eq!(saved.version, seeded + 1);
        assert_eq!(store.current().await.expect("stored").version, seeded + 1);

        // The same body a second time is now stale, and must not go through.
        assert!(store.save(Config::default(), seeded).await.is_err());
        assert_eq!(store.current().await.expect("stored").version, seeded + 1);
    }
}
