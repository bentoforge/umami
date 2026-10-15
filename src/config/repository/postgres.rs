//! The config document in PostgreSQL: one row of a small blob table.
//!
//! The document is stored as bytes, not as `JSONB`, for the same reason S3 stores it as an
//! object: it is read and written whole, and keeping the operator's exact bytes means a document
//! that no longer parses survives intact for repair rather than being rejected on the way in.
//!
//! Unlike S3, Postgres can serialise saves across instances: [`ConfigRepository::save`] locks the
//! row (`SELECT … FOR UPDATE`) for its compare-and-swap, so two editors on two instances cannot
//! both pass the version check.

use super::{ConfigRepository, bump, cache_ttl_from_env, log_cache_ttl, parse_or_default};
use crate::config::Config;
use anyhow::Context;
use async_trait::async_trait;
use chrono::Utc;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use wasabi::postgres::{Column, ColumnType, Database, Table};
use wasabi::record;

const TABLE_BLOBS: &str = "blobs";
const COLUMN_KEY: &str = "key";
const COLUMN_CONTENT: &str = "content";
/// Bumped on every write, so a cache can ask "did it change?" without reading the content.
const COLUMN_REVISION: &str = "revision";
const COLUMN_UPDATED: &str = "updated";

/// Overrides the default cache TTL, in whole seconds. Past the TTL this store checks a revision
/// number by primary key, so a short one costs a cheap query rather than an S3 round trip.
const CACHE_TTL_VARIABLE: &str = "UMAMI_CONFIG_POSTGRES_CACHE_TTL_SECS";

/// Key of the config document in [`TABLE_BLOBS`].
const CONFIG_KEY: &str = "umami/config.json";

static BLOBS: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_BLOBS)
        .column(Column::new(COLUMN_KEY, ColumnType::Text))
        .column(Column::new(COLUMN_CONTENT, ColumnType::Bytea).not_null())
        .column(Column::new(COLUMN_REVISION, ColumnType::BigInt).not_null())
        .column(Column::new(COLUMN_UPDATED, ColumnType::TimestampTz).not_null())
        .primary_key([COLUMN_KEY])
});

/// What [`PostgresConfigRepository::current`] serves between checks.
struct Cached {
    config: Arc<Config>,
    revision: i64,
    checked: Instant,
}

/// PostgreSQL-backed [`ConfigRepository`].
pub struct PostgresConfigRepository {
    database: Database,
    cache: RwLock<Cached>,
    cache_ttl: Duration,
}

impl PostgresConfigRepository {
    /// Builds the store with the cache TTL from `UMAMI_CONFIG_POSTGRES_CACHE_TTL_SECS`.
    pub async fn from_env(database: &Database) -> anyhow::Result<Self> {
        let cache_ttl = cache_ttl_from_env(CACHE_TTL_VARIABLE)?;
        log_cache_ttl(CACHE_TTL_VARIABLE, cache_ttl);
        Self::with_database(database, cache_ttl).await
    }

    /// Creates the blob table if needed, seeds the default document on first boot, and loads it.
    ///
    /// `cache_ttl` bounds how long another instance's save takes to reach this one; past it the
    /// next read checks the row's revision — a primary-key lookup — and reloads only on a change.
    pub async fn with_database(database: &Database, cache_ttl: Duration) -> anyhow::Result<Self> {
        let _ = database
            .ensure_exists(&BLOBS)
            .await
            .context("Cannot provision the PostgreSQL config table")?;

        let client = database.client().await?;
        let default = serde_json::to_vec_pretty(&Config::default())
            .context("Failed to serialize default config")?;
        let seeded = BLOBS
            .insert_if_absent(
                &client,
                record! {
                    COLUMN_KEY => CONFIG_KEY,
                    COLUMN_CONTENT => default,
                    COLUMN_REVISION => 0_i64,
                    COLUMN_UPDATED => Utc::now(),
                },
            )
            .await
            .context("Failed to seed the default config in PostgreSQL")?;
        if seeded {
            tracing::warn!("config absent — seeded the default in PostgreSQL ({CONFIG_KEY})");
        }

        let (config, revision) = load(database).await?;
        Ok(Self {
            database: database.clone(),
            cache: RwLock::new(Cached {
                config: Arc::new(config),
                revision,
                checked: Instant::now(),
            }),
            cache_ttl,
        })
    }

    /// Replaces the cache with what is stored now.
    async fn refresh(&self) -> anyhow::Result<Config> {
        let (config, revision) = load(&self.database).await?;
        *self.cache.write().await = Cached {
            config: Arc::new(config.clone()),
            revision,
            checked: Instant::now(),
        };
        Ok(config)
    }
}

/// The stored document and its revision.
async fn load(database: &Database) -> anyhow::Result<(Config, i64)> {
    let client = database.client().await?;
    let row = BLOBS
        .select_one(&client, record! { COLUMN_KEY => CONFIG_KEY })
        .await
        .context("Failed to read the config from PostgreSQL")?
        .context("The config row is missing from PostgreSQL")?;
    let content: Vec<u8> = row.try_get(COLUMN_CONTENT)?;
    let revision: i64 = row.try_get(COLUMN_REVISION)?;
    Ok((parse_or_default(&content), revision))
}

#[async_trait]
impl ConfigRepository for PostgresConfigRepository {
    async fn current(&self) -> anyhow::Result<Arc<Config>> {
        {
            let cache = self.cache.read().await;
            if cache.checked.elapsed() < self.cache_ttl {
                return Ok(cache.config.clone());
            }
        }

        let client = self.database.client().await?;
        let revision: i64 = client
            .query_one("SELECT revision FROM blobs WHERE key = $1", &[&CONFIG_KEY])
            .await
            .context("Failed to check the config revision in PostgreSQL")?
            .try_get(0)?;

        let mut cache = self.cache.write().await;
        if revision == cache.revision {
            cache.checked = Instant::now();
            return Ok(cache.config.clone());
        }
        drop(cache);
        Ok(Arc::new(self.refresh().await?))
    }

    async fn authoritative(&self) -> anyhow::Result<Config> {
        self.refresh().await
    }

    async fn save(&self, config: Config, expected_version: u64) -> anyhow::Result<Config> {
        let mut client = self.database.client().await?;
        let transaction = client
            .transaction()
            .await
            .context("Failed to start a config transaction")?;

        // The row lock is the compare-and-swap across every instance: a second editor waits here
        // and then compares against the version the first one saved.
        let row = transaction
            .query_one(
                "SELECT content FROM blobs WHERE key = $1 FOR UPDATE",
                &[&CONFIG_KEY],
            )
            .await
            .context("Failed to lock the config in PostgreSQL")?;
        let stored = parse_or_default(&row.try_get::<_, Vec<u8>>(0)?);
        let next = bump(config, stored.version, expected_version)?;

        let bytes = serde_json::to_vec_pretty(&next).context("Failed to serialize config")?;
        let _ = transaction
            .execute(
                "UPDATE blobs SET content = $2, revision = revision + 1, updated = now()
                 WHERE key = $1",
                &[&CONFIG_KEY, &bytes],
            )
            .await
            .context("Failed to write the config to PostgreSQL")?;
        transaction
            .commit()
            .await
            .context("Failed to commit the config")?;

        let _ = self.refresh().await?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::postgres::test::database;

    #[tokio::test]
    async fn saves_are_compare_and_swap_across_instances() {
        let Some(database) = database().await else {
            return;
        };
        let first = PostgresConfigRepository::with_database(&database, Duration::from_secs(60))
            .await
            .unwrap();
        // A second instance on the same database, caching nothing.
        let second = PostgresConfigRepository::with_database(&database, Duration::ZERO)
            .await
            .unwrap();
        let seeded = first.current().await.unwrap().version;

        let saved = first.save(Config::default(), seeded).await.unwrap();
        assert_eq!(saved.version, seeded + 1);
        assert_eq!(second.current().await.unwrap().version, seeded + 1);
        // The first instance's own cache was refreshed by its save.
        assert_eq!(first.current().await.unwrap().version, seeded + 1);

        // The other instance editing from the old version is refused.
        assert!(second.save(Config::default(), seeded).await.is_err());
        assert_eq!(second.authoritative().await.unwrap().version, seeded + 1);
    }

    #[tokio::test]
    async fn concurrent_saves_from_one_version_let_exactly_one_through() {
        let Some(database) = database().await else {
            return;
        };
        let repository = Arc::new(
            PostgresConfigRepository::with_database(&database, Duration::ZERO)
                .await
                .unwrap(),
        );
        let seeded = repository.current().await.unwrap().version;

        let saves = (0..8).map(|_| {
            let repository = repository.clone();
            tokio::spawn(async move { repository.save(Config::default(), seeded).await })
        });
        let mut succeeded = 0;
        for save in saves {
            if save.await.unwrap().is_ok() {
                succeeded += 1;
            }
        }
        assert_eq!(succeeded, 1);
        assert_eq!(repository.current().await.unwrap().version, seeded + 1);
    }

    #[tokio::test]
    async fn a_corrupt_document_reads_as_the_default_and_can_be_repaired() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresConfigRepository::with_database(&database, Duration::ZERO)
            .await
            .unwrap();
        database
            .client()
            .await
            .unwrap()
            .execute(
                "UPDATE blobs SET content = $2, revision = revision + 1 WHERE key = $1",
                &[&CONFIG_KEY, &b"{ not json".to_vec()],
            )
            .await
            .unwrap();

        let shown = repository.authoritative().await.unwrap();
        assert_eq!(shown.version, Config::default().version);
        let repaired = repository.save(shown.clone(), shown.version).await.unwrap();
        assert_eq!(repaired.version, shown.version + 1);
    }
}
