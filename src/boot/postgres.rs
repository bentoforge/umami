//! The one PostgreSQL pool, shared by every seam that picks Postgres.
//!
//! Storage and the config catalog may both run on Postgres, and they should share a pool rather
//! than each opening their own: two pools double the connections a deployment holds for no gain,
//! and two connects at boot are two chances to fail differently. [`Postgres`] is built once in
//! [`Platform::boot`](crate::boot::Platform::boot), like [`Aws`](crate::boot::aws::Aws), and
//! connects lazily — a deployment that picks no Postgres provider never touches it.
//!
//! The connection itself is wasabi's: `POSTGRES_URL`, `POSTGRES_POOL_SIZE` and `POSTGRES_CA_FILE`
//! belong to its naming schema, the way `DYNAMO_TABLE_PREFIX` does.

use tokio::sync::OnceCell;
use wasabi::postgres::Database;

/// The variable whose presence makes Postgres eligible for auto-detection.
pub const URL_VARIABLE: &str = "POSTGRES_URL";

/// The shared pool, connected at most once.
#[derive(Default)]
pub struct Postgres {
    /// The cached outcome. The error is a string because `anyhow::Error` is not `Clone` and every
    /// later caller needs the same answer.
    database: OnceCell<Result<Database, String>>,
}

impl Postgres {
    /// A handle that has not connected yet.
    #[must_use]
    pub fn new() -> Self {
        Postgres::default()
    }

    /// Whether a connection string is set. Says nothing about whether it works — that is
    /// [`Postgres::database`]'s job, and a configured-but-broken database must fail the boot
    /// rather than make a seam fall back.
    pub fn is_configured(&self) -> bool {
        std::env::var(URL_VARIABLE).is_ok_and(|url| !url.trim().is_empty())
    }

    /// Connects on first call, then hands out the same pool.
    pub async fn database(&self) -> anyhow::Result<Database> {
        let outcome = self
            .database
            .get_or_init(|| async {
                match Database::from_env().await {
                    Ok(database) => {
                        tracing::info!("PostgreSQL is usable");
                        Ok(database)
                    }
                    Err(err) => Err(format!("{err:#}")),
                }
            })
            .await;
        match outcome {
            Ok(database) => Ok(database.clone()),
            Err(reason) => Err(anyhow::anyhow!("{reason}")),
        }
    }
}
