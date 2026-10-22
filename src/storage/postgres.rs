//! PostgreSQL-backed storage.
//!
//! ## How an entity becomes a row
//!
//! Every table holds the entity whole, as `data JSONB` in the same camelCase shape the DynamoDB
//! backend stores, plus the columns a query needs as real, typed columns: keys, lookup fields,
//! sort fields, the optimistic-lock `version`, an expiry. Reads always come from `data`; the
//! columns exist to be indexed and filtered on. So an entity field that no query touches costs no
//! schema change, and the two backends can never disagree about what an entity looks like.
//!
//! A write that changes a column-backed field must update the column and `data` together — that
//! is the one invariant this layout asks for.
//!
//! ## Expiry
//!
//! DynamoDB deletes expired items by itself; Postgres does not. Tables with an expiry carry
//! `expires_at TIMESTAMPTZ`, every read filters on it, and writes sweep expired rows of their own
//! table opportunistically, so dead rows neither show nor pile up.
//!
//! ## Where the repositories live
//!
//! Next to their traits, as `<domain>/repository/postgres.rs`. This module only bundles them and
//! holds what every Postgres repository shares.
//!
//! ## Schema
//!
//! Each repository declares its tables with wasabi's `Table` and calls `ensure_exists` from
//! `with_database`, which creates a missing table and applies every change that cannot lose
//! data. Changes that could (a dropped column) are withheld and logged for an operator.

use crate::audit::repository::postgres::PostgresAuditRepository;
use crate::auth::apikeys::repository::postgres::PostgresApiKeyRepository;
use crate::auth::challenge::postgres::PostgresChallengeRepository;
use crate::auth::ratelimit::repository::postgres::PostgresRateLimitRepository;
use crate::auth::session::repository::postgres::PostgresSessionRepository;
use crate::auth::webauthn::repository::postgres::PostgresWebauthnRepository;
use crate::contacts::repository::postgres::PostgresContactRepository;
use crate::limits::repository::postgres::PostgresLimitRepository;
use crate::messaging::repository::postgres::PostgresMessagingRepository;
use crate::recipients::repository::postgres::PostgresRecipientRepository;
use crate::storage::Repositories;
use crate::tenants::repository::postgres::PostgresTenantRepository;
use crate::users::repository::postgres::PostgresUserRepository;
use anyhow::Context;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use wasabi::postgres::{Database, Row, Table};

/// The column holding the whole entity.
pub const COLUMN_DATA: &str = "data";

/// Builds every repository against one pool, creating or migrating the tables it needs.
#[tracing::instrument(skip_all, err(level = "debug", Display))]
pub async fn repositories(database: &Database) -> anyhow::Result<Repositories> {
    Ok(Repositories {
        users: Arc::new(PostgresUserRepository::with_database(database).await?),
        sessions: Arc::new(PostgresSessionRepository::with_database(database).await?),
        tenants: Arc::new(PostgresTenantRepository::with_database(database).await?),
        api_keys: Arc::new(PostgresApiKeyRepository::with_database(database).await?),
        audit: Arc::new(PostgresAuditRepository::with_database(database).await?),
        contacts: Arc::new(PostgresContactRepository::with_database(database).await?),
        challenges: Arc::new(PostgresChallengeRepository::with_database(database).await?),
        messaging: Arc::new(PostgresMessagingRepository::with_database(database).await?),
        rate_limits: Arc::new(PostgresRateLimitRepository::with_database(database).await?),
        webauthn: Arc::new(PostgresWebauthnRepository::with_database(database).await?),
        limits: Arc::new(PostgresLimitRepository::with_database(database).await?),
        recipients: Arc::new(PostgresRecipientRepository::with_database(database).await?),
    })
}

/// Creates or migrates `table`. A withheld change is already logged by wasabi; it does not stop
/// the boot, because the code keeps working against the wider schema it leaves behind.
pub async fn ensure_table(database: &Database, table: &Table) -> anyhow::Result<()> {
    let _ = database
        .ensure_exists(table)
        .await
        .with_context(|| format!("Cannot provision PostgreSQL table '{}'", table.name()))?;
    Ok(())
}

/// The entity as the JSON stored in [`COLUMN_DATA`].
pub fn to_data<T: Serialize>(entity: &T) -> anyhow::Result<serde_json::Value> {
    serde_json::to_value(entity).context("Failed to serialize entity for PostgreSQL")
}

/// The entity stored in a row's [`COLUMN_DATA`].
pub fn from_row<T: DeserializeOwned>(row: &Row) -> anyhow::Result<T> {
    let data: serde_json::Value = row
        .try_get(COLUMN_DATA)
        .context("Row has no readable 'data' column")?;
    serde_json::from_value(data).context("Failed to deserialize entity from PostgreSQL")
}

/// A `u64` counter as the `BIGINT` Postgres stores. Counters never come near `i64::MAX`, but a
/// silent wrap would turn an optimistic lock into a lottery, so the conversion is checked.
pub fn to_bigint(value: u64) -> anyhow::Result<i64> {
    i64::try_from(value).context("Counter exceeds the BIGINT range")
}

/// Test support: an isolated database per test, or `None` to skip.
#[cfg(test)]
pub mod test {
    use wasabi::postgres::Database;

    /// A pool on a fresh schema of `POSTGRES_TEST_URL`, so tests run in parallel without seeing
    /// each other's tables. `None` when the variable is unset — `cargo test` stays green on a
    /// machine without a database.
    pub async fn database() -> Option<Database> {
        let url = std::env::var("POSTGRES_TEST_URL").ok()?;
        let schema = format!("umami_test_{}", rand::random::<u32>());

        let admin = Database::connect(&url, 1, None)
            .await
            .expect("POSTGRES_TEST_URL is set but unreachable");
        admin
            .client()
            .await
            .unwrap()
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .await
            .unwrap();

        let separator = if url.contains('?') { '&' } else { '?' };
        let scoped = format!("{url}{separator}options=-csearch_path%3D{schema}");
        Some(Database::connect(&scoped, 4, None).await.unwrap())
    }
}
