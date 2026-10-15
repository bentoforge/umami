//! PostgreSQL persistence for limit state, ledger and history.
//!
//! The booking rules live in [`crate::limits::accounting`]; this backend only has to make
//! [`LimitRepository::compare_and_swap`] all-or-nothing. It does so with one transaction: the
//! state row under its version guard, the ledger entries, and the history row if-not-exists. Any
//! guard that misses rolls the whole transaction back and reports [`CasOutcome::Conflict`], exactly
//! where the DynamoDB backend's `TransactWriteItems` would be cancelled.
//!
//! Amounts are `i64` and live inside `data`; no counter is computed in SQL, so the database never
//! does arithmetic on them and no exact-decimal column type is needed.

use super::{
    CasOutcome, LimitRepository, READ_PAGE_SIZE, decode_ledger_cursor, encode_ledger_cursor,
    ledger_sort_key,
};
use crate::limits::{HistoryRow, LedgerEntry, LimitState, accounting::Outcome};
use crate::storage::postgres::{COLUMN_DATA, ensure_table, from_row, to_bigint, to_data};
use anyhow::Context;
use async_trait::async_trait;
use std::sync::LazyLock;
use wasabi::postgres::{Column, ColumnType, Database, Index, Record, Table};
use wasabi::record;

const TABLE_LIMIT_STATE: &str = "limit_state";
const TABLE_LIMIT_LEDGER: &str = "limit_ledger";
const TABLE_LIMIT_HISTORY: &str = "limit_history";

const COLUMN_TENANT_ID: &str = "tenant_id";
const COLUMN_LIMIT_CODE: &str = "limit_code";
const COLUMN_VERSION: &str = "version";
/// The DynamoDB ledger sort key, `{code}#{timestamp}#{id}`, kept verbatim so a page cursor means
/// the same thing on both backends.
const COLUMN_LEDGER_SK: &str = "ledger_sk";
const COLUMN_YEAR_MONTH: &str = "year_month";

static LIMIT_STATE: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_LIMIT_STATE)
        .column(Column::new(COLUMN_TENANT_ID, ColumnType::Text))
        .column(Column::new(COLUMN_LIMIT_CODE, ColumnType::Text))
        .column(Column::new(COLUMN_VERSION, ColumnType::BigInt).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_TENANT_ID, COLUMN_LIMIT_CODE])
});

static LIMIT_LEDGER: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_LIMIT_LEDGER)
        .column(Column::new(COLUMN_TENANT_ID, ColumnType::Text))
        .column(Column::new(COLUMN_LEDGER_SK, ColumnType::Text))
        .column(Column::new(COLUMN_LIMIT_CODE, ColumnType::Text).not_null())
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_TENANT_ID, COLUMN_LEDGER_SK])
        // A page filters on the code by equality rather than a `LIKE 'code#%'` prefix: under a
        // non-C collation a prefix match cannot use the index, and every consume adds a row here.
        .index(Index::new(
            "by_limit",
            [COLUMN_TENANT_ID, COLUMN_LIMIT_CODE, COLUMN_LEDGER_SK],
        ))
});

static LIMIT_HISTORY: LazyLock<Table> = LazyLock::new(|| {
    Table::new(TABLE_LIMIT_HISTORY)
        .column(Column::new(COLUMN_TENANT_ID, ColumnType::Text))
        .column(Column::new(COLUMN_LIMIT_CODE, ColumnType::Text))
        .column(Column::new(COLUMN_YEAR_MONTH, ColumnType::Text))
        .column(Column::new(COLUMN_DATA, ColumnType::Jsonb).not_null())
        .primary_key([COLUMN_TENANT_ID, COLUMN_LIMIT_CODE, COLUMN_YEAR_MONTH])
});

/// PostgreSQL-backed implementation of [`LimitRepository`].
#[derive(Clone)]
pub struct PostgresLimitRepository {
    database: Database,
}

impl PostgresLimitRepository {
    /// Builds the repository, creating or migrating its tables.
    #[tracing::instrument(skip(database), err(level = "debug", Display))]
    pub async fn with_database(database: &Database) -> anyhow::Result<Self> {
        ensure_table(database, &LIMIT_STATE).await?;
        ensure_table(database, &LIMIT_LEDGER).await?;
        ensure_table(database, &LIMIT_HISTORY).await?;
        Ok(Self {
            database: database.clone(),
        })
    }

    fn state_row(state: &LimitState) -> anyhow::Result<Record> {
        Ok(record! {
            COLUMN_TENANT_ID => state.tenant_id.as_str(),
            COLUMN_LIMIT_CODE => state.code.as_str(),
            COLUMN_VERSION => to_bigint(state.version)?,
            COLUMN_DATA => to_data(state)?,
        })
    }

    fn ledger_row(entry: &LedgerEntry) -> anyhow::Result<Record> {
        Ok(record! {
            COLUMN_TENANT_ID => entry.tenant_id.as_str(),
            COLUMN_LEDGER_SK => ledger_sort_key(entry),
            COLUMN_LIMIT_CODE => entry.code.as_str(),
            COLUMN_DATA => to_data(entry)?,
        })
    }

    fn history_row(row: &HistoryRow) -> anyhow::Result<Record> {
        Ok(record! {
            COLUMN_TENANT_ID => row.tenant_id.as_str(),
            COLUMN_LIMIT_CODE => row.code.as_str(),
            COLUMN_YEAR_MONTH => row.year_month.as_str(),
            COLUMN_DATA => to_data(row)?,
        })
    }
}

#[async_trait]
impl LimitRepository for PostgresLimitRepository {
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn load_state(&self, tenant_id: &str, code: &str) -> anyhow::Result<Option<LimitState>> {
        let client = self.database.client().await?;
        LIMIT_STATE
            .select_one(
                &client,
                record! { COLUMN_TENANT_ID => tenant_id, COLUMN_LIMIT_CODE => code },
            )
            .await
            .context("Error reading 'limit_state'")?
            .map(|row| from_row(&row))
            .transpose()
    }

    #[tracing::instrument(level = "debug", skip(self, outcome), err(level = "debug", Display))]
    async fn compare_and_swap(
        &self,
        outcome: &Outcome,
        expected_version: Option<u64>,
    ) -> anyhow::Result<CasOutcome> {
        let mut client = self.database.client().await?;
        let transaction = client
            .transaction()
            .await
            .context("Error starting limit transaction")?;

        // The guard is part of the write itself, never a prior read: under READ COMMITTED a racing
        // writer holds the row lock, and once it commits our `WHERE version = $n` is re-checked
        // against its row and matches nothing. A racing first write is caught by the primary key.
        let state = Self::state_row(&outcome.state)?;
        let state_written = match expected_version {
            None => LIMIT_STATE
                .insert_if_absent(&transaction, state)
                .await
                .context("Error inserting into 'limit_state'")?,
            Some(version) => {
                LIMIT_STATE
                    .update(
                        &transaction,
                        state,
                        record! {
                            COLUMN_TENANT_ID => outcome.state.tenant_id.as_str(),
                            COLUMN_LIMIT_CODE => outcome.state.code.as_str(),
                            COLUMN_VERSION => to_bigint(version)?,
                        },
                    )
                    .await
                    .context("Error updating 'limit_state'")?
                    > 0
            }
        };
        if !state_written {
            transaction
                .rollback()
                .await
                .context("Error rolling back limit transaction")?;
            return Ok(CasOutcome::Conflict);
        }

        // An upsert, like DynamoDB's unconditional ledger `Put`: the sort key carries a fresh id,
        // so this never actually meets an existing row.
        for entry in [outcome.ledger.as_ref(), outcome.rollover.as_ref()]
            .into_iter()
            .flatten()
        {
            let _ = LIMIT_LEDGER
                .upsert(&transaction, Self::ledger_row(entry)?)
                .await
                .context("Error appending to 'limit_ledger'")?;
        }

        // A month closes once: a history row already there means another writer closed it, so
        // this whole outcome is stale and must be recomputed, not half-applied.
        if let Some(history) = &outcome.history {
            let inserted = LIMIT_HISTORY
                .insert_if_absent(&transaction, Self::history_row(history)?)
                .await
                .context("Error inserting into 'limit_history'")?;
            if !inserted {
                transaction
                    .rollback()
                    .await
                    .context("Error rolling back limit transaction")?;
                return Ok(CasOutcome::Conflict);
            }
        }

        transaction
            .commit()
            .await
            .context("Error committing limit transaction")?;
        Ok(CasOutcome::Committed)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn read_ledger(
        &self,
        tenant_id: &str,
        code: &str,
        cursor: Option<&str>,
        limit: i32,
    ) -> anyhow::Result<(Vec<LedgerEntry>, Option<String>)> {
        let page = i64::from(limit.clamp(1, READ_PAGE_SIZE));
        let after = cursor.map(decode_ledger_cursor).transpose()?;

        // One row beyond the page tells whether another page exists, so — unlike DynamoDB's
        // `LastEvaluatedKey` — a cursor is offered only when there really is more.
        let client = self.database.client().await?;
        let rows = client
            .query(
                "SELECT data FROM limit_ledger
                 WHERE tenant_id = $1 AND limit_code = $2
                       AND ($3::text IS NULL OR ledger_sk < $3::text)
                 ORDER BY ledger_sk DESC
                 LIMIT $4",
                &[&tenant_id, &code, &after, &(page + 1)],
            )
            .await
            .context("Error reading 'limit_ledger'")?;

        let has_more = rows.len() as i64 > page;
        let entries = rows
            .iter()
            .take(rows.len().min(page as usize))
            .map(from_row::<LedgerEntry>)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let next = match entries.last() {
            Some(last) if has_more => Some(encode_ledger_cursor(&ledger_sort_key(last))),
            _ => None,
        };
        Ok((entries, next))
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn read_history(&self, tenant_id: &str, code: &str) -> anyhow::Result<Vec<HistoryRow>> {
        let client = self.database.client().await?;
        let rows = client
            .query(
                "SELECT data FROM limit_history
                 WHERE tenant_id = $1 AND limit_code = $2
                 ORDER BY year_month DESC
                 LIMIT $3",
                &[&tenant_id, &code, &i64::from(READ_PAGE_SIZE)],
            )
            .await
            .context("Error reading 'limit_history'")?;
        rows.iter().map(from_row).collect()
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn read_month_history(
        &self,
        tenant_id: &str,
        code: Option<&str>,
        year_month: &str,
    ) -> anyhow::Result<Vec<HistoryRow>> {
        let client = self.database.client().await?;
        let rows = client
            .query(
                "SELECT data FROM limit_history
                 WHERE tenant_id = $1 AND year_month = $2
                       AND ($3::text IS NULL OR limit_code = $3::text)
                 ORDER BY limit_code
                 LIMIT $4",
                &[&tenant_id, &year_month, &code, &i64::from(READ_PAGE_SIZE)],
            )
            .await
            .context("Error reading 'limit_history'")?;
        rows.iter().map(from_row).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LimitSettings;
    use crate::limits::ledger_type;
    use crate::storage::postgres::test::database;
    use std::sync::Arc;

    fn fresh(tenant: &str, code: &str, month: &str) -> LimitState {
        LimitState::fresh(
            tenant,
            code,
            month,
            &LimitSettings {
                monthly: Some(1000),
                ..LimitSettings::default()
            },
        )
    }

    fn entry(state: &LimitState, timestamp: &str, id: &str) -> LedgerEntry {
        LedgerEntry {
            tenant_id: state.tenant_id.clone(),
            code: state.code.clone(),
            id: id.to_owned(),
            timestamp: timestamp.to_owned(),
            entry_type: ledger_type::TOPUP.to_owned(),
            amount: 1,
            monthly_drawn: 0,
            custom_drawn: 0,
            extra_allowance_drawn: 0,
            overrun: 0,
            custom_added: 1,
            delta_monthly: 0,
            delta_custom: 1,
            delta_extra_allowance: 0,
            delta_overrun: 0,
            resulting_monthly: state.monthly_remaining,
            resulting_custom: state.custom_balance,
            resulting_extra_allowance: state.extra_allowance_remaining,
            resulting_overrun: state.overrun,
            actor_user_id: None,
            txn_id: None,
            source: None,
        }
    }

    fn history(state: &LimitState, year_month: &str) -> HistoryRow {
        HistoryRow {
            tenant_id: state.tenant_id.clone(),
            code: state.code.clone(),
            year_month: year_month.to_owned(),
            monthly_included: 1000,
            monthly_used: 400,
            monthly_forfeited: 600,
            extra_allowance_limit: 0,
            extra_allowance_used: 0,
            overrun: 0,
            ending_custom_balance: state.custom_balance,
            gauge_value: None,
            gauge_max: None,
        }
    }

    fn outcome(state: LimitState, ledger: Option<LedgerEntry>) -> Outcome {
        Outcome {
            state,
            ledger,
            history: None,
            rollover: None,
            rejected: false,
        }
    }

    /// A top-up of one through the same load → compute → CAS loop the service runs.
    async fn top_up_one(repository: &PostgresLimitRepository, id: &str) {
        loop {
            let existing = repository.load_state("t1", "limit:credits").await.unwrap();
            let expected = existing.as_ref().map(|state| state.version);
            let mut state = existing.unwrap_or_else(|| fresh("t1", "limit:credits", "2026-10"));
            state.custom_balance += 1;
            state.version = expected.map(|version| version + 1).unwrap_or(1);
            let ledger = entry(&state, "2026-10-14T10:00:00.000Z", id);
            match repository
                .compare_and_swap(&outcome(state, Some(ledger)), expected)
                .await
                .unwrap()
            {
                CasOutcome::Committed => return,
                CasOutcome::Conflict => continue,
            }
        }
    }

    #[tokio::test]
    async fn compare_and_swap_guards_version_and_history() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresLimitRepository::with_database(&database)
            .await
            .unwrap();

        assert!(repository.load_state("t1", "c").await.unwrap().is_none());
        let mut state = fresh("t1", "c", "2026-09");
        state.version = 1;
        let first = outcome(state.clone(), None);
        assert_eq!(
            repository.compare_and_swap(&first, None).await.unwrap(),
            CasOutcome::Committed
        );
        assert_eq!(
            repository.compare_and_swap(&first, None).await.unwrap(),
            CasOutcome::Conflict,
            "a second first write must lose"
        );
        assert_eq!(
            repository.load_state("t1", "c").await.unwrap(),
            Some(state.clone())
        );

        // A rollover closes September; replaying it must conflict and leave nothing behind.
        let mut october = fresh("t1", "c", "2026-10");
        october.version = 2;
        let mut rollover = outcome(
            october.clone(),
            Some(entry(&october, "2026-10-02T00:00:00.000Z", "A")),
        );
        rollover.history = Some(history(&state, "2026-09"));
        rollover.rollover = Some(entry(&october, "2026-10-01T00:00:00.000Z", "A-rollover"));
        assert_eq!(
            repository
                .compare_and_swap(&rollover, Some(1))
                .await
                .unwrap(),
            CasOutcome::Committed
        );

        let mut replay = rollover.clone();
        replay.state.version = 3;
        replay.ledger = Some(entry(&october, "2026-10-03T00:00:00.000Z", "B"));
        replay.rollover = None;
        assert_eq!(
            repository.compare_and_swap(&replay, Some(2)).await.unwrap(),
            CasOutcome::Conflict,
            "the history row already exists"
        );
        assert_eq!(
            repository.load_state("t1", "c").await.unwrap(),
            Some(october)
        );
        let (ledger, next) = repository.read_ledger("t1", "c", None, 10).await.unwrap();
        let ids: Vec<_> = ledger.iter().map(|entry| entry.id.as_str()).collect();
        assert_eq!(ids, ["A", "A-rollover"], "the rolled-back entry is gone");
        assert!(next.is_none());

        assert_eq!(
            repository.compare_and_swap(&replay, Some(1)).await.unwrap(),
            CasOutcome::Conflict,
            "a stale version must lose"
        );

        let months = repository.read_history("t1", "c").await.unwrap();
        assert_eq!(months, vec![history(&state, "2026-09")]);
        assert_eq!(
            repository
                .read_month_history("t1", Some("c"), "2026-09")
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            repository
                .read_month_history("t1", Some("other"), "2026-09")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            repository
                .read_month_history("t1", None, "2026-09")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn ledger_pages_newest_first() {
        let Some(database) = database().await else {
            return;
        };
        let repository = PostgresLimitRepository::with_database(&database)
            .await
            .unwrap();

        for (version, timestamp) in (0u64..).zip([
            "2026-10-01T00:00:00.000Z",
            "2026-10-02T00:00:00.000Z",
            "2026-10-03T00:00:00.000Z",
            "2026-10-04T00:00:00.000Z",
            "2026-10-05T00:00:00.000Z",
        ]) {
            let mut state = fresh("t1", "c", "2026-10");
            state.version = version + 1;
            let ledger = entry(&state, timestamp, &format!("E{version}"));
            let expected = (version > 0).then_some(version);
            assert_eq!(
                repository
                    .compare_and_swap(&outcome(state, Some(ledger)), expected)
                    .await
                    .unwrap(),
                CasOutcome::Committed
            );
        }
        // Another limit's entries never leak into this one's pages.
        let mut other = fresh("t1", "c2", "2026-10");
        other.version = 1;
        let stray = entry(&other, "2026-10-09T00:00:00.000Z", "X");
        let _ = repository
            .compare_and_swap(&outcome(other, Some(stray)), None)
            .await
            .unwrap();

        let (first, cursor) = repository.read_ledger("t1", "c", None, 2).await.unwrap();
        assert_eq!(
            first.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            ["E4", "E3"]
        );
        let (second, cursor) = repository
            .read_ledger("t1", "c", cursor.as_deref(), 2)
            .await
            .unwrap();
        assert_eq!(
            second.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            ["E2", "E1"]
        );
        let (last, cursor) = repository
            .read_ledger("t1", "c", cursor.as_deref(), 2)
            .await
            .unwrap();
        assert_eq!(
            last.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            ["E0"]
        );
        assert!(cursor.is_none());
        assert!(
            repository
                .read_ledger("t1", "c", Some("%%%"), 2)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn concurrent_bookings_never_lose_an_update() {
        let Some(database) = database().await else {
            return;
        };
        let repository = Arc::new(
            PostgresLimitRepository::with_database(&database)
                .await
                .unwrap(),
        );

        let tasks: Vec<_> = (0..20)
            .map(|index| {
                let repository = repository.clone();
                tokio::spawn(async move { top_up_one(&repository, &format!("T{index:02}")).await })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }

        let state = repository
            .load_state("t1", "limit:credits")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            state.custom_balance, 20,
            "every booking landed exactly once"
        );
        assert_eq!(state.version, 20);
        let (ledger, _) = repository
            .read_ledger("t1", "limit:credits", None, 100)
            .await
            .unwrap();
        assert_eq!(ledger.len(), 20, "one ledger entry per committed booking");
    }

    #[tokio::test]
    async fn concurrent_writes_from_one_version_commit_once() {
        let Some(database) = database().await else {
            return;
        };
        let repository = Arc::new(
            PostgresLimitRepository::with_database(&database)
                .await
                .unwrap(),
        );
        let mut base = fresh("t1", "c", "2026-10");
        base.version = 1;
        let _ = repository
            .compare_and_swap(&outcome(base.clone(), None), None)
            .await
            .unwrap();

        let tasks: Vec<_> = (0..20)
            .map(|index| {
                let repository = repository.clone();
                let mut state = base.clone();
                state.version = 2;
                state.custom_balance = index;
                tokio::spawn(async move {
                    let ledger = entry(&state, "2026-10-14T00:00:00.000Z", &format!("W{index}"));
                    repository
                        .compare_and_swap(&outcome(state, Some(ledger)), Some(1))
                        .await
                        .unwrap()
                })
            })
            .collect();
        let mut committed = 0;
        for task in tasks {
            if task.await.unwrap() == CasOutcome::Committed {
                committed += 1;
            }
        }
        assert_eq!(committed, 1);
        let (ledger, _) = repository.read_ledger("t1", "c", None, 100).await.unwrap();
        assert_eq!(ledger.len(), 1, "losers leave no ledger entry behind");
        let state = repository.load_state("t1", "c").await.unwrap().unwrap();
        assert_eq!(state.custom_balance, ledger[0].resulting_custom);
    }
}
