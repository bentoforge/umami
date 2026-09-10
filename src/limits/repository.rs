//! DynamoDB persistence for limit state, ledger and history.
//!
//! The trait is deliberately thin: `compare_and_swap` (the one atomic write) plus reads, and nothing
//! that knows the cascade or the rollover — that logic lives in [`crate::limits::accounting`], and
//! the retry loop around the CAS lives in the service. A second backend implements these and
//! inherits every booking rule for free.
//!
//! `compare_and_swap` commits an [`Outcome`] as one `TransactWriteItems`: the state row under its
//! version guard, the ledger entry appended, and — when a month rolled over — the history row put
//! if-not-exists. All-or-nothing, so state and ledger never drift apart.

use crate::limits::accounting::Outcome;
use crate::limits::{HistoryRow, LedgerEntry, LimitState};
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{AttributeValue, BillingMode, Put, TransactWriteItem};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt;
use std::collections::HashMap;
use wasabi::aws::dynamodb::client::{DynamoClient, ItemBuilder};
use wasabi::aws::dynamodb::schema::{str_attribute, with_range_index};
use wasabi::aws::dynamodb::{deserialize_entity, str, stream_all};

/// Table storing per-`(tenant, limit)` counters.
const TABLE_LIMIT_STATE: &str = "limit-state";
/// Table storing the append-only transaction ledger.
const TABLE_LIMIT_LEDGER: &str = "limit-ledger";
/// Table storing closed-month aggregates.
const TABLE_LIMIT_HISTORY: &str = "limit-history";

/// Hash key shared by all three tables (the owning tenant).
const FIELD_TENANT_ID: &str = "tenantId";
/// Range key of the state table (the limit's config code).
const FIELD_CODE: &str = "limitCode";
/// Optimistic-concurrency attribute on the state row.
const FIELD_VERSION: &str = "version";
/// Range key of the ledger table: `"{code}#{timestamp}#{id}"` (a limit's entries, newest last).
const FIELD_LEDGER_SK: &str = "ledgerSk";
/// Range key of the history table: `"{code}#{yearMonth}"` (a limit's months).
const FIELD_HISTORY_SK: &str = "historySk";
/// The closed month on a history row (`"YYYY-MM"`), filtered on for an all-limits month read.
const FIELD_YEAR_MONTH: &str = "yearMonth";

/// Upper bound on rows a single ledger/history read returns.
const READ_PAGE_SIZE: i32 = 100;

/// The outcome of a [`LimitRepository::compare_and_swap`]: whether the guarded write landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasOutcome {
    /// The transaction landed; the [`Outcome`] is now stored.
    Committed,
    /// The version guard failed — a concurrent writer won. The caller reloads and retries.
    Conflict,
}

/// Persistence interface for limit state — the atomic primitive plus the ledger/history reads.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait LimitRepository: Send + Sync {
    /// Loads the state for `(tenant, code)`. `None` when the limit has never been touched.
    async fn load_state(&self, tenant_id: &str, code: &str) -> anyhow::Result<Option<LimitState>>;

    /// Atomically commits an [`Outcome`] — state (version-guarded), ledger (appended) and, when a
    /// month closed, history (if-not-exists). `expected_version`: `None` requires the state row not
    /// to exist yet, `Some(v)` requires the stored version to equal `v`. Returns
    /// [`CasOutcome::Conflict`] when the guard fails, so the caller reloads and retries.
    async fn compare_and_swap(
        &self,
        outcome: &Outcome,
        expected_version: Option<u64>,
    ) -> anyhow::Result<CasOutcome>;

    /// One page of a limit's ledger, newest first. `cursor` resumes after a prior page; `limit` is
    /// clamped to `[1, READ_PAGE_SIZE]`. Returns the page plus the next cursor (`None` when the trail
    /// is exhausted).
    async fn read_ledger(
        &self,
        tenant_id: &str,
        code: &str,
        cursor: Option<&str>,
        limit: i32,
    ) -> anyhow::Result<(Vec<LedgerEntry>, Option<String>)>;

    /// A limit's closed-month history, newest month first, capped at [`READ_PAGE_SIZE`].
    async fn read_history(&self, tenant_id: &str, code: &str) -> anyhow::Result<Vec<HistoryRow>>;

    /// One closed month for billing: the history row(s) for `(tenant, year_month)`. With `code` it
    /// is the single limit's row (empty when that month never closed); without it, every limit's row
    /// for that month. Capped at [`READ_PAGE_SIZE`].
    async fn read_month_history(
        &self,
        tenant_id: &str,
        code: Option<&str>,
        year_month: &str,
    ) -> anyhow::Result<Vec<HistoryRow>>;
}

/// Opaque page cursor over a limit's ledger — the last-seen ledger sort key (`{code}#{ts}#{id}`),
/// base64url-encoded so it survives a query string untouched.
fn encode_ledger_cursor(ledger_sk: &str) -> String {
    URL_SAFE_NO_PAD.encode(ledger_sk)
}

fn decode_ledger_cursor(cursor: &str) -> anyhow::Result<String> {
    let raw = URL_SAFE_NO_PAD
        .decode(cursor)
        .context("Invalid ledger cursor")?;
    String::from_utf8(raw).context("Invalid ledger cursor")
}

/// DynamoDB-backed implementation of [`LimitRepository`].
#[derive(Clone)]
pub struct DynamoLimitRepository {
    client: DynamoClient,
}

impl DynamoLimitRepository {
    #[tracing::instrument(skip(client), err(level = "debug", Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_LIMIT_STATE, |table| {
                let table = table
                    .attribute_definitions(str_attribute(FIELD_TENANT_ID)?)
                    .attribute_definitions(str_attribute(FIELD_CODE)?);
                let table = with_range_index(table, FIELD_TENANT_ID, FIELD_CODE)?;
                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;
        client
            .create_table(TABLE_LIMIT_LEDGER, |table| {
                let table = table
                    .attribute_definitions(str_attribute(FIELD_TENANT_ID)?)
                    .attribute_definitions(str_attribute(FIELD_LEDGER_SK)?);
                let table = with_range_index(table, FIELD_TENANT_ID, FIELD_LEDGER_SK)?;
                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;
        client
            .create_table(TABLE_LIMIT_HISTORY, |table| {
                let table = table
                    .attribute_definitions(str_attribute(FIELD_TENANT_ID)?)
                    .attribute_definitions(str_attribute(FIELD_HISTORY_SK)?);
                let table = with_range_index(table, FIELD_TENANT_ID, FIELD_HISTORY_SK)?;
                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;

        Ok(Self {
            client: client.clone(),
        })
    }
}

/// The ledger sort key: `"{code}#{timestamp}#{id}"`, so one limit's entries are contiguous and
/// ordered by time.
fn ledger_sort_key(entry: &LedgerEntry) -> String {
    format!("{}#{}#{}", entry.code, entry.timestamp, entry.id)
}

/// The history sort key: `"{code}#{yearMonth}"`, so one limit's months are contiguous.
fn history_sort_key(row: &HistoryRow) -> String {
    format!("{}#{}", row.code, row.year_month)
}

#[async_trait]
impl LimitRepository for DynamoLimitRepository {
    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn load_state(&self, tenant_id: &str, code: &str) -> anyhow::Result<Option<LimitState>> {
        // Strongly consistent: the booking path read-modify-writes this row under a version guard,
        // so a stale read must never be the basis of a write.
        let result = self
            .client
            .get_item(TABLE_LIMIT_STATE)
            .key(FIELD_TENANT_ID, str(tenant_id))
            .key(FIELD_CODE, str(code))
            .consistent_read(true)
            .send()
            .await
            .context("Error reading 'limit-state' table")?;

        deserialize_entity(result.item)
    }

    #[tracing::instrument(level = "debug", skip(self, outcome), err(level = "debug", Display))]
    async fn compare_and_swap(
        &self,
        outcome: &Outcome,
        expected_version: Option<u64>,
    ) -> anyhow::Result<CasOutcome> {
        // State: version-guarded put (or attribute_not_exists on the first write).
        let state_item = ItemBuilder::from_entity(&outcome.state)?.build();
        let state_put = self
            .client
            .put_item(TABLE_LIMIT_STATE)
            .set_item(Some(state_item));
        let state_put = match expected_version {
            None => state_put
                .condition_expression("attribute_not_exists(#tenantId)")
                .expression_attribute_names("#tenantId", FIELD_TENANT_ID),
            Some(version) => state_put
                .condition_expression("#version = :expected")
                .expression_attribute_names("#version", FIELD_VERSION)
                .expression_attribute_values(":expected", AttributeValue::N(version.to_string())),
        };
        let state_put = Put::builder()
            .table_name(self.client.effective_name(TABLE_LIMIT_STATE))
            .set_item(state_put.get_item().clone())
            .set_condition_expression(state_put.get_condition_expression().clone())
            .set_expression_attribute_names(state_put.get_expression_attribute_names().clone())
            .set_expression_attribute_values(state_put.get_expression_attribute_values().clone())
            .build()
            .context("Error building limit-state transaction put")?;

        let mut items = vec![TransactWriteItem::builder().put(state_put).build()];

        // Ledger: the operation's entry, plus a `carry`-policy rollover's — each appended (with its
        // storage sort key) in the same atomic transaction. A gauge set records neither.
        for entry in [outcome.ledger.as_ref(), outcome.rollover.as_ref()]
            .into_iter()
            .flatten()
        {
            let mut item = ItemBuilder::from_entity(entry)?;
            item.add_str(FIELD_LEDGER_SK, ledger_sort_key(entry));
            let put = Put::builder()
                .table_name(self.client.effective_name(TABLE_LIMIT_LEDGER))
                .set_item(Some(item.build()))
                .build()
                .context("Error building limit-ledger transaction put")?;
            items.push(TransactWriteItem::builder().put(put).build());
        }

        // History: written once per closed month (idempotent), only on a rollover.
        if let Some(history) = &outcome.history {
            let mut row = ItemBuilder::from_entity(history)?;
            row.add_str(FIELD_HISTORY_SK, history_sort_key(history));
            let history_put = Put::builder()
                .table_name(self.client.effective_name(TABLE_LIMIT_HISTORY))
                .set_item(Some(row.build()))
                .condition_expression("attribute_not_exists(#tenantId)")
                .expression_attribute_names("#tenantId", FIELD_TENANT_ID)
                .build()
                .context("Error building limit-history transaction put")?;
            items.push(TransactWriteItem::builder().put(history_put).build());
        }

        let result = self
            .client
            .client
            .transact_write_items()
            .set_transact_items(Some(items))
            .send()
            .await;

        match result {
            Ok(_) => Ok(CasOutcome::Committed),
            Err(err) => {
                // A cancelled transaction means a guard failed (the version, or a racing history
                // write) — reload and retry rather than surfacing an error.
                if err
                    .as_service_error()
                    .map(|service_err| service_err.is_transaction_canceled_exception())
                    .unwrap_or(false)
                {
                    Ok(CasOutcome::Conflict)
                } else {
                    Err(anyhow::Error::new(err).context("Error committing limit transaction"))
                }
            }
        }
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn read_ledger(
        &self,
        tenant_id: &str,
        code: &str,
        cursor: Option<&str>,
        limit: i32,
    ) -> anyhow::Result<(Vec<LedgerEntry>, Option<String>)> {
        // One bounded page via `Limit` + `ExclusiveStartKey`, so we never drain the whole ledger.
        let mut query = self
            .client
            .query(TABLE_LIMIT_LEDGER)
            .key_condition_expression("#pk = :pk AND begins_with(#sk, :prefix)")
            .expression_attribute_names("#pk", FIELD_TENANT_ID)
            .expression_attribute_names("#sk", FIELD_LEDGER_SK)
            .expression_attribute_values(":pk", str(tenant_id))
            .expression_attribute_values(":prefix", str(format!("{code}#")))
            .scan_index_forward(false)
            .limit(limit.clamp(1, READ_PAGE_SIZE));

        if let Some(cursor) = cursor {
            let ledger_sk = decode_ledger_cursor(cursor)?;
            let start = HashMap::from([
                (FIELD_TENANT_ID.to_owned(), str(tenant_id)),
                (FIELD_LEDGER_SK.to_owned(), str(&ledger_sk)),
            ]);
            query = query.set_exclusive_start_key(Some(start));
        }

        let result = query
            .send()
            .await
            .context("Error reading 'limit-ledger' table")?;
        let has_more = result.last_evaluated_key.is_some();
        let entries: Vec<LedgerEntry> = result
            .items
            .unwrap_or_default()
            .into_iter()
            .filter_map(|item| deserialize_entity::<LedgerEntry>(Some(item)).transpose())
            .collect::<anyhow::Result<_>>()?;

        // Only offer a next cursor when DynamoDB says more may follow (and we have an anchor).
        let next = match entries.last() {
            Some(last) if has_more => Some(encode_ledger_cursor(&ledger_sort_key(last))),
            _ => None,
        };
        Ok((entries, next))
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn read_history(&self, tenant_id: &str, code: &str) -> anyhow::Result<Vec<HistoryRow>> {
        let request = self
            .client
            .query(TABLE_LIMIT_HISTORY)
            .key_condition_expression("#pk = :pk AND begins_with(#sk, :prefix)")
            .expression_attribute_names("#pk", FIELD_TENANT_ID)
            .expression_attribute_names("#sk", FIELD_HISTORY_SK)
            .expression_attribute_values(":pk", str(tenant_id))
            .expression_attribute_values(":prefix", str(format!("{code}#")))
            .scan_index_forward(false)
            .limit(READ_PAGE_SIZE);

        let mut stream = stream_all::<HistoryRow>(request)?;
        let mut rows = Vec::new();
        while let Some(row) = stream.next().await {
            rows.push(row.context("Error reading 'limit-history' table")?);
            if rows.len() >= READ_PAGE_SIZE as usize {
                break;
            }
        }
        Ok(rows)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "debug", Display))]
    async fn read_month_history(
        &self,
        tenant_id: &str,
        code: Option<&str>,
        year_month: &str,
    ) -> anyhow::Result<Vec<HistoryRow>> {
        // With a code the row is addressed exactly (`{code}#{month}`); without one we walk the
        // tenant's history partition and keep only that month. The history sort key is prefixed by
        // code, not month, so an all-limits month read cannot be a range query.
        let request = self
            .client
            .query(TABLE_LIMIT_HISTORY)
            .expression_attribute_names("#pk", FIELD_TENANT_ID)
            .expression_attribute_values(":pk", str(tenant_id));
        let request = match code {
            Some(code) => request
                .key_condition_expression("#pk = :pk AND #sk = :sk")
                .expression_attribute_names("#sk", FIELD_HISTORY_SK)
                .expression_attribute_values(":sk", str(format!("{code}#{year_month}"))),
            None => request
                .key_condition_expression("#pk = :pk")
                .filter_expression("#ym = :ym")
                .expression_attribute_names("#ym", FIELD_YEAR_MONTH)
                .expression_attribute_values(":ym", str(year_month)),
        };

        let mut stream = stream_all::<HistoryRow>(request)?;
        let mut rows = Vec::new();
        while let Some(row) = stream.next().await {
            rows.push(row.context("Error reading 'limit-history' table")?);
            if rows.len() >= READ_PAGE_SIZE as usize {
                break;
            }
        }
        Ok(rows)
    }
}
