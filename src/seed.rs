//! Dev-only seeding of realistic limit data — ledger, closed-month history and a live overrun —
//! for exercising the management UI against a real store. Compiled only in debug builds (see the
//! `#[cfg(debug_assertions)]` in `main.rs`); it never reaches a release binary.
//!
//! Everything is written through the ordinary [`crate::limits::accounting`] path and committed with
//! the repository's `compare_and_swap`, so the seeded rows are indistinguishable from ones a running
//! service would produce — the month rollovers close history rows on their own, and the overrun
//! settles like a real debt.

use crate::config::repository::ConfigRepository;
use crate::config::{LimitKind, LimitSettings, OverrunPolicy};
use crate::limits::LimitState;
use crate::limits::accounting::{self, Actor, Outcome};
use crate::limits::repository::{CasOutcome, LimitRepository};
use crate::tenants::repository::TenantRepository;
use anyhow::{Context, bail};
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Months, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::generate_id;

/// Logical table + key names, mirroring the private consts in [`crate::limits::repository`] — a dev
/// tool may duplicate them.
const TABLE_LIMIT_STATE: &str = "limit-state";
const TABLE_LIMIT_LEDGER: &str = "limit-ledger";
const TABLE_LIMIT_HISTORY: &str = "limit-history";
const FIELD_TENANT_ID: &str = "tenantId";
const FIELD_CODE: &str = "limitCode";
const FIELD_LEDGER_SK: &str = "ledgerSk";
const FIELD_HISTORY_SK: &str = "historySk";

/// The code seeded when the caller names none — override with the second CLI argument.
const DEFAULT_CODE: &str = "limit:ai-credits";

/// Seeds `(tenant, code)` with a multi-month history and a populated ledger — a consumable ends on a
/// live overrun, a gauge on its latest reading.
///
/// `tenant_id` falls back to the configured system tenant, `code` to [`DEFAULT_CODE`]; the kind is
/// taken from the catalogue. Any existing state/ledger/history for the pair is wiped first, so every
/// run reproduces the same dataset.
pub async fn seed_limits(
    limits: Arc<dyn LimitRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    tenant_arg: Option<&str>,
    code_arg: Option<&str>,
) -> anyhow::Result<()> {
    let tenant_id = match tenant_arg.map(str::to_owned).or(system_tenant_id) {
        Some(id) => id,
        None => bail!(
            "no tenant given and UMAMI_SYSTEM_TENANT_ID is unset — pass it: `seed-limits <tenant> [code]`"
        ),
    };
    let code = code_arg.unwrap_or(DEFAULT_CODE).to_owned();

    // Shape the settings from the catalogue definition when it exists, so facets (extra allowance,
    // daily) match a real limit; an orphan is assumed consumable and warned about.
    let current = config.current().await.context("reading the config")?;
    let def = current.limits.iter().find(|d| d.code == code);
    let kind = def.map(|d| d.kind).unwrap_or(LimitKind::Consumable);
    if def.is_none() {
        tracing::warn!(
            "limit '{code}' is not in the config catalogue — seeding it as a consumable orphan; the \
             UI will show it without a name"
        );
    }
    let settings = match kind {
        LimitKind::Gauge => LimitSettings {
            max: Some(50),
            ..Default::default()
        },
        LimitKind::Consumable => LimitSettings {
            monthly: Some(100_000),
            extra_allowance: Some(20_000),
            daily: def.map(|d| d.daily).unwrap_or(true).then_some(10_000),
            max: None,
        },
    };

    ensure_tenant_settings(&tenants, &tenant_id, &code, &settings).await?;

    // Wipe any existing state/ledger/history for this (tenant, code) so the timeline replays cleanly
    // and every run produces the same dataset rather than just appending.
    reset_target(&tenant_id, &code).await?;

    let mut seeder = Seeder {
        limits,
        tenant_id: tenant_id.clone(),
        code: code.clone(),
        settings,
        state: None,
        expected: None,
    };
    match kind {
        LimitKind::Consumable => seeder.full_timeline().await?,
        LimitKind::Gauge => seeder.gauge_timeline().await?,
    }
    tracing::info!("seeded a fresh 4-month timeline for {tenant_id} / {code}");
    Ok(())
}

/// Deletes every state, ledger and history row for one `(tenant, code)` via a raw client, so the
/// seeder can start from a clean slate on each run.
async fn reset_target(tenant_id: &str, code: &str) -> anyhow::Result<()> {
    let client = DynamoClient::from_env().await?;

    // State: a single row, keyed by (tenant, code).
    let _ = client
        .delete_item(TABLE_LIMIT_STATE)
        .key(FIELD_TENANT_ID, AttributeValue::S(tenant_id.to_owned()))
        .key(FIELD_CODE, AttributeValue::S(code.to_owned()))
        .send()
        .await
        .context("deleting the limit-state row")?;

    delete_by_prefix(
        &client,
        TABLE_LIMIT_LEDGER,
        FIELD_LEDGER_SK,
        tenant_id,
        code,
    )
    .await?;
    delete_by_prefix(
        &client,
        TABLE_LIMIT_HISTORY,
        FIELD_HISTORY_SK,
        tenant_id,
        code,
    )
    .await?;
    Ok(())
}

/// Deletes every row of `table` whose sort key begins with `"{code}#"` for `tenant_id`.
async fn delete_by_prefix(
    client: &DynamoClient,
    table: &str,
    sk_field: &str,
    tenant_id: &str,
    code: &str,
) -> anyhow::Result<()> {
    let mut start: Option<HashMap<String, AttributeValue>> = None;
    loop {
        let page = client
            .query(table)
            .key_condition_expression("#pk = :pk AND begins_with(#sk, :prefix)")
            .expression_attribute_names("#pk", FIELD_TENANT_ID)
            .expression_attribute_names("#sk", sk_field)
            .expression_attribute_values(":pk", AttributeValue::S(tenant_id.to_owned()))
            .expression_attribute_values(":prefix", AttributeValue::S(format!("{code}#")))
            .set_exclusive_start_key(start.clone())
            .send()
            .await
            .with_context(|| format!("querying '{table}' to reset"))?;
        for item in page.items() {
            let Some(sk) = item.get(sk_field) else {
                continue;
            };
            let _ = client
                .delete_item(table)
                .key(FIELD_TENANT_ID, AttributeValue::S(tenant_id.to_owned()))
                .key(sk_field, sk.clone())
                .send()
                .await
                .with_context(|| format!("deleting a '{table}' row"))?;
        }
        match page.last_evaluated_key() {
            Some(key) if !key.is_empty() => start = Some(key.clone()),
            _ => break,
        }
    }
    Ok(())
}

/// Makes sure the tenant carries settings for the code, so the limit shows up in the management list
/// (which unions relevant and stored limits) rather than being a state row nothing links to.
async fn ensure_tenant_settings(
    tenants: &Arc<dyn TenantRepository>,
    tenant_id: &str,
    code: &str,
    settings: &LimitSettings,
) -> anyhow::Result<()> {
    let mut tenant = match tenants
        .get_tenant(tenant_id)
        .await
        .context("loading tenant")?
    {
        Some(tenant) => tenant,
        None => bail!("no such tenant '{tenant_id}'"),
    };
    if tenant.limits.get(code) != Some(settings) {
        let _ = tenant.limits.insert(code.to_owned(), settings.clone());
        let _ = tenants
            .put_tenant(tenant)
            .await
            .context("writing tenant settings")?;
    }
    Ok(())
}

/// Carries the running state/version across seeded operations so each commits against the last.
struct Seeder {
    limits: Arc<dyn LimitRepository>,
    tenant_id: String,
    code: String,
    settings: LimitSettings,
    state: Option<LimitState>,
    expected: Option<u64>,
}

impl Seeder {
    /// A representative actor for a seeded ledger entry — a fixed user id and source plus a fresh txn
    /// id, so the ledger's id columns are populated.
    fn actor() -> Actor {
        Actor {
            user_id: Some("seed-user".to_owned()),
            txn_id: Some(generate_id()),
            source: Some("seed-script".to_owned()),
        }
    }

    /// Commits one [`Outcome`], threading the version like the service's CAS loop does. The seeder is
    /// single-threaded, so a conflict here means the store changed underneath us — a hard error.
    async fn commit(&mut self, mut outcome: Outcome) -> anyhow::Result<()> {
        outcome.state.version = self.expected.map(|v| v + 1).unwrap_or(1);
        match self
            .limits
            .compare_and_swap(&outcome, self.expected)
            .await
            .context("committing a seeded outcome")?
        {
            CasOutcome::Committed => {
                self.expected = Some(outcome.state.version);
                self.state = Some(outcome.state);
                Ok(())
            }
            CasOutcome::Conflict => {
                bail!(
                    "unexpected version conflict while seeding — is the service booking this limit?"
                )
            }
        }
    }

    /// One booking, drawn across the cascade, forced to `track` so an overspend is visibly recorded.
    async fn consume(&mut self, amount: i64, when: DateTime<Utc>) -> anyhow::Result<()> {
        let outcome = accounting::apply_consume(
            self.state.clone(),
            &self.tenant_id,
            &self.code,
            &self.settings,
            amount,
            when,
            &generate_id(),
            &Self::actor(),
            OverrunPolicy::Track,
        );
        self.commit(outcome).await
    }

    /// A top-up of the persistent balance (retires any overrun first).
    async fn topup(&mut self, amount: i64, when: DateTime<Utc>) -> anyhow::Result<()> {
        let outcome = accounting::apply_topup(
            self.state.clone(),
            &self.tenant_id,
            &self.code,
            &self.settings,
            amount,
            when,
            &generate_id(),
            &Self::actor(),
        );
        self.commit(outcome).await
    }

    /// Records one gauge value. Set in a new month, it closes the previous gauge month into history.
    async fn gauge(&mut self, value: i64, when: DateTime<Utc>) -> anyhow::Result<()> {
        let outcome = accounting::set_gauge(
            self.state.clone(),
            &self.tenant_id,
            &self.code,
            value,
            self.settings.max,
            when,
            &generate_id(),
            &Self::actor(),
        );
        self.commit(outcome).await
    }

    /// Four months of gauge readings ending on the current one, so each earlier month closes into a
    /// history row (value + bound) and the live value stands at the last.
    async fn gauge_timeline(&mut self) -> anyhow::Result<()> {
        let now = Utc::now();
        let month_ago = |n: u32| now.checked_sub_months(Months::new(n)).unwrap_or(now);
        self.gauge(40, month_ago(3)).await?;
        self.gauge(44, month_ago(2)).await?;
        self.gauge(47, month_ago(1)).await?;
        self.gauge(48, now).await?;
        Ok(())
    }

    /// Four months of activity ending in a live overrun. Each new month's first booking rolls the
    /// previous one shut, so history rows appear without any explicit rollover call.
    async fn full_timeline(&mut self) -> anyhow::Result<()> {
        let now = Utc::now();
        let month_ago = |n: u32| now.checked_sub_months(Months::new(n)).unwrap_or(now);

        // Three months back: modest usage that forfeits most of the budget.
        let m3 = month_ago(3);
        self.consume(15_000, m3).await?;
        self.consume(20_000, m3).await?;

        // Two months back: heavy usage that eats into the extra allowance, plus a top-up.
        let m2 = month_ago(2);
        self.consume(90_000, m2).await?;
        self.topup(25_000, m2).await?;
        self.consume(35_000, m2).await?;

        // One month back: exhausts everything and overruns — this closes into history's overrun.
        let m1 = month_ago(1);
        self.consume(100_000, m1).await?;
        self.consume(60_000, m1).await?;

        // This month: a live overrun to exercise the amber line and the billing figures.
        self.current_month_burst(now).await
    }

    /// A burst in `now`'s month that ends exhausted and overrun, so the live view shows the amber
    /// overrun line and the ledger gains a handful of entries.
    async fn current_month_burst(&mut self, now: DateTime<Utc>) -> anyhow::Result<()> {
        self.consume(40_000, now).await?;
        self.consume(55_000, now).await?;
        self.topup(10_000, now).await?;
        // Blow past monthly + custom + extra allowance, leaving a tracked live overrun.
        self.consume(60_000, now).await?;
        Ok(())
    }
}
