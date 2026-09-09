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
use chrono::{DateTime, Months, Utc};
use std::sync::Arc;
use wasabi::aws::dynamodb::generate_id;

/// The code seeded when the caller names none — override with the second CLI argument.
const DEFAULT_CODE: &str = "limit:ai-credits";

/// Seeds `(tenant, code)` with a multi-month history, a populated ledger and a live overrun.
///
/// `tenant_id` falls back to the configured system tenant, `code` to [`DEFAULT_CODE`]. When the
/// limit already has a state row the timeline cannot be replayed cleanly, so it only appends a fresh
/// current-month burst (more ledger, refreshed live state) and leaves the existing history intact.
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

    // Shape the settings from the catalogue definition when it exists, so facets (extra allowance, daily)
    // match a real limit; otherwise fall back to a full-featured consumable and warn.
    let current = config.current().await.context("reading the config")?;
    let def = current.limits.iter().find(|d| d.code == code);
    if let Some(def) = def {
        if def.kind != LimitKind::Consumable {
            bail!("limit '{code}' is a gauge; this seeder fakes consumable ledger/history/overrun");
        }
    } else {
        tracing::warn!(
            "limit '{code}' is not in the config catalogue — seeding it as an orphan; the UI will \
             show it without a name"
        );
    }
    let settings = LimitSettings {
        monthly: Some(100_000),
        extra_allowance: Some(20_000),
        daily: def.map(|d| d.daily).unwrap_or(true).then_some(10_000),
        max: None,
    };

    ensure_tenant_settings(&tenants, &tenant_id, &code, &settings).await?;

    let existing = limits
        .load_state(&tenant_id, &code)
        .await
        .context("loading any existing state")?;

    let mut seeder = Seeder {
        limits,
        tenant_id: tenant_id.clone(),
        code: code.clone(),
        settings,
        state: existing.clone(),
        // Continue from the stored version (or a first-ever write when there is none yet).
        expected: existing.as_ref().map(|s| s.version),
    };

    if existing.is_none() {
        seeder.full_timeline().await?;
        tracing::info!("seeded a fresh 4-month timeline for {tenant_id} / {code}");
    } else {
        seeder.current_month_burst(Utc::now()).await?;
        tracing::info!(
            "{tenant_id} / {code} already had state — appended a current-month burst instead of \
             replaying history"
        );
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
    /// A representative actor for a seeded ledger entry.
    fn actor(txn: &str) -> Actor {
        Actor {
            user_id: Some("seed".to_owned()),
            user_name: Some("Seed script".to_owned()),
            txn_name: Some(txn.to_owned()),
            txn_id: Some(generate_id()),
            reference: None,
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
            &Self::actor("consume"),
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
            &Self::actor("topup"),
        );
        self.commit(outcome).await
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
