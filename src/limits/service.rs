//! Limit management routes: read a tenant's limit settings, and set them.
//!
//! Cross-tenant admin (`manage:limits`): the tenant is named in the path, like the feature
//! grant/revoke endpoints, because a platform operator manages any tenant's quotas — a limits admin
//! is not confined to their own tenant. The values are validated against the config catalogue
//! ([`crate::config::Config::validate_limit_settings`]) before they are stored on the tenant.

use crate::bail_i18n;
use crate::config::repository::ConfigRepository;
use crate::config::{LimitDef, LimitKind, LimitSettings};
use crate::constants::{
    BOOK_LIMITS_PERMISSION, LIMIT_CAS_BACKOFF_MAX_MS, LIMIT_CAS_BACKOFF_MIN_MS,
    LIMIT_CAS_MAX_ATTEMPTS, MANAGE_LIMITS_PERMISSION, MAX_TEXT_BODY_SIZE, VIEW_LIMITS_PERMISSION,
};
use crate::limits::accounting::{self, Actor, Outcome};
use crate::limits::repository::{CasOutcome, LimitRepository};
use crate::limits::{HistoryRow, LedgerEntry, LimitState};
use crate::tenants::repository::TenantRepository;
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::aws::dynamodb::generate_id;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{DecodedSegment, into_response, with_body_as_json, with_cloneable};
use wasabi::{client_bail, status_bail};

/// Permission required to change a tenant's limits (cross-tenant admin).
const REQUIRE_MANAGE_LIMITS: &[&str] = &[MANAGE_LIMITS_PERMISSION];

/// Permissions that may *read* a tenant's limits: the cross-tenant admin, or a member reading their
/// own tenant (`view:limits`). The own-tenant confinement for the latter is enforced in the handler.
const REQUIRE_READ_LIMITS: &[&str] = &[MANAGE_LIMITS_PERMISSION, VIEW_LIMITS_PERMISSION];

/// Permission required to book against a tenant's limits (product-service key).
const REQUIRE_BOOK_LIMITS: &[&str] = &[BOOK_LIMITS_PERMISSION];

/// A tenant's stored limit settings, keyed by limit code. The definitions (labels, facets) come
/// separately from `GET /config/catalogue`; a screen merges the two.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LimitsResponse {
    limits: BTreeMap<String, LimitSettings>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `GET /tenants/{id}/limits` — a tenant's per-limit settings. `manage:limits` reads any tenant;
/// `view:limits` reads only the caller's own (self-service).
pub fn list_limits_route(
    tenants: Arc<dyn TenantRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "limits")
        .and(warp::get())
        .and(with_cloneable(tenants))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_READ_LIMITS,
        ))
        .and_then(handle_list_limits_route)
        .boxed()
}

/// `PUT /tenants/{id}/limits/{code}/settings` — set a tenant's values for one limit.
pub fn set_limit_settings_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "limits" / DecodedSegment / "settings")
        .and(warp::put())
        .and(with_body_as_json::<LimitSettings>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_LIMITS,
        ))
        .and_then(handle_set_limit_settings_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "GET /tenants/{id}/limits", skip_all)]
async fn handle_list_limits_route(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_limits(tenant_id, tenants, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "PUT /tenants/{id}/limits/{code}/settings",
    skip_all
)]
async fn handle_set_limit_settings_route(
    tenant_id: String,
    code: DecodedSegment,
    settings: LimitSettings,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(set_limit_settings(tenant_id, code.0, settings, tenants, config, caller).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

/// Confines a `view:limits`-only caller to their own tenant; a `manage:limits` admin reads any.
fn enforce_read_scope(tenant_id: &str, caller: &AuthUser) -> anyhow::Result<()> {
    if caller.has_any_permission(REQUIRE_MANAGE_LIMITS) {
        return Ok(());
    }
    if caller.tenant_id()? != tenant_id {
        bail_i18n!(StatusCode::FORBIDDEN, caller.locale(), "tenant.foreign");
    }
    Ok(())
}

async fn list_limits(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    caller: AuthUser,
) -> anyhow::Result<LimitsResponse> {
    enforce_read_scope(&tenant_id, &caller)?;
    let tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };
    Ok(LimitsResponse {
        limits: tenant.limits,
    })
}

async fn set_limit_settings(
    tenant_id: String,
    code: String,
    settings: LimitSettings,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<Value> {
    let config = config.current().await?;
    config.validate_limit_settings(&code, &settings)?;

    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };

    // Phase 1 stores the values. Reconciling them against live counters (grow when a limit rises,
    // shrink or cap at current usage when it falls, warn when already over) is the runtime
    // accounting's job and lands with the state repository — see docs/LIMITS.md.
    if settings == LimitSettings::default() {
        let _ = tenant.limits.remove(&code);
    } else {
        let _ = tenant.limits.insert(code, settings);
    }
    tenant.last_changed_by = Some(caller.user_id()?.to_owned());
    let _ = tenants.put_tenant(tenant).await?;
    Ok(json!({ "status": "saved" }))
}

// ── Booking (check / consume / report / top-up) ──────────────────────────────────

/// Optional actor/context on a booking body — caller-provided, carried onto the ledger entry
/// verbatim (never validated against umami users). `actorUserName` is GDPR-sensitive; a strict
/// deployment omits it and links only by `actorUserId`/`txnId` (see `docs/LIMITS.md`).
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct ActorFields {
    #[serde(default)]
    actor_user_id: Option<String>,
    #[serde(default)]
    actor_user_name: Option<String>,
    #[serde(default)]
    txn_name: Option<String>,
    #[serde(default)]
    txn_id: Option<String>,
    #[serde(default)]
    reference: Option<String>,
}

impl ActorFields {
    fn into_actor(self) -> Actor {
        Actor {
            user_id: self.actor_user_id,
            user_name: self.actor_user_name,
            txn_name: self.txn_name,
            txn_id: self.txn_id,
            reference: self.reference,
        }
    }
}

/// A signed amount to book or top up, plus optional actor/context.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AmountRequest {
    amount: i64,
    #[serde(flatten)]
    actor: ActorFields,
}

/// A gauge value to record, plus optional actor/context.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ValueRequest {
    value: i64,
    #[serde(flatten)]
    actor: ActorFields,
}

/// How a consume drew across the buckets.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Breakdown {
    monthly_drawn: i64,
    custom_drawn: i64,
    overuse_drawn: i64,
    overdrawn: i64,
}

impl Breakdown {
    fn of(entry: &LedgerEntry) -> Self {
        Breakdown {
            monthly_drawn: entry.monthly_drawn,
            custom_drawn: entry.custom_drawn,
            overuse_drawn: entry.overuse_drawn,
            overdrawn: entry.overdrawn,
        }
    }
}

/// What is still spendable, split by bucket.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Remaining {
    monthly: i64,
    custom: i64,
    overuse: i64,
    total: i64,
}

impl Remaining {
    fn of(state: &LimitState) -> Self {
        Remaining {
            monthly: state.monthly_remaining,
            custom: state.custom_balance,
            overuse: state.overuse_remaining,
            total: state.available(),
        }
    }
}

/// Pre-flight answer: whether the amount fits, and what is left right now.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct CheckResponse {
    allowed: bool,
    remaining: Remaining,
}

/// The result of a consume: how it drew, and what is left afterwards.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ConsumeResponse {
    breakdown: Breakdown,
    remaining: Remaining,
}

/// The result of a top-up: the new persistent balance, and the totals it feeds into.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TopupResponse {
    custom_balance: i64,
    remaining: Remaining,
}

/// A gauge read: the value against its bound, with the watermark status the UI highlights on.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GaugeResponse {
    value: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    max: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    percent: Option<i64>,
    /// `"ok"` | `"warning"` (≥ low watermark) | `"critical"` (≥ high watermark).
    status: &'static str,
}

impl GaugeResponse {
    fn new(def: &LimitDef, max: Option<i64>, value: i64) -> Self {
        let (percent, status) = match max.filter(|bound| *bound > 0) {
            Some(bound) => {
                let percent = value.saturating_mul(100) / bound;
                let status = match (def.low_watermark_percent, def.high_watermark_percent) {
                    (_, Some(high)) if percent >= i64::from(high) => "critical",
                    (Some(low), _) if percent >= i64::from(low) => "warning",
                    _ => "ok",
                };
                (Some(percent), status)
            }
            None => (None, "ok"),
        };
        GaugeResponse {
            value,
            max,
            percent,
            status,
        }
    }
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `POST /tenants/{id}/limits/{code}/check` — does `amount` fit? Mutation-free (`book:limits`).
pub fn check_limit_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "limits" / DecodedSegment / "check")
        .and(warp::post())
        .and(with_body_as_json::<AmountRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(limits))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_BOOK_LIMITS,
        ))
        .and_then(handle_check_limit_route)
        .boxed()
}

/// `POST /tenants/{id}/limits/{code}/consume` — book `amount` (`book:limits`).
pub fn consume_limit_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "limits" / DecodedSegment / "consume")
        .and(warp::post())
        .and(with_body_as_json::<AmountRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(limits))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_BOOK_LIMITS,
        ))
        .and_then(handle_consume_limit_route)
        .boxed()
}

/// `POST /tenants/{id}/limits/{code}/report` — set a gauge's current value (`book:limits`).
pub fn report_gauge_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "limits" / DecodedSegment / "report")
        .and(warp::post())
        .and(with_body_as_json::<ValueRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(limits))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_BOOK_LIMITS,
        ))
        .and_then(handle_report_gauge_route)
        .boxed()
}

/// `POST /tenants/{id}/limits/{code}/topup` — grant special balance (`manage:limits`).
pub fn topup_limit_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "limits" / DecodedSegment / "topup")
        .and(warp::post())
        .and(with_body_as_json::<AmountRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(limits))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_LIMITS,
        ))
        .and_then(handle_topup_limit_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(
    level = "debug",
    name = "POST /tenants/{id}/limits/{code}/check",
    skip_all
)]
async fn handle_check_limit_route(
    tenant_id: String,
    code: DecodedSegment,
    request: AmountRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(check_limit(tenant_id, code.0, request, tenants, config, limits).await)
}

#[tracing::instrument(
    level = "debug",
    name = "POST /tenants/{id}/limits/{code}/consume",
    skip_all
)]
async fn handle_consume_limit_route(
    tenant_id: String,
    code: DecodedSegment,
    request: AmountRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(consume_limit(tenant_id, code.0, request, tenants, config, limits).await)
}

#[tracing::instrument(
    level = "debug",
    name = "POST /tenants/{id}/limits/{code}/report",
    skip_all
)]
async fn handle_report_gauge_route(
    tenant_id: String,
    code: DecodedSegment,
    request: ValueRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(report_gauge(tenant_id, code.0, request, tenants, config, limits).await)
}

#[tracing::instrument(
    level = "debug",
    name = "POST /tenants/{id}/limits/{code}/topup",
    skip_all
)]
async fn handle_topup_limit_route(
    tenant_id: String,
    code: DecodedSegment,
    request: AmountRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(topup_limit(tenant_id, code.0, request, tenants, config, limits).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

/// The tenant's settings for a consumable limit, after confirming the code is a defined consumable.
async fn consumable_settings(
    tenant_id: &str,
    code: &str,
    tenants: &Arc<dyn TenantRepository>,
    config: &Arc<dyn ConfigRepository>,
) -> anyhow::Result<LimitSettings> {
    let def = limit_def(config, code).await?;
    if def.kind != LimitKind::Consumable {
        client_bail!("Limit '{code}' is a gauge; use report, not consume/check");
    }
    tenant_limit_settings(tenants, tenant_id, code).await
}

/// A limit's definition, or a client error if the code is unknown.
async fn limit_def(config: &Arc<dyn ConfigRepository>, code: &str) -> anyhow::Result<LimitDef> {
    let config = config.current().await?;
    match config.limits.iter().find(|def| def.code == code) {
        Some(def) => Ok(def.clone()),
        None => client_bail!("Unknown limit '{code}'"),
    }
}

/// A tenant's stored settings for one limit (defaults — all unset — when the tenant has none).
async fn tenant_limit_settings(
    tenants: &Arc<dyn TenantRepository>,
    tenant_id: &str,
    code: &str,
) -> anyhow::Result<LimitSettings> {
    let tenant = match tenants.get_tenant(tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };
    Ok(tenant.limits.get(code).cloned().unwrap_or_default())
}

async fn check_limit(
    tenant_id: String,
    code: String,
    request: AmountRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
) -> anyhow::Result<CheckResponse> {
    if request.amount < 0 {
        client_bail!("amount must not be negative");
    }
    let settings = consumable_settings(&tenant_id, &code, &tenants, &config).await?;
    // Read-only: project the current month in memory (rolling a stale period over) without a write.
    let existing = limits.load_state(&tenant_id, &code).await?;
    let (view, _closed) =
        accounting::rolled_over(existing, &tenant_id, &code, &settings, Utc::now());
    Ok(CheckResponse {
        allowed: view.available() >= request.amount,
        remaining: Remaining::of(&view),
    })
}

async fn consume_limit(
    tenant_id: String,
    code: String,
    request: AmountRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
) -> anyhow::Result<ConsumeResponse> {
    if request.amount < 0 {
        client_bail!("amount must not be negative");
    }
    let settings = consumable_settings(&tenant_id, &code, &tenants, &config).await?;
    let amount = request.amount;
    let actor = request.actor.into_actor();
    let now = Utc::now();
    let entry_id = generate_id();
    let outcome = commit_state(&limits, &tenant_id, &code, |existing| {
        accounting::apply_consume(
            existing, &tenant_id, &code, &settings, amount, now, &entry_id, &actor,
        )
    })
    .await?;
    Ok(ConsumeResponse {
        breakdown: Breakdown::of(&outcome.ledger),
        remaining: Remaining::of(&outcome.state),
    })
}

async fn topup_limit(
    tenant_id: String,
    code: String,
    request: AmountRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
) -> anyhow::Result<TopupResponse> {
    if request.amount < 0 {
        client_bail!("amount must not be negative");
    }
    let def = limit_def(&config, &code).await?;
    if def.kind != LimitKind::Consumable || !def.custom_balance {
        client_bail!("Limit '{code}' has no top-up balance");
    }
    let settings = tenant_limit_settings(&tenants, &tenant_id, &code).await?;
    let amount = request.amount;
    let actor = request.actor.into_actor();
    let now = Utc::now();
    let entry_id = generate_id();
    let outcome = commit_state(&limits, &tenant_id, &code, |existing| {
        accounting::apply_topup(
            existing, &tenant_id, &code, &settings, amount, now, &entry_id, &actor,
        )
    })
    .await?;
    Ok(TopupResponse {
        custom_balance: outcome.state.custom_balance,
        remaining: Remaining::of(&outcome.state),
    })
}

async fn report_gauge(
    tenant_id: String,
    code: String,
    request: ValueRequest,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
) -> anyhow::Result<GaugeResponse> {
    let def = limit_def(&config, &code).await?;
    if def.kind != LimitKind::Gauge {
        client_bail!("Limit '{code}' is consumable; use consume, not report");
    }
    let settings = tenant_limit_settings(&tenants, &tenant_id, &code).await?;
    let value = request.value;
    let actor = request.actor.into_actor();
    let now = Utc::now();
    let entry_id = generate_id();
    let outcome = commit_state(&limits, &tenant_id, &code, |existing| {
        accounting::set_gauge(existing, &tenant_id, &code, value, now, &entry_id, &actor)
    })
    .await?;
    let value = outcome.state.gauge_value.unwrap_or(value);
    Ok(GaugeResponse::new(&def, settings.max, value))
}

/// The optimistic-concurrency loop, shared by every mutating booking op. `produce` turns the loaded
/// state (or `None` on first write) into the [`Outcome`] to commit — state, ledger, and any history
/// a rollover closed. Bounded: after [`LIMIT_CAS_MAX_ATTEMPTS`] version conflicts it fails with a
/// 503 rather than spinning.
async fn commit_state<F>(
    limits: &Arc<dyn LimitRepository>,
    tenant_id: &str,
    code: &str,
    mut produce: F,
) -> anyhow::Result<Outcome>
where
    F: FnMut(Option<LimitState>) -> Outcome,
{
    for _ in 0..LIMIT_CAS_MAX_ATTEMPTS {
        let existing = limits.load_state(tenant_id, code).await?;
        let expected = existing.as_ref().map(|state| state.version);
        let mut outcome = produce(existing);
        outcome.state.version = expected.map(|version| version + 1).unwrap_or(1);
        match limits.compare_and_swap(&outcome, expected).await? {
            CasOutcome::Committed => return Ok(outcome),
            CasOutcome::Conflict => backoff_jitter().await,
        }
    }
    status_bail!(
        StatusCode::SERVICE_UNAVAILABLE,
        "Limit '{code}' is contended; retry"
    );
}

/// Full-jitter sleep in `[MIN, MAX]` ms, so competing bookers do not retry in lockstep.
async fn backoff_jitter() {
    let millis = rand::rng().random_range(LIMIT_CAS_BACKOFF_MIN_MS..=LIMIT_CAS_BACKOFF_MAX_MS);
    tokio::time::sleep(Duration::from_millis(millis)).await;
}

// ── Ledger + history (read-only; view:limits own tenant, manage:limits any) ──────

/// A limit's ledger, newest first.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LedgerResponse {
    entries: Vec<LedgerEntry>,
}

/// A limit's closed-month history, newest month first.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct HistoryResponse {
    months: Vec<HistoryRow>,
}

/// `GET /tenants/{id}/limits/{code}/ledger` — the transaction log for one limit.
pub fn ledger_route(
    limits: Arc<dyn LimitRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "limits" / DecodedSegment / "ledger")
        .and(warp::get())
        .and(with_cloneable(limits))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_READ_LIMITS,
        ))
        .and_then(handle_ledger_route)
        .boxed()
}

/// `GET /tenants/{id}/limits/{code}/history` — the closed-month aggregates for one limit.
pub fn history_route(
    limits: Arc<dyn LimitRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "limits" / DecodedSegment / "history")
        .and(warp::get())
        .and(with_cloneable(limits))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_READ_LIMITS,
        ))
        .and_then(handle_history_route)
        .boxed()
}

#[tracing::instrument(
    level = "debug",
    name = "GET /tenants/{id}/limits/{code}/ledger",
    skip_all
)]
async fn handle_ledger_route(
    tenant_id: String,
    code: DecodedSegment,
    limits: Arc<dyn LimitRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(ledger(tenant_id, code.0, limits, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "GET /tenants/{id}/limits/{code}/history",
    skip_all
)]
async fn handle_history_route(
    tenant_id: String,
    code: DecodedSegment,
    limits: Arc<dyn LimitRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(history(tenant_id, code.0, limits, caller).await)
}

async fn ledger(
    tenant_id: String,
    code: String,
    limits: Arc<dyn LimitRepository>,
    caller: AuthUser,
) -> anyhow::Result<LedgerResponse> {
    enforce_read_scope(&tenant_id, &caller)?;
    let entries = limits.read_ledger(&tenant_id, &code).await?;
    Ok(LedgerResponse { entries })
}

async fn history(
    tenant_id: String,
    code: String,
    limits: Arc<dyn LimitRepository>,
    caller: AuthUser,
) -> anyhow::Result<HistoryResponse> {
    enforce_read_scope(&tenant_id, &caller)?;
    let months = limits.read_history(&tenant_id, &code).await?;
    Ok(HistoryResponse { months })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::repository::StaticConfigRepository;
    use crate::config::{Config, LimitDef, LimitKind};
    use crate::tenants::repository::MockTenantRepository;
    use crate::tenants::{Tenant, slugify};
    use chrono::Utc;
    use wasabi::web::auth::{CLAIM_PERMISSIONS, CLAIM_SUB, CLAIM_TENANT};

    async fn consumable_config() -> Arc<dyn ConfigRepository> {
        let repository = StaticConfigRepository::with_default();
        let limits = vec![
            LimitDef {
                code: "limit:ai-credits".to_owned(),
                name: "AI credits".into(),
                description: None,
                kind: LimitKind::Consumable,
                overuse: true,
                custom_balance: true,
                daily: false,
                low_watermark_percent: None,
                high_watermark_percent: None,
                relevant_if: None,
            },
            LimitDef {
                code: "limit:seats".to_owned(),
                name: "Seats".into(),
                description: None,
                kind: LimitKind::Gauge,
                overuse: false,
                custom_balance: false,
                daily: false,
                low_watermark_percent: Some(70),
                high_watermark_percent: Some(90),
                relevant_if: None,
            },
        ];
        // Save bumps the version; hand it the expected one so optimistic concurrency is satisfied.
        let current = repository.current().await.expect("seeded");
        repository
            .save(
                Config {
                    version: current.version,
                    limits,
                    ..Config::default()
                },
                current.version,
            )
            .await
            .expect("saved");
        Arc::new(repository)
    }

    fn tenant(id: &str) -> Tenant {
        let now = Utc::now();
        Tenant {
            tenant_id: id.to_owned(),
            version: 0,
            features: Vec::new(),
            custom_fields: BTreeMap::new(),
            limits: BTreeMap::new(),
            name: "Acme".to_owned(),
            slug: slugify("Acme"),
            created: now,
            last_updated: now,
            last_active: None,
            last_active_or_created: now,
            created_by: None,
            last_changed_by: None,
        }
    }

    /// A cross-tenant limits admin (holds `manage:limits`).
    fn caller() -> AuthUser {
        AuthUser::builder()
            .with_string(CLAIM_SUB, "admin-1")
            .with_string(CLAIM_TENANT, "system")
            .with_value(CLAIM_PERMISSIONS, json!([MANAGE_LIMITS_PERMISSION]))
            .build()
    }

    /// A plain member of `tenant_id` who may only *read* their own limits (`view:limits`).
    fn member(tenant_id: &str) -> AuthUser {
        AuthUser::builder()
            .with_string(CLAIM_SUB, "member-1")
            .with_string(CLAIM_TENANT, tenant_id)
            .with_value(CLAIM_PERMISSIONS, json!([VIEW_LIMITS_PERMISSION]))
            .build()
    }

    #[tokio::test]
    async fn a_valid_consumable_setting_is_stored() {
        let mut tenants = MockTenantRepository::new();
        tenants
            .expect_get_tenant()
            .returning(|_| Box::pin(async { Ok(Some(tenant("t-1"))) }));
        tenants.expect_put_tenant().returning(|tenant| {
            Box::pin(async move {
                let stored = tenant.limits.get("limit:ai-credits").expect("stored");
                assert_eq!(stored.monthly, Some(1000));
                assert_eq!(stored.overuse, Some(200));
                Ok(tenant)
            })
        });

        let settings = LimitSettings {
            monthly: Some(1000),
            overuse: Some(200),
            daily: None,
            max: None,
        };
        set_limit_settings(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            settings,
            Arc::new(tenants),
            consumable_config().await,
            caller(),
        )
        .await
        .expect("stored");
    }

    #[tokio::test]
    async fn a_gauge_max_on_a_consumable_is_refused() {
        let tenants = MockTenantRepository::new();
        let settings = LimitSettings {
            max: Some(50),
            ..LimitSettings::default()
        };
        let err = set_limit_settings(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            settings,
            Arc::new(tenants),
            consumable_config().await,
            caller(),
        )
        .await
        .expect_err("max is a gauge field");
        assert!(format!("{err:#}").contains("gauge"), "{err:#}");
    }

    #[tokio::test]
    async fn clearing_every_value_removes_the_entry() {
        let mut seeded = tenant("t-1");
        let _ = seeded.limits.insert(
            "limit:ai-credits".to_owned(),
            LimitSettings {
                monthly: Some(10),
                ..LimitSettings::default()
            },
        );
        let mut tenants = MockTenantRepository::new();
        tenants
            .expect_get_tenant()
            .returning(move |_| Box::pin(std::future::ready(Ok(Some(seeded.clone())))));
        tenants.expect_put_tenant().returning(|tenant| {
            Box::pin(async move {
                assert!(!tenant.limits.contains_key("limit:ai-credits"));
                Ok(tenant)
            })
        });

        set_limit_settings(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            LimitSettings::default(),
            Arc::new(tenants),
            consumable_config().await,
            caller(),
        )
        .await
        .expect("removed");
    }

    #[tokio::test]
    async fn an_unknown_limit_is_refused() {
        let tenants = MockTenantRepository::new();
        let err = set_limit_settings(
            "t-1".to_owned(),
            "limit:nope".to_owned(),
            LimitSettings {
                monthly: Some(1),
                ..LimitSettings::default()
            },
            Arc::new(tenants),
            consumable_config().await,
            caller(),
        )
        .await
        .expect_err("unknown limit");
        assert!(format!("{err:#}").contains("Unknown limit"), "{err:#}");
    }

    #[tokio::test]
    async fn a_view_member_is_confined_to_their_own_tenant() {
        let mut tenants = MockTenantRepository::new();
        tenants
            .expect_get_tenant()
            .returning(|_| Box::pin(async { Ok(Some(tenant("t-1"))) }));
        let tenants = Arc::new(tenants);

        // Own tenant: a view member may read it.
        list_limits("t-1".to_owned(), tenants.clone(), member("t-1"))
            .await
            .expect("own tenant readable");

        // Foreign tenant: refused before any store read.
        list_limits("t-2".to_owned(), tenants.clone(), member("t-1"))
            .await
            .expect_err("foreign tenant refused for a view member");

        // A cross-tenant admin reads any tenant.
        list_limits("t-2".to_owned(), tenants, caller())
            .await
            .expect("admin reads any tenant");
    }

    /// A tenant carrying a consumable AI-credits budget.
    fn tenant_with_credits() -> Tenant {
        let mut tenant = tenant("t-1");
        let _ = tenant.limits.insert(
            "limit:ai-credits".to_owned(),
            LimitSettings {
                monthly: Some(1000),
                overuse: Some(200),
                daily: None,
                max: None,
            },
        );
        tenant
    }

    #[tokio::test]
    async fn consume_books_and_retries_a_version_conflict() {
        use crate::limits::repository::MockLimitRepository;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut tenants = MockTenantRepository::new();
        tenants
            .expect_get_tenant()
            .returning(|_| Box::pin(async { Ok(Some(tenant_with_credits())) }));

        let mut limits = MockLimitRepository::new();
        limits
            .expect_load_state()
            .returning(|_, _| Box::pin(async { Ok(None) }));
        // First CAS loses the race, the second lands — the loop must retry, not give up.
        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = attempts.clone();
        limits.expect_compare_and_swap().returning(move |_, _| {
            let n = seen.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(if n == 0 {
                    CasOutcome::Conflict
                } else {
                    CasOutcome::Committed
                })
            })
        });

        let response = consume_limit(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            AmountRequest {
                amount: 300,
                actor: ActorFields::default(),
            },
            Arc::new(tenants),
            consumable_config().await,
            Arc::new(limits),
        )
        .await
        .expect("consumed");
        assert_eq!(response.breakdown.monthly_drawn, 300);
        assert_eq!(response.remaining.monthly, 700);
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            2,
            "one retry after the conflict"
        );
    }

    #[tokio::test]
    async fn consume_gives_up_after_max_conflicts() {
        use crate::limits::repository::MockLimitRepository;

        let mut tenants = MockTenantRepository::new();
        tenants
            .expect_get_tenant()
            .returning(|_| Box::pin(async { Ok(Some(tenant_with_credits())) }));

        let mut limits = MockLimitRepository::new();
        limits
            .expect_load_state()
            .returning(|_, _| Box::pin(async { Ok(None) }));
        // The row is permanently contended: every CAS conflicts.
        limits
            .expect_compare_and_swap()
            .returning(|_, _| Box::pin(async { Ok(CasOutcome::Conflict) }));

        let err = consume_limit(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            AmountRequest {
                amount: 10,
                actor: ActorFields::default(),
            },
            Arc::new(tenants),
            consumable_config().await,
            Arc::new(limits),
        )
        .await
        .expect_err("gives up rather than spinning");
        assert!(format!("{err:#}").contains("contended"), "{err:#}");
    }

    #[tokio::test]
    async fn report_sets_a_gauge_and_flags_the_high_watermark() {
        use crate::limits::repository::MockLimitRepository;

        let mut tenants = MockTenantRepository::new();
        tenants.expect_get_tenant().returning(|_| {
            Box::pin(async {
                let mut tenant = tenant("t-1");
                let _ = tenant.limits.insert(
                    "limit:seats".to_owned(),
                    LimitSettings {
                        max: Some(100),
                        ..LimitSettings::default()
                    },
                );
                Ok(Some(tenant))
            })
        });

        let mut limits = MockLimitRepository::new();
        limits
            .expect_load_state()
            .returning(|_, _| Box::pin(async { Ok(None) }));
        limits
            .expect_compare_and_swap()
            .returning(|_, _| Box::pin(async { Ok(CasOutcome::Committed) }));

        // 95 of 100, high watermark 90 → critical.
        let response = report_gauge(
            "t-1".to_owned(),
            "limit:seats".to_owned(),
            ValueRequest {
                value: 95,
                actor: ActorFields::default(),
            },
            Arc::new(tenants),
            consumable_config().await,
            Arc::new(limits),
        )
        .await
        .expect("reported");
        assert_eq!(response.value, 95);
        assert_eq!(response.percent, Some(95));
        assert_eq!(response.status, "critical");
    }

    #[tokio::test]
    async fn consume_on_a_gauge_is_refused() {
        use crate::limits::repository::MockLimitRepository;

        let mut tenants = MockTenantRepository::new();
        tenants
            .expect_get_tenant()
            .returning(|_| Box::pin(async { Ok(Some(tenant("t-1"))) }));
        let limits = MockLimitRepository::new();

        let err = consume_limit(
            "t-1".to_owned(),
            "limit:seats".to_owned(),
            AmountRequest {
                amount: 1,
                actor: ActorFields::default(),
            },
            Arc::new(tenants),
            consumable_config().await,
            Arc::new(limits),
        )
        .await
        .expect_err("a gauge is not consumable");
        assert!(format!("{err:#}").contains("gauge"), "{err:#}");
    }

    #[tokio::test]
    async fn a_consume_hands_the_repo_a_ledger_entry_with_the_actor() {
        use crate::limits::repository::MockLimitRepository;

        let mut tenants = MockTenantRepository::new();
        tenants
            .expect_get_tenant()
            .returning(|_| Box::pin(async { Ok(Some(tenant_with_credits())) }));

        let mut limits = MockLimitRepository::new();
        limits
            .expect_load_state()
            .returning(|_, _| Box::pin(async { Ok(None) }));
        // The Outcome the loop commits must carry a fully-formed ledger entry: the right type, the
        // bucket split, and the caller-provided actor threaded through.
        limits
            .expect_compare_and_swap()
            .withf(|outcome, _| {
                outcome.ledger.entry_type == crate::limits::ledger_type::CONSUME
                    && outcome.ledger.monthly_drawn == 50
                    && outcome.ledger.actor_user_id.as_deref() == Some("u-7")
                    && outcome.ledger.txn_id.as_deref() == Some("req-1")
            })
            .returning(|_, _| Box::pin(async { Ok(CasOutcome::Committed) }));

        consume_limit(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            AmountRequest {
                amount: 50,
                actor: ActorFields {
                    actor_user_id: Some("u-7".to_owned()),
                    txn_id: Some("req-1".to_owned()),
                    ..ActorFields::default()
                },
            },
            Arc::new(tenants),
            consumable_config().await,
            Arc::new(limits),
        )
        .await
        .expect("consumed");
    }

    #[tokio::test]
    async fn ledger_reads_are_confined_to_a_members_own_tenant() {
        use crate::limits::repository::MockLimitRepository;

        let mut limits = MockLimitRepository::new();
        limits
            .expect_read_ledger()
            .returning(|_, _| Box::pin(async { Ok(Vec::new()) }));
        let limits = Arc::new(limits);

        ledger(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            limits.clone(),
            member("t-1"),
        )
        .await
        .expect("own tenant ledger readable");

        ledger(
            "t-2".to_owned(),
            "limit:ai-credits".to_owned(),
            limits,
            member("t-1"),
        )
        .await
        .expect_err("foreign tenant ledger refused for a view member");
    }
}
