//! Limit management routes: read a tenant's limit settings, and set them.
//!
//! Cross-tenant admin (`manage:limits`): the tenant is named in the path, like the feature
//! grant/revoke endpoints, because a platform operator manages any tenant's quotas — a limits admin
//! is not confined to their own tenant. The values are validated against the config catalogue
//! ([`crate::config::Config::validate_limit_settings`]) before they are stored on the tenant.

use crate::bail_i18n;
use crate::config::repository::ConfigRepository;
use crate::config::{LimitDef, LimitKind, LimitSettings, OverrunPolicy};
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
use std::collections::BTreeSet;
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

/// Max length of a caller-provided actor id (`actorUserId`, `txnId`) — opaque pass-through, capped
/// so a booking cannot stamp unbounded text onto the ledger.
const ACTOR_ID_MAX_LEN: usize = 64;

/// Permissions that may *read* a tenant's limits: the cross-tenant admin, or a member reading their
/// own tenant (`view:limits`). The own-tenant confinement for the latter is enforced in the handler.
const REQUIRE_READ_LIMITS: &[&str] = &[MANAGE_LIMITS_PERMISSION, VIEW_LIMITS_PERMISSION];

/// Permission required to book against a tenant's limits (product-service key).
const REQUIRE_BOOK_LIMITS: &[&str] = &[BOOK_LIMITS_PERMISSION];

/// The live counters for one limit, as a screen shows them (the internal snapshots and version are
/// left out). Present only once the limit has been used at least once.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LimitStateView {
    period_year_month: String,
    monthly_remaining: i64,
    extra_allowance_remaining: i64,
    custom_balance: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_remaining: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    overrun: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gauge_value: Option<i64>,
}

impl LimitStateView {
    fn of(state: &LimitState) -> Self {
        LimitStateView {
            period_year_month: state.period_year_month.clone(),
            monthly_remaining: state.monthly_remaining,
            extra_allowance_remaining: state.extra_allowance_remaining,
            custom_balance: state.custom_balance,
            daily_remaining: state.daily_date.as_ref().map(|_| state.daily_remaining),
            overrun: (state.overrun > 0).then_some(state.overrun),
            gauge_value: state.gauge_value,
        }
    }
}

/// One of a tenant's limits: its stored settings and, when it has been used, the current counters.
/// The definitions (labels, facets, watermarks) come separately from `GET /config/catalogue`; a
/// screen merges the two by `code`.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LimitEntry {
    code: String,
    settings: LimitSettings,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<LimitStateView>,
}

/// A tenant's limits with their live state.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LimitsResponse {
    limits: Vec<LimitEntry>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `GET /tenants/{id}/limits` — a tenant's per-limit settings. `manage:limits` reads any tenant;
/// `view:limits` reads only the caller's own (self-service).
pub fn list_limits_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    limits: Arc<dyn LimitRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "limits")
        .and(warp::get())
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(system_tenant_id))
        .and(with_cloneable(limits))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_READ_LIMITS,
        ))
        .and_then(handle_list_limits_route)
        .boxed()
}

/// `PUT /tenants/{id}/limits/{code}/settings` — set a tenant's values for one limit, reconciling the
/// live counters against the change.
pub fn set_limit_settings_route(
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "limits" / DecodedSegment / "settings")
        .and(warp::put())
        .and(warp::query::<ConfirmQuery>())
        .and(with_body_as_json::<LimitSettings>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_cloneable(limits))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_LIMITS,
        ))
        .and_then(handle_set_limit_settings_route)
        .boxed()
}

/// `?confirm=true` acknowledges a settings change that re-books overrun, so it is applied rather
/// than previewed.
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct ConfirmQuery {
    #[serde(default)]
    confirm: bool,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "GET /tenants/{id}/limits", skip_all)]
async fn handle_list_limits_route(
    tenant_id: String,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    limits: Arc<dyn LimitRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(list_limits(tenant_id, tenants, config, system_tenant_id, limits, caller).await)
}

#[tracing::instrument(
    level = "debug",
    name = "PUT /tenants/{id}/limits/{code}/settings",
    skip_all
)]
#[allow(clippy::too_many_arguments)]
async fn handle_set_limit_settings_route(
    tenant_id: String,
    code: DecodedSegment,
    query: ConfirmQuery,
    settings: LimitSettings,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(
        set_limit_settings(
            tenant_id,
            code.0,
            settings,
            query.confirm,
            tenants,
            config,
            limits,
            caller,
        )
        .await,
    )
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
    config: Arc<dyn ConfigRepository>,
    system_tenant_id: Option<String>,
    limits: Arc<dyn LimitRepository>,
    caller: AuthUser,
) -> anyhow::Result<LimitsResponse> {
    enforce_read_scope(&tenant_id, &caller)?;
    let tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };

    // The codes to show: every limit **relevant** to this tenant (its `relevantIf` holds), plus
    // every limit the tenant already carries settings for — so a limit that stopped being relevant,
    // or lost its definition entirely, stays visible and removable. BTreeSet dedupes and orders.
    let config = config.current().await?;
    let is_system = system_tenant_id.as_deref() == Some(tenant_id.as_str());
    let features = config.eval_feature_set(&tenant.features, is_system);
    let mut codes: BTreeSet<String> = config.relevant_limits(&features).into_iter().collect();
    codes.extend(tenant.limits.keys().cloned());

    let now = Utc::now();
    let mut entries = Vec::with_capacity(codes.len());
    for code in codes {
        let settings = tenant.limits.get(&code).cloned().unwrap_or_default();
        // Project the live state to the current month/day in memory (no write), so the screen shows
        // what is actually left without needing the booking permission.
        let state = match limits.load_state(&tenant_id, &code).await? {
            Some(state) => {
                // The projection reflects a pending `carry` in the displayed balances; the carry
                // ledger itself is discarded (it is written on the next actual booking).
                let policy = config
                    .limits
                    .iter()
                    .find(|def| def.code == code)
                    .map(|def| def.overrun_policy)
                    .unwrap_or_default();
                let (view, _closed, _carry) = accounting::rolled_over(
                    Some(state),
                    &tenant_id,
                    &code,
                    &settings,
                    policy,
                    now,
                    "",
                );
                Some(LimitStateView::of(&view))
            }
            None => None,
        };
        entries.push(LimitEntry {
            code,
            settings,
            state,
        });
    }
    Ok(LimitsResponse { limits: entries })
}

#[allow(clippy::too_many_arguments)]
async fn set_limit_settings(
    tenant_id: String,
    code: String,
    settings: LimitSettings,
    confirm: bool,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    limits: Arc<dyn LimitRepository>,
    caller: AuthUser,
) -> anyhow::Result<SettingsResponse> {
    let config = config.current().await?;
    // Clearing (empty settings) removes the entry and is allowed for *any* code — that is how an
    // orphaned limit, whose definition has since been removed from the config, gets cleaned up. It
    // never re-books (the limit is going away), so it always saves straight through.
    let clearing = settings == LimitSettings::default();
    if !clearing {
        config.validate_limit_settings(&code, &settings)?;
    }
    let policy = config
        .limits
        .iter()
        .find(|def| def.code == code)
        .map(|def| def.overrun_policy)
        .unwrap_or_default();

    // A value change against an existing state row may re-book overrun (a cut below usage adds debt;
    // a rise retires it). That is a real ledger movement, so unless the caller confirmed it, preview
    // the reconcile and, when it would move the overrun, ask first instead of writing anything.
    if !clearing
        && !confirm
        && let Some(state) = limits.load_state(&tenant_id, &code).await?
    {
        let now = Utc::now();
        let (rolled, _, _) = accounting::rolled_over(
            Some(state.clone()),
            &tenant_id,
            &code,
            &settings,
            policy,
            now,
            "",
        );
        let (outcome, warnings) = accounting::apply_settings_change(
            Some(state),
            &tenant_id,
            &code,
            &settings,
            now,
            &generate_id(),
            &settings_actor(&caller),
            policy,
        );
        if outcome.state.overrun != rolled.overrun {
            return Ok(SettingsResponse {
                status: "confirmationRequired",
                requires_confirmation: true,
                warnings,
            });
        }
    }

    let mut tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };

    // Only write the tenant when the stored value actually differs — a re-save of the same settings
    // must not bump the version. (Clearing an already-absent entry is likewise nothing to write.)
    let stored_matches = match tenant.limits.get(&code) {
        Some(stored) => !clearing && stored == &settings,
        None => clearing,
    };
    if !stored_matches {
        if clearing {
            let _ = tenant.limits.remove(&code);
        } else {
            let _ = tenant.limits.insert(code.clone(), settings.clone());
        }
        tenant.last_changed_by = Some(caller.user_id()?.to_owned());
        let _ = tenants.put_tenant(tenant).await?;
    }

    // Reconcile the live counters (L3) to the settings so the change takes effect this month, not
    // just next. Its own preview skips the write when nothing changed, so a true no-op save touches
    // neither store; a state that drifted from L2 still catches up here. Clearing skips it — the
    // limit is gone, so there is nothing to keep consistent (its state row is left orphaned).
    let warnings = if clearing {
        Vec::new()
    } else {
        reconcile_limit_state(&limits, &tenant_id, &code, &settings, &caller, policy).await?
    };
    Ok(SettingsResponse {
        status: "saved",
        requires_confirmation: false,
        warnings,
    })
}

/// The actor stamped on a settings/reconcile ledger entry (the entry's `type` already marks it as a
/// settings change; only the acting user id is recorded).
fn settings_actor(caller: &AuthUser) -> Actor {
    Actor {
        user_id: caller.user_id().ok().map(str::to_owned),
        txn_id: None,
        source: None,
    }
}

/// The result of a settings write: whether it saved (or needs confirmation because it would re-book
/// overrun), and any advisory reconciliation warnings.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SettingsResponse {
    status: &'static str,
    requires_confirmation: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

/// Reconciles an existing state row to changed settings via the CAS loop, recording a `settings`
/// ledger entry. A no-op (no warnings) when the limit has no state yet.
async fn reconcile_limit_state(
    limits: &Arc<dyn LimitRepository>,
    tenant_id: &str,
    code: &str,
    settings: &LimitSettings,
    caller: &AuthUser,
    policy: OverrunPolicy,
) -> anyhow::Result<Vec<String>> {
    let Some(state) = limits.load_state(tenant_id, code).await? else {
        return Ok(Vec::new());
    };
    let actor = settings_actor(caller);
    let now = Utc::now();
    let entry_id = generate_id();

    // Preview the reconcile once: when it changes nothing — the counters already match and no month
    // rolled over — skip the write entirely, so re-saving an unchanged limit leaves no all-zero
    // `settings` ledger entry. Any advisory warnings (e.g. a gauge value now above its max) still
    // come back.
    let (rolled, _, _) = accounting::rolled_over(
        Some(state.clone()),
        tenant_id,
        code,
        settings,
        policy,
        now,
        "",
    );
    let (preview, warnings) = accounting::apply_settings_change(
        Some(state),
        tenant_id,
        code,
        settings,
        now,
        &entry_id,
        &actor,
        policy,
    );
    if preview.state == rolled && preview.history.is_none() && preview.rollover.is_none() {
        return Ok(warnings);
    }

    let (_outcome, warnings) = commit_state(limits, tenant_id, code, |existing| {
        accounting::apply_settings_change(
            existing, tenant_id, code, settings, now, &entry_id, &actor, policy,
        )
    })
    .await?;
    Ok(warnings)
}

// ── Booking (check / consume / report / top-up) ──────────────────────────────────

/// Optional actor/context on a booking body — opaque ids, caller-provided and carried onto the
/// ledger entry verbatim (never validated against umami users), each capped at
/// [`ACTOR_ID_MAX_LEN`] at ingress. `source` names the calling component/client; with `txnId` it
/// identifies exactly which call an entry belongs to. No names or free-text, so nothing
/// GDPR-sensitive is stored.
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct ActorFields {
    #[serde(default)]
    actor_user_id: Option<String>,
    #[serde(default)]
    txn_id: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

impl ActorFields {
    /// Validates the id lengths (a 400 when any is too long), then builds the [`Actor`].
    fn into_actor(self) -> anyhow::Result<Actor> {
        check_actor_id_len("actorUserId", self.actor_user_id.as_deref())?;
        check_actor_id_len("txnId", self.txn_id.as_deref())?;
        check_actor_id_len("source", self.source.as_deref())?;
        Ok(Actor {
            user_id: self.actor_user_id,
            txn_id: self.txn_id,
            source: self.source,
        })
    }
}

/// Rejects an actor id longer than [`ACTOR_ID_MAX_LEN`] characters.
fn check_actor_id_len(field: &str, value: Option<&str>) -> anyhow::Result<()> {
    if let Some(value) = value
        && value.chars().count() > ACTOR_ID_MAX_LEN
    {
        client_bail!("{field} must be at most {ACTOR_ID_MAX_LEN} characters");
    }
    Ok(())
}

/// A signed amount to book or top up, plus optional actor/context.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AmountRequest {
    amount: i64,
    #[serde(flatten)]
    actor: ActorFields,
}

/// A gauge value to record. A gauge writes no ledger, so it carries no actor/context.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ValueRequest {
    value: i64,
}

/// How a consume drew across the buckets.
#[derive(Serialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct Breakdown {
    monthly_drawn: i64,
    custom_drawn: i64,
    extra_allowance_drawn: i64,
    overrun: i64,
}

impl Breakdown {
    fn of(entry: &LedgerEntry) -> Self {
        Breakdown {
            monthly_drawn: entry.monthly_drawn,
            custom_drawn: entry.custom_drawn,
            extra_allowance_drawn: entry.extra_allowance_drawn,
            overrun: entry.overrun,
        }
    }
}

/// What is still spendable, split by bucket. `daily` is the throttle's remaining allowance today —
/// a cap, not a spendable bucket, so it is not part of `total`; absent when the limit has no daily
/// throttle.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Remaining {
    monthly: i64,
    custom: i64,
    extra_allowance: i64,
    total: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily: Option<i64>,
}

impl Remaining {
    fn of(state: &LimitState) -> Self {
        Remaining {
            monthly: state.monthly_remaining,
            custom: state.custom_balance,
            extra_allowance: state.extra_allowance_remaining,
            total: state.available(),
            // Present only once a daily throttle has been applied (its date is then set).
            daily: state.daily_date.as_ref().map(|_| state.daily_remaining),
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
) -> anyhow::Result<(LimitSettings, OverrunPolicy)> {
    let def = limit_def(config, code).await?;
    if def.kind != LimitKind::Consumable {
        client_bail!("Limit '{code}' is a gauge; use report, not consume/check");
    }
    let settings = tenant_limit_settings(tenants, tenant_id, code).await?;
    Ok((settings, def.overrun_policy))
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
    let (settings, policy) = consumable_settings(&tenant_id, &code, &tenants, &config).await?;
    // Read-only: project the current month/day in memory (rolling a stale period over, carry
    // reflected in the balances) without a write.
    let existing = limits.load_state(&tenant_id, &code).await?;
    let (view, _closed, _carry) = accounting::rolled_over(
        existing,
        &tenant_id,
        &code,
        &settings,
        policy,
        Utc::now(),
        "",
    );
    // The daily throttle is an independent gate on top of the spendable buckets.
    let daily_ok = settings.daily.is_none() || view.daily_remaining >= request.amount;
    Ok(CheckResponse {
        allowed: view.available() >= request.amount && daily_ok,
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
    let (settings, policy) = consumable_settings(&tenant_id, &code, &tenants, &config).await?;
    let amount = request.amount;
    let actor = request.actor.into_actor()?;
    let now = Utc::now();
    let entry_id = generate_id();
    let (outcome, ()) = commit_state(&limits, &tenant_id, &code, |existing| {
        (
            accounting::apply_consume(
                existing, &tenant_id, &code, &settings, amount, now, &entry_id, &actor, policy,
            ),
            (),
        )
    })
    .await?;
    if outcome.rejected {
        status_bail!(
            StatusCode::TOO_MANY_REQUESTS,
            "Limit '{code}' is exhausted; booking rejected"
        );
    }
    Ok(ConsumeResponse {
        // A consume always records a ledger entry; the default is an unreachable safety net.
        breakdown: outcome
            .ledger
            .as_ref()
            .map(Breakdown::of)
            .unwrap_or_default(),
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
    let policy = def.overrun_policy;
    let settings = tenant_limit_settings(&tenants, &tenant_id, &code).await?;
    let amount = request.amount;
    let actor = request.actor.into_actor()?;
    let now = Utc::now();
    let entry_id = generate_id();
    let (outcome, ()) = commit_state(&limits, &tenant_id, &code, |existing| {
        (
            accounting::apply_topup(
                existing, &tenant_id, &code, &settings, amount, now, &entry_id, &actor, policy,
            ),
            (),
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
    let now = Utc::now();
    let max = settings.max;
    // A gauge records no ledger entry, so it needs no actor/context — the request's actor fields are
    // ignored.
    let (outcome, ()) = commit_state(&limits, &tenant_id, &code, |existing| {
        (
            accounting::set_gauge(existing, &tenant_id, &code, value, max, now),
            (),
        )
    })
    .await?;
    let value = outcome.state.gauge_value.unwrap_or(value);
    Ok(GaugeResponse::new(&def, settings.max, value))
}

/// The optimistic-concurrency loop, shared by every mutating op. `produce` turns the loaded state
/// (or `None` on first write) into the [`Outcome`] to commit — state, ledger, and any history a
/// rollover closed — plus an `extra` payload it hands back on success (a settings change's warnings;
/// `()` for a booking). Bounded: after [`LIMIT_CAS_MAX_ATTEMPTS`] version conflicts it fails with a
/// 503 rather than spinning.
async fn commit_state<T, F>(
    limits: &Arc<dyn LimitRepository>,
    tenant_id: &str,
    code: &str,
    mut produce: F,
) -> anyhow::Result<(Outcome, T)>
where
    F: FnMut(Option<LimitState>) -> (Outcome, T),
{
    for _ in 0..LIMIT_CAS_MAX_ATTEMPTS {
        let existing = limits.load_state(tenant_id, code).await?;
        let expected = existing.as_ref().map(|state| state.version);
        let (mut outcome, extra) = produce(existing);
        // A rejected booking (reject policy, over budget) writes nothing; the caller turns it into
        // a 429.
        if outcome.rejected {
            return Ok((outcome, extra));
        }
        outcome.state.version = expected.map(|version| version + 1).unwrap_or(1);
        match limits.compare_and_swap(&outcome, expected).await? {
            CasOutcome::Committed => return Ok((outcome, extra)),
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

/// Default ledger page size when the caller names none.
const LEDGER_DEFAULT_PAGE_SIZE: i32 = 50;

/// Ledger paging query: an opaque `cursor` from a prior page, and a `limit` (clamped by the repo).
#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct LedgerQuery {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<i32>,
}

/// A page of a limit's ledger, newest first, with the cursor to fetch the next page (absent at the
/// end of the trail).
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LedgerResponse {
    entries: Vec<LedgerEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
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
        .and(warp::query::<LedgerQuery>())
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
    query: LedgerQuery,
    limits: Arc<dyn LimitRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(ledger(tenant_id, code.0, query, limits, caller).await)
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
    query: LedgerQuery,
    limits: Arc<dyn LimitRepository>,
    caller: AuthUser,
) -> anyhow::Result<LedgerResponse> {
    enforce_read_scope(&tenant_id, &caller)?;
    let limit = query.limit.unwrap_or(LEDGER_DEFAULT_PAGE_SIZE);
    let (entries, next_cursor) = limits
        .read_ledger(&tenant_id, &code, query.cursor.as_deref(), limit)
        .await?;
    Ok(LedgerResponse {
        entries,
        next_cursor,
    })
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

/// The year and month a billing read is for — a `2026`/`9` pair the caller thinks in, normalised to
/// the `"YYYY-MM"` a history row is keyed by.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BillingQuery {
    year: i32,
    month: u32,
}

impl BillingQuery {
    /// `"YYYY-MM"`, or a client error when the month is out of range.
    fn year_month(&self) -> anyhow::Result<String> {
        if self.month < 1 || self.month > 12 {
            client_bail!("month must be between 1 and 12");
        }
        Ok(format!("{:04}-{:02}", self.year, self.month))
    }
}

/// One month's closed aggregates for billing — the settled `extraAllowanceUsed`/`overrun` per
/// limit that a billing tool reconciles against.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BillingResponse {
    year_month: String,
    limits: Vec<HistoryRow>,
}

/// `GET /tenants/{id}/limits/{code}/billing?year=&month=` — one limit's closed month (`manage:limits`).
pub fn billing_route(
    limits: Arc<dyn LimitRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "limits" / DecodedSegment / "billing")
        .and(warp::get())
        .and(warp::query::<BillingQuery>())
        .and(with_cloneable(limits))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_LIMITS,
        ))
        .and_then(handle_billing_route)
        .boxed()
}

/// `GET /tenants/{id}/billing?year=&month=` — every limit's closed month (`manage:limits`).
pub fn billing_month_route(
    limits: Arc<dyn LimitRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "billing")
        .and(warp::get())
        .and(warp::query::<BillingQuery>())
        .and(with_cloneable(limits))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_MANAGE_LIMITS,
        ))
        .and_then(handle_billing_month_route)
        .boxed()
}

#[tracing::instrument(
    level = "debug",
    name = "GET /tenants/{id}/limits/{code}/billing",
    skip_all
)]
async fn handle_billing_route(
    tenant_id: String,
    code: DecodedSegment,
    query: BillingQuery,
    limits: Arc<dyn LimitRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(billing(tenant_id, Some(code.0), query, limits).await)
}

#[tracing::instrument(level = "debug", name = "GET /tenants/{id}/billing", skip_all)]
async fn handle_billing_month_route(
    tenant_id: String,
    query: BillingQuery,
    limits: Arc<dyn LimitRepository>,
    _caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(billing(tenant_id, None, query, limits).await)
}

async fn billing(
    tenant_id: String,
    code: Option<String>,
    query: BillingQuery,
    limits: Arc<dyn LimitRepository>,
) -> anyhow::Result<BillingResponse> {
    // Cross-tenant admin/billing read — the route already gates it on `manage:limits`, so there is
    // no active-tenant scope to enforce here.
    let year_month = query.year_month()?;
    let rows = limits
        .read_month_history(&tenant_id, code.as_deref(), &year_month)
        .await?;
    Ok(BillingResponse {
        year_month,
        limits: rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::repository::StaticConfigRepository;
    use crate::config::{Config, LimitDef, LimitKind};
    use crate::tenants::repository::MockTenantRepository;
    use crate::tenants::{Tenant, slugify};
    use chrono::Utc;
    use serde_json::json;
    use std::collections::BTreeMap;
    use wasabi::web::auth::{CLAIM_PERMISSIONS, CLAIM_SUB, CLAIM_TENANT};

    /// A `LimitRepository` with no state yet — settings reconciliation then skips (no warnings).
    fn no_state_limits() -> Arc<dyn LimitRepository> {
        use crate::limits::repository::MockLimitRepository;
        let mut limits = MockLimitRepository::new();
        limits
            .expect_load_state()
            .returning(|_, _| Box::pin(async { Ok(None) }));
        Arc::new(limits)
    }

    async fn consumable_config() -> Arc<dyn ConfigRepository> {
        let repository = StaticConfigRepository::with_default();
        let limits = vec![
            LimitDef {
                code: "limit:ai-credits".to_owned(),
                name: "AI credits".into(),
                description: None,
                kind: LimitKind::Consumable,
                extra_allowance: true,
                custom_balance: true,
                daily: false,
                low_watermark_percent: None,
                high_watermark_percent: None,
                relevant_if: None,
                unit: None,
                overrun_policy: OverrunPolicy::Track,
            },
            LimitDef {
                code: "limit:seats".to_owned(),
                name: "Seats".into(),
                description: None,
                kind: LimitKind::Gauge,
                extra_allowance: false,
                custom_balance: false,
                daily: false,
                low_watermark_percent: Some(70),
                high_watermark_percent: Some(90),
                relevant_if: None,
                unit: None,
                overrun_policy: OverrunPolicy::Track,
            },
            LimitDef {
                code: "limit:ai-daily".to_owned(),
                name: "AI (throttled)".into(),
                description: None,
                kind: LimitKind::Consumable,
                extra_allowance: false,
                custom_balance: false,
                daily: true,
                low_watermark_percent: None,
                high_watermark_percent: None,
                relevant_if: None,
                unit: None,
                overrun_policy: OverrunPolicy::Track,
            },
            LimitDef {
                code: "limit:prepaid".to_owned(),
                name: "Prepaid".into(),
                description: None,
                kind: LimitKind::Consumable,
                extra_allowance: false,
                custom_balance: false,
                daily: false,
                low_watermark_percent: None,
                high_watermark_percent: None,
                relevant_if: None,
                unit: None,
                overrun_policy: OverrunPolicy::Reject,
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
                assert_eq!(stored.extra_allowance, Some(200));
                Ok(tenant)
            })
        });

        let settings = LimitSettings {
            monthly: Some(1000),
            extra_allowance: Some(200),
            daily: None,
            max: None,
        };
        set_limit_settings(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            settings,
            false,
            Arc::new(tenants),
            consumable_config().await,
            no_state_limits(),
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
            false,
            Arc::new(tenants),
            consumable_config().await,
            no_state_limits(),
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
            false,
            Arc::new(tenants),
            consumable_config().await,
            no_state_limits(),
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
            false,
            Arc::new(tenants),
            consumable_config().await,
            no_state_limits(),
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
        list_limits(
            "t-1".to_owned(),
            tenants.clone(),
            consumable_config().await,
            None,
            no_state_limits(),
            member("t-1"),
        )
        .await
        .expect("own tenant readable");

        // Foreign tenant: refused before any store read.
        list_limits(
            "t-2".to_owned(),
            tenants.clone(),
            consumable_config().await,
            None,
            no_state_limits(),
            member("t-1"),
        )
        .await
        .expect_err("foreign tenant refused for a view member");

        // A cross-tenant admin reads any tenant.
        list_limits(
            "t-2".to_owned(),
            tenants,
            consumable_config().await,
            None,
            no_state_limits(),
            caller(),
        )
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
                extra_allowance: Some(200),
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
            ValueRequest { value: 95 },
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
    async fn a_reject_policy_consume_over_budget_is_refused_and_writes_nothing() {
        use crate::limits::repository::MockLimitRepository;

        let mut tenants = MockTenantRepository::new();
        tenants.expect_get_tenant().returning(|_| {
            Box::pin(async {
                let mut tenant = tenant("t-1");
                let _ = tenant.limits.insert(
                    "limit:prepaid".to_owned(),
                    LimitSettings {
                        monthly: Some(100),
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
        // No compare_and_swap expectation: a rejected booking must never reach the store.

        let err = consume_limit(
            "t-1".to_owned(),
            "limit:prepaid".to_owned(),
            AmountRequest {
                amount: 250,
                actor: ActorFields::default(),
            },
            Arc::new(tenants),
            consumable_config().await,
            Arc::new(limits),
        )
        .await
        .expect_err("over a prepaid cap");
        assert!(format!("{err:#}").contains("exhausted"), "{err:#}");
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
                outcome.ledger.as_ref().is_some_and(|ledger| {
                    ledger.entry_type == crate::limits::ledger_type::CONSUME
                        && ledger.monthly_drawn == 50
                        && ledger.actor_user_id.as_deref() == Some("u-7")
                        && ledger.txn_id.as_deref() == Some("req-1")
                })
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
                    source: Some("chat-web".to_owned()),
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
            .returning(|_, _, _, _| Box::pin(async { Ok((Vec::new(), None)) }));
        let limits = Arc::new(limits);

        ledger(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            LedgerQuery::default(),
            limits.clone(),
            member("t-1"),
        )
        .await
        .expect("own tenant ledger readable");

        ledger(
            "t-2".to_owned(),
            "limit:ai-credits".to_owned(),
            LedgerQuery::default(),
            limits,
            member("t-1"),
        )
        .await
        .expect_err("foreign tenant ledger refused for a view member");
    }

    #[tokio::test]
    async fn check_refuses_when_the_daily_throttle_is_spent() {
        use crate::limits::repository::MockLimitRepository;

        let now = Utc::now();
        let month = accounting::year_month(now);
        let today = now.format("%Y-%m-%d").to_string();
        let daily_settings = LimitSettings {
            monthly: Some(1000),
            extra_allowance: None,
            daily: Some(100),
            max: None,
        };

        let mut tenants = MockTenantRepository::new();
        let tenant_settings = daily_settings.clone();
        tenants.expect_get_tenant().returning(move |_| {
            let settings = tenant_settings.clone();
            Box::pin(async move {
                let mut tenant = tenant("t-1");
                let _ = tenant.limits.insert("limit:ai-daily".to_owned(), settings);
                Ok(Some(tenant))
            })
        });

        // State for the current month/day with the monthly budget untouched but the day spent.
        let mut seeded = LimitState::fresh("t-1", "limit:ai-daily", &month, &daily_settings);
        seeded.daily_remaining = 0;
        seeded.daily_date = Some(today);
        let mut limits = MockLimitRepository::new();
        limits.expect_load_state().returning(move |_, _| {
            let state = seeded.clone();
            Box::pin(async move { Ok(Some(state)) })
        });

        let response = check_limit(
            "t-1".to_owned(),
            "limit:ai-daily".to_owned(),
            AmountRequest {
                amount: 10,
                actor: ActorFields::default(),
            },
            Arc::new(tenants),
            consumable_config().await,
            Arc::new(limits),
        )
        .await
        .expect("checked");

        // The monthly budget still has 1000, but today's throttle is spent → refused.
        assert!(!response.allowed);
        assert_eq!(response.remaining.monthly, 1000);
        assert_eq!(response.remaining.daily, Some(0));
    }

    #[tokio::test]
    async fn a_settings_change_reconciles_the_live_state_and_warns() {
        use crate::limits::repository::MockLimitRepository;

        let now = Utc::now();
        let month = accounting::year_month(now);

        let mut tenants = MockTenantRepository::new();
        tenants.expect_get_tenant().returning(|_| {
            Box::pin(async {
                let mut tenant = tenant("t-1");
                // Stored at 1000; the save below lowers it to 200 — a genuine change.
                let _ = tenant.limits.insert(
                    "limit:ai-credits".to_owned(),
                    LimitSettings {
                        monthly: Some(1000),
                        extra_allowance: None,
                        daily: None,
                        max: None,
                    },
                );
                Ok(Some(tenant))
            })
        });
        tenants
            .expect_put_tenant()
            .returning(|tenant| Box::pin(async move { Ok(tenant) }));

        // Existing state this month: 900 of 1000 already used.
        let mut seeded = LimitState::fresh(
            "t-1",
            "limit:ai-credits",
            &month,
            &LimitSettings {
                monthly: Some(1000),
                extra_allowance: None,
                daily: None,
                max: None,
            },
        );
        seeded.monthly_remaining = 100;
        let mut limits = MockLimitRepository::new();
        limits.expect_load_state().returning(move |_, _| {
            let state = seeded.clone();
            Box::pin(async move { Ok(Some(state)) })
        });
        limits
            .expect_compare_and_swap()
            .returning(|_, _| Box::pin(async { Ok(CasOutcome::Committed) }));

        // New monthly 200 is below the 900 already used → capped at 0, with a warning.
        let response = set_limit_settings(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            LimitSettings {
                monthly: Some(200),
                extra_allowance: None,
                daily: None,
                max: None,
            },
            true,
            Arc::new(tenants),
            consumable_config().await,
            Arc::new(limits),
            caller(),
        )
        .await
        .expect("saved");
        assert_eq!(response.status, "saved");
        assert_eq!(response.warnings.len(), 1);
        assert!(
            response.warnings[0].contains("monthly"),
            "{:?}",
            response.warnings
        );
    }

    #[tokio::test]
    async fn an_unchanged_settings_save_writes_nothing() {
        use crate::limits::repository::MockLimitRepository;

        let month = accounting::year_month(Utc::now());
        let mut tenants = MockTenantRepository::new();
        tenants.expect_get_tenant().returning(|_| {
            Box::pin(async {
                let mut tenant = tenant("t-1");
                let _ = tenant.limits.insert(
                    "limit:ai-credits".to_owned(),
                    LimitSettings {
                        monthly: Some(1000),
                        extra_allowance: None,
                        daily: None,
                        max: None,
                    },
                );
                Ok(Some(tenant))
            })
        });
        // No expect_put_tenant: an unchanged save must not write the tenant (no version bump).

        // 600 already used of 1000; the save re-submits the same 1000.
        let mut seeded = LimitState::fresh(
            "t-1",
            "limit:ai-credits",
            &month,
            &LimitSettings {
                monthly: Some(1000),
                extra_allowance: None,
                daily: None,
                max: None,
            },
        );
        seeded.monthly_remaining = 400;
        let mut limits = MockLimitRepository::new();
        limits.expect_load_state().returning(move |_, _| {
            let state = seeded.clone();
            Box::pin(async move { Ok(Some(state)) })
        });
        // No expect_compare_and_swap: an unchanged reconcile must not write a ledger entry.

        let response = set_limit_settings(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            LimitSettings {
                monthly: Some(1000),
                extra_allowance: None,
                daily: None,
                max: None,
            },
            false,
            Arc::new(tenants),
            consumable_config().await,
            Arc::new(limits),
            caller(),
        )
        .await
        .expect("saved");
        assert_eq!(response.status, "saved");
        assert!(response.warnings.is_empty());
    }

    #[tokio::test]
    async fn lowering_a_used_limit_asks_to_confirm_and_writes_nothing() {
        use crate::limits::repository::MockLimitRepository;

        let month = accounting::year_month(Utc::now());
        // 900 of the 1000 monthly is already used this month.
        let mut seeded = LimitState::fresh(
            "t-1",
            "limit:ai-credits",
            &month,
            &LimitSettings {
                monthly: Some(1000),
                extra_allowance: Some(200),
                daily: None,
                max: None,
            },
        );
        seeded.monthly_remaining = 100;

        let mut tenants = MockTenantRepository::new();
        tenants
            .expect_get_tenant()
            .returning(|_| Box::pin(async { Ok(Some(tenant_with_credits())) }));
        // No expect_put_tenant: the preview path must not write the tenant.
        let mut limits = MockLimitRepository::new();
        limits.expect_load_state().returning(move |_, _| {
            let state = seeded.clone();
            Box::pin(async move { Ok(Some(state)) })
        });
        // No expect_compare_and_swap: the preview path must not reconcile the state either.

        // Cutting monthly 1000 -> 500 (below the 900 used) re-books overrun, so without confirm it
        // asks first and writes nothing.
        let response = set_limit_settings(
            "t-1".to_owned(),
            "limit:ai-credits".to_owned(),
            LimitSettings {
                monthly: Some(500),
                extra_allowance: Some(200),
                daily: None,
                max: None,
            },
            false,
            Arc::new(tenants),
            consumable_config().await,
            Arc::new(limits),
            caller(),
        )
        .await
        .expect("previewed");
        assert_eq!(response.status, "confirmationRequired");
        assert!(response.requires_confirmation);
        assert!(!response.warnings.is_empty());
    }

    #[tokio::test]
    async fn listing_limits_includes_the_projected_state() {
        use crate::limits::repository::MockLimitRepository;

        let month = accounting::year_month(Utc::now());
        let mut tenants = MockTenantRepository::new();
        tenants
            .expect_get_tenant()
            .returning(|_| Box::pin(async { Ok(Some(tenant_with_credits())) }));

        let mut seeded = LimitState::fresh(
            "t-1",
            "limit:ai-credits",
            &month,
            &LimitSettings {
                monthly: Some(1000),
                extra_allowance: Some(200),
                daily: None,
                max: None,
            },
        );
        seeded.monthly_remaining = 400;
        let mut limits = MockLimitRepository::new();
        // Only the credits limit has state; the other (relevant, unset) catalogue limits have none.
        limits.expect_load_state().returning(move |_, code| {
            let state = (code == "limit:ai-credits").then(|| seeded.clone());
            Box::pin(async move { Ok(state) })
        });

        let response = list_limits(
            "t-1".to_owned(),
            Arc::new(tenants),
            consumable_config().await,
            None,
            Arc::new(limits),
            caller(),
        )
        .await
        .expect("listed");
        let entry = response
            .limits
            .iter()
            .find(|entry| entry.code == "limit:ai-credits")
            .expect("the credits limit is listed");
        let state = entry
            .state
            .as_ref()
            .expect("a used limit carries its state");
        assert_eq!(state.monthly_remaining, 400);
        assert_eq!(state.extra_allowance_remaining, 200);
    }

    #[tokio::test]
    async fn the_listing_unions_relevant_and_stored_limits() {
        use crate::limits::repository::MockLimitRepository;

        // A catalogue with one always-relevant limit and one gated behind `feature:ai`.
        let repository = StaticConfigRepository::with_default();
        let gated = |code: &str, relevant_if: Option<&str>| LimitDef {
            code: code.to_owned(),
            name: code.into(),
            description: None,
            kind: LimitKind::Consumable,
            extra_allowance: false,
            custom_balance: false,
            daily: false,
            low_watermark_percent: None,
            high_watermark_percent: None,
            relevant_if: relevant_if.map(str::to_owned),
            unit: None,
            overrun_policy: OverrunPolicy::Track,
        };
        let current = repository.current().await.expect("seeded");
        repository
            .save(
                Config {
                    version: current.version,
                    limits: vec![
                        gated("limit:always", None),
                        gated("limit:ai-only", Some("feature:ai")),
                    ],
                    ..Config::default()
                },
                current.version,
            )
            .await
            .expect("saved");
        let config: Arc<dyn ConfigRepository> = Arc::new(repository);

        // The tenant lacks `feature:ai` but carries a stored limit whose definition is gone.
        let mut tenants = MockTenantRepository::new();
        tenants.expect_get_tenant().returning(|_| {
            Box::pin(async {
                let mut tenant = tenant("t-1");
                let _ = tenant.limits.insert(
                    "limit:legacy".to_owned(),
                    LimitSettings {
                        monthly: Some(5),
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

        let response = list_limits(
            "t-1".to_owned(),
            Arc::new(tenants),
            config,
            None,
            Arc::new(limits),
            caller(),
        )
        .await
        .expect("listed");
        let codes: Vec<&str> = response.limits.iter().map(|e| e.code.as_str()).collect();
        // Relevant-to-all is shown, and the stored orphan is shown so it can be cleaned up …
        assert!(codes.contains(&"limit:always"), "{codes:?}");
        assert!(codes.contains(&"limit:legacy"), "{codes:?}");
        // … but a limit that is neither relevant nor stored is not.
        assert!(!codes.contains(&"limit:ai-only"), "{codes:?}");
    }

    #[test]
    fn an_actor_id_over_the_cap_is_rejected_at_ingress() {
        let ok = ActorFields {
            actor_user_id: Some("u".repeat(ACTOR_ID_MAX_LEN)),
            txn_id: Some("t".repeat(ACTOR_ID_MAX_LEN)),
            source: Some("s".repeat(ACTOR_ID_MAX_LEN)),
        };
        assert!(ok.into_actor().is_ok());

        let long_user = ActorFields {
            actor_user_id: Some("u".repeat(ACTOR_ID_MAX_LEN + 1)),
            ..Default::default()
        };
        assert!(long_user.into_actor().is_err());

        let long_txn = ActorFields {
            txn_id: Some("t".repeat(ACTOR_ID_MAX_LEN + 1)),
            ..Default::default()
        };
        assert!(long_txn.into_actor().is_err());

        let long_source = ActorFields {
            source: Some("s".repeat(ACTOR_ID_MAX_LEN + 1)),
            ..Default::default()
        };
        assert!(long_source.into_actor().is_err());
    }

    fn history_row(code: &str, year_month: &str) -> HistoryRow {
        HistoryRow {
            tenant_id: "t-1".to_owned(),
            code: code.to_owned(),
            year_month: year_month.to_owned(),
            monthly_included: 1000,
            monthly_used: 1000,
            monthly_forfeited: 0,
            extra_allowance_limit: 200,
            extra_allowance_used: 120,
            overrun: 30,
            ending_custom_balance: 0,
            gauge_value: None,
            gauge_max: None,
        }
    }

    #[tokio::test]
    async fn billing_reads_one_limit_for_the_month() {
        use crate::limits::repository::MockLimitRepository;

        let mut limits = MockLimitRepository::new();
        limits
            .expect_read_month_history()
            .withf(|_, code, ym| code == &Some("limit:ai-credits") && ym == "2026-09")
            .returning(|_, _, _| {
                Box::pin(async { Ok(vec![history_row("limit:ai-credits", "2026-09")]) })
            });

        let response = billing(
            "t-1".to_owned(),
            Some("limit:ai-credits".to_owned()),
            BillingQuery {
                year: 2026,
                month: 9,
            },
            Arc::new(limits),
        )
        .await
        .expect("billed");
        assert_eq!(response.year_month, "2026-09");
        assert_eq!(response.limits.len(), 1);
        assert_eq!(response.limits[0].extra_allowance_used, 120);
        assert_eq!(response.limits[0].overrun, 30);
    }

    #[tokio::test]
    async fn billing_without_a_code_reads_every_limit_for_the_month() {
        use crate::limits::repository::MockLimitRepository;

        let mut limits = MockLimitRepository::new();
        limits
            .expect_read_month_history()
            .withf(|_, code, ym| code.is_none() && ym == "2026-09")
            .returning(|_, _, _| {
                Box::pin(async {
                    Ok(vec![
                        history_row("limit:ai-credits", "2026-09"),
                        history_row("limit:storage", "2026-09"),
                    ])
                })
            });

        let response = billing(
            "t-1".to_owned(),
            None,
            BillingQuery {
                year: 2026,
                month: 9,
            },
            Arc::new(limits),
        )
        .await
        .expect("billed");
        assert_eq!(response.limits.len(), 2);
    }

    #[tokio::test]
    async fn billing_rejects_a_month_out_of_range() {
        use crate::limits::repository::MockLimitRepository;

        let limits = MockLimitRepository::new(); // never queried
        let error = billing(
            "t-1".to_owned(),
            None,
            BillingQuery {
                year: 2026,
                month: 13,
            },
            Arc::new(limits),
        )
        .await
        .expect_err("rejected");
        assert!(error.to_string().contains("month"), "{error}");
    }
}
