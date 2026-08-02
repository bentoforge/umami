//! Usage metering: per-period, per-metric counters with atomic increments.
//!
//! Each `(tenant, period, metric)` is a row in the `usage` table incremented via DynamoDB `ADD`
//! (atomic, contention-free). The period is the calendar month (`YYYY-MM`), so rollover is
//! automatic — a new month is simply a new row. Quotas are resolved from the config limits
//! (entitlements), not stored here. A metric is a config limit code (e.g. `ai-tokens`).

use crate::config::repository::ConfigRepository;
use crate::constants::{MAX_TEXT_BODY_SIZE, WRITE_USAGE_PERMISSION};
use crate::tenants::effective_limits;
use crate::tenants::repository::TenantRepository;
use anyhow::Context;
use async_trait::async_trait;
use aws_sdk_dynamodb::types::{AttributeValue, BillingMode, ReturnValue};
use chrono::{Datelike, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::aws::dynamodb::client::DynamoClient;
use wasabi::aws::dynamodb::schema::{str_attribute, with_range_index};
use wasabi::aws::dynamodb::{find_all, str};
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::with_user_with_any_permission;
use wasabi::web::warp::{into_response, with_body_as_json, with_cloneable};
use wasabi::{client_bail, status_bail};

/// Permission required to read/meter usage.
const REQUIRE_WRITE_USAGE: &[&str] = &[WRITE_USAGE_PERMISSION];

const TABLE_USAGE: &str = "usage";
const FIELD_TENANT_ID: &str = "tenantId";
const FIELD_USAGE_KEY: &str = "usageKey";
const FIELD_PERIOD: &str = "period";
const FIELD_METRIC: &str = "metric";
const FIELD_USED: &str = "used";

/// Current usage period — the calendar month, `YYYY-MM`.
fn current_period() -> String {
    let today = Utc::now().date_naive();
    format!("{:04}-{:02}", today.year(), today.month())
}

/// A usage row (subset read back when listing).
#[derive(Serialize, Deserialize, Debug, Clone)]
struct UsageRecord {
    metric: String,
    used: i64,
}

/// Persistence for usage counters.
#[async_trait]
pub trait UsageRepository: Send + Sync {
    /// Atomically increments a metric for the period, returning the new total.
    async fn add_usage(
        &self,
        tenant_id: &str,
        period: &str,
        metric: &str,
        amount: i64,
    ) -> anyhow::Result<i64>;

    /// Lists all metrics + totals for a period.
    async fn list_usage(
        &self,
        tenant_id: &str,
        period: &str,
    ) -> anyhow::Result<BTreeMap<String, i64>>;
}

/// DynamoDB-backed implementation of [`UsageRepository`].
#[derive(Clone)]
pub struct DynamoUsageRepository {
    client: DynamoClient,
}

impl DynamoUsageRepository {
    #[tracing::instrument(skip(client), err(Display))]
    pub async fn with_client(client: &DynamoClient) -> anyhow::Result<Self> {
        client
            .create_table(TABLE_USAGE, |table| {
                let table = table
                    .attribute_definitions(str_attribute(FIELD_TENANT_ID)?)
                    .attribute_definitions(str_attribute(FIELD_USAGE_KEY)?);
                let table = with_range_index(table, FIELD_TENANT_ID, FIELD_USAGE_KEY)?;
                Ok(table.billing_mode(BillingMode::PayPerRequest))
            })
            .await?;
        Ok(Self {
            client: client.clone(),
        })
    }
}

#[async_trait]
impl UsageRepository for DynamoUsageRepository {
    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn add_usage(
        &self,
        tenant_id: &str,
        period: &str,
        metric: &str,
        amount: i64,
    ) -> anyhow::Result<i64> {
        let result = self
            .client
            .update_item(TABLE_USAGE)
            .key(FIELD_TENANT_ID, str(tenant_id))
            .key(FIELD_USAGE_KEY, str(format!("{period}#{metric}")))
            .update_expression(
                "ADD #used :amount \
                 SET #period = if_not_exists(#period, :period), \
                     #metric = if_not_exists(#metric, :metric)",
            )
            .expression_attribute_names("#used", FIELD_USED)
            .expression_attribute_names("#period", FIELD_PERIOD)
            .expression_attribute_names("#metric", FIELD_METRIC)
            .expression_attribute_values(":amount", AttributeValue::N(amount.to_string()))
            .expression_attribute_values(":period", str(period))
            .expression_attribute_values(":metric", str(metric))
            .return_values(ReturnValue::UpdatedNew)
            .send()
            .await
            .context("Error updating 'usage' table")?;

        let used = result
            .attributes
            .and_then(|mut attrs| attrs.remove(FIELD_USED))
            .and_then(|value| value.as_n().ok().and_then(|raw| raw.parse::<i64>().ok()))
            .unwrap_or(amount);
        Ok(used)
    }

    #[tracing::instrument(level = "debug", skip(self), err(Display))]
    async fn list_usage(
        &self,
        tenant_id: &str,
        period: &str,
    ) -> anyhow::Result<BTreeMap<String, i64>> {
        let query = self
            .client
            .query(TABLE_USAGE)
            .key_condition_expression("#tenantId = :tenantId AND begins_with(#usageKey, :prefix)")
            .expression_attribute_names("#tenantId", FIELD_TENANT_ID)
            .expression_attribute_names("#usageKey", FIELD_USAGE_KEY)
            .expression_attribute_values(":tenantId", str(tenant_id))
            .expression_attribute_values(":prefix", str(format!("{period}#")))
            .limit(100);

        let records: Vec<UsageRecord> = find_all(query).await.context("Error listing 'usage'")?;
        Ok(records
            .into_iter()
            .map(|record| (record.metric, record.used))
            .collect())
    }
}

// ── Request/response types ───────────────────────────────────────────────────

/// Increment request; `amount` defaults to 1.
#[derive(Deserialize, Debug)]
struct IncrementRequest {
    amount: Option<i64>,
}

/// A metric's usage against its resolved limit.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MetricUsage {
    metric: String,
    used: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<Decimal>,
    over_quota: bool,
}

/// `GET /tenants/{id}/usage` response.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct UsageResponse {
    period: String,
    metrics: Vec<MetricUsage>,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `POST /tenants/{id}/usage/{metric}` — meter usage (requires `write:usage`).
pub fn increment_usage_route(
    usage: Arc<dyn UsageRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "usage" / String)
        .and(warp::post())
        .and(with_body_as_json::<IncrementRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(usage))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_USAGE,
        ))
        .and_then(handle_increment_usage_route)
        .boxed()
}

/// `GET /tenants/{id}/usage` — current period's usage vs limits (requires `write:usage`).
pub fn get_usage_route(
    usage: Arc<dyn UsageRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "usage")
        .and(warp::get())
        .and(with_cloneable(usage))
        .and(with_cloneable(tenants))
        .and(with_cloneable(config))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_WRITE_USAGE,
        ))
        .and_then(handle_get_usage_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "POST /tenants/{id}/usage/{metric}", skip_all)]
async fn handle_increment_usage_route(
    tenant_id: String,
    metric: String,
    request: IncrementRequest,
    usage: Arc<dyn UsageRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(increment_usage(tenant_id, metric, request, usage, tenants, config, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /tenants/{id}/usage", skip_all)]
async fn handle_get_usage_route(
    tenant_id: String,
    usage: Arc<dyn UsageRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(get_usage(tenant_id, usage, tenants, config, caller).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

fn enforce_own(tenant_id: &str, caller: &AuthUser) -> anyhow::Result<()> {
    if caller.tenant_id()? != tenant_id {
        status_bail!(StatusCode::FORBIDDEN, "You may only meter your own tenant");
    }
    Ok(())
}

/// Builds a [`MetricUsage`] for a metric/used pair against the resolved limits.
fn metric_usage(metric: String, used: i64, limits: &BTreeMap<String, Decimal>) -> MetricUsage {
    let limit = limits.get(&metric).copied();
    let over_quota = limit.is_some_and(|limit| Decimal::from(used) > limit);
    MetricUsage {
        metric,
        used,
        limit,
        over_quota,
    }
}

#[allow(clippy::too_many_arguments)]
async fn increment_usage(
    tenant_id: String,
    metric: String,
    request: IncrementRequest,
    usage: Arc<dyn UsageRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<MetricUsage> {
    enforce_own(&tenant_id, &caller)?;

    let amount = request.amount.unwrap_or(1);
    if amount <= 0 {
        client_bail!("'amount' must be a positive integer");
    }

    let period = current_period();
    let used = usage
        .add_usage(&tenant_id, &period, &metric, amount)
        .await?;

    let tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };
    let config = config.current().await?;
    let limits = effective_limits(config.as_ref(), &tenant);

    Ok(metric_usage(metric, used, &limits))
}

async fn get_usage(
    tenant_id: String,
    usage: Arc<dyn UsageRepository>,
    tenants: Arc<dyn TenantRepository>,
    config: Arc<dyn ConfigRepository>,
    caller: AuthUser,
) -> anyhow::Result<UsageResponse> {
    enforce_own(&tenant_id, &caller)?;

    let period = current_period();
    let counts = usage.list_usage(&tenant_id, &period).await?;

    let tenant = match tenants.get_tenant(&tenant_id).await? {
        Some(tenant) => tenant,
        None => client_bail!("No such tenant"),
    };
    let config = config.current().await?;
    let limits = effective_limits(config.as_ref(), &tenant);

    let metrics = counts
        .into_iter()
        .map(|(metric, used)| metric_usage(metric, used, &limits))
        .collect();

    Ok(UsageResponse { period, metrics })
}
