//! Read routes for the audit log: a tenant's trail (admin) and the caller's own trail.

use crate::audit::AuditEntry;
use crate::audit::repository::AuditRepository;
use crate::constants::{ADMIN_TENANT_PERMISSION, MAX_LIST_RESULTS};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp::Filter;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use wasabi::status_bail;
use wasabi::web::auth::authenticator::Authenticator;
use wasabi::web::auth::user::User as AuthUser;
use wasabi::web::auth::{with_user, with_user_with_any_permission};
use wasabi::web::warp::{into_response, with_cloneable};

/// Default number of entries returned when `limit` is omitted.
const DEFAULT_LIMIT: i32 = 100;

const REQUIRE_ADMIN_TENANT: &[&str] = &[ADMIN_TENANT_PERMISSION];

/// Optional `?limit=` (clamped to `1..=MAX_LIST_RESULTS`).
#[derive(Deserialize, Debug)]
struct AuditQuery {
    limit: Option<i32>,
}

impl AuditQuery {
    fn effective(&self) -> i32 {
        self.limit
            .unwrap_or(DEFAULT_LIMIT)
            .clamp(1, MAX_LIST_RESULTS as i32)
    }
}

/// Audit-list response.
#[derive(Serialize, Debug)]
struct AuditListResponse {
    entries: Vec<AuditEntry>,
}

/// `GET /tenants/{id}/audit[?limit=]` — the tenant's audit trail (requires `admin:tenant`, own tenant).
pub fn tenant_audit_route(
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("tenants" / String / "audit")
        .and(warp::get())
        .and(warp::query::<AuditQuery>())
        .and(with_cloneable(audit))
        .and(with_user_with_any_permission(
            authenticator,
            REQUIRE_ADMIN_TENANT,
        ))
        .and_then(handle_tenant_audit_route)
        .boxed()
}

/// `GET /auth/me/audit[?limit=]` — the authenticated user's own audit trail.
pub fn my_audit_route(
    audit: Arc<dyn AuditRepository>,
    authenticator: Arc<Authenticator>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "me" / "audit")
        .and(warp::get())
        .and(warp::query::<AuditQuery>())
        .and(with_cloneable(audit))
        .and(with_user(authenticator))
        .and_then(handle_my_audit_route)
        .boxed()
}

#[tracing::instrument(level = "debug", name = "GET /tenants/{id}/audit", skip_all)]
async fn handle_tenant_audit_route(
    tenant_id: String,
    query: AuditQuery,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(tenant_audit(tenant_id, query, audit, caller).await)
}

#[tracing::instrument(level = "debug", name = "GET /auth/me/audit", skip_all)]
async fn handle_my_audit_route(
    query: AuditQuery,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(my_audit(query, audit, caller).await)
}

async fn tenant_audit(
    tenant_id: String,
    query: AuditQuery,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<AuditListResponse> {
    if caller.tenant_id()? != tenant_id {
        status_bail!(
            StatusCode::FORBIDDEN,
            "You may only read your own tenant's audit log"
        );
    }
    Ok(AuditListResponse {
        entries: audit.list_by_tenant(&tenant_id, query.effective()).await?,
    })
}

async fn my_audit(
    query: AuditQuery,
    audit: Arc<dyn AuditRepository>,
    caller: AuthUser,
) -> anyhow::Result<AuditListResponse> {
    Ok(AuditListResponse {
        entries: audit
            .list_by_user(caller.user_id()?, query.effective())
            .await?,
    })
}
