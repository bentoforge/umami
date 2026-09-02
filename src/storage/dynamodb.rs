//! DynamoDB-backed storage — umami's only backend today.
//!
//! Each repository provisions its own table in `with_client`, so building the bundle is also what
//! creates the tables on a fresh deployment. That is why this is `async` and why it is the one
//! place allowed to know about `DynamoClient`.

use crate::audit::repository::DynamoAuditRepository;
use crate::auth::apikeys::repository::DynamoApiKeyRepository;
use crate::auth::challenge::DynamoChallengeRepository;
use crate::auth::ratelimit::repository::DynamoRateLimitRepository;
use crate::auth::session::repository::DynamoSessionRepository;
use crate::auth::webauthn::repository::DynamoWebauthnRepository;
use crate::contacts::repository::DynamoContactRepository;
use crate::messaging::repository::DynamoMessagingRepository;
use crate::storage::Repositories;
use crate::tenants::repository::DynamoTenantRepository;
use crate::users::repository::DynamoUserRepository;
use std::sync::Arc;
use wasabi::aws::dynamodb::client::DynamoClient;

/// Builds every repository against one `DynamoClient`, creating the tables it does not find.
#[tracing::instrument(skip_all, err(Display))]
pub async fn repositories(client: &DynamoClient) -> anyhow::Result<Repositories> {
    Ok(Repositories {
        users: Arc::new(DynamoUserRepository::with_client(client).await?),
        sessions: Arc::new(DynamoSessionRepository::with_client(client).await?),
        tenants: Arc::new(DynamoTenantRepository::with_client(client).await?),
        api_keys: Arc::new(DynamoApiKeyRepository::with_client(client).await?),
        audit: Arc::new(DynamoAuditRepository::with_client(client).await?),
        contacts: Arc::new(DynamoContactRepository::with_client(client).await?),
        challenges: Arc::new(DynamoChallengeRepository::with_client(client).await?),
        messaging: Arc::new(DynamoMessagingRepository::with_client(client).await?),
        rate_limits: Arc::new(DynamoRateLimitRepository::with_client(client).await?),
        webauthn: Arc::new(DynamoWebauthnRepository::with_client(client).await?),
    })
}
