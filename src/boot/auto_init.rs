//! First-run bootstrap: the very first tenant and owner on an empty deployment.

use crate::auth;
use crate::boot::Platform;
use crate::constants::ROLE_OWNER;
use crate::users::repository::NewUser;
use std::env;
use wasabi::aws::dynamodb::generate_id;

/// Bootstraps the first tenant + owner on an empty deployment when `UMAMI_AUTO_INIT=true`.
///
/// No-op unless auto-init is enabled and **zero** tenants exist. Creates the system tenant — with a
/// caller-supplied `UMAMI_SYSTEM_TENANT_ID` when set (so the owner is immediately a system admin),
/// otherwise a freshly generated id — and an owner user (`UMAMI_ROOT_USERNAME`, default `root`) with
/// a **randomly generated** one-time password. The tenant id, username and password are logged once,
/// prominently; no credentials are hard-coded. Intended for first-run/dev, not steady-state
/// provisioning.
#[tracing::instrument(skip_all, err(Display))]
pub async fn maybe_auto_init(platform: &Platform) -> anyhow::Result<()> {
    let tenants = &platform.repos.tenants;
    let users = &platform.repos.users;
    let system_tenant_id = platform.system_tenant_id.as_deref();

    if env::var("UMAMI_AUTO_INIT").as_deref() != Ok("true") {
        return Ok(());
    }
    if !tenants.find_tenants("", 1).await?.0.is_empty() {
        return Ok(());
    }

    let tenant = match system_tenant_id {
        Some(id) => {
            tenants
                .create_tenant_with_id(id, "System", "system", None)
                .await?
        }
        None => tenants.create_tenant("System", "system", None).await?,
    };

    // Generated, single-use bootstrap credentials — never hard-coded. Logged once below; the
    // operator must sign in and change the password immediately.
    let username = env::var("UMAMI_ROOT_USERNAME")
        .ok()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "root".to_owned());
    let password = generate_id();
    let password_hash = auth::password::hash(&password)?;
    let owner = users
        .create_user(NewUser {
            tenant_id: tenant.tenant_id.clone(),
            roles: vec![ROLE_OWNER.to_owned()],
            username: username.clone(),
            title: None,
            salutation: crate::users::Salutation::default(),
            firstname: None,
            lastname: Some("Root Admin".to_owned()),
            password_hash: Some(password_hash),
            custom_fields: std::collections::BTreeMap::new(),
            created_by: None,
            password_generated: false,
        })
        .await?;

    // One-time, prominent credential dump. The password is only ever shown here.
    let system_hint = if system_tenant_id.is_some() {
        String::new()
    } else {
        format!(
            "\n  ⚠ set UMAMI_SYSTEM_TENANT_ID={} (and restart) to grant cross-tenant/system admin",
            tenant.tenant_id
        )
    };
    tracing::warn!(
        "\n================= UMAMI AUTO-INIT =================\n\
         Bootstrapped an empty deployment. These credentials are shown ONCE:\n\
         \x20 tenant id : {}\n\
         \x20 username  : {}\n\
         \x20 password  : {}\n\
         \x20 user id   : {}\n\
         ⚠ CHANGE THE PASSWORD IMMEDIATELY.{}\n\
         ==================================================",
        tenant.tenant_id,
        username,
        password,
        owner.user_id,
        system_hint
    );

    Ok(())
}
