//! Password recovery: "I forgot my password" → a mailed link → a new password.
//!
//! ## Why umami mails this itself
//!
//! Handing the reset token to another service would let that service take over any account. So this
//! is one of the two flows that cannot be delegated (see [`crate::notify`]) — umami mints the token
//! and hands over only the finished mail.
//!
//! ## Why the entry point always answers the same way
//!
//! `POST /auth/forgot-password` returns **202 for everything**: unknown identifier, known one,
//! unverified address, ambiguous address, nothing to send to. Any difference — a different status, a
//! different message, even a noticeably different response time — turns the endpoint into an oracle
//! for "does this account exist here", and that is exactly what a login page spends effort not
//! revealing. The operator sees what happened in the audit log; the caller never does.
//!
//! ## Why the address must be verified
//!
//! A reset link is account takeover in one click for whoever reads it. An address nobody has proven
//! possession of is not a place to send that, and an admin who typed an address in has proven
//! nothing. This is the whole reason verification exists before recovery does.
//!
//! ## Ambiguity
//!
//! Addresses are deliberately not unique — two users may share `info@acme.com`. Recovering by such
//! an address is refused rather than guessed at: mailing "reset your password" for an account the
//! reader may not own is worse than making them use their username.

use crate::audit::repository::{AuditRepository, record_best_effort};
use crate::audit::{AuditSeverity, NewAuditEntry};
use crate::auth::challenge::{ChallengeRepository, Purpose};
use crate::auth::ratelimit::{
    Decision, POLICY_MAIL_SEND, POLICY_PER_IP_RECOVER, Policy, RateLimiter, too_many_requests,
};
use crate::config::repository::ConfigRepository;
use crate::constants::MAX_TEXT_BODY_SIZE;
use crate::contacts::normalize_email;
use crate::contacts::repository::ContactRepository;
use crate::notify::{Notifier, OutboundMail};
use crate::users::User;
use crate::users::repository::UserRepository;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::{Filter, Reply};
use wasabi::status_bail;
use wasabi::web::warp::{
    client_ip, into_rejection, into_response, with_body_as_json, with_cloneable,
};

/// Everything the recovery flow needs.
#[derive(Clone)]
pub struct RecoveryDeps {
    /// User store.
    pub users: Arc<dyn UserRepository>,
    /// Contact store (resolving an address, and checking it is verified).
    pub contacts: Arc<dyn ContactRepository>,
    /// Challenge store.
    pub challenges: Arc<dyn ChallengeRepository>,
    /// Config (TTLs, password policy, rate limits).
    pub config: Arc<dyn ConfigRepository>,
    /// The outbound seam.
    pub notifier: Arc<dyn Notifier>,
    /// Rate limits (per-IP on the entry point, per-user on the mail).
    pub rate_limiter: Arc<RateLimiter>,
    /// umami's public base URL, for the link in the mail.
    pub public_base_url: String,
}

/// Request starting a recovery. The identifier is a username **or** an email address.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ForgotRequest {
    identifier: String,
}

/// Request finishing a recovery.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ResetRequest {
    token: String,
    new_password: String,
}

// ── Routes ──────────────────────────────────────────────────────────────────────

/// `POST /auth/forgot-password` — mail a reset link. **Unauthenticated**; always 202.
pub fn forgot_password_route(
    deps: RecoveryDeps,
    audit: Arc<dyn AuditRepository>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "forgot-password")
        .and(warp::post())
        .and(with_body_as_json::<ForgotRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and(client_ip())
        .and_then(handle_forgot_password_route)
        .boxed()
}

/// `POST /auth/reset-password` — set a new password with the secret from the mail.
///
/// Named for the *recovery* rather than the path so it cannot be confused with
/// [`crate::users::service::reset_password_route`], which is the admin action on somebody else's
/// account. These are different powers: one is proven by a mailed secret, the other by
/// `manage:users`.
pub fn complete_recovery_route(
    deps: RecoveryDeps,
    audit: Arc<dyn AuditRepository>,
) -> BoxedFilter<(impl warp::Reply,)> {
    warp::path!("auth" / "reset-password")
        .and(warp::post())
        .and(with_body_as_json::<ResetRequest>(MAX_TEXT_BODY_SIZE))
        .and(with_cloneable(deps))
        .and(with_cloneable(audit))
        .and_then(handle_reset_password_route)
        .boxed()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[tracing::instrument(level = "debug", name = "POST /auth/forgot-password", skip_all)]
async fn handle_forgot_password_route(
    request: ForgotRequest,
    deps: RecoveryDeps,
    audit: Arc<dyn AuditRepository>,
    ip: Option<String>,
) -> Result<impl warp::Reply, warp::Rejection> {
    match forgot_password(request, deps, audit, ip.as_deref().unwrap_or("unknown")).await {
        // The only distinguishable answer, and it is about the *caller's* volume rather than about
        // any account: a flood from one IP is refused whether or not the identifiers exist.
        Ok(Some(retry_after)) => Ok(too_many_requests(retry_after)),
        Ok(None) => Ok(warp::reply::with_status(
            warp::reply::json(&json!({ "status": "accepted" })),
            StatusCode::ACCEPTED,
        )
        .into_response()),
        Err(err) => Err(into_rejection(err)),
    }
}

#[tracing::instrument(level = "debug", name = "POST /auth/reset-password", skip_all)]
async fn handle_reset_password_route(
    request: ResetRequest,
    deps: RecoveryDeps,
    audit: Arc<dyn AuditRepository>,
) -> Result<impl warp::Reply, warp::Rejection> {
    into_response(reset_password(request, deps, audit).await)
}

// ── Business logic ──────────────────────────────────────────────────────────────

/// Starts a recovery. `Ok(Some(retry_after))` means rate-limited; `Ok(None)` is the uniform accept,
/// whatever actually happened.
async fn forgot_password(
    request: ForgotRequest,
    deps: RecoveryDeps,
    audit: Arc<dyn AuditRepository>,
    ip: &str,
) -> anyhow::Result<Option<i64>> {
    let config = deps.config.current().await?;
    let per_ip = Policy::new(
        config.security.rate_limits.per_ip.max_per_window,
        config.security.rate_limits.per_ip.window_secs,
        config.security.rate_limits.per_ip.block_secs,
    );
    if let Decision::Block { retry_after } = deps
        .rate_limiter
        .check(POLICY_PER_IP_RECOVER, &per_ip, ip, Utc::now())
        .await
    {
        return Ok(Some(retry_after));
    }

    // From here on every path returns Ok(None). Failures are recorded, never reported: the caller
    // must not be able to tell an unknown identifier from a known one.
    let identifier = request.identifier.trim().to_owned();
    if identifier.is_empty() {
        return Ok(None);
    }

    let Some((user, address)) = resolve_target(&deps, &identifier).await? else {
        record_best_effort(
            &audit,
            NewAuditEntry::new(
                AuditSeverity::Neutral,
                None,
                None,
                "Password recovery requested for an unknown or unreachable identifier".to_owned(),
            ),
        )
        .await;
        return Ok(None);
    };

    // No mail path: record it and answer as always. An operator sees this in the log; a caller must
    // not learn from it that the account exists.
    if !deps.notifier.is_configured() {
        record_best_effort(
            &audit,
            NewAuditEntry::new(
                AuditSeverity::Bad,
                Some(user.tenant_id.clone()),
                Some(user.user_id.clone()),
                "Password recovery requested but this deployment cannot send mail".to_owned(),
            ),
        )
        .await;
        return Ok(None);
    }

    // Per-account cap on outbound mail, the same budget address confirmation spends. Exhausting it
    // is *not* reported as a 429 here — that would confirm the account exists.
    let mail_policy = Policy::new(
        config.security.rate_limits.mail_send.max_per_window,
        config.security.rate_limits.mail_send.window_secs,
        config.security.rate_limits.mail_send.block_secs,
    );
    if let Decision::Block { .. } = deps
        .rate_limiter
        .check(POLICY_MAIL_SEND, &mail_policy, &user.user_id, Utc::now())
        .await
    {
        record_best_effort(
            &audit,
            NewAuditEntry::new(
                AuditSeverity::Bad,
                Some(user.tenant_id.clone()),
                Some(user.user_id.clone()),
                "Password recovery throttled (per-account mail budget exhausted)".to_owned(),
            ),
        )
        .await;
        return Ok(None);
    }

    let secret = deps
        .challenges
        .issue(
            Purpose::ResetPassword,
            &user.user_id,
            &user.tenant_id,
            &address,
            config.security.password_reset_ttl_secs as i64,
        )
        .await?;

    let locale = crate::i18n::resolve(&config, user.locale.as_deref(), None);
    // One composition for both the greeting in the text and the parts a worker's template gets, so
    // the two cannot address the same person differently.
    let recipient = crate::notify::Recipient::of(&user, &locale);
    let link = format!(
        "{}app/reset-password?token={}",
        deps.public_base_url, secret
    );
    // The link the body already carries, structured — so a worker can put it on a button without
    // parsing it back out of the text, and so the text itself can name it.
    let link_context = json!({ "link": link });
    let vars = crate::notify::render::MailContext {
        recipient: Some(&recipient),
        context: Some(&link_context),
        global_context: &config.mail.global_context,
        notification: None,
    };
    let mail = OutboundMail::new(
        address.clone(),
        crate::notify::render::message(&locale, "auth.reset.subject", &vars)?,
        crate::notify::render::message(&locale, "auth.reset.body", &vars)?,
        locale,
        user.user_id.clone(),
        user.tenant_id.clone(),
    )
    .with_template(Some(crate::notify::TEMPLATE_PASSWORD_RESET.to_owned()))
    .with_recipient(recipient)
    .with_context(Some(link_context))
    .with_deployment(&config.mail, &deps.public_base_url)?;
    let message_id = mail.message_id.clone();
    deps.notifier.send(mail).await?;

    record_best_effort(
        &audit,
        NewAuditEntry::new(
            AuditSeverity::Neutral,
            Some(user.tenant_id.clone()),
            Some(user.user_id.clone()),
            format!("Password recovery mail queued (message {message_id})"),
        ),
    )
    .await;
    Ok(None)
}

/// Resolves an identifier to the user and the **verified** address to mail.
///
/// Tries the username first — that is the login identity, and it is unambiguous. Only then the
/// identifier is treated as an address, and only when exactly one account holds it.
async fn resolve_target(
    deps: &RecoveryDeps,
    identifier: &str,
) -> anyhow::Result<Option<(User, String)>> {
    if let Some(user) = deps.users.find_by_username(identifier).await? {
        return reachable_address(deps, user).await;
    }

    // Not a username. An address, maybe — but only an unambiguous one.
    let Ok(address) = normalize_email(identifier) else {
        return Ok(None);
    };
    let holders = deps.contacts.contacts_for_address(&address).await?;
    let verified: Vec<_> = holders
        .into_iter()
        .filter(|contact| contact.verified)
        .collect();
    let [only] = verified.as_slice() else {
        // Zero holders, or more than one. Both end here: guessing which account a shared address
        // belongs to would mail a takeover link to someone who may not own it.
        return Ok(None);
    };
    match deps.users.get_user(&only.user_id).await? {
        Some(user) if !user.locked => Ok(Some((user, only.address.clone()))),
        _ => Ok(None),
    }
}

/// The address a reset link for `user` may go to: their preferred one when it is verified, else
/// their single verified address. Locked accounts are unreachable by design.
async fn reachable_address(
    deps: &RecoveryDeps,
    user: User,
) -> anyhow::Result<Option<(User, String)>> {
    if user.locked {
        return Ok(None);
    }
    let verified: Vec<String> = deps
        .contacts
        .list_contacts(&user.user_id)
        .await?
        .into_iter()
        .filter(|contact| contact.verified)
        .map(|contact| contact.address)
        .collect();

    // Preference first, but only if it is one of the verified ones — a stale preference must not
    // silently redirect a takeover link.
    if let Some(preferred) = user.preferred_contact.as_deref()
        && verified.iter().any(|address| address == preferred)
    {
        let address = preferred.to_owned();
        return Ok(Some((user, address)));
    }
    // Otherwise only an unambiguous choice. With several verified addresses and no preference there
    // is no basis for picking one, and picking wrong means the link is somewhere the user is not
    // looking.
    match verified.as_slice() {
        [only] => {
            let address = only.clone();
            Ok(Some((user, address)))
        }
        _ => Ok(None),
    }
}

/// Finishes a recovery: sets the new password and logs every session out.
async fn reset_password(
    request: ResetRequest,
    deps: RecoveryDeps,
    audit: Arc<dyn AuditRepository>,
) -> anyhow::Result<Value> {
    let proven = match deps
        .challenges
        .consume(Purpose::ResetPassword, request.token.trim())
        .await?
    {
        Some(proven) => proven,
        None => status_bail!(
            StatusCode::NOT_FOUND,
            "This reset link is invalid or has expired"
        ),
    };

    let config = deps.config.current().await?;
    config.validate_password(&request.new_password)?;

    let mut user = match deps.users.get_user(&proven.user_id).await? {
        Some(user) if !user.locked => user,
        _ => status_bail!(StatusCode::NOT_FOUND, "This account is not active"),
    };
    user.password_hash = Some(crate::auth::password::hash(&request.new_password)?);
    // The user chose this password, so it is a *change*, not an admin reset waiting to be changed —
    // stamping `last_password_reset` here would flag the account as holding a generated password.
    user.last_password_change = Some(Utc::now());
    // Whoever could still be in the account loses access at their next refresh. A recovery is often
    // a recovery *from* something, so bumping the revocation counter is the point, not a side effect.
    user.token_version = user.token_version.saturating_add(1);
    let _ = deps.users.put_user(user.clone()).await?;

    record_best_effort(
        &audit,
        NewAuditEntry::new(
            AuditSeverity::Good,
            Some(user.tenant_id.clone()),
            Some(user.user_id.clone()),
            "Password reset via a mailed recovery link; all sessions revoked".to_owned(),
        ),
    )
    .await;

    Ok(json!({ "status": "reset" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::repository::MockAuditRepository;
    use crate::auth::challenge::MockChallengeRepository;
    use crate::auth::challenge::Proven;
    use crate::auth::ratelimit::repository::MockRateLimitRepository;
    use crate::config::repository::StaticConfigRepository;
    use crate::contacts::Contact;
    use crate::contacts::repository::MockContactRepository;
    use crate::users::Salutation;
    use crate::users::repository::MockUserRepository;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// A notifier that keeps what it was handed, so a test can assert on *whether* a mail was
    /// queued and to which address — the fact the uniform 202 deliberately hides from a caller.
    struct RecordingNotifier {
        configured: bool,
        sent: Mutex<Vec<OutboundMail>>,
    }

    #[async_trait]
    impl Notifier for RecordingNotifier {
        async fn send(&self, mail: OutboundMail) -> anyhow::Result<()> {
            if let Ok(mut sent) = self.sent.lock() {
                sent.push(mail);
            }
            Ok(())
        }
        fn is_configured(&self) -> bool {
            self.configured
        }
    }

    /// A rate limiter that always allows: first hit in the window, no block on record.
    fn permissive_limiter() -> Arc<RateLimiter> {
        let mut repo = MockRateLimitRepository::new();
        let _ = repo
            .expect_increment()
            .returning(|_, _| Box::pin(async { Ok(1) }));
        let _ = repo
            .expect_get_block()
            .returning(|_| Box::pin(async { Ok(None) }));
        Arc::new(RateLimiter::new(Arc::new(repo), 16))
    }

    fn user(id: &str, locked: bool, preferred: Option<&str>) -> User {
        let now = Utc::now();
        User {
            user_id: id.to_owned(),
            tenant_id: "tenant-1".to_owned(),
            roles: Vec::new(),
            username: "jane".to_owned(),
            title: None,
            locale: Some("en".to_owned()),
            salutation: Salutation::Madam,
            firstname: Some("Jane".to_owned()),
            lastname: Some("Doe".to_owned()),
            password_hash: Some("hash".to_owned()),
            locked,
            token_version: 3,
            totp_secret: None,
            totp_pending: None,
            custom_fields: Default::default(),
            created: now,
            last_updated: now,
            last_seen: None,
            last_active_or_created: now,
            last_password_reset: None,
            last_password_change: None,
            has_passkey: false,
            created_by: None,
            last_changed_by: None,
            preferred_contact: preferred.map(str::to_owned),
            notification_choices: Default::default(),
        }
    }

    fn contact(user_id: &str, address: &str, verified: bool) -> Contact {
        Contact {
            user_id: user_id.to_owned(),
            address: address.to_owned(),
            tenant_id: "tenant-1".to_owned(),
            label: None,
            verified,
            verified_at: None,
            created: Utc::now(),
        }
    }

    /// What a test gets back: the deps under test, the notifier to inspect, the audit sink to pass
    /// in, and the log the sink writes to.
    type Harness = (
        RecoveryDeps,
        Arc<RecordingNotifier>,
        Arc<dyn AuditRepository>,
        Arc<Mutex<Vec<String>>>,
    );

    /// Assembles deps around the two stores a test cares about, with an allowing limiter, a real
    /// default config, and an audit sink that records the messages.
    fn build_deps(
        users: MockUserRepository,
        contacts: MockContactRepository,
        challenges: MockChallengeRepository,
        configured: bool,
    ) -> Harness {
        let notifier = Arc::new(RecordingNotifier {
            configured,
            sent: Mutex::new(Vec::new()),
        });
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = log.clone();
        let mut audit = MockAuditRepository::new();
        let _ = audit.expect_record().returning(move |entry| {
            let sink = sink.clone();
            Box::pin(async move {
                if let Ok(mut lines) = sink.lock() {
                    lines.push(entry.message);
                }
                Ok(())
            })
        });
        let deps = RecoveryDeps {
            users: Arc::new(users),
            contacts: Arc::new(contacts),
            challenges: Arc::new(challenges),
            config: Arc::new(StaticConfigRepository::with_default()),
            notifier: notifier.clone(),
            rate_limiter: permissive_limiter(),
            public_base_url: "https://umami.example.com/".to_owned(),
        };
        (deps, notifier, Arc::new(audit), log)
    }

    fn forgot(identifier: &str) -> ForgotRequest {
        ForgotRequest {
            identifier: identifier.to_owned(),
        }
    }

    fn issuing_challenges() -> MockChallengeRepository {
        let mut challenges = MockChallengeRepository::new();
        let _ = challenges
            .expect_issue()
            .returning(|_, _, _, _, _| Box::pin(async { Ok("secret-value".to_owned()) }));
        challenges
    }

    fn sent_addresses(notifier: &RecordingNotifier) -> Vec<String> {
        notifier
            .sent
            .lock()
            .map(|sent| sent.iter().map(|mail| mail.to.clone()).collect())
            .unwrap_or_default()
    }

    /// The whole point of the endpoint's shape: the caller learns nothing, the operator learns
    /// everything. Every case below asserts both halves.
    #[tokio::test]
    async fn an_unknown_identifier_is_accepted_and_sends_nothing() {
        let mut users = MockUserRepository::new();
        let _ = users
            .expect_find_by_username()
            .returning(|_| Box::pin(async { Ok(None) }));
        let mut contacts = MockContactRepository::new();
        let _ = contacts
            .expect_contacts_for_address()
            .returning(|_| Box::pin(async { Ok(Vec::new()) }));

        let (deps, notifier, audit, log) =
            build_deps(users, contacts, MockChallengeRepository::new(), true);
        assert!(
            forgot_password(forgot("nobody@example.com"), deps, audit, "1.2.3.4")
                .await
                .unwrap()
                .is_none(),
            "an unknown identifier must be accepted like any other"
        );
        assert!(sent_addresses(&notifier).is_empty());
        let lines = log.lock().unwrap().clone();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("unknown or unreachable")),
            "the operator must see it: {lines:?}"
        );
    }

    #[tokio::test]
    async fn a_username_with_one_confirmed_address_gets_a_mail() {
        let mut users = MockUserRepository::new();
        let _ = users
            .expect_find_by_username()
            .returning(|_| Box::pin(async { Ok(Some(user("user-1", false, None))) }));
        let mut contacts = MockContactRepository::new();
        let _ = contacts.expect_list_contacts().returning(|_| {
            Box::pin(async {
                Ok(vec![
                    contact("user-1", "jane@example.com", true),
                    contact("user-1", "old@example.com", false),
                ])
            })
        });

        let (deps, notifier, audit, _log) = build_deps(users, contacts, issuing_challenges(), true);
        assert!(
            forgot_password(forgot("jane"), deps, audit, "1.2.3.4")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            sent_addresses(&notifier),
            vec!["jane@example.com".to_owned()],
            "only the confirmed address may receive a reset link"
        );
    }

    /// An unconfirmed address is not a place to send account takeover in one click.
    #[tokio::test]
    async fn an_account_with_no_confirmed_address_gets_nothing() {
        let mut users = MockUserRepository::new();
        let _ = users
            .expect_find_by_username()
            .returning(|_| Box::pin(async { Ok(Some(user("user-1", false, None))) }));
        let mut contacts = MockContactRepository::new();
        let _ = contacts.expect_list_contacts().returning(|_| {
            Box::pin(async { Ok(vec![contact("user-1", "jane@example.com", false)]) })
        });

        let (deps, notifier, audit, _log) =
            build_deps(users, contacts, MockChallengeRepository::new(), true);
        assert!(
            forgot_password(forgot("jane"), deps, audit, "1.2.3.4")
                .await
                .unwrap()
                .is_none()
        );
        assert!(sent_addresses(&notifier).is_empty());
    }

    /// Two accounts may share an address. Mailing "reset your password" for one of them to a reader
    /// who may own the other is worse than asking for a username.
    #[tokio::test]
    async fn a_shared_address_is_refused_rather_than_guessed() {
        let mut users = MockUserRepository::new();
        let _ = users
            .expect_find_by_username()
            .returning(|_| Box::pin(async { Ok(None) }));
        let mut contacts = MockContactRepository::new();
        let _ = contacts.expect_contacts_for_address().returning(|_| {
            Box::pin(async {
                Ok(vec![
                    contact("user-1", "info@acme.com", true),
                    contact("user-2", "info@acme.com", true),
                ])
            })
        });

        let (deps, notifier, audit, _log) =
            build_deps(users, contacts, MockChallengeRepository::new(), true);
        assert!(
            forgot_password(forgot("info@acme.com"), deps, audit, "1.2.3.4")
                .await
                .unwrap()
                .is_none()
        );
        assert!(sent_addresses(&notifier).is_empty());
    }

    #[tokio::test]
    async fn an_address_held_by_exactly_one_account_resolves() {
        let mut users = MockUserRepository::new();
        let _ = users
            .expect_find_by_username()
            .returning(|_| Box::pin(async { Ok(None) }));
        let _ = users
            .expect_get_user()
            .returning(|_| Box::pin(async { Ok(Some(user("user-1", false, None))) }));
        let mut contacts = MockContactRepository::new();
        let _ = contacts.expect_contacts_for_address().returning(|_| {
            Box::pin(async { Ok(vec![contact("user-1", "jane@example.com", true)]) })
        });

        let (deps, notifier, audit, _log) = build_deps(users, contacts, issuing_challenges(), true);
        let _ = forgot_password(forgot("Jane@Example.COM"), deps, audit, "1.2.3.4")
            .await
            .unwrap();
        assert_eq!(
            sent_addresses(&notifier),
            vec!["jane@example.com".to_owned()],
            "the identifier is normalized before the lookup"
        );
    }

    #[tokio::test]
    async fn a_locked_account_is_unreachable() {
        let mut users = MockUserRepository::new();
        let _ = users
            .expect_find_by_username()
            .returning(|_| Box::pin(async { Ok(Some(user("user-1", true, None))) }));
        let contacts = MockContactRepository::new();

        let (deps, notifier, audit, _log) =
            build_deps(users, contacts, MockChallengeRepository::new(), true);
        assert!(
            forgot_password(forgot("jane"), deps, audit, "1.2.3.4")
                .await
                .unwrap()
                .is_none()
        );
        assert!(sent_addresses(&notifier).is_empty());
    }

    /// With several confirmed addresses and no preference there is no basis for picking one, and
    /// picking wrong puts the link where the user is not looking.
    #[tokio::test]
    async fn several_confirmed_addresses_need_a_preference() {
        let build = |preferred: Option<&'static str>| {
            let mut users = MockUserRepository::new();
            let _ = users.expect_find_by_username().returning(move |_| {
                Box::pin(async move { Ok(Some(user("user-1", false, preferred))) })
            });
            let mut contacts = MockContactRepository::new();
            let _ = contacts.expect_list_contacts().returning(|_| {
                Box::pin(async {
                    Ok(vec![
                        contact("user-1", "a@example.com", true),
                        contact("user-1", "b@example.com", true),
                    ])
                })
            });
            (users, contacts)
        };

        let (users, contacts) = build(None);
        let (deps, notifier, audit, _log) = build_deps(users, contacts, issuing_challenges(), true);
        let _ = forgot_password(forgot("jane"), deps, audit, "1.2.3.4")
            .await
            .unwrap();
        assert!(
            sent_addresses(&notifier).is_empty(),
            "ambiguous without a preference"
        );

        let (users, contacts) = build(Some("b@example.com"));
        let (deps, notifier, audit, _log) = build_deps(users, contacts, issuing_challenges(), true);
        let _ = forgot_password(forgot("jane"), deps, audit, "1.2.3.4")
            .await
            .unwrap();
        assert_eq!(sent_addresses(&notifier), vec!["b@example.com".to_owned()]);
    }

    /// A preference naming an address that is gone or unconfirmed must not silently redirect the
    /// link — it falls back to the unambiguous confirmed one.
    #[tokio::test]
    async fn a_stale_preference_does_not_redirect_the_link() {
        let mut users = MockUserRepository::new();
        let _ = users.expect_find_by_username().returning(|_| {
            Box::pin(async { Ok(Some(user("user-1", false, Some("gone@example.com")))) })
        });
        let mut contacts = MockContactRepository::new();
        let _ = contacts.expect_list_contacts().returning(|_| {
            Box::pin(async { Ok(vec![contact("user-1", "jane@example.com", true)]) })
        });

        let (deps, notifier, audit, _log) = build_deps(users, contacts, issuing_challenges(), true);
        let _ = forgot_password(forgot("jane"), deps, audit, "1.2.3.4")
            .await
            .unwrap();
        assert_eq!(
            sent_addresses(&notifier),
            vec!["jane@example.com".to_owned()]
        );
    }

    /// No mail path: still a 202, and the operator sees why nothing happened.
    #[tokio::test]
    async fn without_a_mail_path_the_answer_is_unchanged() {
        let mut users = MockUserRepository::new();
        let _ = users
            .expect_find_by_username()
            .returning(|_| Box::pin(async { Ok(Some(user("user-1", false, None))) }));
        let mut contacts = MockContactRepository::new();
        let _ = contacts.expect_list_contacts().returning(|_| {
            Box::pin(async { Ok(vec![contact("user-1", "jane@example.com", true)]) })
        });

        let (deps, notifier, audit, log) =
            build_deps(users, contacts, MockChallengeRepository::new(), false);
        assert!(
            forgot_password(forgot("jane"), deps, audit, "1.2.3.4")
                .await
                .unwrap()
                .is_none()
        );
        assert!(sent_addresses(&notifier).is_empty());
        let lines = log.lock().unwrap().clone();
        assert!(
            lines.iter().any(|line| line.contains("cannot send mail")),
            "the operator must see the misconfiguration: {lines:?}"
        );
    }

    /// The reset itself: a new hash, a bumped revocation counter, and `lastPasswordChange` rather
    /// than `lastPasswordReset` — the user chose this password, so the account must not read as
    /// holding a generated one.
    #[tokio::test]
    async fn a_reset_revokes_every_session_and_counts_as_a_change() {
        let mut challenges = MockChallengeRepository::new();
        let _ = challenges.expect_consume().returning(|_, _| {
            Box::pin(async {
                Ok(Some(Proven {
                    user_id: "user-1".to_owned(),
                    tenant_id: "tenant-1".to_owned(),
                    address: "jane@example.com".to_owned(),
                }))
            })
        });
        let mut users = MockUserRepository::new();
        let _ = users
            .expect_get_user()
            .returning(|_| Box::pin(async { Ok(Some(user("user-1", false, None))) }));
        let saved = Arc::new(Mutex::new(None));
        let sink = saved.clone();
        let _ = users.expect_put_user().returning(move |user| {
            let sink = sink.clone();
            Box::pin(async move {
                if let Ok(mut slot) = sink.lock() {
                    *slot = Some(user.clone());
                }
                Ok(user)
            })
        });

        let (deps, _notifier, audit, _log) =
            build_deps(users, MockContactRepository::new(), challenges, true);
        let _ = reset_password(
            ResetRequest {
                token: "secret-value".to_owned(),
                new_password: "a-long-enough-password".to_owned(),
            },
            deps,
            audit,
        )
        .await
        .unwrap();

        let stored = saved.lock().unwrap().clone().expect("user was written");
        assert_eq!(stored.token_version, 4, "every session must die at refresh");
        assert!(stored.last_password_change.is_some());
        assert!(
            stored.last_password_reset.is_none(),
            "a self-chosen password is not a pending admin reset"
        );
        assert_ne!(stored.password_hash.as_deref(), Some("hash"));
    }

    /// Unknown, used, expired and wrong-purpose all arrive here as `None`, and all answer alike.
    #[tokio::test]
    async fn an_unusable_reset_token_is_refused() {
        let mut challenges = MockChallengeRepository::new();
        let _ = challenges
            .expect_consume()
            .returning(|_, _| Box::pin(async { Ok(None) }));

        let (deps, _notifier, audit, _log) = build_deps(
            MockUserRepository::new(),
            MockContactRepository::new(),
            challenges,
            true,
        );
        let result = reset_password(
            ResetRequest {
                token: "nope".to_owned(),
                new_password: "a-long-enough-password".to_owned(),
            },
            deps,
            audit,
        )
        .await;
        assert!(result.is_err());
    }
}
