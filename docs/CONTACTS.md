# umami contacts

A **contact** is one email address a user can be reached at, plus whether its owner has proven
possession of it. That is the whole concept.

Chat identities (Telegram/WhatsApp) are a **different** thing and documented in
[CONFIG.md](CONFIG.md) §7: they answer "which user sent this message", which ends in a minted token
rather than a delivered mail. The two shared a table for a while and it made every function branch on
which half of the data it was looking at — so they are apart, and stay apart.

---

## 1. Why a list, not one field on the user

The deciding case is a **change of address**:

- With a list the user adds the new address, verifies it, and only then drops the old one. They are
  reachable the whole way through.
- With a single field the new address overwrites a verified one while still unverified — so the user
  is unreachable exactly when the confirmation mail has to arrive.

"Work and private" is the second reason and the cheaper one.

---

## 2. Verification

`verified` records one fact: *this address really belongs to this user*, proven by them answering a
challenge sent to it.

- **An address an admin typed in is never verified.** Verification is proof of possession, and nobody
  can supply it on the owner's behalf.
- **Only a verified address is ever sent to.** An unverified row is an intention, not a contact.

The UI badges the unverified ones for exactly that reason: an address sitting there without a badge
would look like a working way to reach someone.

### The ceremony

```
   user                         umami                          mail worker
    │                             │                                  │
    │ POST …/{address}/verify      │                                  │
    ├────────────────────────────► │  mint secret, store sha256(it)   │
    │                             │  render mail, one SQS write       │
    │                             ├─────────────────────────────────► │
    │                             │                          deliver  │
    │ ◄─────────────────── mail with …/app/verify-contact?token=<secret>
    │                             │                                  │
    │ POST /auth/contacts/verify  │  delete row → address verified    │
    ├────────────────────────────► │                                  │
```

Four properties worth knowing, each there for a reason:

- **The finish step is unauthenticated.** The link is opened in a mail client, regularly on a
  different device than the one that started the flow. The secret *is* the proof; demanding a
  session on top would lock out exactly the people reading mail on a phone.
- **Only `sha256(secret)` is stored.** Same reason as the refresh secrets: a table dump must not hand
  out working challenges.
- **Single-use by construction.** Consuming the challenge *is* the delete, so two concurrent clicks
  cannot both succeed — only one receives the old row. Rows also carry a DynamoDB TTL, and an
  unexpired-but-stale row is rejected on read, because TTL deletion is eventual.
- **One message for invalid, used and expired alike.** Telling a holder of a stale link which of the
  three it is helps nobody legitimate.

**Adding and confirming are one step.** They were never really two: an unverified row is an
intention, nothing is ever sent to one, and splitting them only produced addresses sitting
unconfirmed because nobody noticed a second button. The mail is **best-effort** — the row exists
either way, and turning a stored address into an error would invite a retry that answers `409`. What
the caller gets instead is `verificationSent`, so the screen can say which of the two happened.
`POST /auth/me/contacts/verify` stays, as the way to send again.

Re-verifying an already-confirmed address is free and sends nothing. A challenge outliving its
address — removed between the mail arriving and the link being clicked — is not an error; there is
simply nothing left to confirm.

### Rate limiting

`security.rateLimits.mailSend` caps how many mails one **user** can have umami send (default 5/hour).
Keyed on the account rather than the IP, because the address being mailed sits on that account's
list: without the cap, anyone with a login can add a stranger's address and have umami mail them on
repeat. A blocked send answers `429` with `Retry-After`.

---

## 3. What the mail worker receives

umami renders the mail — subject and plain-text body, in the recipient's own language from
`locales/app.yml` — and hands it over as one SQS message. Delivery, retries, bounces and provider
credentials belong to the worker; a dead-letter queue on the SQS side is the retry story.

```jsonc
{ "messageId": "…", "template": "umami::contact-verification",
  "to": "jane@example.com", "subject": "…", "body": "…",
  "recipient": { "addressableName": "Frau Dr. Doe", "fullName": "Frau Dr. Jane Doe",
                 "name": "Dr. Jane Doe", "salutation": "Frau", "salutationKey": "MADAM",
                 "firstName": "Jane", "lastName": "Doe" },
  "context": { "link": "https://umami.example.com/app/verify-contact?token=…" },
  "footer": "noonu GmbH · …",                       // from the config, already in `body` too
  "globalContext": { "baseUrl": "https://noonu.dev" },
  "locale": "de", "userId": "…", "tenantId": "…" }
```

`messageId` is the **idempotency key** — SQS is at-least-once, so a worker that retries must be able
to recognise a message it already delivered. `userId`/`tenantId` are for the worker's own audit
trail, never for addressing.

`template` names the layout, and it is the **only** selector a worker switches on. umami puts its
own names on its own mails — `umami::contact-verification` and `umami::password-reset` — and
forwards whatever an app named its layout for anything sent through `/notifications/send`. It never
interprets either; a worker that does not know a name falls back to `subject`/`body`, which is
always filled in for umami's own mails.

One field rather than one per sender, so there is one thing to switch on. What keeps them apart in
it is that **every name carries its sender's namespace** — `umami::password-reset`,
`wsc::new-content`, `abc::report-ready` — and that is a rule rather than a convention:
`POST /notifications/send` refuses a template with no namespace, and refuses `umami::` outright.

Both halves of that matter. Without the reservation a caller could have its notification rendered as
a password reset by a worker doing exactly what it was told; without the requirement, two apps that
both invent `digest` would silently share a layout. The namespace is lowercase letters, digits and
`-`; what follows the `::` is the sender's own business.

`notification` is what says which side a mail came from: present means it came through
`/notifications/send`.

The rest is there so a worker rendering its own layout never has to ask umami anything:

| Field | What |
|---|---|
| `recipient` | every name form umami can compose, plus `salutationKey` (`""`/`SIR`/`MADAM`) — the **stable** code, because the `salutation` word beside it is already in the reader's language and useless in a condition |
| `context` | the same single-use link the body carries, structured, so a button does not need it parsed back out of the text |
| `footer` | the deployment's imprint in this mail's language, rendered, from config `mail.footer` |
| `globalContext` | the deployment's template constants, plus umami's own `umamiBaseUrl` |

All of it is a convenience. `subject`/`body` are always filled in for umami's own mails, the footer
is already appended to that body, and a worker that just delivers the text is correct and complete.

A mail from `POST /notifications/send` looks the same but carries the app's side of it — `template`,
`context` and a `notification` block. See [NOTIFICATIONS.md](NOTIFICATIONS.md) §5.

**Never log `context`.** For umami's own mails it holds a single-use link; for an app's, whatever
the app put there.

### The way back: a bounce

umami hands a message over and never sees what happened to it, so the one thing it cannot learn on
its own is that an address has stopped existing. The worker reports that:

```
POST /notifications/undeliverable          (notifications:report, scope:mail-worker)
{ "userId": "…", "address": "jane@example.com", "event": "bounced", "messageId": "…" }
```

The address's confirmation is **withdrawn** — the row stays, the flag clears. It was proven once and
the proof is now stale, so the user sees what happened and can confirm it again if the mailbox comes
back. Without this a dead address stays confirmed forever and every later message, reset links
included, goes on being sent into nothing.

**Hard failures only.** A full mailbox or a greylisting is the worker's to retry and says nothing
about whether the address is still the user's. `complained` is accepted too and treated the same way:
somebody saying "do not mail me here" is at least as good a reason to stop.

Its own permission and its own scope, separate from `notifications:send`: the worker and the app
asking for a send are different principals, and the worker has no business resolving an audience.

With no mail transport configured, outbound mail is off: `GET /auth/me/contacts` reports
`verificationAvailable: false`, the UI hides the action, and the endpoint answers `503` instead of
accepting a request that goes nowhere. Which transports there are, and what each costs, is
[SEAMS.md](SEAMS.md) — a deployment too small for a worker can have umami call SES directly, at the
price of never learning about the bounce this section describes.

---

## 4. Storage

One table, `user-contacts`, keyed **`(userId, address)`**. That composite key is the design:

| Job | How |
|-----|-----|
| uniqueness per user | *is* the primary key — one conditional put both writes the row and rejects a duplicate; no guard table, no read-then-write window |
| list a user's addresses | a query on the hash key — no by-user index |
| delete one | a keyed delete — no ownership check to get wrong, because the caller's own `userId` is half the key |
| "who holds this address" | one GSI on `address`, for the password-reset entry point where no session and therefore no tenant exists yet |

Addresses are normalized (trimmed, lowercased, sanity-checked) before they touch the key. That is
load-bearing rather than cosmetic: two spellings of one address must collapse to one string, or the
same mailbox lands in two rows and only one of them ever gets verified.

---

## 5. Endpoints

All gated on `manage:contacts`, which the default config grants in the **baseline** self-service rule
— see [CONFIG.md](CONFIG.md) §4.

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/auth/me/contacts` | the caller's addresses + the preferred one |
| `POST` | `/auth/me/contacts` | `{address, label?}` → 201, unverified — **and the confirmation goes out with it**. `verificationSent: false` when the deployment cannot mail or the caller is over the cap; the address is stored either way. A duplicate is a 409 |
| `DELETE` | `/auth/me/contacts` | `{address}` — also drops an explicit choice that named it |
| `POST` | `/auth/me/contacts/verify` | `{address}` → mails a fresh confirmation link, 202. Free no-op when already confirmed; `503` with no mail path; `429` over the cap |
| `PUT` | `/auth/me/preferred-contact` | `{address}`, or `null` to clear. `409` for an unconfirmed address |
| `GET` | `/users/{id}/contacts` | admin, read-only, `manage:users`; scoped server-side to the caller's tenant |
| `POST` | `/auth/contacts/verify` | **unauthenticated** — `{token}` from the mailed link |

**No address ever appears in a path.** Every one of these takes it in the body, even where a path
segment would read better, because a URL is copied into every access log, proxy log and tracing span
between the browser and umami — places with no retention policy and no erasure story. umami already
refuses to hand addresses to the apps it serves (`/notifications/audience` returns none); handing
them to the infrastructure instead would be the same leak by another route. Opaque ids — user,
tenant, session, key — stay in the path, where they belong.

**Every mutation is audited** — added, removed, verified, preference changed, and mail queued, with
its `messageId`. So is a verification mail that was **not** sent, for
want of a queue or against the rate limit: a user clicking "confirm" and getting an error is the
symptom of a misconfigured deployment, and the operator who has to notice it is not the person
seeing the error. Reachability is a security-relevant property: whoever controls the address a reset
link goes to controls the account, so the trail exists from the start rather than being added after
the first incident.

### The preferred address

`user.preferredContact` records what the user **chose**. Where mail actually goes is *derived* from
it, every time, by the profile screen and by every sender alike:

1. the chosen address, while the user still holds it and has confirmed it;
2. otherwise the **oldest** confirmed address they hold;
3. otherwise nothing — the user is unreachable, and `send` answers `no-address`.

The fallback is by age because the address proven longest is the one the user has been reachable at
longest, and picking by age gives every caller the same answer.

Deriving rather than storing is deliberate. The alternative — rewriting the stored value whenever an
address is added, removed, confirmed or bounced — still needs rule 2 anyway, since no sender can
trust a value written by an earlier version of that logic. Two mechanisms answering one question is
how a profile screen and a password reset end up disagreeing about which mailbox is the user's.

Everything therefore follows without a repair job:

- confirming a first address makes it the one mail goes to;
- deleting the chosen address hands over to the next confirmed one;
- a bounce that withdraws a confirmation does the same, immediately, not at the next failed send.

`GET /auth/me/contacts` returns the **resolved** address in `preferred`, so the badge in the UI marks
the row that actually receives mail, and the raw choice in `chosen` beside it. The two are reported
separately because only an explicit choice can be un-chosen: offering to un-pick a derived
preference would be an action that visibly does nothing.

Setting a preference is where the rule is enforced up front instead: `PUT
/auth/me/preferred-contact` refuses an unconfirmed address with a `409`. Nothing is ever sent to one,
so the setting would change nothing while reading as though the account's mail now went there — and
there the user is present and can be told which step is missing. Deleting the chosen address clears
the stored value too, so a later address of the same name does not silently inherit a preference set
in another life.

---

## 6. A user record has no email field

It used to have one. The field is **gone**, not hidden, and four things went with it:

- **The `email` claim is no longer minted.** umami puts no personal data in every token by default; a
  deployment that wants an address in its tokens maps one through the API's `claims` block.
- **`username` is required** on `POST /users` and on the tenant-owner form. The old "fall back to the
  email as the username" convenience is gone: a contact is not an identity.
- **`PATCH /users/{id}` does not accept `email`.** There is exactly one place an address is managed,
  which is the point.
- **Admin user search** covers username, name parts and custom fields — not addresses. Pulling
  addresses into that search would mean a read per user across the whole tenant scan; looking a user
  up *by* an address is a direct query on `ByAddressIndex` instead, which is cheaper than the scan.

**`$user.email` is available as a claim** for a deployment that wants an address in its tokens —
sourced from the preferred address, which is a confirmed one by the rules above. It is resolved **only** when
a target API's mapping actually references it, so nobody pays a read for an option they did not take,
and it is *omitted* rather than empty when there is no confirmed address.

---

## 7. Password recovery

`POST /auth/forgot-password` (identifier = username **or** address) → mailed link →
`POST /auth/reset-password`. Both unauthenticated, for the same reason the confirmation step is: the
link arrives by mail, and here it *has* to work without a session — the premise is that the user
cannot sign in.

Five decisions worth knowing:

- **The entry point always answers 202.** Unknown identifier, known one, unconfirmed address,
  ambiguous address, no mail path — all identical. Any difference turns the endpoint into an oracle
  for "does this account exist here", which is exactly what the sign-in screen spends effort not
  revealing. The operator sees what happened in the audit log; the caller never does. The one
  distinguishable answer is `429`, and it is about the caller's own volume rather than any account.
- **The address must be confirmed.** A reset link is account takeover in one click for whoever reads
  it, so an address nobody proved possession of is not a place to send it. This is the reason
  confirmation exists before recovery does.
- **An ambiguous address is refused, not guessed.** Two accounts may share `info@acme.com`; mailing
  "reset your password" for an account the reader may not own is worse than asking for a username.
- **The purpose is stored on the challenge and checked on consume.** A confirmation link and a reset
  link share one table, so without that check the former would be redeemable as the latter — turning
  "can receive mail here" into "can take over this account".
- **A successful reset bumps `tokenVersion`**, so every existing session dies at its next refresh. A
  recovery is often a recovery *from* something; that is the point, not a side effect. It stamps
  `lastPasswordChange`, not `lastPasswordReset` — the user chose this password, so the account must
  not show as holding a generated one.

Two TTLs, deliberately different: `contactChallengeTtlSecs` defaults to 24h (a mail read the next
morning should still work), `passwordResetTtlSecs` to 1h (someone who just asked for it is looking at
their inbox now).

`GET /auth/capabilities` — public, account-independent — tells the sign-in screen whether to offer
the link at all: `{ "passwordRecovery": bool }`, true exactly when a mail queue is configured.

---

## 8. Not implemented yet
- Nothing outstanding from this file's own scope.
