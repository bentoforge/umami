# ADR 0021 — External recipients: a notification address without an identity

- **Status:** accepted
- **Date:** 2026-10-22
- **Extends:** [ADR 0014](0014-transactional-mail-outside-notification-catalogue.md),
  [ADR 0015](0015-app-owns-notification-clock.md)
- **Builds on:** [ADR 0011](0011-contacts-as-verified-list.md),
  [ADR 0012](0012-mail-worker-outbound-seam.md)

## Context

The notification machinery knows one kind of recipient: a **user**. An app fires a type for a
tenant (`POST /notifications/audience`), umami answers with the users whose eligibility and stored
choice match, the app hands finished text back (`POST /notifications/send`), and the worker
delivers it with the deployment's footer. Every recipient is somebody with a login, a role and a
seat in the tenant's user list.

WSC uses this for `form-submission`: every submission on a customer's site goes to the staff who
switched the type on. Customers now ask for one more thing — the submission should also reach a
mailbox nobody logs in with, `info@kuechen-mueller.de`, read by whoever is at the front desk. That
mailbox is not a person in the tenant. It has no role, needs no password, must not count as a seat,
and must not appear in the user list. It is an *address with consent*, nothing more.

Three ways to get there were on the table, and each put the machinery in the wrong place:

- **The app sends such mail itself**, through its own SES access. That makes two senders of one
  message type, two footers to keep identical, and a second place bounces and complaints have to be
  handled — or are not, and a dead mailbox is mailed forever. It also means the app knows the
  address, which the audience design exists to prevent (NOTIFICATIONS.md §5).
- **`send` accepts a raw address.** umami would become a relay to any address an app names,
  with no proof that the mailbox agreed to anything and no way for its owner to stop it. Consent is
  the whole point of the catalogue (ADR 0014); an address field on `send` bypasses it.
- **A user without a login.** Roles, listings, seat counts, limits, admin screens and a
  "set your password" mail arriving at a shared mailbox — a whole identity's worth of machinery for
  something that only ever needs an address, a language and a choice per type.

What the case actually needs is small: an address a tenant admin can add, confirmed by the mailbox
itself, carrying a choice per type, reachable through the existing audience and send calls, and
removable by its owner without ever signing in.

## Decision

umami gets a second kind of notification recipient: the **external recipient**, owned by a tenant
and carrying no identity.

### What it is

- A recipient is **address, display name, locale and one choice per notification type** — and a
  tenant. Nothing else: no role, no password, no session, no membership, no custom fields.
- It is **not a user**. It does not appear in `GET /users`, is not counted wherever users are
  counted (seats, limits), cannot be a tenant owner, and cannot be switched to.
- The address is normalized as a contact's is and is unique **per tenant**. The same mailbox may be
  a recipient in two tenants, and may also be a user's contact; those are independent facts in
  independent tables.
- Storage is its own table, `tenant-recipients`, keyed by a `generate_id()` recipient id, with an
  index on `(tenantId, address)` for the listing, the uniqueness check and the bounce report. Separate from
  `user-contacts` for the reason ADR 0011 gave for keeping chat identities out: shared rows make
  every function branch on which kind it is looking at.

### Consent: confirmed like a contact

- Creating a recipient sends a **confirmation link** to the address, exactly as adding a contact
  does: a single-use challenge, `sha256(secret)` stored, consumed by an unauthenticated endpoint,
  one message for invalid, used and expired alike. The challenge table is reused with its own
  purpose, so a contact confirmation is not redeemable as a recipient confirmation.
- The confirmation mail **names the tenant and the types chosen for the recipient**. The mailbox is
  agreeing to something specific, and the mail is where it learns what.
- **Unconfirmed, a recipient is in no audience.** The row exists so the admin can see it and resend
  the link; nothing is ever sent to it except the confirmation itself.
- **A hard bounce or a complaint withdraws the confirmation**, through the same
  `POST /notifications/undeliverable` report, with the same semantics as CONTACTS.md §3: the row
  stays, the flag clears, the admin sees it and may resend the link if the mailbox comes back.

### Choices: explicit, never defaulted

- A recipient's choice per type uses the user value space — `off`, `on` or a cadence code — but
  **there is no *unset* state and the type's `default` never applies**. A type the recipient has
  no explicit choice for is off.

  A user sees the picker and the default beside it; a recipient never sees a screen. A default that
  is switched on or changed later would subscribe mailboxes to something their owners were never
  told about, and the confirmation mail could not have listed it. For a recipient the stored choices
  are the complete statement of consent.
- The tenant admin sets the choices when creating the recipient and may change them later; both
  are audited. The recipient's own recourse is the link below.

### Which types a recipient may subscribe to: `recipients: true` on the type

`eligibleIf` is evaluated over a user's offline subject set — their roles, their tenant's features
and the system-tenant markers. A recipient has no roles, so the expression cannot mean the same
thing for it, and umami must not guess what it means.

- A notification type declares **`recipients: true`** to be subscribable by external recipients.
  Default `false`, so every existing catalogue is unchanged and no type reaches outside the tenant's
  members until the deployment says so. Being readable by an outside mailbox is a property of the
  type's content — "a form was submitted" is for the customer, "your build failed" is for staff —
  and that is a decision the catalogue should state, not one derived from a role predicate.
- For a recipient, `eligibleIf` is evaluated over the **tenant's** subjects only: `feature:*` and
  the `is:system-tenant*` markers. A tenant without `feature:forms` gets no form notifications to
  anyone, user or recipient.
- `validate_catalogue` **refuses** a `recipients: true` type whose `eligibleIf` names a `role:*`
  subject. The alternative — treating `role:*` as simply unfulfilled — reads well for
  `role:editor` and wrong for `!role:readonly`, which would then admit every recipient. Worse, a
  deployment that later adds a role gate to such a type would silently drop every recipient from
  its audience with no error anywhere, which is the failure mode ADR 0015 built the config gate to
  catch.
- `PATCH` / `POST` refuse a choice for a type that is not `recipients: true` or whose cadence the
  type does not declare, with a `400` — the same rule as `PUT /auth/me/notifications/{code}`.

### The link in every mail: manage and unsubscribe without a login

- Every message sent to a recipient carries a **management link** with a long-lived, per-recipient
  token: umami appends it to the finished `body` below the text and ahead of the signature
  separator (what follows that separator is what clients fold out of sight), and puts it,
  structured, into the worker payload (`recipient.manageUrl`, and as the `List-Unsubscribe` value
  a worker may set).
  The app never produces or sees it; the audience carries no address and no token.
- The token is a capability over **this recipient's choices only**: read them, change them, set
  everything to `off`, or delete the recipient. It cannot change the address — a different mailbox
  is a different recipient and starts with its own confirmation — so a leaked link costs at most a
  subscription, never a redirection.
- The secret is stored **encrypted** with the deployment's secret box, not hashed: umami has to
  put the plaintext into every mail it sends the recipient, so a hash alone would not do, and a
  table dump must still not hand out working links. Deleting the recipient is the revocation;
  there is no separate rotation.
- The endpoints behind the link are **unauthenticated** and take the token in the body, like
  `POST /auth/contacts/verify`: the link is opened from a mail client on whatever device is at
  hand, and demanding a login contradicts the premise.

### API shape: `userId` and `recipientId` side by side

- `POST /notifications/audience` returns users and recipients in **one list with one shape**:
  `addressableName`, `locale` and `cadence` as today, plus **exactly one** of `userId` or
  `recipientId`. A recipient's `addressableName` is its display name as entered; no salutation is
  composed, and `salutationKey` in the worker payload is empty.
- `POST /notifications/send` accepts a message with exactly one of `userId` or `recipientId`. Both
  or neither is a `400`, and the batch is validated as a whole before anything goes out, as today.
  The per-message result echoes whichever id was given.
- No neutral `id` field. The two ids name rows in different tables with different lifecycles and a
  different address rule (a user's preferred contact, CONTACTS.md §5; a recipient's single
  address), so umami would need a discriminator beside a neutral id anyway — the field name *is*
  the discriminator. It is also the additive choice: a caller that reaches only users keeps copying
  `userId` and changes nothing; a caller that spreads an audience entry into its message
  (`{ ...recipient, subject, body }`) reaches recipients without a code change, because `send`
  ignores the fields it does not read. A caller that copies `userId` by name produces a message
  with neither id when a recipient appears, and the batch fails loudly instead of skipping the
  recipient — WSC needs that one-line change before a tenant creates its first recipient.
- `POST /notifications/undeliverable` accepts `recipientId` in place of `userId`; the worker payload
  carries `recipientId` and `tenantId` for the worker's audit trail, never for addressing.

### Permission: `manage:recipients`

Creating, changing and deleting a tenant's recipients is gated on a **new permission**,
`manage:recipients`, granted by default where `manage:users` is (`role:owner`, `role:admin`).

- Not `manage:contacts`: that permission is about one's *own* addresses and sits in the baseline
  rule, so reusing it would let every member of a tenant make umami mail confirmation links to
  arbitrary addresses. Adding a recipient is an admin act on behalf of the tenant, not self-service.
- Not `manage:users`: recipients are defined by not being users, and a deployment may well want to
  hand recipient management to someone who must not administer accounts. Granting the two together
  by default costs nothing; forcing them together would.
- The admin's `mailSend` rate limit (CONTACTS.md §2) applies to the confirmation mails they cause,
  for the same reason it applies to contacts: without it, a login is a way to make umami mail
  strangers on repeat.

### Endpoints

Admin, `manage:recipients`, scoped to the caller's tenant:

| Method | Path | Notes |
|---|---|---|
| `GET` | `/tenants/{id}/recipients` | list, with `confirmed` per row |
| `POST` | `/tenants/{id}/recipients` | `{address, displayName, locale, choices}` → `201`, unconfirmed, confirmation mail out (`verificationSent` as for contacts). Duplicate address: `409` |
| `PATCH` | `/tenants/{id}/recipients/{recipientId}` | `displayName`, `locale`, `choices`. Never the address |
| `DELETE` | `/tenants/{id}/recipients/{recipientId}` | |
| `POST` | `/tenants/{id}/recipients/{recipientId}/verify` | send the confirmation again; `503` with no mail path, `429` over the cap |

Unauthenticated, token in the body, the recipient's own:

| Method | Path | Notes |
|---|---|---|
| `POST` | `/recipients/confirm` | `{token}` from the confirmation mail |
| `POST` | `/recipients/manage` | `{token}` → tenant name, display name, the eligible types and the current choices, in the recipient's locale |
| `PUT` | `/recipients/manage` | `{token, choices}` |
| `DELETE` | `/recipients/manage` | `{token}` — unsubscribe from everything by removing the recipient |

No address ever appears in a path, for the reason CONTACTS.md §5 gives. The recipient id is opaque
and may.

### Audit

Every mutation is audited in the tenant's log, as a contact's is: created, confirmation mail sent or
not sent (and why), confirmed, choices changed, unsubscribed, deleted, confirmation withdrawn by a
bounce or complaint. A change made through the management link is recorded with the recipient
itself as the actor, so "I never asked for these" can be answered for a mailbox exactly as it can
for a user. `audience` and `send` keep counting recipients into the totals they already audit.

## Alternatives considered

- **The app sends through its own SES.** Rejected: a second sender for one message type, a second
  footer to keep in sync, bounces handled twice or not at all, and the app learns the address.
- **`POST /notifications/send` with a raw address.** Rejected: umami becomes a relay to any address
  an app names, with no consent and no way for the owner to stop it. It would also hand the app the
  one thing the audience design withholds.
- **A user without a login.** Rejected: roles, listings, counts, limits, admin screens and a
  password mail to a shared mailbox, all to carry an address and a choice.
- **`role:*` treated as unfulfilled for recipients, no flag on the type.** Rejected: negated role
  predicates then admit recipients, and a later role gate on a type silently empties its recipient
  audience. The flag makes the deployment say which types may leave the member circle.
- **A neutral `id` on audience and send.** Rejected: umami would need a discriminator beside it,
  and every existing caller would change, including those that never use recipients.
- **Recipients follow the type's `default` like users do.** Rejected: nobody shows a recipient the
  default, so a changed default would subscribe mailboxes to something they never agreed to.
- **Single-use management tokens, rotated with every mail.** Rejected: a link in last month's mail
  must still work, and a recipient's choices are the only thing the token can touch.

## Consequences

- WSC keeps saying only "type fired for tenant"; the customer's mailbox is umami's concern from
  creation to unsubscribe. The app never sees an address or a token.
- WSC must copy `recipientId` as well as `userId` when turning an audience into messages, or spread
  the entry. Until it does, the first recipient in a tenant makes its `send` batch fail with a
  `400` — loudly, by design.
- The catalogue grows a boolean per type, and `validate_catalogue` grows one more rule. Existing
  configs are valid unchanged and reach no recipient.
- A new permission, a new table, a new challenge purpose, a new audit vocabulary and a new SPA
  page for the management link. The user model, the contacts table and the session code are
  untouched.
- The confirmation mail becomes the record of what a mailbox agreed to; its wording has to list the
  tenant and the types, and changing a recipient's choices afterwards is visible only in the audit
  and through the link in the next mail.
- Recipients are a handful of mailboxes per tenant, not a mailing list: the admin's `mailSend` cap
  governs how fast they can be created, and a deployment that wants a ceiling on their number
  declares a limit for it (LIMITS.md) — this ADR fixes no number.
