# umami notifications

umami decides **who** hears about something and **where** they can be reached. The app decides
**when** and **what**. That split is the whole design, and everything below follows from it.

For the addresses themselves see [CONTACTS.md](CONTACTS.md); for the permission DSL,
[PERMISSIONS.md](PERMISSIONS.md).

Related decisions:

- [ADR 0014 — Transactional mail stays outside the notification catalogue](adr/0014-transactional-mail-outside-notification-catalogue.md)
- [ADR 0015 — The app owns the notification clock; cadences are opaque strings](adr/0015-app-owns-notification-clock.md)
- [ADR 0021 — External recipients: a notification address without an identity](adr/0021-external-recipients-without-identity.md)

---

## 1. Three kinds of message, and only two are here

| | What it is | How it is sent |
|---|---|---|
| **1. Transactional** | one person, one reason — a password reset, an address confirmation | the sender fetches the user and sends. **Never consults this catalogue** |
| **2. Informational, no rhythm** | "your build failed" | resolve an audience by type; the choice is on or off |
| **3. Informational, with a rhythm** | "new content" | same, plus a cadence match |

Cases 2 and 3 are one code path; an **empty `cadences` list** is what distinguishes them.

There is no "not suppressible" flag on a type: case 1 does not ask, so it cannot be switched off.
Why: [ADR 0014](adr/0014-transactional-mail-outside-notification-catalogue.md).

---

## 2. Cadences, and why the app owns the clock

The app runs its own jobs; umami schedules nothing. When a job fires it says which cadences that
firing represents, and umami answers with the users whose choice matches — one string comparison per
user, nothing accumulated or grouped. Why: [ADR 0015](adr/0015-app-owns-notification-clock.md).

**A firing may be several cadences at once.** The Friday run is the daily and the weekly run; on the
first Friday of the month it is the monthly one too. So a firing carries a set:

```json
{ "tenantId": "…", "type": "new-content", "cadences": ["daily", "weekly", "monthly"] }
```

Each user still appears at most once, because a user's choice is a single value.

### A cadence is a string

There is no cadence enum; umami never interprets one, so `on-publish` or `quarterly` are as valid as
`weekly`. There is **no "immediate" or "push" concept** either: a type with no rhythm of its own
declares a single cadence, called whatever suits, and its subscribers choose that string.

Each cadence carries its own **label**, exactly as a role or a feature does: a `LocalizedText`, a
plain string or a map of locale tag to string. `GET /auth/me/notifications` resolves it into the
reader's language, so the picker gets one string per entry either way — see [CONFIG.md](CONFIG.md)
(*Labels*).

Typos are caught against the declared list:

| Typo in | Caught by |
|---|---|
| a firing | the type's declared `cadences` — `400`, not an empty audience |
| a user's choice | the same list — refused at `PUT`, not stored |
| the declaration itself | `validate_catalogue` on `PUT /config` |

The declaration has nothing to be compared against at runtime, so the gate refuses a duplicate code,
a type with no cadences, a non-lowercase cadence (it would never match a normalized firing), and a
`default` naming a cadence the type is never fired at — which would silently park every untouched
user in a group that receives nothing.

---

## 3. The type catalogue

In the config, `notificationTypes`, shaped like the other catalogues:

```jsonc
"notificationTypes": [
  { "code": "new-content",          // stable: it keys every user's stored choice
    "name": { "de": "Neue Inhalte", "en": "New content" },   // or a plain string, = {"*": …}
    "description": "Seiten, die seit der letzten Nachricht veröffentlicht wurden.",
    "cadences": [                       // what the app actually fires, with the words a user reads
      { "code": "daily",   "name": { "de": "Täglich",    "en": "Daily" } },
      { "code": "weekly",  "name": { "de": "Wöchentlich", "en": "Weekly" } },
      { "code": "monthly", "name": { "de": "Monatlich",  "en": "Monthly" } }
    ],
    "default": "weekly",                // "on", a cadence code, or omitted for off
    "eligibleIf": "role:editor,feature:pro" },   // optional

  // Case 2 — no rhythm of its own, so no `cadences` at all. The choice is "on" or "off".
  { "code": "build-failed",
    "name": "Build fehlgeschlagen",
    "default": "on",
    "eligibleIf": "role:editor" },

  // Open to a tenant's external recipients (§7) — mailboxes with no login. Such a type may gate
  // on the tenant's features, never on a role: a recipient has none, and PUT /config refuses it.
  { "code": "form-submission",
    "name": { "de": "Formular-Eingaben", "en": "Form submissions" },
    "default": "on",
    "eligibleIf": "feature:forms",
    "recipients": true }
]
```

The app then fires:

```
POST /notifications/audience
{ "tenantId": "…", "type": "new-content", "cadences": ["daily", "weekly"] }
```

— its Friday job, which is both the daily and the weekly run. Someone who chose `monthly` is simply
not in the answer; they wait for the run that says `monthly`.

`eligibleIf` is the **input** vocabulary, not the output: `role:*` (the recipient's),
`feature:*` (their tenant's), plus `is:system-tenant` / `is:system-tenant-member`. Same DSL as the
`apis` rules.

**Session markers do not work here and must not be used.** `is:2fa`, `is:passkey` and `is:totp`
describe how a *session* authenticated, and a notification has no session — an expression naming one
would simply never match, with nothing anywhere to explain why. If you need the 2FA-ish predicate,
what you want is "has 2FA configured", which is a different statement and not currently exposed.

A type with **no `cadences`** is case 2: the app fires it without naming any, and the user's choice
is `on` or `off`. Naming a cadence on such a firing is a `400`, and so is omitting them on a type
that declares some — a caller confused about which kind of thing it is firing should hear about it
rather than resolve an empty audience.

---

## 4. What a user can choose

One value space for both kinds of type, so there is no separate on/off switch beside a cadence
picker:

| Stored | Means |
|---|---|
| key absent | *unset* — follow the type's `default`, now and whenever it changes |
| `"off"` | an explicit no, which the deployment cannot override |
| `"on"` | an explicit yes, for a type with no rhythm |
| a cadence code | an explicit yes, at that rhythm |

`off` and `on` are **reserved** and cannot be cadence codes — otherwise a stored choice would be
ambiguous. The gate refuses a catalogue that tries.

**`off` is offered for every type**, with or without a rhythm. Switching something off must never
depend on it having a schedule, and it must not be the option somebody has to hunt for — so in the
profile it is the *first* entry in the picker, ahead of the default.

Unset stays distinguishable from `off` on purpose. Normalising "unset" into today's default at write
time would freeze it, and a later change to that default would then fail to reach exactly the people
who never expressed an opinion. So `DELETE` removes the key rather than writing the default into it.

---

## 5. Endpoints

### Self-service — `manage:contacts`

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/auth/me/notifications` | eligible types with `cadences`, `default`, `choice`, `effective` |
| `PUT` | `/auth/me/notifications/{code}` | `{choice}` — `"off"`, `"on"` or a cadence code. Anything the type does not accept is a `400` |
| `DELETE` | `/auth/me/notifications/{code}` | back to *unset* |

Both writes are **audited**. "I never asked for these" is a claim umami has to be able to answer,
and the answer is only as good as the record of who changed what when.

### Machine — system-tenant service keys (`scope:notifier`)

| Method | Path | Permission |
|--------|------|-----------|
| `POST` | `/notifications/audience` | `notifications:audience` |
| `POST` | `/notifications/send` | `notifications:send` |
| `POST` | `/notifications/undeliverable` | `notifications:report` (`scope:mail-worker`) — the way back for a hard bounce; see [CONTACTS.md](CONTACTS.md) §3 |

```
POST /notifications/audience
{ "tenantId": "…", "type": "new-content", "cadences": ["daily","weekly"] }
→ { "recipients": [ { "userId": "…", "addressableName": "Ms Doe",
                      "locale": "de", "cadence": "weekly" },
                    { "recipientId": "…", "addressableName": "Front desk",   // an external
                      "locale": "de", "cadence": "weekly" } ],             // recipient, §8
    "truncated": false }

POST /notifications/send
{ "type": "new-content",          // omit entirely for a transactional message (case 1)
  "messages": [ { "userId": "…", "subject": "…", "body": "…" },
                { "recipientId": "…", "subject": "…", "body": "…" } ] }
→ { "results": [ { "userId": "…", "status": "queued", "messageId": "…" },
                 { "recipientId": "…", "status": "queued", "messageId": "…" } ] }
```

Every entry and every message carries **exactly one** of `userId` and `recipientId`: a user, or one
of the tenant's external recipients. A message with both or neither is a `400` for the whole batch
— neither is the shape a caller produces when it copies `userId` by name and meets its first
recipient, and the batch failing loudly beats the mailbox being skipped in silence. A caller that
spreads the audience entry into its message (`{ ...recipient, subject, body }`) reaches both kinds
without a code change.

### Finished text, or something for the worker to render

A message may hand over finished text, name a layout the worker renders, or both:

```jsonc
{ "type": "new-content",
  "messages": [
    { "userId": "…",
      "subject": "…", "body": "…",     // optional when `template` is given
      "template": "app::new-content",  // your namespaced layout name; umami forwards it
      "context": { "pages": 3 },       // opaque data for that layout
      "cadence": "weekly" }            // which cadence this recipient matched
  ] }
```

**Every template name is namespaced**, and that is checked: `app::new-content`, not
`new-content`. A worker keys its layout off this one field and every sender writes into it, so an
unnamespaced name is refused (two apps inventing `digest` would share a layout) and so is anything
under `umami::`, which is reserved for the mails umami sends itself. The namespace is lowercase
letters, digits and `-`; what follows the `::` is yours.

**One of the two is always required.** A message with neither is a `400`, and so is half the text —
`subject` without `body` is a caller that lost the other half, never a deliberate hand-over. Sending
**both** is the robust combination: a worker that does not know the layout name still has something
to deliver.

The batch is validated as a whole, before the first message goes out. A batch rejected halfway would
leave the earlier half delivered and answer with a `400` that says nothing about which half.

umami adds what only it has, so a worker rendering its own layout does not need to ask:

| Field | What |
|---|---|
| `notification.type` / `.cadence` | the codes, normalized. **Codes only** — a catalogue label is whatever languages the deployment happened to write, so sending one along would look like a translation without reliably being one, and a layout wants the stable code anyway |
| `recipient` | every name form umami can compose, plus `salutationKey` for a template that branches |
| `locale` | the recipient's resolved language |
| `footer` / `globalContext` | the deployment's imprint and template constants, from the config `mail` block |

`cadence` is passed back by the caller rather than re-derived, because `send` never re-reads a
preference — but it is checked against the type all the same. A cadence the type is never fired at
means the caller and the catalogue disagree, and the mail would otherwise go out worded for a rhythm
nobody chose.

**Keep personal data out of `context`** beyond what the mail itself says, and never log it. It
travels into the queue and through the worker's logs — places with no retention policy and no
erasure story, which is the same reason no address ever appears in a umami URL. It is capped at
**4 KB** per message: it renders a template, it does not carry a payload.

`send` **never re-checks a preference.** The caller is trusted to have resolved an audience, and
`notifications:send` is the control on that trust — which is also why it is a separate permission
from `notifications:audience`.

**The audience carries no addresses.** A recipient is a `userId`, a name to address them by and their
language — everything needed to *write* a message, nothing needed to harvest a mailing list. Hand the
`userId` back to `send` and umami resolves the address itself, so no address ever leaves the service.
An app gets to reach people without getting to know them.

The two permissions are separate on purpose: an app that only needs to send must not also be able to
enumerate a tenant's users. The default config grants both to `scope:notifier` because one key does
both jobs today; a deployment wanting a send-only app writes two scopes.

Other properties worth knowing:

- A recipient with **no confirmed address** is left out of the audience rather than returned and then
  failed — naming somebody unreachable would only produce a `no-address` on the way back.
- `send` takes at most **500** messages. The caller already holds the audience, so it can page.
- Per-recipient status (`queued` / `no-address` / `failed`); one failure does not abandon the batch,
  because partial success is the normal case.
- Both endpoints are **audited** with type, cadences and recipient count. That is also the only
  visible symptom of an app whose schedule drifted from its config: "monthly: 0 recipients" three
  months running.

---

## 6. Which address a notification goes to

Their chosen address while it is confirmed, otherwise the oldest confirmed one they hold — resolved
through the single rule in [CONTACTS.md](CONTACTS.md) §5, the same one the profile screen displays.
A user with no confirmed address at all is left out of the audience and answered `no-address` by
`send`.

Delivery itself is one write per message — to a queue, or straight to SES in a deployment small
enough to skip the worker ([SEAMS.md](SEAMS.md)). Such a mail carries the app's own `template` name
and a `notification` block; the payload and the worker's contract are documented in
[CONTACTS.md](CONTACTS.md) §3.

---

## 7. External recipients

A tenant can register addresses that are **not users** — a shared `info@` mailbox nobody logs in
with — and have them hear about the types the catalogue opens to them. Why this exists, and why it
is neither a user without a login nor a raw address on `send`:
[ADR 0021](adr/0021-external-recipients-without-identity.md).

A recipient is an address, a display name, a language and one choice per type, owned by a tenant.
No role, no password, no session, no seat: it is not in `GET /users` and not counted anywhere a
user is.

**Consent, exactly as for a contact.** Creating a recipient mails a single-use confirmation link;
the mail names the tenant and the types chosen, so the mailbox agrees to something specific.
Unconfirmed, a recipient is in no audience. A hard bounce or a complaint withdraws the
confirmation through the same report the worker files for a contact (`recipientId` in place of
`userId`, see [CONTACTS.md](CONTACTS.md) §3).

**Choices are explicit, never defaulted.** A type absent from a recipient's choices is off, whatever
the type's `default` says — nobody ever showed the mailbox a default, so it cannot have agreed to
it. A recipient has to be created with at least one choice that is not `off`.

**Which types: `recipients: true`.** A type is closed to recipients unless the catalogue says
otherwise. Such a type may gate on the tenant's `feature:*` (and the `is:system-tenant*` markers)
but not on a `role:*` — a recipient has none, and `PUT /config` refuses the combination rather than
guessing what a role predicate means for a mailbox.

**The link in every mail.** Each notification sent to a recipient carries a management link with
the recipient's own long-lived token, appended to the body above the signature separator and
carried as `recipient.manageUrl` in the worker payload (a worker may set it as `List-Unsubscribe`).
Behind it the mailbox reads and changes its choices or removes itself — without a login, and
without ever touching the address: a different mailbox is a different recipient. The secret is
stored encrypted, because umami has to put the plaintext into every mail; deleting the recipient
is the revocation.

### Endpoints

Admin, `manage:recipients`, scoped to the caller's own tenant:

| Method | Path | Notes |
|---|---|---|
| `GET` | `/tenants/{id}/recipients` | the recipients, the types open to them (labels in the caller's language), `verificationAvailable` |
| `POST` | `/tenants/{id}/recipients` | `{address, displayName, locale, choices}` → `201`, unconfirmed, confirmation mail out (`verificationSent`). Duplicate address in the tenant: `409` |
| `PATCH` | `/tenants/{id}/recipients/{recipientId}` | `displayName`, `locale`, `choices` — never the address |
| `DELETE` | `/tenants/{id}/recipients/{recipientId}` | |
| `POST` | `/tenants/{id}/recipients/{recipientId}/verify` | send the confirmation again; `503` with no mail path, `429` over the admin's `mailSend` cap |

Unauthenticated, the token in the **body** (never in a path or query umami logs):

| Method | Path | Notes |
|---|---|---|
| `POST` | `/recipients/confirm` | `{token}` from the confirmation mail → `{status, tenantName}` |
| `POST` | `/recipients/manage` | `{token}` → tenant name, display name, the eligible types and the current choices, in the recipient's language |
| `PUT` | `/recipients/manage` | `{token, choices}` |
| `DELETE` | `/recipients/manage` | `{token}` — unsubscribe from everything by removing the recipient |

The management UI has a *Recipients* screen for the admin side, and two standalone pages
(`/app/confirm-recipient`, `/app/recipient`) for the links.

`manage:recipients` is its own permission: not `manage:contacts`, which is baseline self-service
over one's own addresses and would let every member make umami mail strangers, and not
`manage:users`, because a recipient is defined by not being a user. The default config grants it
alongside `manage:users`. The admin's `mailSend` cap applies to the confirmation mails they cause.

Every mutation is audited in the tenant's log — created, confirmation mailed or not and why,
confirmed, choices changed (by the admin, or by the recipient itself), unsubscribed, deleted,
confirmation withdrawn by a bounce. Deleting a tenant deletes its recipients with it.

---

## 8. Not implemented yet

- **Digests.** Nothing accumulates, so "everything since last week in one mail" is the app's job —
  it holds the content anyway.
- **Per-type channel choice.** There is one channel (email) and one preferred address per user. A
  matrix of type × channel is a form nobody fills in.
- **Templates.** umami forwards a `template` name and its `context`; it does not store, render or
  validate one. Which layouts exist is between the app and its worker, and a name umami does not
  know is not an error here — the worker falls back to the text.
