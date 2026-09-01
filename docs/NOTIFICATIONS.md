# umami notifications

umami decides **who** hears about something and **where** they can be reached. The app decides
**when** and **what**. That split is the whole design, and everything below follows from it.

For the addresses themselves see [CONTACTS.md](CONTACTS.md); for the permission DSL,
[PERMISSIONS.md](PERMISSIONS.md).

---

## 1. Three kinds of message, and only two are here

| | What it is | How it is sent |
|---|---|---|
| **1. Transactional** | one person, one reason — a password reset, an address confirmation | the sender fetches the user and sends. **Never consults this catalogue** |
| **2. Informational, no rhythm** | "your build failed" | resolve an audience by type; the choice is on or off |
| **3. Informational, with a rhythm** | "new content" | same, plus a cadence match |

Cases 2 and 3 are one code path; an **empty `cadences` list** is what distinguishes them.

There is deliberately no "not suppressible" flag on a type. Case 1 does not ask, so it cannot be
switched off — and a flag saying so would only invite somebody to route a password reset through the
consent machinery, where it does not belong.

---

## 2. Cadences, and why the app owns the clock

An app already runs its own jobs. wsc asks "is there new content" daily, weekly and monthly. umami
does **not** reproduce that: when a job fires it says which cadences that firing represents, and
umami answers with the users whose choice matches.

Nothing is accumulated, nothing is grouped, nothing is scheduled here. The decision is one string
comparison per user, and that is deliberate — a store of pending items plus a scheduler plus digest
templates plus a per-user timezone is a large amount of machinery for something the app's own
calendar already expresses.

**A firing is legitimately several cadences at once.** The Friday run *is* the daily run and the
weekly run; on the first Friday of the month it is the monthly one too. So a firing carries a set:

```json
{ "tenantId": "…", "type": "wsc-new-content", "cadences": ["daily", "weekly", "monthly"] }
```

Each user still appears at most once, because a user's choice is a single value.

### A cadence is a string

There is no cadence enum. umami never *interprets* one — no arithmetic, no ordering, no scheduling —
so a closed vocabulary would only dictate words umami has no business dictating. An app whose rhythm
is `on-publish` or `quarterly` is not wrong.

Consequently there is **no "immediate" or "push" concept** either. A type with no rhythm of its own
declares a single cadence, called whatever suits, and its subscribers choose that string. umami
cannot tell it apart from a weekly type and does not need to.

Each cadence carries its own **label**, exactly as a role or a feature does — a vocabulary the
deployment invents has to bring its own words, because nothing in a client's message catalogue could
know what `on-publish` should read as in a picker.

The typo protection an enum would have bought lives where it has to:

| Typo in | Caught by |
|---|---|
| a firing | the type's declared `cadences` — `400`, not an empty audience |
| a user's choice | the same list — refused at `PUT`, not stored |
| the declaration itself | `validate_catalogue` on `PUT /config` |

That last one matters most, because the declaration is the source of truth and has nothing to be
compared against at runtime. The gate refuses a duplicate code, a type with no cadences, a
non-lowercase cadence (it would never match a normalized firing), and a `default` naming a cadence
the type is never fired at — which would silently park every untouched user in a group that receives
nothing.

---

## 3. The type catalogue

In the config, `notificationTypes`, shaped like the other catalogues:

```jsonc
"notificationTypes": [
  { "code": "wsc-new-content",          // stable: it keys every user's stored choice
    "name": "Neue Inhalte",
    "description": "Seiten, die seit der letzten Nachricht veröffentlicht wurden.",
    "cadences": [                       // what the app actually fires, with the words a user reads
      { "code": "daily",   "name": "Täglich" },
      { "code": "weekly",  "name": "Wöchentlich" },
      { "code": "monthly", "name": "Monatlich" }
    ],
    "default": "weekly",                // "on", a cadence code, or omitted for off
    "eligibleIf": "role:wsc-editor,feature:pro" },   // optional

  // Case 2 — no rhythm of its own, so no `cadences` at all. The choice is "on" or "off".
  { "code": "wsc-build-failed",
    "name": "Build fehlgeschlagen",
    "default": "on",
    "eligibleIf": "role:wsc-editor" }
]
```

The app then fires:

```
POST /notifications/audience
{ "tenantId": "…", "type": "wsc-new-content", "cadences": ["daily", "weekly"] }
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
{ "tenantId": "…", "type": "wsc-new-content", "cadences": ["daily","weekly"] }
→ { "recipients": [ { "userId": "…", "addressableName": "Ms Doe",
                      "locale": "de", "cadence": "weekly" } ],
    "truncated": false }

POST /notifications/send
{ "type": "wsc-new-content",          // omit entirely for a transactional message (case 1)
  "messages": [ { "userId": "…", "subject": "…", "body": "…" } ] }
→ { "results": [ { "userId": "…", "status": "queued", "messageId": "…" } ] }
```

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

Delivery itself is one SQS write per message with `kind: "notification"`; the payload and the
worker's contract are documented in [CONTACTS.md](CONTACTS.md) §3.

---

## 7. Not implemented yet

- **Digests.** Nothing accumulates, so "everything since last week in one mail" is the app's job —
  it holds the content anyway.
- **Per-type channel choice.** There is one channel (email) and one preferred address per user. A
  matrix of type × channel is a form nobody fills in.
- **Digest wording per cadence.** The matched cadence comes back with each recipient, but nothing
  helps an app word "your week" differently from "today" — that is its own templating.
