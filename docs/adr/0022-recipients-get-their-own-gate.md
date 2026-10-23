# ADR 0022 — External recipients get their own gate: `recipientsIf`

- **Status:** accepted
- **Date:** 2026-10-23
- **Amends:** [ADR 0021](0021-external-recipients-without-identity.md), section "Which types a
  recipient may subscribe to"

## Context

ADR 0021 opened a notification type to a tenant's external recipients with a boolean,
`recipients: true`, and evaluated the type's `eligibleIf` for both audiences: over the user's
subjects for a member, over the tenant's subjects for a recipient. Because a recipient has no
roles, `PUT /config` refused a `recipients: true` type whose `eligibleIf` named a `role:*`.

The first real catalogue hit the wall that rule builds. Form submissions are for the people who
handle forms, so the member gate is a role (`feature:forms + role:forms`), and they are also for
the tenant's `info@` mailbox, which has no role at all. One expression cannot say both. The only
way through was to drop the role from `eligibleIf` and notify every member of the tenant, which is
the opposite of what the role was for.

The two audiences are asked different questions. For a member: "is this person one of those who
should hear about it?" — a question about roles. For a recipient: "may this tenant's mailboxes hear
about it at all?" — a question about the tenant. Sharing one expression forces the answer to the
second question onto the first.

## Decision

- The boolean is replaced by an expression: **`recipientsIf`**, in the same DSL as `eligibleIf`.
  - Absent: the type is closed to every recipient. As before, nothing leaves the member circle
    until the catalogue says so.
  - Present: the type is open to the recipients of every tenant whose subjects satisfy it — the
    tenant's `feature:*` and the `is:system-tenant*` markers. `""` holds everywhere, as an empty
    expression does in the DSL.
- **`eligibleIf` applies to members only.** It no longer plays any part for a recipient, so it is
  free to name roles on a type that is open to recipients.
- The role check moves with the question: `validate_catalogue` refuses a `role:*` term in
  `recipientsIf`, negated or not, for the reason ADR 0021 gave (`!role:readonly` would admit every
  mailbox). It no longer looks at `eligibleIf` for this.
- **The old boolean is still read.** A type stored as `"recipients": true` is read as
  `recipientsIf` = its `eligibleIf` (or `""` without one). Under ADR 0021 that `eligibleIf` could
  not name a role, so it was exactly the recipient gate, and the type keeps reaching the same
  mailboxes after an upgrade. `"recipients": false` is read as absent. Setting both `recipients`
  and `recipientsIf` on one type is refused as ambiguous. The catalogue is written back in the new
  shape only.

## Alternatives considered

- **Rename to `eligibleUserIf` and `eligibleRecipientIf`.** Symmetric, but every catalogue in the
  field would have to change for a field whose meaning for members does not change at all. Keeping
  `eligibleIf` and adding one field breaks nothing.
- **Keep the boolean and add `recipientsIf` beside it.** Two fields for one decision, and a state
  (`recipients: false` with a `recipientsIf`) that means nothing. The presence of the expression is
  the decision.
- **Keep the boolean and treat `role:*` as unfulfilled for recipients.** Already rejected in ADR
  0021, and still wrong: a negated role predicate would admit every mailbox, and a role gate added
  later would silently empty the recipient audience.
- **Drop the old boolean without reading it.** Cleaner code, but a stored catalogue with
  `recipients: true` would deserialize with the field ignored and close the type to every
  recipient, with no error anywhere — the silent failure ADR 0015's config gate exists to prevent.

## Consequences

- A type can reach members by role and the tenant's mailboxes by feature at once. The feature gate
  usually appears in both expressions; that is the point, since each audience is narrowed on its
  own terms.
- The recipient endpoints (`GET /tenants/{id}/recipients`, `/recipients/manage`, choice checks on
  `POST`/`PATCH`) and the recipient half of `POST /notifications/audience` evaluate `recipientsIf`
  instead of the flag plus `eligibleIf`. Nothing else in the recipient model changes.
- The TypeScript client's `NotificationTypeDef` has `recipientsIf?: string` instead of
  `recipients?: boolean`.
- The compatibility read stays until no stored catalogue carries the boolean; any `PUT /config`
  rewrites it away.
