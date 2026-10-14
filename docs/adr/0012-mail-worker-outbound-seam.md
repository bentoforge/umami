# ADR 0012 — umami renders mail, a worker delivers it

- **Status:** accepted
- **Date:** 2026-08-31

## Context

With contacts, umami has to send mail of its own: address confirmations and password-reset links.
Delivering mail means providers, credentials, retries and bounces — machinery that is not an
identity service's job. At the same time the content of these two mails, a single-use secret,
is something only umami can produce.

## Decision

umami **renders** the mail and **hands it over** as one SQS message; a mail worker does the rest.

- umami renders subject and plain-text body in the recipient's language (from `locales/app.yml`),
  with the deployment's footer appended.
- Delivery, retries, bounces and provider credentials belong to the worker. A dead-letter queue on
  the SQS side is the retry story.
- `messageId` is the idempotency key, because SQS delivers at least once. `userId`/`tenantId` are for
  the worker's own audit trail, never for addressing.
- The message also carries structured data (`template`, `recipient`, `context`, `footer`,
  `globalContext`) so a worker rendering its own layout never has to ask umami anything. All of it
  is a convenience: a worker that just delivers `subject`/`body` is correct and complete.
- **The way back is a bounce report.** umami never learns what happened to a message, so the worker
  reports a hard failure via `POST /notifications/undeliverable`, under its own permission
  (`notifications:report`) and scope (`scope:mail-worker`). The address's confirmation is withdrawn
  — the row stays, the flag clears. `complained` is treated the same way. Soft failures (full
  mailbox, greylisting) are the worker's to retry and are not reported.
- With no mail transport configured, outbound mail is off: the verification action is reported as
  unavailable and refused with `503` rather than accepted and dropped.

## Alternatives considered

- **Keep a dead address confirmed.** Without the bounce report every later message, reset links
  included, goes on being sent into nothing.
- **Report soft failures too.** Rejected: a full mailbox says nothing about whether the address is
  still the user's.
- **Let the bounce report share `notifications:send`.** Rejected: the worker and an app asking for a
  send are different principals, and the worker has no business resolving an audience.

## Consequences

- umami holds no provider credentials and runs no delivery retries; a deployment needs a worker
  behind the queue (or a different transport, see SEAMS.md — direct SES gives up learning about
  bounces).
- Workers must deduplicate on `messageId`.
- `context` holds a single-use link for umami's own mails and must never be logged.
- A withdrawn confirmation is visible to the user, who can confirm the address again if the mailbox
  comes back.
