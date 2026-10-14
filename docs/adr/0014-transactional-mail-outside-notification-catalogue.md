# ADR 0014 — Transactional mail stays outside the notification catalogue

- **Status:** accepted
- **Date:** 2026-08-31

## Context

umami decides **who** hears about something and **where** they can be reached; the app decides
**when** and **what**. The messages a deployment sends fall into three kinds:

1. **Transactional** — one person, one reason: a password reset, an address confirmation.
2. **Informational, no rhythm** — "your build failed".
3. **Informational, with a rhythm** — "new content".

Kinds 2 and 3 are about consent: a user may or may not want them, and at some rhythm. Kind 1 is not:
a password reset has to arrive whatever the user chose about anything else.

## Decision

Only kinds 2 and 3 go through umami's notification machinery:

- They share one code path. A type is declared in the `notificationTypes` catalogue, the app
  resolves an audience by type, and the user's choice decides membership. An **empty `cadences`
  list** is the only thing that distinguishes kind 2 (choice is on or off) from kind 3 (choice is a
  cadence).
- **Transactional mail never consults the catalogue.** The sender fetches the user and sends; on
  `POST /notifications/send` the `type` is simply omitted.
- There is **no "not suppressible" flag** on a notification type. Transactional mail does not ask, so
  it cannot be switched off; everything that does ask can be.

## Alternatives considered

- **A "not suppressible" flag on a type.** Rejected: it would only invite somebody to route a
  password reset through the consent machinery, where it does not belong.

## Consequences

- Every catalogued type is suppressible: `off` is offered for every type, with or without a rhythm.
- Mixing up the two informational kinds is a caller error, not an empty audience: naming a cadence
  when firing a type without `cadences`, or omitting them for a type that declares some, is a `400`.
- A sender of transactional mail is responsible for it on its own; the catalogue, user choices and
  audience resolution play no part in it.
