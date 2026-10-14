# ADR 0013 — Password recovery by mailed link

- **Status:** accepted
- **Date:** 2026-08-31

## Context

A user who cannot sign in needs a way back into the account. With verified contacts and an
outbound mail seam, umami can mail a reset link. But a reset link is account takeover in one click
for whoever reads it, and an entry point that answers differently per identifier is an oracle for
"does this account exist here" — exactly what the sign-in screen spends effort not revealing.

## Decision

`POST /auth/forgot-password` (identifier = username **or** address) mails a link;
`POST /auth/reset-password` consumes it. Both are unauthenticated: the premise is that the user
cannot sign in.

- **The entry point always answers 202** — unknown identifier, known one, unconfirmed address,
  ambiguous address, no mail path alike. The operator sees what happened in the audit log; the
  caller never does. The one distinguishable answer is `429`, which is about the caller's own volume.
- **Only a confirmed address receives a reset link.** An address nobody proved possession of is not
  a place to send account takeover.
- **An ambiguous address is refused, not guessed.** If two accounts share an address, umami does not
  pick one; the user has to give a username.
- **The challenge stores its purpose, checked on consume.** Confirmation and reset links share one
  table; without the check a confirmation link would be redeemable as a reset.
- **A successful reset bumps `tokenVersion`**, ending every existing session at its next refresh.
  A recovery is often a recovery *from* something. It stamps `lastPasswordChange`, not
  `lastPasswordReset`: the user chose this password.
- **Short-lived links:** `passwordResetTtlSecs` defaults to 1h (someone who just asked is looking at
  their inbox), unlike the 24h of `contactChallengeTtlSecs`.
- `GET /auth/capabilities` (public) tells the sign-in screen whether to offer recovery at all —
  true exactly when a mail queue is configured.

## Alternatives considered

- **Distinct answers per case** (unknown user, unconfirmed address, …). Rejected: it makes the
  endpoint an account-existence oracle.
- **Guessing among accounts that share an address.** Rejected: mailing "reset your password" for an
  account the reader may not own is worse than asking for a username.

## Consequences

- Address confirmation is a precondition for recovery; a user with no confirmed address cannot
  recover by mail.
- A user gets no feedback on why a reset mail did not arrive; diagnosing it is the operator's job,
  via the audit log.
- A reset signs the user out everywhere.
- Deployments without a mail transport have no self-service recovery, and the sign-in screen hides
  the link.
