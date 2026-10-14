# ADR 0011 — Contacts as a verified list, not an email field on the user

- **Status:** accepted
- **Date:** 2026-08-31

## Context

A user record carried a single `email` field. umami needs addresses it can actually reach a user
at — for address confirmation and password recovery — and a reset link sent to an address is
account takeover for whoever reads it.

Two cases decide the shape:

- **A change of address.** With a single field the new address overwrites a verified one while still
  unverified, so the user is unreachable exactly when the confirmation mail has to arrive.
- **Work and private.** A user may want more than one address — the second, cheaper reason.

Chat identities (Telegram/WhatsApp) shared a table with addresses for a while. They answer a
different question ("which user sent this message") and end in a minted token rather than a
delivered mail, and sharing the table made every function branch on which half of the data it was
looking at.

## Decision

A user's addresses are a **list of contacts**: one email address each, plus `verified`.

- `verified` records one fact: the owner proved possession by answering a challenge sent to the
  address. An address an admin typed in is never verified — nobody can supply that proof on the
  owner's behalf.
- **Only a verified address is ever sent to.** An unverified row is an intention, not a contact.
- Storage is one table, `user-contacts`, keyed `(userId, address)`, with addresses normalized before
  they touch the key.
- **The user record has no email field.** It is removed, not hidden:
  - the `email` claim is no longer minted by default; a deployment that wants one maps
    `$user.email` (the preferred, confirmed address) through an API's `claims` block;
  - `username` is required on `POST /users` and the tenant-owner form — a contact is not an
    identity, so there is no fallback to the email as username;
  - `PATCH /users/{id}` does not accept `email`; there is exactly one place an address is managed;
  - admin user search does not cover addresses; lookup by address is a direct query on
    `ByAddressIndex`.
- Chat identities stay a separate concept and storage, documented in CONFIG.md §7.

## Alternatives considered

- **One email field on the user.** Rejected: a change of address leaves the user unreachable while
  the new address is unverified.
- **Contacts and chat identities in one table.** Tried and undone: every function had to branch on
  which kind of row it was looking at.

## Consequences

- A change of address is gap-free: add the new address, verify it, then drop the old one.
- umami puts no personal data in every token by default.
- Callers that relied on `email` on the user record, on `PATCH /users/{id}` with `email`, or on the
  username falling back to the email have to move to the contacts endpoints and an explicit
  username.
- Searching users by address through the admin search is gone; `ByAddressIndex` serves lookup by
  address instead, which is cheaper than pulling addresses into the tenant scan.
- Anything that sends mail has to resolve a verified address first; a user without one is
  unreachable.
