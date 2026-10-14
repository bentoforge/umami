# ADR 0015 — The app owns the notification clock; cadences are opaque strings

- **Status:** accepted
- **Date:** 2026-08-31

## Context

Some notifications have a rhythm: a user wants "new content" daily, weekly or monthly. An app that
sends such notifications already runs its own jobs — it asks "is there new content" on its own
calendar. Something has to decide which users hear about a given run.

## Decision

umami does **not** schedule, accumulate or group anything. When an app's job fires, it tells umami
which cadences that firing represents, and umami answers with the users whose stored choice matches
— one string comparison per user.

- **A firing is a set of cadences.** The Friday run *is* the daily and the weekly run; on the first
  Friday of the month it is the monthly one too. A user still appears at most once, because a
  user's choice is a single value.
- **A cadence is a string, not an enum.** umami never interprets one — no arithmetic, no ordering,
  no scheduling — so it does not dictate the vocabulary. `on-publish` or `quarterly` are as valid
  as `weekly`.
- **There is no "immediate" or "push" concept.** A type with no rhythm of its own declares a single
  cadence under whatever name suits; umami cannot tell it apart from a weekly type and does not
  need to.
- **Each cadence brings its own label**, a `LocalizedText` like a role's or a feature's label,
  because a vocabulary the deployment invents has to bring its own words.
- **Typo protection lives in the declared list** instead of an enum: a firing naming an undeclared
  cadence is a `400`, a user choice naming one is refused at `PUT`, and `validate_catalogue` on
  `PUT /config` checks the declaration itself (no duplicate codes, no type without cadences, no
  non-lowercase cadence, no `default` naming a cadence the type is never fired at).

## Alternatives considered

- **umami schedules and digests.** A store of pending items plus a scheduler plus digest templates
  plus a per-user timezone. Rejected: a large amount of machinery for something the app's own
  calendar already expresses.
- **A closed cadence enum.** Rejected: umami never interprets a cadence, so a fixed vocabulary would
  only dictate words umami has no business dictating.

## Consequences

- **Digests are the app's job.** Nothing accumulates in umami, so "everything since last week in one
  mail" is built by the app, which holds the content anyway.
- **The declaration is the source of truth** and has nothing to be compared against at runtime,
  which is why the config gate matters most. A `default` naming an unfired cadence would silently
  park every untouched user in a group that receives nothing.
- **Schedule drift is only visible in the audit.** An app whose jobs no longer match its catalogue
  shows up as "monthly: 0 recipients" in the audited audience calls, month after month.
