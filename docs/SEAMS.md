# umami backends (seams)

umami talks to the outside world through traits, so the same binary can run on different
infrastructure. Four of those seams are selectable at runtime, one environment variable each:

| Seam | Variable | Values | Unset (auto) |
|---|---|---|---|
| Storage (all repositories) | `UMAMI_STORAGE` | `dynamodb` | `dynamodb` |
| Config catalog | `UMAMI_CONFIG_STORE` | `s3`, `memory` | `s3` when AWS works and a bucket is available, else `memory` |
| Signing keys | `UMAMI_KEY_STORE` | `env` | `env` |
| Outbound mail | `UMAMI_MAIL_TRANSPORT` | `sqs`, `ses`, `stdout`, `none` | `sqs` when a queue is set and AWS works, else `ses` when a sender is set and AWS works; else `stdout` in a debug build, `none` in a release build |

Today most seams have one implementation. The variables exist anyway, because they are what makes
the *strict* behaviour below possible — and because a deployment that has written down which backend
it runs on does not silently change backends when its environment does.

## How the variables are named

A seam's **selector** is named after the seam (`UMAMI_MAIL_TRANSPORT`). A **provider's own
settings** carry the provider's name (`UMAMI_MAIL_SQS_QUEUE_URL`), so it is readable which setting
belongs to which backend and two providers of the same seam cannot collide over one variable — an
SMTP transport would bring `UMAMI_MAIL_SMTP_HOST` and nothing has to be renamed for it.

The two exceptions are not umami's to name: `S3_BUCKET_SUFFIX` and `DYNAMO_TABLE_PREFIX` come from
wasabi's naming schema, and every wasabi service reads them under those names.

## Is AWS usable? (the eligibility probe)

Three of these providers are AWS-backed, and they share a precondition none of them can check by
reading environment variables: `aws_config::load()` always succeeds, because it only builds a
credential *chain*. Whether that chain can produce credentials is discovered on the first real API
call — so an expired SSO session or a missing role looks perfectly configured until umami provisions
its first table.

umami therefore probes once, at boot, with a single **`sts:GetCallerIdentity`** call. It resolves
the credential chain, signs a request and talks to AWS, so it catches expired sessions, a missing
region and an unreachable network together — and it needs **no IAM permission**, so probing cannot
lock out a least-privilege deployment the way `dynamodb:DescribeTable` would. The result is cached:
all three seams asking is one call, and the answer is logged.

```
INFO AWS is usable: account 194722421767 in eu-central-1 as arn:aws:sts::…:assumed-role/Developer/aha
WARN AWS is NOT usable: sts:GetCallerIdentity failed — credentials are missing, expired or unreachable: …
```

An unusable AWS makes every AWS-backed provider **ineligible for auto-detection** (the config store
falls back to `memory`, mail to `stdout`/`none`) and makes an **explicitly named** one fail the boot,
with the probe's reason as the cause. That is what will keep DynamoDB from winning auto-detection
over Postgres or Mongo on a host where it could never work.

The probe is lazy: a deployment that picks no AWS provider at all never pays for it.

## The three rules

**1. Explicit wins, and is strict.** Naming a backend states what the deployment needs. If its
prerequisite is missing, umami refuses to start:

```
UMAMI_CONFIG_STORE=s3    without S3_BUCKET_SUFFIX      → boot fails
UMAMI_CONFIG_STORE=s3    with AWS unusable             → boot fails
UMAMI_MAIL_TRANSPORT=sqs without UMAMI_MAIL_SQS_QUEUE_URL  → boot fails
UMAMI_MAIL_TRANSPORT=sqs with AWS unusable             → boot fails
UMAMI_MAIL_TRANSPORT=ses without UMAMI_MAIL_SES_FROM   → boot fails
```

Falling back instead would produce a service that answers every health check and quietly does the
wrong thing — resetting the config catalog on every restart, or refusing every password recovery.
Both surface days later, as data loss or as a support ticket.

**2. Unset means auto-detect.** What umami did before these variables existed, kept for local dev:
probe the environment, take what is there, log which one won. A degraded choice also emits its own
`WARN` explaining what is lost and how to fix it.

**3. An unknown value never falls back.** A typo fails the boot and the error lists the valid names:

```
UMAMI_STORAGE='postgres' names a backend umami does not implement.
Valid values: dynamodb. Leave UMAMI_STORAGE unset to auto-detect.
```

Values are trimmed and case-insensitive, and an empty value is the same as unset — a templated
`UMAMI_MAIL_TRANSPORT=` from an unset deployment variable must not fail a boot.

Note what these rules do *not* include: a `PRODUCTION=true` switch. Strictness follows from
explicitness, so there is nothing to remember to turn on, and no way for a deployment to be strict
about one seam and lax about the next.

## Asking for a degraded mode on purpose

`memory`, `stdout` and `none` are real, nameable choices, not just what you get when something is
missing. Setting one says "this deployment has no S3 / no mail queue, and that is intended": the
boot report still shows what it costs, but the `WARN` about *stumbling into* it is gone.

## Mail without a worker: `ses`

`UMAMI_MAIL_TRANSPORT=ses` with `UMAMI_MAIL_SES_FROM` set makes umami call SES itself. No queue, no
worker, no infrastructure beyond a verified sender identity — the right shape for a deployment where
a worker is more machinery than the mail is worth.

It costs three things, and all three are properties of *not having a worker* rather than of SES:

- **Nothing retries.** `sqs` hands the mail to a queue whose redrive policy owns the retry. Here a
  failed `SendEmail` is a failed request, and the user is told to try again.
- **The request waits on SES.** Bounded by the same tight client timeouts the SQS transport uses, so
  a bad day at SES surfaces as a failed verification rather than a stalled request handler — but it
  is not free the way a queue write is.
- **An asynchronous bounce is never learned.** SES accepts the message and reports the failure
  minutes later, to an event destination this setup does not have. So a dead address stays
  `verified` and umami goes on sending reset links into nothing — the exact failure
  `POST /notifications/undeliverable` exists to prevent. A *synchronous* rejection is logged with
  the recipient, which is the one hard signal this transport gets.

Every mail carries `umamiMessageId` and `umamiUserId` as SES message tags, so a deployment that
later adds `UMAMI_MAIL_SES_CONFIGURATION_SET` and an event destination can correlate a bounce back
to a user — and report it — without umami changing.

Prerequisites are SES's, not umami's: the sender must be a verified identity in the account's
region, and the account must be out of the SES sandbox to reach anyone who has not verified
themselves. umami checks only the shape of the address, because proving the identity is verified
would need `ses:GetEmailIdentity` — which a policy granting only `ses:SendEmail` legitimately
withholds.

With **both** `UMAMI_MAIL_SQS_QUEUE_URL` and `UMAMI_MAIL_SES_FROM` set, auto-detection takes the
queue and logs a `WARN` saying so. Not because it is better, but because the answer has to be fixed
and the queue is the one with a way back for a bounce. Name the transport to decide it.

## Mail in development: `stdout`

`UMAMI_MAIL_TRANSPORT=stdout` prints each mail to the log — **body and single-use link included** —
instead of sending it. That is the point in local development: confirm an address or reset a
password by copying the link out of the console, with no queue and no worker in the loop. It reports
itself as able to deliver, so `/auth/capabilities` shows `passwordRecovery: true` and the flows work.

It is also the reason the auto-detected default depends on the build profile:

- **debug build** (`cargo run`) with nothing configured → `stdout`
- **release build** (what the Dockerfile ships) with nothing configured → `none`

A verification or recovery body carries a single-use secret. Printed into a production log it is an
account takeover for anyone who can read logs, so the binary that runs in production must not drift
into that state by forgetting a variable — a forgotten queue URL there *refuses* recovery, which is
visible immediately (`/auth/capabilities` reports `passwordRecovery: false`). `stdout` stays
selectable in a release build for anyone who genuinely wants it, because naming it puts the decision
on the record.

## The boot report

Every start logs the resolved set as one block, so the answer to "what is this instance actually
running on?" is one grep away:

```
Resolved backends:
  storage        dynamodb  — default (UMAMI_STORAGE unset)
  config store   s3        — auto-detected (UMAMI_CONFIG_STORE unset)
  signing keys   env       — default (UMAMI_KEY_STORE unset)
  mail transport stdout    — auto-detected (UMAMI_MAIL_TRANSPORT unset)
                 ↳ mail is printed to the log, single-use links included — never in production
```

## Exit codes

A boot that fails exits **1**. An orchestrator restarting on non-zero, a `docker run` in a deploy
script and a CI job all read the exit code, not the log — and umami failing to start is the one
event the rest of the fleet cannot work around. A clean shutdown (SIGTERM/SIGINT) exits 0.

## Adding a backend

The storage seam resolves as **one bundle**: `storage::Repositories` holds all ten repository ports
and one backend answers for all of them. A second backend is therefore a bounded piece of work —
implement the traits, return a `Repositories`, add the name to the seam's provider list — and the
compiler enumerates what is still missing. A backend covering nine of ten ports does not compile,
rather than starting and failing on the tenth.

Nobody runs users on DynamoDB and sessions on Postgres, so the bundle deliberately offers no way to
mix. What it does offer is a single place where the mixing would have to be introduced, should a
deployment ever genuinely need it.
