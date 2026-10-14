# ADR 0010 — HMAC signed key exchange keyed by the stored secret hash

- **Status:** accepted
- **Date:** 2026-08-22

## Context

Mode 2 of the API-key auth modes (see [ADR 0003](0003-api-key-auth-modes.md)) is a signed
request: the client proves possession of its key without sending the secret, so a proxy or log
capturing the exchange learns nothing reusable beyond the request itself.

umami stores only `sha256(secret)` per key, never the raw secret. A classic HMAC over the raw
secret would force the server to keep that secret at rest.

The first plan for Mode 2 signed `<keyId>.<timestamp>.<nonce>` with the raw secret, required
`|now − timestamp| ≤ ~120 s`, and rejected reused nonces via a short-TTL `nonces` table.

## Decision

The exchange accepts, besides the raw key, a signed form `keyId` + `mac`:

```
mac = base64url( HMAC-SHA256( key = SHA-256(secret), "umami:apikey:<keyId>:<hourBucket>" ) )
hourBucket = floor(unixSeconds / 3600)
```

- **The HMAC key is `SHA-256(secret)` — exactly the digest umami already stores.** The client
  derives it from its secret, the server verifies with the stored hash: no raw secret on the wire
  *and* none kept at rest.
- umami accepts the current hour **±1** (clock skew and bucket boundaries) and compares in
  constant time. The message binds the `keyId`, so a MAC for one key cannot be replayed against
  another.
- **No per-request nonce.** A captured MAC is replayable within its ~±1 h window; TLS plus the
  narrow window bound the exposure.
- HMAC-SHA256 is the algorithm.
- Service keys carry `allowSecretLogin` (default **false**). Unless it is enabled, a service key is
  HMAC-only and the raw-secret exchange is refused even with the correct secret. PATs are
  unaffected: they are used as raw bearer tokens, so their raw-secret exchange stays on.

## Alternatives considered

- **Timestamp + nonce with a `nonces` replay cache** (true anti-replay). First planned, then kept
  as deferred hardening, then dropped as not planned. The ~±1 h replay window is accepted and
  documented as the tradeoff instead.
- **HMAC-SHA1.** Still sound as a MAC, but SHA-256 is the modern default.

## Consequences

- No new table and no server-side state per request; verification is a recomputation against the
  stored hash.
- Replay within the window is possible. Mode 2 protects the *transport*, not a secret that lives in
  browser JS; rate-limiting remains the backstop.
- Clients need an HMAC-SHA256 implementation (the TypeScript SDK uses WebCrypto).
- Service keys default to the stronger mode; enabling the raw-secret exchange is an explicit
  per-key choice.
