# ADR 0003 — Three API-key auth modes and an honest browser threat model

- **Status:** accepted
- **Date:** 2026-08-02

## Context

An API key is a credential a client exchanges at `POST /auth/token` for a short-lived access token
(JWT) — OAuth2 `client_credentials` in spirit. The first design treated keys as strictly
server-side: never put a key in a browser, use user login or a backend-for-frontend instead.

Real integrations do not all have a backend. The motivating case is an app embedded in a shop
`iframe` that has to call product services with nothing but frontend JS. For such a client the
key necessarily sits in the browser.

A secret that reaches a **browser** is not secret — anyone who opens the page can read it. So the
question is never "how do I hide a frontend key" (impossible) but "how much do I cap the damage".

## Decision

umami offers **three auth modes**; a customer picks one per integration based on what they can run
and how much protection they need. The modes trade off *where the secret lives* against *client
complexity*:

1. **API key + Origin allowlist** — the key sits in frontend JS and is accepted as a
   **semi-public, rate-limited** credential (the Google Maps / Firebase web-key profile). The key
   carries `allowedOrigins`; the browser-unspoofable `Origin` header stops "someone embeds my key in
   *their* site". It is explicitly **not a boundary**: an extracted key replays from a script with a
   forged `Origin`.
2. **Signed request (HMAC proof-of-possession)** — the secret is used to sign, never sent. Protects
   the transport; in a browser the secret is still readable from the JS.
3. **Backend-for-Frontend (BFF)** — the key lives only on a backend, which does the exchange and
   hands the frontend a short-lived scoped JWT, never the key. This is the **recommended default
   whenever a backend exists**.

Rule of thumb: backend available → Mode 3. No backend but a real (non-browser) client that can
HMAC → Mode 2. Plain static frontend with low-value cost → Mode 1, with a strict rate limit.

**The real cost cap is rate-limiting** the exchange and the downstream API: even a leaked key can
only burn what the rate limits allow. Modes 1 and 2 depend on this; Mode 3 benefits from it too.

## Alternatives considered

- **Keys are server-side only** (the original golden rule). Replaced: it leaves backend-less
  frontends without an option, and the honest answer for them is damage capping, not a ban.
- **Client-side hashing to hide a browser key.** Rejected: it still requires the key to be in the
  JS; it hides the key from network logs, not from whoever loaded the page.
- **`Referer` instead of `Origin`** for the allowlist. Rejected: `Referer` is suppressible by
  `Referrer-Policy` / privacy tools and leaks the path.

## Consequences

- Mode 1 keys are knowingly extractable. They must be low-value and rate-limited; the Origin check
  only stops casual reuse.
- The Origin check sees the *app's* origin, not the embedding shop's. Restricting which site may
  embed the app is a separate mechanism (CSP `frame-ancestors` on the app), not part of the key.
- Rate limiting of the exchange is load-bearing for security, not just operations.
- All modes share one key format, one table and one exchange endpoint; they differ only in how
  possession of the key is proven and where the secret lives.
