# umami-client

Typed TypeScript client SDK for the [umami](../../README.md) micro-IAM service. It holds the access
token **in memory only** and silently refreshes it via the `HttpOnly` cookie on a 401 — the refresh
token's value is never touched by JS.

```bash
npm install umami-client
```

```ts
import { UmamiClient } from "umami-client";

const umami = new UmamiClient({
  baseUrl: "https://umami.example.com",
  onTokenChange: (token) => {
    /* update app state */
  },
});

// Password login (handles the MFA challenge shape)
const res = await umami.login("owner@acme.test", "secret");
if (res.mfaRequired) {
  await umami.login("owner@acme.test", "secret", "123456"); // with the TOTP code
}

const me = await umami.getMe();
umami.hasPermission("write:members"); // decodes the token's claims

// Passwordless passkey login (browser)
await umami.loginWithPasskey("owner@acme.test");

// Silent refresh on page reload
await umami.refresh();
```

## What it covers

- **Auth**: `login`, `refresh`, `logout`, `logoutAll`, `getMe`, `getClaims`, `hasPermission`
- **MFA**: `totpSetup` / `totpVerify` / `totpDisable`; `registerPasskey` / `loginWithPasskey`
  (wrapping `navigator.credentials`)
- **API keys**: `exchangeApiKey` (M2M/BFF), plus `createApiKey` / `listApiKeys` / `deleteApiKey`
- **Tenants**: signup, get/patch, status/license, packages, features, entitlements, usage
- **Users**: `createUser` / `listUsers` / `patchUser`
- **Config**: `getConfig` / `putConfig`

All request/response types mirror the Rust server contract (see [`src/types.ts`](src/types.ts));
errors throw `UmamiError` with the HTTP `status` and parsed `body`.

## Build

```bash
npm install
npm run build      # tsc → dist/
npm run typecheck
```

> API keys are **server-side credentials** — never ship an `umk_…` key in browser JS. In a browser
> use `login`/`loginWithPasskey` (user auth); use `exchangeApiKey` only from a backend/BFF. See
> [docs/API-KEYS.md](../../docs/API-KEYS.md).
