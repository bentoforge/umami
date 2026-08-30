import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import "./index.css";
import "./i18n/i18n";
import { App } from "./App";
import { UmamiProvider } from "./auth/UmamiProvider";
import { brandingTitle } from "./branding";
import { initTheme } from "./theme";

// Apply the stored theme (light/dark/auto) before the app renders, and keep "auto" in sync with OS.
initTheme();

// Same-origin by default: dev goes through the vite proxy, prod hosts the UI on umami's origin.
//
// `VITE_UMAMI_URL` is for the case where the API genuinely lives elsewhere, and it costs CORS with
// credentials. To aim the dev proxy at another port, set `VITE_UMAMI_PROXY` instead and stay
// same-origin.
const baseUrl = import.meta.env.VITE_UMAMI_URL ?? "";

// Router basename = the Vite `base` without its trailing slash, so client routes live under the
// same path the app is served from (/ui/umami).
const basename = import.meta.env.BASE_URL.replace(/\/$/, "");

// Branding assets are served by umami under the app base (favicon, operator custom CSS). Wire them
// at runtime with an absolute `BASE_URL` path: a `<link>` in index.html would be base-rewritten by
// Vite's dev server into a doubled `/app/app/…`, and a relative href would break on a deep-route
// reload. `import.meta.env.BASE_URL` (e.g. `/app/`) is correct in dev and build.
for (const [rel, file, type] of [
  ["icon", "favicon", "image/svg+xml"],
  ["stylesheet", "branding.css", ""],
] as const) {
  const link = document.createElement("link");
  link.rel = rel;
  if (type) {
    link.type = type;
  }
  link.href = `${import.meta.env.BASE_URL}${file}`;
  document.head.appendChild(link);
}

// Document title from umami's public branding (`branding.title`). Shares the one
// fetch with everything else that needs the deployment's name.
void brandingTitle().then((title) => {
  if (title) {
    document.title = title;
  }
});

const root = document.getElementById("root");
if (!root) throw new Error("missing #root");

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <BrowserRouter basename={basename}>
      <UmamiProvider baseUrl={baseUrl}>
        <App />
      </UmamiProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
