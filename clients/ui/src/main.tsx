import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import "./index.css";
import "./i18n/i18n";
import { App } from "./App";
import { UmamiProvider } from "./auth/UmamiProvider";

// Same-origin by default (dev uses the vite proxy; prod hosts the UI on umami's origin). Override
// with VITE_UMAMI_URL when the API lives elsewhere (then CORS with credentials must be configured).
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
