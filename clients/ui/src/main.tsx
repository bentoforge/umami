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
