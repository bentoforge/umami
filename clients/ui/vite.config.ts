import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Dev: proxy the umami API paths to the local server so the SPA is same-origin (the HttpOnly
// refresh cookie then works). In production, host the UI on the same origin as umami (or set
// VITE_UMAMI_URL + configure CORS with credentials).
const apiPaths = ["/auth", "/users", "/tenants", "/config", "/info", "/user-info", "/.well-known"];
// Branding assets are served by umami itself under /app (see src/web_ui.rs). They live under Vite's
// `base` ("/app/"), so proxy exactly these to the backend — everything else under /app/ (the SPA
// shell + /app/assets/* bundles) stays served by Vite — to test the real favicon/logo/branding CSS.
const brandingPaths = ["/app/favicon", "/app/branding", "/app/logo"];
const target = process.env.VITE_UMAMI_URL ?? "http://localhost:8093";

export default defineConfig({
  // Served by umami itself under /app (see src/web_ui.rs). The router basename derives from this.
  base: "/app/",
  plugins: [react()],
  server: {
    proxy: Object.fromEntries(
      [...apiPaths, ...brandingPaths].map((path) => [path, { target, changeOrigin: false }]),
    ),
  },
});
