import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: proxy the umami API paths to the local server so the SPA is same-origin (the HttpOnly
// refresh cookie then works). In production, host the UI on the same origin as umami (or set
// VITE_UMAMI_URL + configure CORS with credentials).
const apiPaths = ["/auth", "/users", "/tenants", "/config", "/info", "/user-info", "/.well-known"];
const target = process.env.VITE_UMAMI_URL ?? "http://localhost:8093";

export default defineConfig({
  // Served by umami itself under /app (see src/web_ui.rs). The router basename derives from this.
  base: "/app/",
  plugins: [react()],
  server: {
    proxy: Object.fromEntries(apiPaths.map((path) => [path, { target, changeOrigin: false }])),
  },
});
