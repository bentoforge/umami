/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  // Dark mode is toggled by a `dark` class on <html> (see src/theme.ts): light / dark / auto.
  darkMode: "class",
  theme: {
    extend: {
      // Sourced from CSS variables (space-separated RGB channels) so the accent is swappable at
      // runtime via /app/branding.css (config `branding.customCss`), keeping Tailwind's opacity
      // modifiers (e.g. bg-brand/10) working.
      colors: {
        // Primary = the functional action color (buttons, focus, selection) — a serious blue.
        primary: {
          DEFAULT: "rgb(var(--primary) / <alpha-value>)",
          dark: "rgb(var(--primary-dark) / <alpha-value>)",
        },
        // Brand = the identity accent, used sparingly (nav highlights, small badges).
        brand: {
          DEFAULT: "rgb(var(--brand) / <alpha-value>)",
          dark: "rgb(var(--brand-dark) / <alpha-value>)",
        },
        // Header chrome, so the top bar can be rebranded on its own. Inactive nav
        // items are `header-fg` at reduced opacity rather than a fifth token —
        // which is exactly what the space-separated RGB form is for.
        header: {
          bg: "rgb(var(--header-bg) / <alpha-value>)",
          fg: "rgb(var(--header-fg) / <alpha-value>)",
          accent: "rgb(var(--header-accent) / <alpha-value>)",
          border: "rgb(var(--header-border) / <alpha-value>)",
        },
      },
    },
  },
  plugins: [],
};
