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
      },
    },
  },
  plugins: [],
};
