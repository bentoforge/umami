/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      // Sourced from CSS variables (space-separated RGB channels) so the accent is swappable at
      // runtime via /app/branding.css (config `branding.customCss`), keeping Tailwind's opacity
      // modifiers (e.g. bg-brand/10) working.
      colors: {
        brand: {
          DEFAULT: "rgb(var(--brand) / <alpha-value>)",
          dark: "rgb(var(--brand-dark) / <alpha-value>)",
        },
      },
    },
  },
  plugins: [],
};
