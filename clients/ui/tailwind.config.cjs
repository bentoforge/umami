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
        // Header chrome, so the top bar can be rebranded on its own.
        //
        // `muted` and `hover` are their own colours rather than `fg` at reduced
        // opacity: 70% of a dark grey on white reads as restrained, 70% of white on
        // a dark bar reads as washed out, and the same goes for a 10% hover wash.
        // Opacity does not carry across backgrounds, so whoever recolours the bar
        // needs to set these too.
        header: {
          bg: "rgb(var(--header-bg) / <alpha-value>)",
          text: "rgb(var(--header-text) / <alpha-value>)",
          muted: "rgb(var(--header-text-muted) / <alpha-value>)",
          hover: "rgb(var(--header-hover) / <alpha-value>)",
          accent: "rgb(var(--header-accent) / <alpha-value>)",
          border: "rgb(var(--header-border) / <alpha-value>)",
        },
        // Sign-in screen. Button hovers are element-level opacity rather than more
        // tokens: unlike a colour wash, that behaves the same whatever is behind.
        login: {
          bg: "rgb(var(--login-bg) / <alpha-value>)",
          card: "rgb(var(--login-card) / <alpha-value>)",
          text: "rgb(var(--login-text) / <alpha-value>)",
          primary: "rgb(var(--login-primary) / <alpha-value>)",
          "primary-text": "rgb(var(--login-primary-text) / <alpha-value>)",
          secondary: "rgb(var(--login-secondary) / <alpha-value>)",
          "secondary-text": "rgb(var(--login-secondary-text) / <alpha-value>)",
        },
      },
    },
  },
  plugins: [],
};
