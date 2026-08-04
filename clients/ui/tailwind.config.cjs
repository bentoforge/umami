/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: { brand: { DEFAULT: "#4f46e5", dark: "#4338ca" } },
    },
  },
  plugins: [],
};
