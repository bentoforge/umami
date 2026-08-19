// Theme management: light / dark / auto. Tailwind is in `class` dark mode (tailwind.config.cjs),
// so we toggle a `dark` class on <html>. "auto" follows the OS `prefers-color-scheme`.

export type Theme = "light" | "dark" | "auto";

const STORAGE_KEY = "umami.theme";
const media = () => window.matchMedia("(prefers-color-scheme: dark)");

/** The persisted theme choice, defaulting to "auto". */
export function getTheme(): Theme {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === "light" || stored === "dark" || stored === "auto") {
    return stored;
  }
  return "auto";
}

/** Whether the given theme resolves to dark right now. */
function resolvesDark(theme: Theme): boolean {
  return theme === "dark" || (theme === "auto" && media().matches);
}

/** Applies a theme to the document (toggles the `dark` class). */
export function applyTheme(theme: Theme): void {
  document.documentElement.classList.toggle("dark", resolvesDark(theme));
}

/** Persists and applies a theme. */
export function setTheme(theme: Theme): void {
  localStorage.setItem(STORAGE_KEY, theme);
  applyTheme(theme);
}

/** Applies the stored theme and keeps "auto" in sync with OS changes. Call once at startup. */
export function initTheme(): void {
  applyTheme(getTheme());
  media().addEventListener("change", () => {
    if (getTheme() === "auto") {
      applyTheme("auto");
    }
  });
}
