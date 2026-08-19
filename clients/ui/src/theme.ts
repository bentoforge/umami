// Theme management: light / dark / auto. Tailwind is in `class` dark mode (tailwind.config.cjs),
// so we toggle a `dark` class on <html>. "auto" follows the OS `prefers-color-scheme`.

export type Theme = "light" | "dark" | "auto";

const STORAGE_KEY = "umami.theme";
const media = () => window.matchMedia("(prefers-color-scheme: dark)");

// Subscribers notified whenever the effective theme changes (explicit switch or OS change while
// "auto") — lets components like the logo react to the resolved light/dark state.
const listeners = new Set<() => void>();
function notify(): void {
  for (const listener of listeners) {
    listener();
  }
}

/** Subscribe to theme changes; returns an unsubscribe function. */
export function subscribeTheme(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Whether the current effective theme is dark right now. */
export function resolvedDark(): boolean {
  const theme = getTheme();
  return theme === "dark" || (theme === "auto" && media().matches);
}

/** The persisted theme choice, defaulting to "auto". */
export function getTheme(): Theme {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === "light" || stored === "dark" || stored === "auto") {
    return stored;
  }
  return "auto";
}

/** Applies a theme to the document (toggles the `dark` class). */
export function applyTheme(theme: Theme): void {
  document.documentElement.classList.toggle(
    "dark",
    theme === "dark" || (theme === "auto" && media().matches),
  );
}

/** Persists and applies a theme, then notifies subscribers. */
export function setTheme(theme: Theme): void {
  localStorage.setItem(STORAGE_KEY, theme);
  applyTheme(theme);
  notify();
}

/** Applies the stored theme and keeps "auto" in sync with OS changes. Call once at startup. */
export function initTheme(): void {
  applyTheme(getTheme());
  media().addEventListener("change", () => {
    // An OS change only affects "auto", but re-applying + notifying unconditionally is harmless.
    applyTheme(getTheme());
    notify();
  });
}
