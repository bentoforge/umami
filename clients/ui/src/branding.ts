import { useEffect, useState } from "react";

/**
 * The deployment's own name, from `branding.title`.
 *
 * Used wherever the product names itself to a person: the browser tab, and the
 * logo's alt text — which is what a screen reader announces and what stands in
 * when the image fails. A deployment that hangs its own logo up there and is
 * still announced as "umami" has been branded only to people who can see it.
 *
 * Fetched once and shared. The value arrives after first paint, so consumers
 * fall back to their translated default until it does.
 */
let pending: Promise<string | null> | null = null;

export function brandingTitle(): Promise<string | null> {
  pending ??= fetch(`${import.meta.env.BASE_URL}branding.json`)
    .then((response) => (response.ok ? response.json() : null))
    .then((branding: { title?: string } | null) => branding?.title ?? null)
    .catch(() => null);
  return pending;
}

/** The configured name, or `undefined` until it loads (and if none is set). */
export function useBrandingTitle(): string | undefined {
  const [title, setTitle] = useState<string>();
  useEffect(() => {
    let cancelled = false;
    void brandingTitle().then((value) => {
      if (!cancelled && value) {
        setTitle(value);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);
  return title;
}
