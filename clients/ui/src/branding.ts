import { useEffect, useState } from "react";

/**
 * The deployment's public branding, from `/app/branding.json`.
 *
 * Read once, before first paint, and shared: the document title, the foot-of-page
 * legal line, and the build this server is. All of it is public — the file is
 * fetched before anyone signs in — so nothing secret belongs here.
 *
 * The value arrives after first paint, so consumers fall back to their own
 * defaults (a translated product name, no footer) until it does.
 */

/** A label in one language, or many — the wire shape of the server's `LocalizedText`. */
export type Localized = string | Record<string, string>;

interface BrandingDoc {
  /** The deployment's own name; used for the tab title and the logo's alt text. */
  title?: string;
  /** Raw HTML for the foot of every page, authored by the operator, per locale. */
  footer?: Localized;
  /** The build this server is — the git tag it was built from. Absent in dev. */
  version?: string;
}

let pending: Promise<BrandingDoc> | null = null;

/** The whole branding document, fetched once and shared. Empty object on any error. */
function brandingDoc(): Promise<BrandingDoc> {
  pending ??= fetch(`${import.meta.env.BASE_URL}branding.json`)
    .then((response) => (response.ok ? (response.json() as Promise<BrandingDoc>) : {}))
    .catch(() => ({}));
  return pending;
}

export function brandingTitle(): Promise<string | null> {
  return brandingDoc().then((doc) => doc.title ?? null);
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

/**
 * Resolve a localized value for `locale`, mirroring the server's `LocalizedText`:
 * the exact tag, then its primary subtag (`de-AT` → `de`), then `*` — the
 * operator's explicit "anything else" — then whatever non-blank entry is left, so
 * a configured footer never renders as nothing.
 */
export function resolveLocalized(value: Localized | undefined, locale: string): string {
  if (!value) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  const tag = locale.toLowerCase();
  const primary = tag.split(/[-_]/)[0];
  const pick =
    value[tag] ??
    value[primary] ??
    value["*"] ??
    Object.values(value).find((text) => text.trim() !== "");
  return pick ?? "";
}

/** The footer HTML and the build version, or `undefined` until branding loads. */
export function useBranding(): { footer?: Localized; version?: string } {
  const [doc, setDoc] = useState<BrandingDoc>({});
  useEffect(() => {
    let cancelled = false;
    void brandingDoc().then((value) => {
      if (!cancelled) {
        setDoc(value);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);
  return { footer: doc.footer, version: doc.version };
}
