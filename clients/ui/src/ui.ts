// Shared Tailwind class strings so the admin screens stay visually consistent.

// `inline-block` is load-bearing, not decoration. On a <button> the UA stylesheet already supplies
// it, but these classes are also worn by a <Link>, which renders an inline <a> — and an inline box
// ignores vertical margin, so `space-y-*` on the surrounding stack silently does nothing and the
// button ends up glued to the text above it.
export const primaryButton =
  "inline-block rounded-lg bg-primary hover:bg-primary-dark text-white text-sm font-medium px-4 py-2 disabled:opacity-50 disabled:cursor-not-allowed";

export const ghostButton =
  "rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 text-sm font-medium px-4 py-2 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50";

export const dangerButton =
  "rounded-lg border border-red-300 dark:border-red-800 text-red-700 dark:text-red-300 text-sm font-medium px-3 py-1.5 hover:bg-red-50 dark:hover:bg-red-950 disabled:opacity-50";

export const input =
  "w-full rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary";

export const iconButton =
  "inline-flex items-center justify-center rounded-lg p-2 text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700";

/**
 * The same button, inside the top bar.
 *
 * Separate rather than scoped CSS: everything in the header declares its own
 * colour, so a rule on `<header>` is never inherited and never reaches these.
 * Following `--header-text` is the only way they move with a rebranded bar.
 */
export const headerIconButton =
  "inline-flex items-center justify-center rounded-lg p-2 text-header-muted hover:text-header-text hover:bg-header-hover";

/**
 * An error, in a box that brings its own background.
 *
 * Deliberately not theme-aware and deliberately not brandable. The surface behind
 * it is the operator's to colour — the sign-in card can be any shade in either
 * mode — so bare red text has no reliable contrast to rely on. Carrying its own
 * light ground makes the box readable on anything, and an error is not a place to
 * express identity anyway.
 */
export const errorBox =
  "rounded-lg border border-red-700 bg-red-100 text-red-800 text-sm px-3 py-2";

/** A statement of fact rather than a failure — same self-supplied ground as `errorBox`, calmer. */
export const noticeBox =
  "rounded-lg border border-amber-600 bg-amber-50 text-amber-900 text-sm px-3 py-2";

export const card =
  "rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 p-6";

export const th =
  "text-left text-xs font-semibold uppercase tracking-wide text-slate-500 px-3 py-2";
export const td = "px-3 py-2 text-sm text-slate-800 dark:text-slate-200 align-middle";

/**
 * Column spans for a `grid-cols-12` form, named after the width they take on a wide screen.
 *
 * Both collapse the same way: halves at `md`, one field per row below that — a 12-column grid on a
 * phone is a handful of unreadable columns. Salutation and title hold a word each and take a
 * sixth, everything else a third.
 */
export const spanSixth = "col-span-12 md:col-span-6 lg:col-span-2";
export const spanThird = "col-span-12 md:col-span-6 lg:col-span-4";
