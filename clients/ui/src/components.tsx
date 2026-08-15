import type { ReactNode } from "react";

/** Extracts a human-readable message from a thrown value (UmamiError, Error, or anything). */
export const errMsg = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/** A labelled form field wrapper. */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs text-slate-500">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}

/** A multi-select of code chips (checkboxes). `options` is the assignable set; any already-`selected`
 * code not in `options` is still shown (and checked) so a legacy selection is never silently dropped. */
export function CheckboxTags({
  options,
  selected,
  onChange,
  empty = "none available",
}: {
  options: string[];
  selected: string[];
  onChange: (next: string[]) => void;
  empty?: string;
}) {
  const all = Array.from(new Set([...options, ...selected]));
  if (all.length === 0) {
    return <span className="text-xs text-slate-400">{empty}</span>;
  }
  const toggle = (code: string, on: boolean) =>
    onChange(on ? [...selected, code] : selected.filter((c) => c !== code));
  return (
    <div className="flex flex-wrap gap-1.5">
      {all.map((code) => {
        const on = selected.includes(code);
        return (
          <label
            key={code}
            className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs cursor-pointer select-none ${
              on
                ? "border-brand bg-brand/10 text-brand"
                : "border-slate-300 dark:border-slate-600 text-slate-500"
            }`}
          >
            <input
              type="checkbox"
              className="sr-only"
              checked={on}
              onChange={(e) => toggle(code, e.target.checked)}
            />
            {code}
          </label>
        );
      })}
    </div>
  );
}

/** An inline status banner (error or success). Renders nothing for empty content. */
export function Banner({ tone, children }: { tone: "error" | "ok"; children: ReactNode }) {
  if (!children) return null;
  const cls =
    tone === "error"
      ? "bg-red-50 dark:bg-red-950 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800"
      : "bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800";
  return <div className={`rounded-lg border px-4 py-2 text-sm ${cls}`}>{children}</div>;
}
