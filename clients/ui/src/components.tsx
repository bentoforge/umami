import type { ReactNode } from "react";
import type { CustomFieldDef } from "umami-client";
import { input } from "./ui";

/** Extracts a human-readable message from a thrown value (UmamiError, Error, or anything). */
export const errMsg = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/** Renders a custom-field value for a read-only table cell. */
export const formatFieldValue = (value: unknown): string => {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "yes" : "no";
  return String(value);
};

/** A schema-driven form for config-defined custom fields (`string` / `number` / `bool` / `select`).
 * Values are a flat `key → value` map; `onChange` receives the whole updated map. Required fields
 * are marked with `*` (server-enforced). */
export function CustomFieldsForm({
  defs,
  values,
  onChange,
}: {
  defs: CustomFieldDef[];
  values: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
}) {
  if (defs.length === 0) return null;
  const set = (key: string, value: unknown) => onChange({ ...values, [key]: value });

  return (
    <>
      {defs.map((def) => {
        const value = values[def.key];
        const label = def.required ? `${def.label} *` : def.label;
        return (
          <Field key={def.key} label={label}>
            {def.type === "select" ? (
              <select
                className={input}
                value={typeof value === "string" ? value : ""}
                onChange={(e) => set(def.key, e.target.value || undefined)}
              >
                <option value="">—</option>
                {(def.options ?? []).map((opt) => (
                  <option key={opt} value={opt}>
                    {opt}
                  </option>
                ))}
              </select>
            ) : def.type === "bool" || def.type === "boolean" ? (
              <input
                type="checkbox"
                className="h-4 w-4 accent-brand"
                checked={value === true}
                onChange={(e) => set(def.key, e.target.checked)}
              />
            ) : def.type === "number" ? (
              <input
                className={input}
                type="number"
                value={value === null || value === undefined ? "" : String(value)}
                onChange={(e) => set(def.key, e.target.value === "" ? undefined : Number(e.target.value))}
              />
            ) : (
              <input
                className={input}
                value={typeof value === "string" ? value : ""}
                onChange={(e) => set(def.key, e.target.value)}
              />
            )}
          </Field>
        );
      })}
    </>
  );
}

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
