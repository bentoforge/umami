import type {
  ApiKeyView,
  AuditEntry,
  CatalogueEntry,
  Contact,
  CustomFieldView,
  MessagingLink,
} from "@bentoforge/umami-iam";
import { EllipsisVerticalIcon } from "@heroicons/react/24/outline";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { resolveLocalized, useBranding, useBrandingTitle } from "./branding";
import i18n from "./i18n/i18n";
import { resolvedDark, subscribeTheme } from "./theme";
import { ghostButton, iconButton, input } from "./ui";

/** A centered spinner with a caption below — the standard "content is loading" placeholder. */
export function Loader({ label }: { label?: string }) {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12 text-slate-500">
      <div className="h-8 w-8 rounded-full border-2 border-slate-200 dark:border-slate-700 border-t-primary dark:border-t-primary animate-spin" />
      <span className="text-sm">{label ?? t("common.loading")}</span>
    </div>
  );
}

/** Extracts a human-readable message from a thrown value (UmamiError, Error, or anything). */
export const errMsg = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/**
 * The foot of every screen — the operator's legal line, and the build this server is.
 *
 * The line itself is operator HTML from `branding.footer`, resolved to the reader's current
 * language and injected as authored: trusted config, the same footing as `branding.css`, so a
 * `<a href>` is just a link. The version is the build tag, a shade quieter — a thing to read only
 * when someone asks "which build?". Nothing to show → nothing renders, rather than an empty bar.
 *
 * `className` carries the text colour: the two hosts sit on different grounds — the sign-in card's
 * own palette, and the admin's slate page.
 */
export function Footer({ className = "" }: { className?: string }) {
  const { i18n } = useTranslation();
  const { footer, version } = useBranding();
  const html = resolveLocalized(footer, i18n.language);
  const title = useBrandingTitle() ?? "umami";
  if (!html && !version) {
    return null;
  }
  return (
    <footer className={`px-6 py-6 text-center text-xs ${className}`}>
      {html && (
        <div
          className="[&_a]:underline [&_a]:underline-offset-2 [&_a:hover]:opacity-100"
          // biome-ignore lint/security/noDangerouslySetInnerHtml: operator-authored branding config, trusted like branding.css — see branding.ts
          dangerouslySetInnerHTML={{ __html: html }}
        />
      )}
      {version && <div className="mt-1 font-mono opacity-60">{`${title} ${version}`}</div>}
    </footer>
  );
}

/** Date+time in the active language: German uses the DIN 5008 shape `TT.MM.JJJJ HH:MM:SS`; other
 * languages get an unambiguous ISO-like `YYYY-MM-DD HH:MM:SS`. Both render in local time. */
export function formatDateTime(value: string | number | Date): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    return "—";
  }
  const p = (n: number) => String(n).padStart(2, "0");
  const time = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  if (i18n.language.startsWith("de")) {
    return `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()} ${time}`;
  }
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${time}`;
}

/** Renders audit entries as a severity-dotted list (message + timestamp). */
export function AuditList({ entries }: { entries: AuditEntry[] }) {
  const dot: Record<string, string> = {
    good: "bg-emerald-500",
    neutral: "bg-slate-400",
    bad: "bg-red-500",
  };
  return (
    <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
      {entries.map((entry) => (
        <li key={entry.id} className="flex items-start gap-3 py-2">
          <span
            className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${dot[entry.severity] ?? dot.neutral}`}
          />
          <div className="min-w-0">
            <div className="text-sm text-slate-800 dark:text-slate-200">{entry.message}</div>
            <div className="text-xs text-slate-400">
              {formatDateTime(entry.timestamp)}
              {entry.ip && <span className="font-mono"> · {entry.ip}</span>}
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}

/** An on/off switch (the "Schieberle"). Controlled: `checked` + `onChange(next)`. */
export function Toggle({
  checked,
  onChange,
  disabled = false,
  label,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-1 dark:focus:ring-offset-slate-800 disabled:opacity-50 disabled:cursor-not-allowed ${
        checked ? "bg-primary" : "bg-slate-300 dark:bg-slate-600"
      }`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
          checked ? "translate-x-4" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}

/** Reactive "is the effective theme dark?" — re-renders on a theme switch or an OS change. */
export function useResolvedDark(): boolean {
  const [dark, setDark] = useState(resolvedDark());
  useEffect(() => subscribeTheme(() => setDark(resolvedDark())), []);
  return dark;
}

/** Branding logo that follows the *effective* theme (config `branding.logoLight`/`logoDark`, else
 * built-in) — the resolved theme, not the OS media query, so a manual override wins. */
/**
 * The deployment's logo.
 *
 * The alt text defaults to the configured `branding.title`, because that is what
 * the image depicts. Hanging your own logo here and still being announced as
 * "umami" would brand the page only for people who can see it.
 */
export function Logo({ className, alt }: { className?: string; alt?: string }) {
  const brandName = useBrandingTitle();
  const dark = useResolvedDark();
  return (
    <img
      src={dark ? "/app/logo/dark" : "/app/logo/light"}
      alt={alt ?? brandName ?? "umami"}
      className={className}
    />
  );
}

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
  defs: CustomFieldView[];
  values: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
}) {
  if (defs.length === 0) return null;
  const set = (key: string, value: unknown) => onChange({ ...values, [key]: value });

  return (
    <>
      {defs.map((def) => {
        const value = values[def.code];
        const label = def.required ? `${def.label} *` : def.label;
        return (
          <Field key={def.code} label={label}>
            {def.type === "select" ? (
              <select
                className={input}
                value={typeof value === "string" ? value : ""}
                onChange={(e) => set(def.code, e.target.value || undefined)}
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
                className="h-4 w-4 accent-primary"
                checked={value === true}
                onChange={(e) => set(def.code, e.target.checked)}
              />
            ) : def.type === "number" ? (
              <input
                className={input}
                type="number"
                value={value === null || value === undefined ? "" : String(value)}
                onChange={(e) =>
                  set(def.code, e.target.value === "" ? undefined : Number(e.target.value))
                }
              />
            ) : (
              <input
                className={input}
                value={typeof value === "string" ? value : ""}
                onChange={(e) => set(def.code, e.target.value)}
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

/** Assign/unassign roles as a toggle list: a switch on the left, the role name in bold, its
 * description (or code) muted below. Rows `canToggle` rejects render disabled instead of vanishing,
 * so a grant the caller may not change stays visible. */
export function RoleToggleList({
  roles,
  selected,
  onToggle,
  disabled = false,
  canToggle,
  empty,
}: {
  roles: CatalogueEntry[];
  selected: string[];
  onToggle: (code: string, assigned: boolean) => void;
  disabled?: boolean;
  canToggle?: (code: string) => boolean;
  empty?: string;
}) {
  if (roles.length === 0) {
    return <span className="text-xs text-slate-400">{empty}</span>;
  }
  return (
    <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
      {roles.map((def) => {
        const assigned = selected.includes(def.code);
        const subtitle = def.description || def.code;
        return (
          <li key={def.code} className="flex items-start gap-3 py-3">
            <div className="pt-0.5">
              <Toggle
                checked={assigned}
                disabled={disabled || (canToggle ? !canToggle(def.code) : false)}
                label={def.name}
                onChange={() => onToggle(def.code, assigned)}
              />
            </div>
            <div className="min-w-0">
              <div className="text-sm font-semibold text-slate-900 dark:text-white">{def.name}</div>
              {subtitle && (
                <div className="text-xs text-slate-400 dark:text-slate-500">{subtitle}</div>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/** The role rows to offer for a grant: the catalogue entries the tenant can actually hold
 * (`assignable`) plus everything already `selected`. A role the tenant cannot get is absent rather
 * than greyed out — a disabled row reads as "you lack a right" when the truth is usually "this does
 * not apply here". Already-granted codes stay visible even when the catalogue no longer defines
 * them, `unknownLabel` as their description: hiding a grant would make it unremovable and invisible
 * at the same time. */
export function roleCatalog(
  defs: CatalogueEntry[],
  assignable: string[],
  selected: string[],
  unknownLabel: string,
): CatalogueEntry[] {
  return [
    ...defs.filter((d) => assignable.includes(d.code) || selected.includes(d.code)),
    ...selected
      .filter((code) => !defs.some((d) => d.code === code))
      .map((code) => ({ code, name: code, description: unknownLabel })),
  ];
}

/** One entry in a {@link DropdownMenu}. */
export type MenuAction = { label: string; onSelect: () => void; danger?: boolean };

/** A vertical-3-dots menu (row actions / page actions). The panel is positioned `fixed` (anchored
 * to the trigger) so it escapes any `overflow`-clipping ancestor like a scrollable table card.
 * Closes on outside-click, scroll, resize, or after a pick.
 *
 * `triggerLabel` switches the trigger to an outline secondary button showing the dots + the label
 * (the label collapses to just the dots below `md`); without it the trigger is a bare icon button. */
export function DropdownMenu({
  actions,
  label,
  triggerLabel,
}: {
  actions: MenuAction[];
  label: string;
  triggerLabel?: string;
}) {
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const WIDTH = 192; // 12rem — keep in sync with the panel's inline width.

  const toggle = () => {
    if (pos) {
      setPos(null);
      return;
    }
    const r = btnRef.current?.getBoundingClientRect();
    if (r) {
      setPos({ top: r.bottom + 4, left: Math.max(8, r.right - WIDTH) });
    }
  };

  useEffect(() => {
    if (!pos) {
      return;
    }
    const onClick = (e: MouseEvent) => {
      const target = e.target as Node;
      if (!menuRef.current?.contains(target) && !btnRef.current?.contains(target)) {
        setPos(null);
      }
    };
    const close = () => setPos(null);
    document.addEventListener("mousedown", onClick);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      document.removeEventListener("mousedown", onClick);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [pos]);

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        className={triggerLabel ? `${ghostButton} inline-flex items-center gap-1.5` : iconButton}
        aria-label={label}
        aria-haspopup="menu"
        onClick={toggle}
      >
        <EllipsisVerticalIcon className="h-5 w-5" />
        {triggerLabel && <span className="hidden md:inline">{triggerLabel}</span>}
      </button>
      {pos && (
        <div
          ref={menuRef}
          style={{ position: "fixed", top: pos.top, left: pos.left, width: WIDTH }}
          className="z-50 rounded-2xl bg-white dark:bg-slate-800 p-1.5 shadow-lg ring-1 ring-black/5 dark:ring-white/10"
        >
          {actions.map((action) => (
            <button
              key={action.label}
              type="button"
              onClick={() => {
                setPos(null);
                action.onSelect();
              }}
              className={`block w-full text-left rounded-lg px-3 py-2 text-sm ${
                action.danger
                  ? "text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950"
                  : "text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700"
              }`}
            >
              {action.label}
            </button>
          ))}
        </div>
      )}
    </>
  );
}

/** List of personal access tokens: name in bold, and a muted subline
 * "<roles or all roles> · Last used … · Created: …". When `onDelete` is given, each row gets a
 * 3-dots menu with a destructive Delete action (profile); without it the list is read-only
 * (user-edit screen). `roleLabel` maps a role code to a display name (defaults to the raw code). */
export function PatList({
  pats,
  roleLabel = (code) => code,
  onDelete,
  renderDetails,
}: {
  pats: ApiKeyView[];
  roleLabel?: (code: string) => string;
  onDelete?: (pat: ApiKeyView) => void;
  /** Extra content below a row — the rate-limit disclosure on the screens that offer it. */
  renderDetails?: (pat: ApiKeyView) => ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
      {pats.map((pat) => {
        const roles = pat.roles.length ? pat.roles.map(roleLabel).join(", ") : t("pats.allRoles");
        const lastUsed = pat.lastUsedAt
          ? `${t("pats.lastUsed")}: ${formatDateTime(pat.lastUsedAt)}`
          : t("pats.neverUsed");
        return (
          <li key={pat.keyId} className="flex items-start justify-between gap-3 py-3">
            <div className="min-w-0">
              <div className="text-sm font-medium text-slate-900 dark:text-white">{pat.name}</div>
              <div className="text-xs text-slate-400">
                {roles} · {lastUsed} · {t("pats.created")}: {formatDateTime(pat.created)}
              </div>
              {renderDetails && <div className="mt-2">{renderDetails(pat)}</div>}
            </div>
            {onDelete && (
              <DropdownMenu
                label={t("pats.menu")}
                actions={[{ label: t("pats.delete"), danger: true, onSelect: () => onDelete(pat) }]}
              />
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** List of a user's messaging (Telegram/WhatsApp) identity links: the platform in bold, and a muted
 * subline "<externalId> · Linked: <date>". When `onDelete` is given, each row gets a 3-dots menu
 * with a destructive Delete (profile); without it the list is read-only (user-edit screen). */
export function MessagingLinkList({
  links,
  onDelete,
}: {
  links: MessagingLink[];
  onDelete?: (link: MessagingLink) => void;
}) {
  const { t } = useTranslation();
  return (
    <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
      {links.map((link) => {
        const platform = link.platform.charAt(0).toUpperCase() + link.platform.slice(1);
        return (
          <li key={link.linkKey} className="flex items-start justify-between gap-3 py-3">
            <div className="min-w-0">
              <div className="text-sm font-medium text-slate-900 dark:text-white">{platform}</div>
              <div className="truncate text-xs text-slate-400">
                <span className="font-mono">{link.externalId}</span> · {t("messaging.linkedOn")}:{" "}
                {formatDateTime(link.created)}
              </div>
            </div>
            {onDelete && (
              <DropdownMenu
                label={t("messaging.menu")}
                actions={[
                  { label: t("messaging.delete"), danger: true, onSelect: () => onDelete(link) },
                ]}
              />
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** List of a user's email addresses: the address in bold, a muted "Added: <date>" subline, and a
 * tag on the unverified ones plus the preferred one.
 *
 * The unverified tag is not decoration — only a verified address is ever sent to, so one sitting
 * there unverified would otherwise look like a working contact. With `onDelete`/`onPrefer` each row
 * gets a 3-dots menu (profile); without them the list is read-only (user-edit screen). */
export function ContactList({
  contacts,
  preferred,
  chosen,
  onDelete,
  onPrefer,
  onVerify,
}: {
  contacts: Contact[];
  preferred?: string | null;
  /** The address the user explicitly picked, if any. Only that one can be un-picked — clearing a
   * preference umami derived would change no answer, so the action is not offered. */
  chosen?: string | null;
  onDelete?: (contact: Contact) => void;
  onPrefer?: (contact: Contact, prefer: boolean) => void;
  /** Offered only for unverified rows, and only when the deployment can actually send mail. */
  onVerify?: (contact: Contact) => void;
}) {
  const { t } = useTranslation();
  return (
    <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
      {contacts.map((contact) => {
        const isPreferred = preferred === contact.address;
        return (
          <li key={contact.address} className="flex items-center justify-between gap-3 py-4">
            <div className="min-w-0 space-y-1">
              <div className="flex flex-wrap items-center gap-2 text-sm font-medium text-slate-900 dark:text-white">
                <span className="truncate">{contact.address}</span>
                {contact.label && <span className="text-xs text-slate-400">{contact.label}</span>}
                {isPreferred && <Tag tone="info">{t("contacts.preferred")}</Tag>}
                {!contact.verified && <Tag tone="warn">{t("contacts.unverified")}</Tag>}
              </div>
              <div className="text-xs text-slate-400">
                {t("contacts.addedOn")}: {formatDateTime(contact.created)}
              </div>
            </div>
            {(onDelete || onPrefer || onVerify) && (
              <DropdownMenu
                label={t("contacts.menu")}
                actions={[
                  ...(onVerify && !contact.verified
                    ? [{ label: t("contacts.verify"), onSelect: () => onVerify(contact) }]
                    : []),
                  // Only a confirmed address can be preferred — the server refuses the rest, so
                  // the menu does not offer a click that can only end in an error.
                  ...(onPrefer && contact.verified && !isPreferred
                    ? [
                        {
                          label: t("contacts.setPreferred"),
                          onSelect: () => onPrefer(contact, true),
                        },
                      ]
                    : []),
                  ...(onPrefer && chosen === contact.address
                    ? [
                        {
                          label: t("contacts.clearPreferred"),
                          onSelect: () => onPrefer(contact, false),
                        },
                      ]
                    : []),
                  ...(onDelete
                    ? [
                        {
                          label: t("contacts.delete"),
                          danger: true,
                          onSelect: () => onDelete(contact),
                        },
                      ]
                    : []),
                ]}
              />
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** A small status pill: "you", "locked", "preferred", "unconfirmed".
 *
 * Fixed palettes, not the brand token. These state a fact about the row — this is you, this address
 * is unconfirmed — so rebranding must not repaint them, and the accent must not land on something
 * merely informational. */
export function Tag({
  tone = "neutral",
  children,
}: {
  tone?: "neutral" | "info" | "warn" | "danger";
  children: string;
}) {
  const cls = {
    info: "bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300",
    warn: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
    danger: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300",
    neutral: "bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300",
  }[tone];
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ${cls}`}
    >
      {children}
    </span>
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
