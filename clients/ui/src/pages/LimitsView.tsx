import type {
  LedgerEntry,
  LimitCatalogueEntry,
  LimitEntry,
  LimitHistoryRow,
  LimitKind,
  LimitSettings,
} from "@bentoforge/umami-iam";
import {
  ArrowLeftIcon,
  ClipboardDocumentIcon,
  ClockIcon,
  ListBulletIcon,
  PlusCircleIcon,
  TrashIcon,
} from "@heroicons/react/24/outline";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import {
  Banner,
  DropdownMenu,
  errMsg,
  Field,
  formatDateTime,
  formatNumber,
  Loader,
  type MenuAction,
} from "../components";
import { card, ghostButton, input, primaryButton, td, th } from "../ui";

const LEDGER_PAGE = 10;
const HISTORY_MONTHS = 24;

/** Compact cells for the limits table — a touch less padding than the shared `td`/`th`. */
const cell = "px-2 py-1 text-sm text-slate-800 align-top dark:text-slate-200";
const headCell = "px-2 py-1 text-left text-xs font-semibold uppercase tracking-wide text-slate-500";

/** A tenant's limit merged with its catalogue definition. `def` is absent for an orphan (a stored
 * limit whose definition has been removed from the config); `kind` is then inferred from the shape
 * of its stored settings — a `max` means gauge, anything else consumable. */
interface Row {
  entry: LimitEntry;
  def?: LimitCatalogueEntry;
  kind: LimitKind;
}

/** Which sub-view of the card is showing; `list` is the table, the rest are scoped to `code`. */
type Mode =
  | { view: "list" }
  | { view: "edit"; code: string }
  | { view: "ledger"; code: string }
  | { view: "history"; code: string }
  | { view: "topup"; code: string };

/** Reusable limits surface shared by the tenant editor (`readOnly=false`, full management) and the
 * start page's self view (`readOnly=true`, only the ledger/history switches). A single card with an
 * internal view mode: `list` shows the limits table; edit/ledger/history/topup swap the body and
 * offer a Back to the list.
 *
 * Renders nothing when the tenant has no relevant or stored limits — a deployment that does not use
 * limits, or a tenant none apply to — rather than an empty card. */
export function LimitsView({
  tenantId,
  title,
  readOnly = false,
}: {
  tenantId: string;
  title: string;
  readOnly?: boolean;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [defs, setDefs] = useState<LimitCatalogueEntry[] | null>(null);
  const [entries, setEntries] = useState<LimitEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>({ view: "list" });

  useEffect(() => {
    client
      .catalogue()
      .then((c) => setDefs(c.limits))
      .catch(() => setDefs([]));
  }, [client]);

  const loadLimits = useCallback(() => {
    client
      .getTenantLimits(tenantId)
      .then((r) => setEntries(r.limits))
      .catch((err) => setError(errMsg(err)));
  }, [client, tenantId]);

  useEffect(() => loadLimits(), [loadLimits]);

  // No relevant or stored limits — omit the card rather than showing an empty box.
  if (defs !== null && entries !== null && entries.length === 0) {
    return null;
  }

  const backToList = () => setMode({ view: "list" });
  const reloadAndList = () => {
    loadLimits();
    backToList();
  };

  const rows: Row[] =
    defs !== null && entries !== null
      ? entries.map((entry) => {
          const def = defs.find((d) => d.code === entry.code);
          const kind: LimitKind = def
            ? def.kind
            : entry.settings.max != null
              ? "gauge"
              : "consumable";
          return { entry, def, kind };
        })
      : [];

  const selected = "code" in mode ? rows.find((r) => r.entry.code === mode.code) : undefined;
  const selectedName = selected ? (selected.def?.name ?? selected.entry.code) : "";

  // In every sub-view the card heading carries the context ("Limits – Transactions") and the limit's
  // name becomes the subheading — one heading per view, not several stacked ones.
  const contextLabel =
    mode.view === "ledger"
      ? t("limits.ledger")
      : mode.view === "history"
        ? t("limits.history")
        : mode.view === "edit"
          ? t("limits.edit")
          : mode.view === "topup"
            ? t("limits.credit")
            : null;

  return (
    <section className={`${card} space-y-4`}>
      <div>
        <h2 className="font-medium text-slate-800 dark:text-slate-200">
          {title}
          {contextLabel && <span className="text-slate-400"> – {contextLabel}</span>}
        </h2>
        {contextLabel && selected && (
          <p className="text-sm text-slate-500 dark:text-slate-400">{selectedName}</p>
        )}
      </div>

      {error && <Banner tone="error">{error}</Banner>}

      {defs === null || entries === null ? (
        <Loader />
      ) : mode.view === "list" ? (
        <LimitsTable
          rows={rows}
          readOnly={readOnly}
          onAction={(view, code) => setMode({ view, code })}
          onDelete={(code) => void deleteLimit(client, tenantId, code, t, loadLimits, setError)}
        />
      ) : selected === undefined ? (
        <BackButton onClick={backToList} />
      ) : mode.view === "edit" ? (
        <LimitEditor
          tenantId={tenantId}
          row={selected}
          onSaved={reloadAndList}
          onCancel={backToList}
          onError={setError}
        />
      ) : mode.view === "topup" ? (
        <TopupForm
          tenantId={tenantId}
          code={selected.entry.code}
          onDone={reloadAndList}
          onCancel={backToList}
          onError={setError}
        />
      ) : mode.view === "ledger" ? (
        <LedgerView tenantId={tenantId} code={selected.entry.code} onBack={backToList} />
      ) : (
        <HistoryView
          tenantId={tenantId}
          code={selected.entry.code}
          kind={selected.kind}
          onBack={backToList}
        />
      )}
    </section>
  );
}

async function deleteLimit(
  client: ReturnType<typeof useUmami>["client"],
  tenantId: string,
  code: string,
  t: (key: string) => string,
  onChanged: () => void,
  onError: (msg: string) => void,
) {
  if (!window.confirm(t("limits.deleteConfirm"))) {
    return;
  }
  try {
    await client.setTenantLimitSettings(tenantId, code, {});
    onChanged();
  } catch (err) {
    onError(errMsg(err));
  }
}

const unitSuffix = (unit?: string) => (unit ? ` ${unit}` : "");

/** A short explanatory note under a form field. */
function FieldHint({ children }: { children: ReactNode }) {
  return <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{children}</p>;
}

/** The name cell — the limit's label as a click-to-edit link (primary colour, pointer) when
 * editable, else plain; for an orphan its code with a muted "no longer defined". */
function NameCell({ row, editable, onEdit }: { row: Row; editable: boolean; onEdit: () => void }) {
  const { t } = useTranslation();
  if (row.def) {
    return (
      <div>
        {editable ? (
          <button
            type="button"
            onClick={onEdit}
            className="cursor-pointer font-medium text-primary hover:underline"
          >
            {row.def.name}
          </button>
        ) : (
          <div className="font-medium text-slate-900 dark:text-white">{row.def.name}</div>
        )}
        {row.def.description && (
          <div className="text-slate-400 dark:text-slate-500">{row.def.description}</div>
        )}
      </div>
    );
  }
  return (
    <div>
      <div className="font-mono text-slate-900 dark:text-white">{row.entry.code}</div>
      <div className="text-slate-400 dark:text-slate-500">{t("limits.noLongerDefined")}</div>
    </div>
  );
}

/** The single limits table: name, the per-budget lines (label, ceiling, current value), and the
 * actions menu. A limit with several budget lines repeats them as rows; its name and menu cells span
 * all of them (rowSpan 1..5). */
function LimitsTable({
  rows,
  readOnly,
  onAction,
  onDelete,
}: {
  rows: Row[];
  readOnly: boolean;
  onAction: (view: "edit" | "ledger" | "history" | "topup", code: string) => void;
  onDelete: (code: string) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr className="border-b border-slate-200 dark:border-slate-700">
            <th className={headCell}>{t("limits.name")}</th>
            <th className={headCell}>{t("limits.limit")}</th>
            <th className={`${headCell} text-right`}>{t("limits.ceiling")}</th>
            <th className={`${headCell} text-right`}>{t("limits.current")}</th>
            <th className={headCell} />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <LimitRow
              key={row.entry.code}
              row={row}
              readOnly={readOnly}
              onAction={onAction}
              onDelete={onDelete}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** One budget line of a limit: a bobble + label, its ceiling (a gauge/balance/overrun line has
 * none), and the current value. */
interface DetailLine {
  key: string;
  label: string;
  /** What this value means, shown as a tooltip on the label. */
  hint: string;
  bobble: ReactNode;
  ceiling: number | null;
  value: number;
}

function detailLines(row: Row, t: (key: string) => string): DetailLine[] {
  const s = row.entry.settings;
  const st = row.entry.state;

  if (row.kind === "gauge") {
    return [
      {
        key: "gauge",
        label: t("limits.value"),
        hint: t("limits.ceilingHint"),
        bobble: (
          <Bobble
            value={st?.gaugeValue}
            max={s.max}
            low={row.def?.lowWatermarkPercent}
            high={row.def?.highWatermarkPercent}
          />
        ),
        ceiling: s.max ?? 0,
        value: st?.gaugeValue ?? 0,
      },
    ];
  }

  const budget = (
    key: string,
    label: string,
    hint: string,
    ceiling: number,
    remaining: number,
  ): DetailLine => ({
    key,
    label,
    hint,
    bobble: <AvailabilityBobble remaining={remaining} limit={ceiling} />,
    ceiling,
    value: remaining,
  });

  const lines: DetailLine[] = [];
  const monthly = s.monthly ?? 0;
  lines.push(
    budget(
      "monthly",
      t("limits.monthlyBudget"),
      t("limits.monthlyHint"),
      monthly,
      st?.monthlyRemaining ?? monthly,
    ),
  );
  if (row.def?.daily && (s.daily ?? 0) > 0) {
    const daily = s.daily ?? 0;
    lines.push(
      budget(
        "daily",
        t("limits.dailyBudget"),
        t("limits.dailyHint"),
        daily,
        st?.dailyRemaining ?? daily,
      ),
    );
  }
  if (row.def?.extraAllowance && (s.extraAllowance ?? 0) > 0) {
    const extraAllowance = s.extraAllowance ?? 0;
    lines.push(
      budget(
        "extraAllowance",
        t("limits.extraAllowance"),
        t("limits.extraAllowanceHint"),
        extraAllowance,
        st?.extraAllowanceRemaining ?? extraAllowance,
      ),
    );
  }
  if ((st?.customBalance ?? 0) > 0) {
    lines.push({
      key: "balance",
      label: t("limits.balance"),
      hint: t("limits.balanceHint"),
      bobble: <ToneDot className="bg-green-500" />,
      ceiling: null,
      value: st?.customBalance ?? 0,
    });
  }
  if ((st?.overrun ?? 0) > 0) {
    lines.push({
      key: "overrun",
      label: t("limits.overrun"),
      hint: t("limits.overrunHint"),
      bobble: <ToneDot className="bg-amber-400" />,
      ceiling: null,
      value: st?.overrun ?? 0,
    });
  }
  return lines;
}

function LimitRow({
  row,
  readOnly,
  onAction,
  onDelete,
}: {
  row: Row;
  readOnly: boolean;
  onAction: (view: "edit" | "ledger" | "history" | "topup", code: string) => void;
  onDelete: (code: string) => void;
}) {
  const { t } = useTranslation();
  const code = row.entry.code;
  const editable = !readOnly && row.def != null;
  const unit = unitSuffix(row.def?.unit);
  const lines = detailLines(row, t);
  const span = lines.length;

  return (
    <>
      {lines.map((line, i) => {
        const divider = i === span - 1 ? "border-b border-slate-100 dark:border-slate-700/50" : "";
        return (
          <tr key={line.key} className={divider}>
            {i === 0 && (
              <td className={`${cell} whitespace-nowrap`} rowSpan={span}>
                <NameCell row={row} editable={editable} onEdit={() => onAction("edit", code)} />
              </td>
            )}
            <td className={cell}>
              <span className="inline-flex items-center gap-2">
                {line.bobble}
                {line.label && (
                  <span
                    className="font-mono decoration-slate-300 decoration-dotted underline-offset-2 hover:underline"
                    title={line.hint}
                  >
                    {line.label}
                  </span>
                )}
              </span>
            </td>
            <td className={`${cell} text-right font-mono`}>
              {line.ceiling != null ? `${formatNumber(line.ceiling)}${unit}` : ""}
            </td>
            <td className={`${cell} text-right font-mono font-medium`}>
              {formatNumber(line.value)}
              {unit}
            </td>
            {i === 0 && (
              <td className={`${cell} text-right`} rowSpan={span}>
                <RowMenu row={row} readOnly={readOnly} onAction={onAction} onDelete={onDelete} />
              </td>
            )}
          </tr>
        );
      })}
    </>
  );
}

/** A small round status dot (fixed tone). */
function ToneDot({ className }: { className: string }) {
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${className}`} />;
}

/** A round availability dot before a budget line: gray when untouched (remaining == limit), then
 * light green (> 75% left), green (> 25%), amber (some left), red (nothing left). */
function AvailabilityBobble({ remaining, limit }: { remaining: number; limit: number }) {
  let color = "bg-slate-300";
  if (limit > 0 && remaining < limit) {
    const ratio = remaining / limit;
    if (ratio > 0.75) {
      color = "bg-emerald-300";
    } else if (ratio > 0.25) {
      color = "bg-green-500";
    } else if (remaining > 0) {
      color = "bg-amber-400";
    } else {
      color = "bg-red-500";
    }
  }
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${color}`} />;
}

/** A round status dot before a gauge reading: gray below the low watermark (or when the percent is
 * unknown), green in the healthy band, red at or above the high watermark. */
function Bobble({
  value,
  max,
  low,
  high,
}: {
  value?: number;
  max?: number;
  low?: number;
  high?: number;
}) {
  const percent = max != null && max > 0 && value != null ? (value / max) * 100 : null;
  let color = "bg-slate-300";
  if (percent != null) {
    if (high != null && percent >= high) {
      color = "bg-red-500";
    } else if (low != null && percent < low) {
      color = "bg-slate-300";
    } else {
      color = "bg-green-500";
    }
  }
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${color}`} />;
}

/** The non-edit actions, always behind a 3-dots menu (edit is the pencil in the name). A consumable
 * offers its ledger and history, and — when writable and it carries a top-up balance — a credit; a
 * gauge is only set, so it offers just its history; an orphan offers Delete. */
function RowMenu({
  row,
  readOnly,
  onAction,
  onDelete,
}: {
  row: Row;
  readOnly: boolean;
  onAction: (view: "edit" | "ledger" | "history" | "topup", code: string) => void;
  onDelete: (code: string) => void;
}) {
  const { t } = useTranslation();
  const code = row.entry.code;

  const actions: MenuAction[] = [];
  if (row.def) {
    // A consumable is booked, so it has a transaction ledger; a gauge is only set, so it does not —
    // both keep a month-by-month history.
    if (row.def.kind === "consumable") {
      actions.push({
        label: t("limits.ledger"),
        icon: ListBulletIcon,
        onSelect: () => onAction("ledger", code),
      });
    }
    actions.push({
      label: t("limits.history"),
      icon: ClockIcon,
      onSelect: () => onAction("history", code),
    });
    if (!readOnly && row.def.kind === "consumable" && row.def.customBalance) {
      actions.push({
        label: t("limits.credit"),
        icon: PlusCircleIcon,
        dividerBefore: true,
        onSelect: () => onAction("topup", code),
      });
    }
  } else if (!readOnly) {
    actions.push({
      label: t("limits.delete"),
      danger: true,
      icon: TrashIcon,
      onSelect: () => onDelete(code),
    });
  }

  if (actions.length === 0) {
    return null;
  }
  return <DropdownMenu label={t("limits.actions")} actions={actions} />;
}

/** A full-card editor for one limit's settings, shaped by kind and facets: a consumable edits its
 * monthly allowance plus extra-allowance/daily when it has them, a gauge edits its max. Save surfaces the
 * server's capping `warnings` in an amber banner; with none, it returns to the list. */
function LimitEditor({
  tenantId,
  row,
  onSaved,
  onCancel,
  onError,
}: {
  tenantId: string;
  row: Row;
  onSaved: () => void;
  onCancel: () => void;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [settings, setSettings] = useState<LimitSettings>(row.entry.settings);
  const [saving, setSaving] = useState(false);
  const [warnings, setWarnings] = useState<string[]>([]);
  // A change that would re-book overrun is previewed first: the server reports it without writing,
  // and we ask for an explicit confirm before re-sending. Any edit invalidates that preview.
  const [needsConfirm, setNeedsConfirm] = useState(false);

  const setNum = (key: keyof LimitSettings, value: string) => {
    setSettings((s) => ({ ...s, [key]: value === "" ? undefined : Number(value) }));
    setNeedsConfirm(false);
    setWarnings([]);
  };
  const numValue = (key: keyof LimitSettings) => {
    const v = settings[key];
    return v === undefined || v === null ? "" : String(v);
  };

  const save = async (confirm = false) => {
    setSaving(true);
    onError("");
    try {
      const res = await client.setTenantLimitSettings(tenantId, row.entry.code, settings, {
        confirm,
      });
      if (res.status === "confirmationRequired") {
        // A booking would happen — show it and wait for the confirm click, writing nothing yet.
        setNeedsConfirm(true);
        setWarnings(res.warnings ?? []);
      } else if (!confirm && res.warnings && res.warnings.length > 0) {
        // Saved straight through, but with advisory reconcile notes.
        setWarnings(res.warnings);
      } else {
        onSaved();
      }
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {row.kind === "consumable" ? (
          <>
            <Field label={t("limits.monthlyBudget")}>
              <input
                className={input}
                type="number"
                value={numValue("monthly")}
                onChange={(e) => setNum("monthly", e.target.value)}
              />
              <FieldHint>{t("limits.monthlyHint")}</FieldHint>
            </Field>
            {row.def?.daily && (
              <Field label={t("limits.dailyBudget")}>
                <input
                  className={input}
                  type="number"
                  value={numValue("daily")}
                  onChange={(e) => setNum("daily", e.target.value)}
                />
                <FieldHint>{t("limits.dailyHint")}</FieldHint>
              </Field>
            )}
            {row.def?.extraAllowance && (
              <Field label={t("limits.extraAllowance")}>
                <input
                  className={input}
                  type="number"
                  value={numValue("extraAllowance")}
                  onChange={(e) => setNum("extraAllowance", e.target.value)}
                />
                <FieldHint>{t("limits.extraAllowanceHint")}</FieldHint>
              </Field>
            )}
          </>
        ) : (
          <Field label={t("limits.ceiling")}>
            <input
              className={input}
              type="number"
              value={numValue("max")}
              onChange={(e) => setNum("max", e.target.value)}
            />
            <FieldHint>{t("limits.ceilingHint")}</FieldHint>
          </Field>
        )}
      </div>

      {warnings.length > 0 && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-300">
          {needsConfirm && <p className="mb-1 font-medium">{t("limits.confirmBookingTitle")}</p>}
          <ul className="list-disc space-y-0.5 pl-4">
            {warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex gap-2">
        {needsConfirm ? (
          <button className={primaryButton} disabled={saving} onClick={() => void save(true)}>
            {t("limits.confirmBooking")}
          </button>
        ) : (
          <button className={primaryButton} disabled={saving} onClick={() => void save()}>
            {t("limits.save")}
          </button>
        )}
        <button className={ghostButton} disabled={saving} onClick={onCancel}>
          {t("limits.back")}
        </button>
      </div>
    </div>
  );
}

/** The top-up (credit) form for a consumable with a custom balance: an amount, credited to the
 * balance that survives the monthly reset. */
function TopupForm({
  tenantId,
  code,
  onDone,
  onCancel,
  onError,
}: {
  tenantId: string;
  code: string;
  onDone: () => void;
  onCancel: () => void;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [amount, setAmount] = useState("");
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    const value = Number(amount);
    if (amount === "" || Number.isNaN(value)) {
      return;
    }
    setSaving(true);
    onError("");
    try {
      await client.topupLimit(tenantId, code, value);
      onDone();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="max-w-xs">
        <Field label={t("limits.creditAmount")}>
          <input
            className={input}
            type="number"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
          />
        </Field>
      </div>
      <div className="flex gap-2">
        <button className={primaryButton} disabled={saving} onClick={() => void submit()}>
          {t("limits.credit")}
        </button>
        <button className={ghostButton} disabled={saving} onClick={onCancel}>
          {t("limits.back")}
        </button>
      </div>
    </div>
  );
}

/** A limit's transaction ledger, newest-first and paged via `nextCursor`. The card heading names the
 * limit; each row's amount is coloured by direction and its txn/user ids expand from the source
 * column into the details cell. */
function LedgerView({
  tenantId,
  code,
  onBack,
}: {
  tenantId: string;
  code: string;
  onBack: () => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [entries, setEntries] = useState<LedgerEntry[] | null>(null);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    client
      .getLimitLedger(tenantId, code, { limit: LEDGER_PAGE })
      .then((page) => {
        if (alive) {
          setEntries(page.entries);
          setCursor(page.nextCursor);
        }
      })
      .catch(() => {
        if (alive) {
          setEntries([]);
        }
      });
    return () => {
      alive = false;
    };
  }, [client, tenantId, code]);

  const loadMore = async () => {
    if (!cursor) {
      return;
    }
    setBusy(true);
    try {
      const page = await client.getLimitLedger(tenantId, code, { cursor, limit: LEDGER_PAGE });
      setEntries((prev) => [...(prev ?? []), ...page.entries]);
      setCursor(page.nextCursor);
    } finally {
      setBusy(false);
    }
  };

  const copy = (value: string) => {
    void navigator.clipboard?.writeText(value);
  };

  const muted = "font-mono text-xs text-slate-400 dark:text-slate-500";

  return (
    <div className="space-y-4">
      {entries === null ? (
        <Loader />
      ) : entries.length === 0 ? (
        <p className="text-sm text-slate-500">{t("limits.noLedger")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={th}>{t("limits.when")}</th>
                <th className={th}>{t("limits.type")}</th>
                <th className={`${th} text-right`}>{t("limits.amount")}</th>
                <th className={th}>
                  {t("limits.current")} <span className="text-slate-400">*</span>
                </th>
                <th className={th} />
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => {
                const ids: MenuAction[] = [];
                if (e.txnId != null) {
                  ids.push({
                    label: `${t("limits.transaction")}: ${e.txnId}`,
                    icon: ClipboardDocumentIcon,
                    onSelect: () => copy(e.txnId as string),
                  });
                }
                if (e.actorUserId != null) {
                  ids.push({
                    label: `${t("limits.user")}: ${e.actorUserId}`,
                    icon: ClipboardDocumentIcon,
                    onSelect: () => copy(e.actorUserId as string),
                  });
                }
                return (
                  <tr key={e.id} className="border-b border-slate-100 dark:border-slate-700/50">
                    <td className={`${td} whitespace-nowrap`}>{formatDateTime(e.timestamp)}</td>
                    <td className={td}>
                      {t(`limits.ledgerType.${e.type}`, { defaultValue: e.type })}
                      {e.source != null && (
                        <span className="ml-1 text-slate-400 dark:text-slate-500">
                          ({e.source})
                        </span>
                      )}
                    </td>
                    <td className={`${td} text-right whitespace-nowrap font-mono`}>
                      <LedgerAmount entry={e} />
                    </td>
                    <td className={`${td} whitespace-nowrap ${muted}`}>
                      {formatNumber(e.resultingMonthly)} · {formatNumber(e.resultingExtraAllowance)}{" "}
                      · {formatNumber(e.resultingCustom)} ·{" "}
                      <span className={e.resultingOverrun > 0 ? "text-amber-500" : undefined}>
                        {formatNumber(e.resultingOverrun)}
                      </span>
                    </td>
                    <td className={`${td} text-right`}>
                      {ids.length > 0 && (
                        <DropdownMenu actions={ids} label={t("common.moreActions")} />
                      )}
                    </td>
                  </tr>
                );
              })}
              {cursor && (
                <tr>
                  <td colSpan={5} className="px-2 py-3 text-center">
                    <button
                      type="button"
                      className="text-primary hover:underline disabled:opacity-50"
                      disabled={busy}
                      onClick={() => void loadMore()}
                    >
                      {t("common.loadMore")}
                    </button>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          <p className="mt-2 text-xs text-slate-400 dark:text-slate-500">
            *{" "}
            {t("limits.standFootnote", {
              accounts: `${t("limits.monthlyBudget")} · ${t("limits.extraAllowance")} · ${t("limits.balance")} · ${t("limits.overrun")}`,
            })}
          </p>
        </div>
      )}
      <BackButton onClick={onBack} />
    </div>
  );
}

/** The amount for one ledger entry, right-aligned and coloured by direction: a debit
 * (consume/carry) red with a `−`, a credit (top-up) green with a `+`, and a settings entry — which
 * has no quantity — a muted dash. */
function LedgerAmount({ entry }: { entry: LedgerEntry }) {
  // No quantity for a settings change or a month-end reset marker.
  if (entry.type === "settings" || entry.type === "reset") {
    return <span className="text-slate-400 dark:text-slate-500">—</span>;
  }
  const value = formatNumber(entry.amount);
  if (entry.type === "topup") {
    return <span className="text-green-600 dark:text-green-400">+{value}</span>;
  }
  if (entry.type === "consume" || entry.type === "carry") {
    return <span className="text-red-600 dark:text-red-400">−{value}</span>;
  }
  return <span>{value}</span>;
}

/** A two-line table header: the label, and a muted `used / limit` clarifier under it. */
function UsedLimitHead({ label }: { label: string }) {
  const { t } = useTranslation();
  return (
    <th className={`${th} text-right align-top`}>
      <div>{label}</div>
      <div className="text-[10px] font-normal normal-case text-slate-400">
        {t("limits.monthlyUsed")} / {t("limits.limit")}
      </div>
    </th>
  );
}

/** A limit's month-by-month history, the most recent {@link HISTORY_MONTHS} months. The card heading
 * names the limit; this renders the table only. A consumable shows used/limit per bucket and the net
 * balance (credit minus overrun, red when negative); a gauge shows the value it closed each month at
 * against its bound. */
function HistoryView({
  tenantId,
  code,
  kind,
  onBack,
}: {
  tenantId: string;
  code: string;
  kind: LimitKind;
  onBack: () => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [months, setMonths] = useState<LimitHistoryRow[] | null>(null);

  useEffect(() => {
    let alive = true;
    client
      .getLimitHistory(tenantId, code)
      .then((h) => {
        if (alive) {
          setMonths(h.months);
        }
      })
      .catch(() => {
        if (alive) {
          setMonths([]);
        }
      });
    return () => {
      alive = false;
    };
  }, [client, tenantId, code]);

  const rows = months?.slice(0, HISTORY_MONTHS) ?? [];

  return (
    <div className="space-y-4">
      {months === null ? (
        <Loader />
      ) : months.length === 0 ? (
        <p className="text-sm text-slate-500">{t("limits.noHistory")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={`${th} align-top`}>{t("limits.month")}</th>
                {kind === "gauge" ? (
                  <>
                    <th className={`${th} text-right align-top`}>{t("limits.value")}</th>
                    <th className={`${th} text-right align-top`}>{t("limits.ceiling")}</th>
                  </>
                ) : (
                  <>
                    <UsedLimitHead label={t("limits.monthlyBudget")} />
                    <UsedLimitHead label={t("limits.extraAllowance")} />
                    <th className={`${th} text-right align-top`}>{t("limits.balance")}</th>
                  </>
                )}
              </tr>
            </thead>
            <tbody>
              {rows.map((m) => {
                const net = m.endingCustomBalance - m.overrun;
                return (
                  <tr
                    key={m.yearMonth}
                    className="border-b border-slate-100 dark:border-slate-700/50"
                  >
                    <td className={`${td} whitespace-nowrap font-mono`}>{m.yearMonth}</td>
                    {kind === "gauge" ? (
                      <>
                        <td className={`${td} text-right font-mono`}>
                          {m.gaugeValue != null ? formatNumber(m.gaugeValue) : "—"}
                        </td>
                        <td className={`${td} text-right font-mono`}>
                          {m.gaugeMax != null ? formatNumber(m.gaugeMax) : "—"}
                        </td>
                      </>
                    ) : (
                      <>
                        <td className={`${td} text-right font-mono`}>
                          {formatNumber(m.monthlyUsed)} / {formatNumber(m.monthlyIncluded)}
                        </td>
                        <td className={`${td} text-right font-mono`}>
                          {formatNumber(m.extraAllowanceUsed)} /{" "}
                          {formatNumber(m.extraAllowanceLimit)}
                        </td>
                        <td
                          className={`${td} text-right font-mono ${net < 0 ? "text-red-500" : ""}`}
                        >
                          {formatNumber(net)}
                        </td>
                      </>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <BackButton onClick={onBack} />
    </div>
  );
}

/** The header of an expanded sub-view: the view's context label (transactions / history) over the
 * selected limit's name and its description, so the swapped-in body keeps its bearings. */
/** The Back-to-list control shared by every sub-view. */
function BackButton({ onClick }: { onClick: () => void }) {
  const { t } = useTranslation();
  return (
    <button className={`${ghostButton} inline-flex items-center gap-1.5`} onClick={onClick}>
      <ArrowLeftIcon className="h-4 w-4" />
      {t("limits.back")}
    </button>
  );
}
