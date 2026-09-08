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
  ClockIcon,
  PencilSquareIcon,
  PlusCircleIcon,
  QueueListIcon,
  TrashIcon,
} from "@heroicons/react/24/outline";
import { type ComponentType, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, DropdownMenu, errMsg, Field, formatDateTime, Loader } from "../components";
import { card, ghostButton, input, primaryButton, td, th } from "../ui";

const LEDGER_PAGE = 10;
const HISTORY_MONTHS = 24;

/** A tenant's limit merged with its catalogue definition. `def` is absent for an orphan (a stored
 * limit whose definition has been removed from the config); `kind` is then inferred from the shape
 * of its stored settings — a `max` means gauge, anything else consumable. */
interface Row {
  entry: LimitEntry;
  def?: LimitCatalogueEntry;
  kind: LimitKind;
}

/** Which sub-view of the card is showing; `list` is the two tables, the rest are scoped to `code`. */
type Mode =
  | { view: "list" }
  | { view: "edit"; code: string }
  | { view: "ledger"; code: string }
  | { view: "history"; code: string }
  | { view: "topup"; code: string };

/** Reusable limits surface shared by the tenant editor (`readOnly=false`, full management) and the
 * start page's self view (`readOnly=true`, only the ledger/history switches). A single card with an
 * internal view mode: `list` shows a consumable and a gauge table, each only when it has a row;
 * edit/ledger/history/topup swap the body and offer a Back to the list.
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
  const consumables = rows.filter((r) => r.kind === "consumable");
  const gauges = rows.filter((r) => r.kind === "gauge");

  return (
    <section className={`${card} space-y-4`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">{title}</h2>

      {error && <Banner tone="error">{error}</Banner>}

      {defs === null || entries === null ? (
        <Loader />
      ) : mode.view === "list" ? (
        <div className="space-y-6">
          {consumables.length > 0 && (
            <ConsumableTable
              rows={consumables}
              readOnly={readOnly}
              onAction={(view, code) => setMode({ view, code })}
              onDelete={(code) => void deleteLimit(client, tenantId, code, t, loadLimits, setError)}
            />
          )}
          {gauges.length > 0 && (
            <GaugeTable
              rows={gauges}
              readOnly={readOnly}
              onAction={(view, code) => setMode({ view, code })}
              onDelete={(code) => void deleteLimit(client, tenantId, code, t, loadLimits, setError)}
            />
          )}
        </div>
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
          name={selected.def?.name ?? selected.entry.code}
          onDone={reloadAndList}
          onCancel={backToList}
          onError={setError}
        />
      ) : mode.view === "ledger" ? (
        <LedgerView tenantId={tenantId} code={selected.entry.code} onBack={backToList} />
      ) : (
        <HistoryView tenantId={tenantId} code={selected.entry.code} onBack={backToList} />
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

/** The name cell — the limit's label, or for an orphan its code with a muted "no longer defined". */
function NameCell({ row }: { row: Row }) {
  const { t } = useTranslation();
  if (row.def) {
    return (
      <div>
        <div className="font-medium text-slate-900 dark:text-white">{row.def.name}</div>
        {row.def.description && (
          <div className="text-xs text-slate-400 dark:text-slate-500">{row.def.description}</div>
        )}
      </div>
    );
  }
  return (
    <div>
      <div className="font-mono text-slate-900 dark:text-white">{row.entry.code}</div>
      <div className="text-xs text-slate-400 dark:text-slate-500">
        {t("limits.noLongerDefined")}
      </div>
    </div>
  );
}

function ConsumableTable({
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
    <div>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
        {t("limits.consumableTitle")}
      </h3>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse">
          <thead>
            <tr className="border-b border-slate-200 dark:border-slate-700">
              <th className={th}>{t("limits.name")}</th>
              <th className={th}>{t("limits.usageBudget")}</th>
              <th className={th}>{t("limits.customBudget")}</th>
              <th className={th}>{t("limits.overuseMax")}</th>
              <th className={`${th} text-right`}>{t("limits.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const s = row.entry.settings;
              const st = row.entry.state;
              const unit = unitSuffix(row.def?.unit);
              const budget = s.monthly ?? 0;
              const usedMonth = st ? Math.max(0, budget - st.monthlyRemaining) : 0;
              const customBudget = st?.customBalance ?? 0;
              const maxOveruse = s.overuse ?? 0;
              const overuseUsed = st ? Math.max(0, (s.overuse ?? 0) - st.overuseRemaining) : 0;
              const showDaily = row.def?.daily ?? false;
              const budgetToday = s.daily ?? 0;
              const usedToday =
                st?.dailyRemaining != null ? Math.max(0, (s.daily ?? 0) - st.dailyRemaining) : 0;
              return (
                <tr
                  key={row.entry.code}
                  className="border-b border-slate-100 dark:border-slate-700/50"
                >
                  <td className={td}>
                    <NameCell row={row} />
                  </td>
                  <td className={td}>
                    <div>
                      {usedMonth} / {budget}
                      {unit}
                    </div>
                    {showDaily && (
                      <div className="text-xs text-slate-400 dark:text-slate-500">
                        {t("limits.today")}: {usedToday} / {budgetToday}
                        {unit}
                      </div>
                    )}
                  </td>
                  <td className={td}>
                    {customBudget}
                    {unit}
                  </td>
                  <td className={td}>
                    {overuseUsed} / {maxOveruse}
                    {unit}
                  </td>
                  <td className={`${td} text-right`}>
                    <RowActions
                      row={row}
                      readOnly={readOnly}
                      onAction={onAction}
                      onDelete={onDelete}
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function GaugeTable({
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
    <div>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
        {t("limits.gaugeTitle")}
      </h3>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse">
          <thead>
            <tr className="border-b border-slate-200 dark:border-slate-700">
              <th className={th}>{t("limits.name")}</th>
              <th className={th}>{t("limits.value")}</th>
              <th className={th}>{t("limits.limitMax")}</th>
              <th className={`${th} text-right`}>{t("limits.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const unit = unitSuffix(row.def?.unit);
              const value = row.entry.state?.gaugeValue;
              const max = row.entry.settings.max;
              return (
                <tr
                  key={row.entry.code}
                  className="border-b border-slate-100 dark:border-slate-700/50"
                >
                  <td className={td}>
                    <NameCell row={row} />
                  </td>
                  <td className={td}>
                    <div className="flex items-center gap-2">
                      <Bobble
                        value={value}
                        max={max}
                        low={row.def?.lowWatermarkPercent}
                        high={row.def?.highWatermarkPercent}
                      />
                      <span>{value != null ? `${value}${unit}` : "—"}</span>
                    </div>
                  </td>
                  <td className={td}>{max != null ? `${max}${unit}` : "—"}</td>
                  <td className={`${td} text-right`}>
                    <RowActions
                      row={row}
                      readOnly={readOnly}
                      onAction={onAction}
                      onDelete={onDelete}
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
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
  return <span className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${color}`} />;
}

interface Action {
  key: string;
  label: string;
  icon: ComponentType<{ className?: string }>;
  onSelect: () => void;
  danger?: boolean;
}

/** The per-row actions. On `sm` and up they are inline icon+label buttons; below that they collapse
 * into a vertical 3-dots {@link DropdownMenu}. Read-only rows offer only the ledger and history
 * switches; an orphan offers only Delete; a defined limit offers Edit, ledger, history, and — for a
 * consumable with a top-up balance — a credit action. */
function RowActions({
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

  const ledger: Action = {
    key: "ledger",
    label: t("limits.ledger"),
    icon: QueueListIcon,
    onSelect: () => onAction("ledger", code),
  };
  const history: Action = {
    key: "history",
    label: t("limits.history"),
    icon: ClockIcon,
    onSelect: () => onAction("history", code),
  };

  let actions: Action[];
  if (readOnly) {
    actions = [ledger, history];
  } else if (!row.def) {
    actions = [
      {
        key: "delete",
        label: t("limits.delete"),
        icon: TrashIcon,
        danger: true,
        onSelect: () => onDelete(code),
      },
    ];
  } else {
    actions = [
      {
        key: "edit",
        label: t("limits.edit"),
        icon: PencilSquareIcon,
        onSelect: () => onAction("edit", code),
      },
      ledger,
      history,
    ];
    if (row.def.kind === "consumable" && row.def.customBalance) {
      actions.push({
        key: "topup",
        label: t("limits.credit"),
        icon: PlusCircleIcon,
        onSelect: () => onAction("topup", code),
      });
    }
  }

  return (
    <>
      <div className="hidden sm:flex items-center justify-end gap-1">
        {actions.map((action) => {
          const Icon = action.icon;
          return (
            <button
              key={action.key}
              type="button"
              onClick={action.onSelect}
              className={`inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium ${
                action.danger
                  ? "text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950"
                  : "text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700"
              }`}
            >
              <Icon className="h-4 w-4" />
              {action.label}
            </button>
          );
        })}
      </div>
      <div className="sm:hidden flex justify-end">
        <DropdownMenu
          label={t("limits.actions")}
          actions={actions.map((a) => ({
            label: a.label,
            danger: a.danger,
            onSelect: a.onSelect,
          }))}
        />
      </div>
    </>
  );
}

/** A full-card editor for one limit's settings, shaped by kind and facets: a consumable edits its
 * monthly allowance plus overuse/daily when it has them, a gauge edits its max. Save surfaces the
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

  const setNum = (key: keyof LimitSettings, value: string) =>
    setSettings((s) => ({ ...s, [key]: value === "" ? undefined : Number(value) }));
  const numValue = (key: keyof LimitSettings) => {
    const v = settings[key];
    return v === undefined || v === null ? "" : String(v);
  };

  const save = async () => {
    setSaving(true);
    onError("");
    try {
      const res = await client.setTenantLimitSettings(tenantId, row.entry.code, settings);
      if (res.warnings && res.warnings.length > 0) {
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
      <h3 className="font-medium text-slate-800 dark:text-slate-200">
        {row.def?.name ?? row.entry.code}
      </h3>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {row.kind === "consumable" ? (
          <>
            <Field label={t("limits.monthly")}>
              <input
                className={input}
                type="number"
                value={numValue("monthly")}
                onChange={(e) => setNum("monthly", e.target.value)}
              />
            </Field>
            {row.def?.overuse && (
              <Field label={t("limits.overuse")}>
                <input
                  className={input}
                  type="number"
                  value={numValue("overuse")}
                  onChange={(e) => setNum("overuse", e.target.value)}
                />
              </Field>
            )}
            {row.def?.daily && (
              <Field label={t("limits.daily")}>
                <input
                  className={input}
                  type="number"
                  value={numValue("daily")}
                  onChange={(e) => setNum("daily", e.target.value)}
                />
              </Field>
            )}
          </>
        ) : (
          <Field label={t("limits.max")}>
            <input
              className={input}
              type="number"
              value={numValue("max")}
              onChange={(e) => setNum("max", e.target.value)}
            />
          </Field>
        )}
      </div>

      {warnings.length > 0 && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-300">
          <ul className="list-disc space-y-0.5 pl-4">
            {warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex gap-2">
        <button className={primaryButton} disabled={saving} onClick={() => void save()}>
          {t("limits.save")}
        </button>
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
  name,
  onDone,
  onCancel,
  onError,
}: {
  tenantId: string;
  code: string;
  name: string;
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
      <h3 className="font-medium text-slate-800 dark:text-slate-200">{name}</h3>
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

/** A limit's transaction ledger, newest-first and paged via `nextCursor`. */
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

  return (
    <div className="space-y-4">
      <h3 className="font-medium text-slate-800 dark:text-slate-200">{t("limits.ledgerTitle")}</h3>
      {entries === null ? (
        <Loader />
      ) : entries.length === 0 ? (
        <p className="text-sm text-slate-500">{t("limits.noLedger")}</p>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-700">
                  <th className={th}>{t("limits.when")}</th>
                  <th className={th}>{t("limits.type")}</th>
                  <th className={th}>{t("limits.amount")}</th>
                  <th className={th}>{t("limits.resulting")}</th>
                  <th className={th}>{t("limits.actor")}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.id} className="border-b border-slate-100 dark:border-slate-700/50">
                    <td className={`${td} whitespace-nowrap`}>{formatDateTime(e.timestamp)}</td>
                    <td className={td}>{e.type}</td>
                    <td className={td}>{e.gaugeValue != null ? e.gaugeValue : e.amount}</td>
                    <td className={`${td} whitespace-nowrap font-mono text-xs`}>
                      {e.resultingMonthly} · {e.resultingCustom} · {e.resultingOveruse}
                    </td>
                    <td className={td}>{e.actorUserName || e.actorUserId || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {cursor && (
            <button
              type="button"
              className="text-sm text-primary hover:underline disabled:opacity-50"
              disabled={busy}
              onClick={() => void loadMore()}
            >
              {t("common.loadMore")}
            </button>
          )}
        </>
      )}
      <BackButton onClick={onBack} />
    </div>
  );
}

/** A limit's month-by-month usage history, the most recent {@link HISTORY_MONTHS} months. */
function HistoryView({
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

  return (
    <div className="space-y-4">
      <h3 className="font-medium text-slate-800 dark:text-slate-200">{t("limits.historyTitle")}</h3>
      {months === null ? (
        <Loader />
      ) : months.length === 0 ? (
        <p className="text-sm text-slate-500">{t("limits.noHistory")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={th}>{t("limits.month")}</th>
                <th className={th}>{t("limits.monthlyIncluded")}</th>
                <th className={th}>{t("limits.monthlyUsed")}</th>
                <th className={th}>{t("limits.forfeited")}</th>
                <th className={th}>{t("limits.overuseUsed")}</th>
                <th className={th}>{t("limits.endingBalance")}</th>
              </tr>
            </thead>
            <tbody>
              {months.slice(0, HISTORY_MONTHS).map((m) => (
                <tr
                  key={m.yearMonth}
                  className="border-b border-slate-100 dark:border-slate-700/50"
                >
                  <td className={`${td} whitespace-nowrap font-mono`}>{m.yearMonth}</td>
                  <td className={td}>{m.monthlyIncluded}</td>
                  <td className={td}>{m.monthlyUsed}</td>
                  <td className={td}>{m.monthlyForfeited}</td>
                  <td className={td}>
                    {m.overuseUsed} / {m.overuseLimit}
                  </td>
                  <td className={td}>{m.endingCustomBalance}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <BackButton onClick={onBack} />
    </div>
  );
}

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
