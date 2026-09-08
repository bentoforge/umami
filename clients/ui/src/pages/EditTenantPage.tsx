import type {
  CatalogueEntry,
  CustomFieldView,
  LedgerEntry,
  LimitCatalogueEntry,
  LimitEntry,
  LimitHistoryRow,
  LimitSettings,
  Tenant,
} from "@bentoforge/umami-iam";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate, useParams } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import {
  Banner,
  CustomFieldsForm,
  DropdownMenu,
  errMsg,
  Field,
  formatDateTime,
  formatFieldValue,
  Loader,
  Tag,
  Toggle,
} from "../components";
import { card, ghostButton, input, primaryButton, td, th } from "../ui";

/** Per-tenant edit view: a details card (read + inline edit), a features card, and an in-app Back. */
export function EditTenantPage() {
  const { client, me, activeTenantId, switchTenant } = useUmami();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { tenantId = "" } = useParams();

  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [defs, setDefs] = useState<CustomFieldView[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);

  // The system tenant (home) and the tenant currently being acted in must not be deletable.
  const homeTenantId = me?.user.tenantId;
  const currentTenantId = activeTenantId ?? homeTenantId;
  const isProtected = (id: string) => id === homeTenantId || id === currentTenantId;

  const reload = useCallback(async () => {
    setError(null);
    try {
      setTenant(await client.getTenant(tenantId));
    } catch (err) {
      setError(errMsg(err));
      setMissing(true);
    }
  }, [client, tenantId]);

  useEffect(() => {
    void reload();
  }, [reload]);

  useEffect(() => {
    client
      .getCustomFields()
      .then((r) => setDefs(r.tenant))
      .catch(() => setDefs([]));
  }, [client]);

  const onDelete = async () => {
    if (!tenant || !window.confirm(t("tenants.deleteConfirm", { name: tenant.name }))) {
      return;
    }
    try {
      await client.deleteTenant(tenant.tenantId);
      navigate("/tenants");
    } catch (err) {
      setError(errMsg(err));
    }
  };

  // Back that stays inside our SPA history (never bounces to another site / the login page).
  const goBack = () => {
    const idx = (window.history.state as { idx?: number } | null)?.idx ?? 0;
    if (idx > 0) {
      navigate(-1);
    } else {
      navigate("/tenants");
    }
  };

  if (missing) {
    return (
      <div className="space-y-4">
        <Banner tone="error">{error ?? t("tenants.notFound")}</Banner>
        <button className={ghostButton} onClick={goBack}>
          {t("tenants.back")}
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
          {t("tenants.editTitle")}
        </h1>
        {tenant && (
          <DropdownMenu
            label={t("tenants.actions")}
            triggerLabel={t("common.moreActions")}
            actions={[
              {
                label: t("tenants.impersonate"),
                onSelect: () => void switchTenant(tenant.tenantId, tenant.name),
              },
              ...(isProtected(tenant.tenantId)
                ? []
                : [
                    {
                      label: t("tenants.delete"),
                      danger: true,
                      onSelect: () => void onDelete(),
                    },
                  ]),
            ]}
          />
        )}
      </div>

      {error && <Banner tone="error">{error}</Banner>}
      {notice && <Banner tone="ok">{notice}</Banner>}

      {tenant === null ? (
        <Loader />
      ) : (
        <>
          <DetailsCard
            tenant={tenant}
            defs={defs}
            onSaved={async () => {
              setNotice(t("tenants.saved"));
              await reload();
            }}
            onError={setError}
          />
          <FeaturesCard tenant={tenant} onChanged={reload} onError={setError} />
          {client.hasPermission("manage:limits") && (
            <LimitsCard tenant={tenant} onError={setError} />
          )}
          <MetaBox tenant={tenant} />
        </>
      )}

      <button className={ghostButton} onClick={goBack}>
        {t("tenants.back")}
      </button>
    </div>
  );
}

/** Read-only detail rows with an Edit toggle that turns Name + custom fields into inputs. Dates and
 * the ID are never editable. */
function DetailsCard({
  tenant,
  defs,
  onSaved,
  onError,
}: {
  tenant: Tenant;
  defs: CustomFieldView[];
  onSaved: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(tenant.name);
  const [fields, setFields] = useState<Record<string, unknown>>({ ...tenant.customFields });
  const [saving, setSaving] = useState(false);

  // Reset the draft whenever the underlying tenant reloads.
  useEffect(() => {
    setName(tenant.name);
    setFields({ ...tenant.customFields });
  }, [tenant]);

  const cancel = () => {
    setName(tenant.name);
    setFields({ ...tenant.customFields });
    setEditing(false);
  };

  const save = async () => {
    setSaving(true);
    onError("");
    try {
      await client.patchTenant(tenant.tenantId, { name, customFields: fields });
      setEditing(false);
      await onSaved();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className={`${card} space-y-4`}>
      <div className="flex items-center justify-between">
        <h2 className="font-medium text-slate-800 dark:text-slate-200">
          {t("tenants.detailsTitle")}
        </h2>
        {!editing && (
          <button className={ghostButton} onClick={() => setEditing(true)}>
            {t("tenants.edit")}
          </button>
        )}
      </div>

      {editing ? (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label={t("tenants.nameLabel")}>
              <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <CustomFieldsForm defs={defs} values={fields} onChange={setFields} />
          </div>
          <div className="flex gap-2">
            <button className={primaryButton} disabled={saving} onClick={() => void save()}>
              {t("tenants.save")}
            </button>
            <button className={ghostButton} disabled={saving} onClick={cancel}>
              {t("tenants.cancel")}
            </button>
          </div>
        </>
      ) : (
        <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
          <DetailRow label={t("tenants.nameLabel")}>{tenant.name}</DetailRow>
          {defs.map((def) => (
            <DetailRow key={def.code} label={def.label}>
              {formatFieldValue(tenant.customFields[def.code])}
            </DetailRow>
          ))}
        </dl>
      )}
    </section>
  );
}

/** Muted gray box with the read-only system metadata: ID, last active, last updated, created.
 * Two columns on desktop, one below. */
function MetaBox({ tenant }: { tenant: Tenant }) {
  const { t } = useTranslation();
  const rows: { label: string; value: ReactNode }[] = [
    {
      label: t("tenants.id"),
      value: <span className="font-mono text-xs break-all">{tenant.tenantId}</span>,
    },
    {
      label: t("tenants.lastActive"),
      value: tenant.lastActive ? formatDateTime(tenant.lastActive) : "—",
    },
    { label: t("tenants.updatedAt"), value: formatDateTime(tenant.lastUpdated) },
    { label: t("tenants.createdAt"), value: formatDateTime(tenant.created) },
  ];
  return (
    <section className="rounded border border-slate-200 dark:border-slate-700/50 bg-slate-200/60 dark:bg-slate-950/50 p-6">
      <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-3">
        {rows.map((row) => (
          <div key={row.label}>
            <dt className="text-xs text-slate-400">{row.label}</dt>
            <dd className="text-sm text-slate-600 dark:text-slate-300">{row.value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-slate-800 dark:text-slate-200">{children}</dd>
    </>
  );
}

/** Grant/revoke a tenant's authorization features (`feature:*`) as a toggle list: a switch on the
 * left, the feature's name in bold, and its description (or code) muted below. A feature that is
 * neither granted nor currently grantable (unmet prerequisite) shows as a disabled switch. */
function FeaturesCard({
  tenant,
  onChanged,
  onError,
}: {
  tenant: Tenant;
  onChanged: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [defs, setDefs] = useState<CatalogueEntry[]>([]);
  const [grantable, setGrantable] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    client
      .catalogue()
      .then((c) => setDefs(c.features))
      .catch(() => setDefs([]));
  }, [client]);

  const loadGrantable = useCallback(() => {
    client
      .assignableFeatures(tenant.tenantId)
      .then((r) => setGrantable(r.codes))
      .catch(() => setGrantable([]));
  }, [client, tenant.tenantId]);

  useEffect(() => loadGrantable(), [loadGrantable]);

  const toggle = async (code: string, granted: boolean) => {
    setBusy(true);
    onError("");
    try {
      if (granted) {
        await client.revokeFeature(tenant.tenantId, code);
      } else {
        await client.grantFeature(tenant.tenantId, code);
      }
      await onChanged();
      loadGrantable();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  // The catalog, plus any already-granted code the catalog no longer defines (never hide a grant).
  const catalog: CatalogueEntry[] = [
    ...defs,
    ...tenant.features
      .filter((code) => !defs.some((d) => d.code === code))
      .map((code) => ({ code, name: code })),
  ];

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">
        {t("tenants.featuresTitle")}
      </h2>
      {catalog.length === 0 ? (
        <span className="text-xs text-slate-400">{t("tenants.featuresNone")}</span>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
          {catalog.map((def) => {
            const granted = tenant.features.includes(def.code);
            const canToggle = granted || grantable.includes(def.code);
            const subtitle = def.description || def.code;
            return (
              <li key={def.code} className="flex items-start gap-3 py-3">
                <div className="pt-0.5">
                  <Toggle
                    checked={granted}
                    disabled={busy || !canToggle}
                    label={def.name}
                    onChange={() => void toggle(def.code, granted)}
                  />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-slate-900 dark:text-white">
                    {def.name}
                  </div>
                  {subtitle && (
                    <div className="text-xs text-slate-400 dark:text-slate-500">{subtitle}</div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

const LEDGER_PAGE = 10;

/** Per-tenant quotas: every catalogue limit is shown (so an admin can configure one not yet set),
 * merged by `code` with the tenant's own settings + live state. Each row is a {@link LimitRow}. */
function LimitsCard({ tenant, onError }: { tenant: Tenant; onError: (msg: string) => void }) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [defs, setDefs] = useState<LimitCatalogueEntry[] | null>(null);
  const [entries, setEntries] = useState<LimitEntry[]>([]);

  useEffect(() => {
    client
      .catalogue()
      .then((c) => setDefs(c.limits))
      .catch(() => setDefs([]));
  }, [client]);

  const loadLimits = useCallback(() => {
    client
      .getTenantLimits(tenant.tenantId)
      .then((r) => setEntries(r.limits))
      .catch((err) => onError(errMsg(err)));
  }, [client, tenant.tenantId, onError]);

  useEffect(() => loadLimits(), [loadLimits]);

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("limits.title")}</h2>
      {defs === null ? (
        <Loader />
      ) : entries.length === 0 ? (
        <span className="text-xs text-slate-400">{t("limits.none")}</span>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
          {entries.map((entry) => {
            const def = defs.find((d) => d.code === entry.code);
            return def ? (
              <LimitRow
                key={entry.code}
                tenantId={tenant.tenantId}
                def={def}
                entry={entry}
                onChanged={loadLimits}
                onError={onError}
              />
            ) : (
              <OrphanedLimitRow
                key={entry.code}
                tenantId={tenant.tenantId}
                entry={entry}
                onChanged={loadLimits}
                onError={onError}
              />
            );
          })}
        </ul>
      )}
    </section>
  );
}

/** One limit's editor: settings inputs shaped by `kind`/facets, its live state read out beside
 * them, a Save (surfacing the server's capping `warnings`), a top-up control for a consumable with
 * a custom balance, and an expandable ledger + history. */
function LimitRow({
  tenantId,
  def,
  entry,
  onChanged,
  onError,
}: {
  tenantId: string;
  def: LimitCatalogueEntry;
  entry?: LimitEntry;
  onChanged: () => void;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [settings, setSettings] = useState<LimitSettings>(entry?.settings ?? {});
  const [saving, setSaving] = useState(false);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [topup, setTopup] = useState("");
  const [expanded, setExpanded] = useState(false);

  // Reset the draft whenever the tenant's limits reload.
  useEffect(() => setSettings(entry?.settings ?? {}), [entry]);

  const state = entry?.state;
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
      const res = await client.setTenantLimitSettings(tenantId, def.code, settings);
      setWarnings(res.warnings ?? []);
      onChanged();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setSaving(false);
    }
  };

  const doTopup = async () => {
    const amount = Number(topup);
    if (topup === "" || Number.isNaN(amount)) {
      return;
    }
    setSaving(true);
    onError("");
    try {
      await client.topupLimit(tenantId, def.code, amount);
      setTopup("");
      onChanged();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setSaving(false);
    }
  };

  // Gauge watermark: colour the live reading by how close it sits to the configured ceiling.
  const gaugeTone = (): "danger" | "warn" | "neutral" => {
    if (settings.max == null || state?.gaugeValue == null || settings.max === 0) {
      return "neutral";
    }
    const percent = (state.gaugeValue / settings.max) * 100;
    if (def.highWatermarkPercent != null && percent >= def.highWatermarkPercent) {
      return "danger";
    }
    if (def.lowWatermarkPercent != null && percent >= def.lowWatermarkPercent) {
      return "warn";
    }
    return "neutral";
  };

  return (
    <li className="space-y-3 py-4">
      <div>
        <div className="text-sm font-semibold text-slate-900 dark:text-white">{def.name}</div>
        <div className="text-xs text-slate-400 dark:text-slate-500">
          {def.description || def.code}
        </div>
      </div>

      {def.kind === "consumable" ? (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Field label={t("limits.monthly")}>
              <input
                className={input}
                type="number"
                value={numValue("monthly")}
                onChange={(e) => setNum("monthly", e.target.value)}
              />
            </Field>
            {def.overuse && (
              <Field label={t("limits.overuse")}>
                <input
                  className={input}
                  type="number"
                  value={numValue("overuse")}
                  onChange={(e) => setNum("overuse", e.target.value)}
                />
              </Field>
            )}
            {def.daily && (
              <Field label={t("limits.daily")}>
                <input
                  className={input}
                  type="number"
                  value={numValue("daily")}
                  onChange={(e) => setNum("daily", e.target.value)}
                />
              </Field>
            )}
          </div>
          {state && (
            <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
              <StateFigure label={t("limits.monthlyRemaining")} value={state.monthlyRemaining} />
              {def.overuse && (
                <StateFigure label={t("limits.overuseRemaining")} value={state.overuseRemaining} />
              )}
              {def.customBalance && (
                <StateFigure label={t("limits.customBalance")} value={state.customBalance} />
              )}
              {def.daily && state.dailyRemaining != null && (
                <StateFigure label={t("limits.dailyRemaining")} value={state.dailyRemaining} />
              )}
            </div>
          )}
        </>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Field label={t("limits.max")}>
              <input
                className={input}
                type="number"
                value={numValue("max")}
                onChange={(e) => setNum("max", e.target.value)}
              />
            </Field>
          </div>
          {state?.gaugeValue != null && (
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <span>{t("limits.gaugeValue")}</span>
              <Tag tone={gaugeTone()}>
                {settings.max != null
                  ? `${state.gaugeValue} / ${settings.max}`
                  : String(state.gaugeValue)}
              </Tag>
            </div>
          )}
        </>
      )}

      {warnings.length > 0 && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-300">
          <ul className="list-disc space-y-0.5 pl-4">
            {warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <button className={primaryButton} disabled={saving} onClick={() => void save()}>
          {t("limits.save")}
        </button>
        {def.kind === "consumable" && def.customBalance && (
          <div className="flex items-center gap-2">
            <input
              className={`${input} w-28`}
              type="number"
              placeholder={t("limits.topupPlaceholder")}
              value={topup}
              onChange={(e) => setTopup(e.target.value)}
            />
            <button className={ghostButton} disabled={saving} onClick={() => void doTopup()}>
              {t("limits.topup")}
            </button>
          </div>
        )}
        <button
          type="button"
          className="text-sm text-primary hover:underline"
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded ? t("limits.hideActivity") : t("limits.showActivity")}
        </button>
      </div>

      {expanded && <LimitDetails tenantId={tenantId} code={def.code} />}
    </li>
  );
}

/** A limit stored on the tenant whose definition has been removed from the config — shown only so an
 * admin can clean it up. No typed inputs (there is no definition to shape them), just a Remove. */
function OrphanedLimitRow({
  tenantId,
  entry,
  onChanged,
  onError,
}: {
  tenantId: string;
  entry: LimitEntry;
  onChanged: () => void;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [removing, setRemoving] = useState(false);

  const remove = async () => {
    setRemoving(true);
    try {
      await client.setTenantLimitSettings(tenantId, entry.code, {});
      onChanged();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setRemoving(false);
    }
  };

  return (
    <li className="flex flex-wrap items-center justify-between gap-2 py-4">
      <div>
        <div className="text-sm font-semibold text-slate-900 dark:text-white">{entry.code}</div>
        <div className="text-xs text-slate-400 dark:text-slate-500">{t("limits.orphaned")}</div>
      </div>
      <button className={ghostButton} disabled={removing} onClick={() => void remove()}>
        {t("limits.remove")}
      </button>
    </li>
  );
}

/** One "label: value" live-state figure, laid out inline. */
function StateFigure({ label, value }: { label: string; value: number }) {
  return (
    <span>
      {label}: <span className="font-medium text-slate-700 dark:text-slate-200">{value}</span>
    </span>
  );
}

/** A limit's transaction ledger (paged, newest-first) and its month-by-month history, loaded when
 * the row is expanded. */
function LimitDetails({ tenantId, code }: { tenantId: string; code: string }) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [entries, setEntries] = useState<LedgerEntry[] | null>(null);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [months, setMonths] = useState<LimitHistoryRow[] | null>(null);
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
    <div className="space-y-4 rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900/40">
      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
          {t("limits.historyTitle")}
        </h3>
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
                  <th className={th}>{t("limits.monthlyUsed")}</th>
                  <th className={th}>{t("limits.monthlyIncluded")}</th>
                  <th className={th}>{t("limits.forfeited")}</th>
                  <th className={th}>{t("limits.overuseUsed")}</th>
                  <th className={th}>{t("limits.endingBalance")}</th>
                </tr>
              </thead>
              <tbody>
                {months.map((m) => (
                  <tr
                    key={m.yearMonth}
                    className="border-b border-slate-100 dark:border-slate-700/50"
                  >
                    <td className={`${td} whitespace-nowrap font-mono`}>{m.yearMonth}</td>
                    <td className={td}>{m.monthlyUsed}</td>
                    <td className={td}>{m.monthlyIncluded}</td>
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
      </div>

      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
          {t("limits.ledgerTitle")}
        </h3>
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
                className="mt-2 text-sm text-primary hover:underline disabled:opacity-50"
                disabled={busy}
                onClick={() => void loadMore()}
              >
                {t("common.loadMore")}
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}
