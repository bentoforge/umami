import type { AuditEntry, AuditSeverity } from "@bentoforge/umami-iam";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, errMsg, formatDateTime } from "../components";
import { card, ghostButton, td, th } from "../ui";

/** Entries fetched per page (and per "load more"). */
const PAGE = 250;

/** Severity "Bobbel" — the small colored dot, same palette as the per-user audit list. */
const SEVERITY_DOT: Record<AuditSeverity, string> = {
  good: "bg-emerald-500",
  neutral: "bg-slate-400",
  bad: "bg-red-500",
};

/** Tenant audit trail (admin:tenant), newest first, paged with a "load more" button. */
export function AuditPage() {
  const { client, me } = useUmami();
  const { t } = useTranslation();
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const tenantId = me?.user.tenantId;

  const load = useCallback(async () => {
    if (!tenantId) return;
    setError(null);
    try {
      const page = await client.tenantAudit(tenantId, PAGE);
      setEntries(page.entries);
      setCursor(page.nextCursor);
    } catch (err) {
      setError(errMsg(err));
      setEntries([]);
    }
  }, [client, tenantId]);

  useEffect(() => {
    void load();
  }, [load]);

  const loadMore = async () => {
    if (!tenantId || !cursor) return;
    setBusy(true);
    setError(null);
    try {
      const page = await client.tenantAudit(tenantId, PAGE, cursor);
      setEntries((prev) => [...(prev ?? []), ...page.entries]);
      setCursor(page.nextCursor);
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">{t("audit.title")}</h1>
        <button className={ghostButton} onClick={() => void load()}>
          {t("audit.reload")}
        </button>
      </div>

      <Banner tone="error">{error}</Banner>

      <section className={`${card} overflow-x-auto`}>
        {entries === null ? (
          <p className="text-slate-500">{t("common.loading")}</p>
        ) : entries.length === 0 ? (
          <p className="text-slate-500">{t("audit.empty")}</p>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={`${th} w-0 align-bottom`}>
                  <span className="sr-only">{t("audit.severity")}</span>
                </th>
                <th className={`${th} align-bottom`}>
                  <div>{t("audit.when")}</div>
                  <div className="text-[10px] font-normal text-slate-400">
                    {t("audit.ip")} · {t("audit.userId")}
                  </div>
                </th>
                <th className={`${th} align-bottom`}>{t("audit.event")}</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => {
                const meta = [e.ip, e.user ? e.user.slice(0, 10) : null]
                  .filter(Boolean)
                  .join(" · ");
                return (
                  <tr key={e.id} className="border-b border-slate-100 dark:border-slate-700/50">
                    <td className={`${td} align-top`}>
                      <span
                        className={`mt-1.5 inline-block h-2.5 w-2.5 shrink-0 rounded-full ${SEVERITY_DOT[e.severity] ?? SEVERITY_DOT.neutral}`}
                      />
                    </td>
                    <td className={`${td} whitespace-nowrap align-top`}>
                      <div className="text-slate-700 dark:text-slate-200">
                        {formatDateTime(e.timestamp)}
                      </div>
                      <div className="font-mono text-xs text-slate-400">{meta || "—"}</div>
                    </td>
                    <td className={`${td} align-top`}>{e.message}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>

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
    </div>
  );
}
