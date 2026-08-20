import type { AuditEntry, AuditSeverity } from "@bentoforge/umami-iam";
import { useCallback, useEffect, useState } from "react";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, errMsg, formatDateTime } from "../components";
import { card, ghostButton, td, th } from "../ui";

const SEVERITY_STYLE: Record<AuditSeverity, string> = {
  good: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300",
  neutral: "bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300",
  bad: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300",
};

/** Tenant audit trail (admin:tenant), newest first. */
export function AuditPage() {
  const { client, me } = useUmami();
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const tenantId = me?.user.tenantId;

  const load = useCallback(async () => {
    if (!tenantId) return;
    setError(null);
    try {
      setEntries(await client.tenantAudit(tenantId, 250));
    } catch (err) {
      setError(errMsg(err));
      setEntries([]);
    }
  }, [client, tenantId]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">Audit log</h1>
        <button className={ghostButton} onClick={() => void load()}>
          Reload
        </button>
      </div>

      <Banner tone="error">{error}</Banner>

      <section className={`${card} overflow-x-auto`}>
        {entries === null ? (
          <p className="text-slate-500">Loading…</p>
        ) : entries.length === 0 ? (
          <p className="text-slate-500">No audit entries.</p>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={th}>When</th>
                <th className={th}>Severity</th>
                <th className={th}>User</th>
                <th className={th}>Event</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} className="border-b border-slate-100 dark:border-slate-700/50">
                  <td className={`${td} whitespace-nowrap text-slate-500`}>
                    {formatDateTime(e.timestamp)}
                  </td>
                  <td className={td}>
                    <span
                      className={`rounded-full px-2 py-0.5 text-xs font-medium ${SEVERITY_STYLE[e.severity]}`}
                    >
                      {e.severity}
                    </span>
                  </td>
                  <td className={`${td} font-mono text-xs text-slate-400`}>
                    {e.user ? e.user.slice(0, 10) : "—"}
                  </td>
                  <td className={td}>{e.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
