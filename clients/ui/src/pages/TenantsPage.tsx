import type { CustomFieldDef, Tenant } from "@bentoforge/umami-iam";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, DropdownMenu, errMsg, formatDateTime, formatFieldValue } from "../components";
import { card, input, primaryButton, td, th } from "../ui";

/** System-admin screen: search / list tenants. Create opens a dedicated view; the name links to
 * the per-tenant edit view; the row's 3-dot menu impersonates or deletes. */
export function TenantsPage() {
  const { client, me, switchTenant } = useUmami();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [tenants, setTenants] = useState<Tenant[] | null>(null);
  const [defs, setDefs] = useState<CustomFieldDef[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const tableDefs = defs.filter((d) => d.showInTable);

  useEffect(() => {
    client
      .getCustomFields()
      .then((r) => setDefs(r.tenant))
      .catch(() => setDefs([]));
  }, [client]);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await client.listTenants(query.trim() || undefined);
      setTenants(res.tenants);
      setTruncated(res.truncated);
    } catch (err) {
      setError(errMsg(err));
      setTenants([]);
    }
  }, [client, query]);

  // Debounced: reload as the search box changes.
  useEffect(() => {
    const handle = setTimeout(() => void load(), 250);
    return () => clearTimeout(handle);
  }, [load]);

  const onDelete = async (tenant: Tenant) => {
    if (!window.confirm(t("tenants.deleteConfirm", { name: tenant.name }))) {
      return;
    }
    setError(null);
    setNotice(null);
    try {
      await client.deleteTenant(tenant.tenantId);
      setNotice(t("tenants.deleted", { name: tenant.name }));
      await load();
    } catch (err) {
      setError(errMsg(err));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
          {t("tenants.title")}
        </h1>
        <input
          className={`${input} max-w-xs`}
          placeholder={t("tenants.search")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button className={primaryButton} onClick={() => navigate("/tenants/new")}>
          {t("tenants.new")}
        </button>
      </div>

      {error && <Banner tone="error">{error}</Banner>}
      {notice && <Banner tone="ok">{notice}</Banner>}
      {truncated && (
        <p className="text-xs text-amber-600 dark:text-amber-400">
          {t("tenants.truncated", { count: tenants?.length ?? 0 })}
        </p>
      )}

      <section className={`${card} overflow-x-auto`}>
        {tenants === null ? (
          <p className="text-slate-500">{t("tenants.loading")}</p>
        ) : tenants.length === 0 ? (
          <p className="text-slate-500">{t("tenants.empty")}</p>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={th}>{t("tenants.colName")}</th>
                <th className={th}>{t("tenants.colUpdated")}</th>
                {tableDefs.map((def) => (
                  <th key={def.key} className={th}>
                    {def.label}
                  </th>
                ))}
                <th className={`${th} text-right`}>
                  <span className="sr-only">{t("tenants.actions")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {tenants.map((tenant) => (
                <tr
                  key={tenant.tenantId}
                  className="border-b border-slate-100 dark:border-slate-700/50"
                >
                  <td className={td}>
                    <Link
                      to={`/tenants/${encodeURIComponent(tenant.tenantId)}`}
                      className="font-medium text-primary hover:underline"
                    >
                      {tenant.name}
                    </Link>
                    {tenant.tenantId === me?.user.tenantId && (
                      <span className="ml-2 rounded bg-brand/10 text-brand px-1.5 py-0.5 text-[10px] align-middle">
                        {t("tenants.system")}
                      </span>
                    )}
                    <div className="text-xs text-slate-400 font-mono">{tenant.tenantId}</div>
                  </td>
                  <td className={td}>{formatDateTime(tenant.lastUpdated)}</td>
                  {tableDefs.map((def) => (
                    <td key={def.key} className={td}>
                      {formatFieldValue(tenant.customFields[def.key])}
                    </td>
                  ))}
                  <td className={`${td} text-right whitespace-nowrap`}>
                    <DropdownMenu
                      label={t("tenants.actions")}
                      actions={[
                        {
                          label: t("tenants.impersonate"),
                          onSelect: () => void switchTenant(tenant.tenantId, tenant.name),
                        },
                        {
                          label: t("tenants.delete"),
                          danger: true,
                          onSelect: () => void onDelete(tenant),
                        },
                      ]}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
