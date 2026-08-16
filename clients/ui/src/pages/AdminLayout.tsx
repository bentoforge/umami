import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { Tenant } from "umami-client";
import { useUmami } from "../auth/UmamiProvider";
import { errMsg } from "../components";
import { card, ghostButton, input, primaryButton } from "../ui";

/** Authenticated shell: title bar, permission-gated tab nav, tenant switcher, and the active route. */
export function AdminLayout() {
  const { t } = useTranslation();
  const { client, me, signOut, activeTenantId, activeTenantName } = useUmami();
  const can = (permission: string) => client.hasPermission(permission);

  const homeTenantId = me?.user.tenantId;
  const switched = !!activeTenantId && activeTenantId !== homeTenantId;

  const tabs: { to: string; label: string; show: boolean }[] = [
    { to: "/", label: "Profile", show: true },
    { to: "/tenants", label: "Tenants", show: can("manage:tenants") },
    { to: "/users", label: "Users", show: can("manage:users") },
    { to: "/api-tokens", label: "API Tokens", show: can("manage:service-keys") },
    { to: "/audit", label: "Audit", show: can("admin:tenant") },
    { to: "/config", label: "Config", show: can("manage:config") },
  ];

  return (
    <div className="min-h-screen bg-slate-100 dark:bg-slate-900">
      <header className="bg-white dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">
        <div className="mx-auto max-w-5xl px-6 py-4 flex items-center justify-between gap-3">
          {/* Swappable logo (config `branding.logoLight`/`logoDark`); the browser picks by theme. */}
          <picture>
            <source srcSet="/app/logo/dark" media="(prefers-color-scheme: dark)" />
            <img src="/app/logo/light" alt={t("app.title")} className="h-8 w-auto" />
          </picture>
          <div className="flex items-center gap-2">
            {can("switch:tenant") && <TenantSwitcher />}
            <button onClick={() => void client.logoutAll()} className={ghostButton}>
              {t("dashboard.logoutAll")}
            </button>
            <button onClick={() => void signOut()} className={primaryButton}>
              {t("dashboard.logout")}
            </button>
          </div>
        </div>
        {switched && (
          <div className="bg-amber-50 dark:bg-amber-950/40 border-t border-amber-200 dark:border-amber-900">
            <div className="mx-auto max-w-5xl px-6 py-1.5 text-xs text-amber-700 dark:text-amber-300">
              Viewing tenant <strong>{activeTenantName ?? activeTenantId}</strong> — you are acting as
              a system admin.
            </div>
          </div>
        )}
        <nav className="mx-auto max-w-5xl px-6 flex gap-1">
          {tabs
            .filter((tab) => tab.show)
            .map((tab) => (
              <NavLink
                key={tab.to}
                to={tab.to}
                end={tab.to === "/"}
                className={({ isActive }) =>
                  `px-4 py-2 text-sm font-medium border-b-2 -mb-px ${
                    isActive
                      ? "border-brand text-brand dark:text-indigo-300"
                      : "border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
                  }`
                }
              >
                {tab.label}
              </NavLink>
            ))}
        </nav>
      </header>

      {/* Keyed on the active tenant so a switch remounts the pages → they refetch against the new
          token without a full reload (a reload would silently refresh back to the home tenant). */}
      <main key={activeTenantId ?? "none"} className="mx-auto max-w-5xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}

/** Top-right dropdown: search tenants (5 shown, newest-updated first) and switch into one. */
function TenantSwitcher() {
  const { client, me, activeTenantId, switchTenant } = useUmami();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Tenant[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  const homeTenantId = me?.user.tenantId;
  const switched = !!activeTenantId && activeTenantId !== homeTenantId;

  // Close on outside click.
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  // Debounced search whenever the dropdown is open.
  useEffect(() => {
    if (!open) return;
    const handle = setTimeout(async () => {
      setError(null);
      try {
        const res = await client.listTenants(query.trim() || undefined);
        setResults(res.tenants.slice(0, 5));
      } catch (err) {
        setError(errMsg(err));
        setResults([]);
      }
    }, 200);
    return () => clearTimeout(handle);
  }, [open, query, client]);

  const pick = async (tenant: Tenant) => {
    setBusy(true);
    setError(null);
    try {
      await switchTenant(tenant.tenantId, tenant.name);
      setOpen(false);
      setQuery("");
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative" ref={boxRef}>
      <button className={ghostButton} onClick={() => setOpen((v) => !v)}>
        Switch tenant
      </button>
      {open && (
        <div
          className={
            card + " absolute right-0 mt-2 w-80 z-20 p-3 space-y-2 shadow-lg max-h-96 overflow-auto"
          }
        >
          <input
            autoFocus
            className={input}
            placeholder="Search tenants…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          {error && <p className="text-xs text-red-600 dark:text-red-400">{error}</p>}
          {switched && homeTenantId && (
            <button
              disabled={busy}
              onClick={() => void pick({ tenantId: homeTenantId, name: "home tenant" } as Tenant)}
              className="w-full text-left rounded-lg px-3 py-2 text-sm text-brand hover:bg-slate-50 dark:hover:bg-slate-700"
            >
              ← Back to home tenant
            </button>
          )}
          {results.length === 0 ? (
            <p className="text-xs text-slate-400 px-1">No matching tenants.</p>
          ) : (
            <ul className="space-y-0.5">
              {results.map((tenant) => (
                <li key={tenant.tenantId}>
                  <button
                    disabled={busy}
                    onClick={() => void pick(tenant)}
                    className={`w-full text-left rounded-lg px-3 py-2 text-sm hover:bg-slate-50 dark:hover:bg-slate-700 ${
                      tenant.tenantId === activeTenantId
                        ? "text-brand"
                        : "text-slate-700 dark:text-slate-200"
                    }`}
                  >
                    <div className="font-medium">{tenant.name}</div>
                    <div className="text-xs text-slate-400 font-mono">{tenant.tenantId}</div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
