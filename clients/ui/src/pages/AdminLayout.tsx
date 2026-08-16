import { NavLink, Outlet } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import { ghostButton, primaryButton } from "../ui";

/** Authenticated shell: title bar, permission-gated tab nav, and the active route via <Outlet/>. */
export function AdminLayout() {
  const { t } = useTranslation();
  const { client, signOut } = useUmami();
  const can = (permission: string) => client.hasPermission(permission);

  const tabs: { to: string; label: string; show: boolean }[] = [
    { to: "/", label: "Profile", show: true },
    { to: "/tenants", label: "Tenants", show: can("admin:tenant") },
    { to: "/users", label: "Users", show: can("write:members") },
    { to: "/api-tokens", label: "API Tokens", show: can("write:members") },
    { to: "/audit", label: "Audit", show: can("admin:tenant") },
    { to: "/config", label: "Config", show: can("manage:config") },
  ];

  return (
    <div className="min-h-screen bg-slate-100 dark:bg-slate-900">
      <header className="bg-white dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">
        <div className="mx-auto max-w-5xl px-6 py-4 flex items-center justify-between">
          <span className="text-lg font-semibold text-slate-900 dark:text-white">
            {t("app.title")}
          </span>
          <div className="flex gap-2">
            <button onClick={() => void client.logoutAll()} className={ghostButton}>
              {t("dashboard.logoutAll")}
            </button>
            <button onClick={() => void signOut()} className={primaryButton}>
              {t("dashboard.logout")}
            </button>
          </div>
        </div>
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

      <main className="mx-auto max-w-5xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
