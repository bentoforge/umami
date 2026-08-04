import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";

export function DashboardPage() {
  const { t } = useTranslation();
  const { client, me, signOut } = useUmami();
  const [notice, setNotice] = useState<string | null>(null);
  const claims = client.getClaims();

  if (!me) return null;

  const onRegisterPasskey = async () => {
    setNotice(null);
    try {
      await client.registerPasskey();
      setNotice(t("dashboard.passkeyAdded"));
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="min-h-screen bg-slate-100 dark:bg-slate-900">
      <header className="bg-white dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">
        <div className="mx-auto max-w-3xl px-6 py-4 flex items-center justify-between">
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
      </header>

      <main className="mx-auto max-w-3xl px-6 py-8 space-y-6">
        <section className="rounded-2xl bg-white dark:bg-slate-800 shadow p-6">
          <p className="text-sm text-slate-500">{t("dashboard.signedInAs")}</p>
          <p className="text-xl font-semibold text-slate-900 dark:text-white">{me.user.name}</p>
          <p className="text-slate-500">{me.user.email}</p>
          <dl className="mt-4 grid grid-cols-2 gap-3 text-sm">
            <Row label={t("dashboard.tenant")} value={me.tenant?.name ?? me.user.tenantId} />
            <Row label={t("dashboard.role")} value={me.user.roles.join(", ") || "—"} />
          </dl>
        </section>

        <section className="rounded-2xl bg-white dark:bg-slate-800 shadow p-6">
          <p className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
            {t("dashboard.permissions")}
          </p>
          <div className="flex flex-wrap gap-2">
            {(claims?.permissions ?? []).length === 0 && <span className="text-slate-400">—</span>}
            {(claims?.permissions ?? []).map((p) => (
              <span
                key={p}
                className="rounded-full bg-brand/10 text-brand dark:text-indigo-300 px-3 py-1 text-xs font-medium"
              >
                {p}
              </span>
            ))}
          </div>
        </section>

        <section className="rounded-2xl bg-white dark:bg-slate-800 shadow p-6">
          <button onClick={() => void onRegisterPasskey()} className={ghostButton}>
            {t("dashboard.registerPasskey")}
          </button>
          {notice && <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">{notice}</p>}
        </section>
      </main>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-slate-900 dark:text-white font-medium">{value}</dd>
    </div>
  );
}

const primaryButton = "rounded-lg bg-brand hover:bg-brand-dark text-white text-sm font-medium px-4 py-2";
const ghostButton =
  "rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 text-sm font-medium px-4 py-2 hover:bg-slate-50 dark:hover:bg-slate-700";
