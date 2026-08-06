import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import { card, ghostButton } from "../ui";

/** Profile tab: signed-in user, tenant, decoded permissions, passkey enrolment. */
export function ProfilePage() {
  const { t } = useTranslation();
  const { client, me } = useUmami();
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
    <div className="space-y-6">
      <section className={card}>
        <p className="text-sm text-slate-500">{t("dashboard.signedInAs")}</p>
        <p className="text-xl font-semibold text-slate-900 dark:text-white">{me.user.name}</p>
        <p className="text-slate-500">
          {me.user.username}
          {me.user.email ? ` · ${me.user.email}` : ""}
        </p>
        <dl className="mt-4 grid grid-cols-2 gap-3 text-sm">
          <div>
            <dt className="text-slate-500">{t("dashboard.tenant")}</dt>
            <dd className="text-slate-900 dark:text-white font-medium">
              {me.tenant?.name ?? me.user.tenantId}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">{t("dashboard.role")}</dt>
            <dd className="text-slate-900 dark:text-white font-medium">
              {me.user.roles.join(", ") || "—"}
            </dd>
          </div>
        </dl>
      </section>

      <section className={card}>
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

      <section className={card}>
        <button onClick={() => void onRegisterPasskey()} className={ghostButton}>
          {t("dashboard.registerPasskey")}
        </button>
        {notice && <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">{notice}</p>}
      </section>
    </div>
  );
}
