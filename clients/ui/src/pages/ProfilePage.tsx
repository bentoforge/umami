import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { ApiKeyView } from "umami-client";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, Field, errMsg } from "../components";
import { card, dangerButton, ghostButton, input, primaryButton } from "../ui";

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

      <PatsPanel />
    </div>
  );
}

/** Personal access tokens: create (secret shown once), list, revoke — all for the current user. */
function PatsPanel() {
  const { client } = useUmami();
  const [pats, setPats] = useState<ApiKeyView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState("");
  const [busy, setBusy] = useState(false);
  const [freshSecret, setFreshSecret] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setPats(await client.listMyPats());
    } catch (err) {
      setError(errMsg(err));
      setPats([]);
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  const create = async () => {
    setBusy(true);
    setError(null);
    setFreshSecret(null);
    try {
      const res = await client.createMyPat({
        name,
        scopes: scopes
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      });
      setFreshSecret(res.apiKey);
      setName("");
      setScopes("");
      await load();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (pat: ApiKeyView) => {
    if (!window.confirm(`Revoke token "${pat.name}"? Anything using it stops working.`)) return;
    setError(null);
    try {
      await client.deleteMyPat(pat.keyId);
      await load();
    } catch (err) {
      setError(errMsg(err));
    }
  };

  return (
    <section className={card + " space-y-4"}>
      <div>
        <h2 className="font-medium text-slate-800 dark:text-slate-200">Personal access tokens</h2>
        <p className="text-sm text-slate-500">
          Long-lived credentials for CLIs/scripts that act as you. Exchange one at{" "}
          <code>POST /auth/token</code> for a short-lived token. Leave scopes empty for your full
          permissions, or list a subset to narrow it.
        </p>
      </div>

      <Banner tone="error">{error}</Banner>

      {freshSecret && (
        <div className="rounded-lg border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950 p-3">
          <p className="text-xs text-emerald-700 dark:text-emerald-300 mb-1">
            Copy this now — it is shown only once:
          </p>
          <code className="block break-all text-sm text-slate-900 dark:text-slate-100">
            {freshSecret}
          </code>
        </div>
      )}

      <div className="flex flex-wrap items-end gap-3">
        <Field label="Name">
          <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Scopes (comma-separated, optional)">
          <input
            className={input}
            placeholder="write:usage, …"
            value={scopes}
            onChange={(e) => setScopes(e.target.value)}
          />
        </Field>
        <button className={primaryButton} disabled={busy || !name.trim()} onClick={() => void create()}>
          Create token
        </button>
      </div>

      {pats && pats.length > 0 && (
        <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
          {pats.map((pat) => (
            <li key={pat.keyId} className="flex items-center justify-between py-2">
              <div>
                <div className="text-sm font-medium text-slate-900 dark:text-white">{pat.name}</div>
                <div className="text-xs text-slate-400">
                  {pat.scopes.length ? `scopes: ${pat.scopes.join(", ")}` : "full permissions"} ·
                  created {new Date(pat.created).toLocaleDateString()}
                  {pat.lastUsedAt ? ` · last used ${new Date(pat.lastUsedAt).toLocaleDateString()}` : ""}
                </div>
              </div>
              <button className={dangerButton} onClick={() => void revoke(pat)}>
                Revoke
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
