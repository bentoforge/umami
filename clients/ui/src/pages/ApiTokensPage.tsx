import type { ApiKeyView, ScopeDef } from "@bentoforge/umami-iam";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, DropdownMenu, errMsg, Field, formatDateTime, Loader, Toggle } from "../components";
import { card, ghostButton, input, primaryButton, td, th } from "../ui";

/** Top-aligned cell: `td` bakes in `align-middle`, which a trailing `align-top` won't override. */
const tdTop = td.replace("align-middle", "align-top");

/** Own-tenant screen: manage service keys (M2M machine principals). Personal access tokens live in
 * the profile; this page is for tenant-owned keys exchanged at `POST /auth/token`. */
export function ApiTokensPage() {
  const { client, me } = useUmami();
  const { t } = useTranslation();
  const tenantId = me?.user.tenantId ?? "";
  const [keys, setKeys] = useState<ApiKeyView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [freshSecret, setFreshSecret] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      setKeys(await client.listApiKeys(tenantId));
    } catch (err) {
      setError(errMsg(err));
      setKeys([]);
    }
  }, [client, tenantId]);

  useEffect(() => {
    void load();
  }, [load]);

  const onDelete = async (key: ApiKeyView) => {
    if (!window.confirm(t("apiTokens.deleteConfirm", { name: key.name }))) {
      return;
    }
    setError(null);
    try {
      await client.deleteApiKey(tenantId, key.keyId);
      await load();
    } catch (err) {
      setError(errMsg(err));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
          {t("apiTokens.title")}
        </h1>
        {!creating && (
          <button className={primaryButton} onClick={() => setCreating(true)}>
            {t("apiTokens.new")}
          </button>
        )}
      </div>

      <Banner tone="error">{error}</Banner>

      {freshSecret && (
        <div className="rounded-lg border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950 p-3">
          <p className="text-xs text-emerald-700 dark:text-emerald-300 mb-1">
            {t("apiTokens.secretOnce")}
          </p>
          <code className="block break-all text-sm text-slate-900 dark:text-slate-100">
            {freshSecret}
          </code>
        </div>
      )}

      {creating && (
        <CreateKey
          tenantId={tenantId}
          onDone={async (secret) => {
            setCreating(false);
            setFreshSecret(secret);
            await load();
          }}
          onCancel={() => setCreating(false)}
          onError={setError}
        />
      )}

      <section className={`${card} overflow-x-auto`}>
        {keys === null ? (
          <Loader />
        ) : keys.length === 0 ? (
          <p className="text-slate-500">{t("apiTokens.empty")}</p>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={th}>{t("apiTokens.name")}</th>
                <th className={th}>{t("apiTokens.scopes")}</th>
                <th className={th}>{t("apiTokens.lastUsed")}</th>
                <th className={th}>{t("apiTokens.expires")}</th>
                <th className={`${th} w-0`} />
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.keyId} className="border-b border-slate-100 dark:border-slate-700/50">
                  <td className={`${tdTop}`}>
                    <div className="font-medium text-slate-900 dark:text-white">{key.name}</div>
                    <div className="text-xs text-slate-400 font-mono">{key.keyId}</div>
                  </td>
                  <td className={`${tdTop}`}>
                    <div>{key.scopes.join(", ") || "—"}</div>
                    <div className="text-xs text-slate-400">
                      {key.allowedOrigins.join(", ") || "—"}
                    </div>
                  </td>
                  <td className={`${tdTop} whitespace-nowrap`}>
                    {key.lastUsedAt ? formatDateTime(key.lastUsedAt) : t("apiTokens.neverUsed")}
                  </td>
                  <td className={`${tdTop} whitespace-nowrap`}>
                    {key.expiresAt ? formatDateTime(key.expiresAt) : "—"}
                  </td>
                  <td className={`${tdTop} text-right`}>
                    <DropdownMenu
                      label={t("apiTokens.menu")}
                      actions={[
                        {
                          label: t("apiTokens.delete"),
                          danger: true,
                          onSelect: () => void onDelete(key),
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

function CreateKey({
  tenantId,
  onDone,
  onCancel,
  onError,
}: {
  tenantId: string;
  onDone: (secret: string) => Promise<void>;
  onCancel: () => void;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>([]);
  const [defs, setDefs] = useState<ScopeDef[]>([]);
  const [assignable, setAssignable] = useState<string[]>([]);
  const [origins, setOrigins] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [allowSecretLogin, setAllowSecretLogin] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    client
      .assignableScopes(tenantId)
      .then((r) => setAssignable(r.codes))
      .catch(() => setAssignable([]));
  }, [client, tenantId]);

  useEffect(() => {
    client
      .getConfig()
      .then((c) => setDefs(c.scopes))
      .catch(() => setDefs([]));
  }, [client]);

  // Assignable scopes with their config name/description; any assignable code the catalog no longer
  // defines still shows (labelled by its code) so it is never silently hidden.
  const scopeCatalog: ScopeDef[] = assignable.map(
    (code) => defs.find((d) => d.code === code) ?? { code, name: code },
  );

  const split = (text: string) =>
    text
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

  const reset = () => {
    setName("");
    setScopes([]);
    setOrigins("");
    setExpiresAt("");
    setAllowSecretLogin(false);
  };

  const toggleScope = (code: string) => {
    setScopes((prev) => (prev.includes(code) ? prev.filter((s) => s !== code) : [...prev, code]));
  };

  const submit = async () => {
    setBusy(true);
    onError("");
    try {
      const res = await client.createApiKey(tenantId, {
        name,
        scopes,
        allowSecretLogin,
        allowedOrigins: split(origins),
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : undefined,
      });
      reset();
      await onDone(res.apiKey);
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={`${card} space-y-4`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("apiTokens.newKey")}</h2>

      <Field label={t("apiTokens.name")}>
        <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
      </Field>

      <div>
        <div className="text-sm font-medium text-slate-800 dark:text-slate-200">
          {t("apiTokens.scopes")}
        </div>
        {scopeCatalog.length === 0 ? (
          <p className="mt-1 text-xs text-slate-400">{t("apiTokens.scopesEmpty")}</p>
        ) : (
          <ul className="mt-2 divide-y divide-slate-100 dark:divide-slate-700/50">
            {scopeCatalog.map((def) => (
              <li key={def.code} className="flex items-start gap-3 py-2">
                <div className="pt-0.5">
                  <Toggle
                    checked={scopes.includes(def.code)}
                    disabled={busy}
                    label={def.name}
                    onChange={() => toggleScope(def.code)}
                  />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-slate-900 dark:text-white">
                    {def.name}
                  </div>
                  {def.description && (
                    <div className="text-xs text-slate-400 dark:text-slate-500">
                      {def.description}
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <Field label={t("apiTokens.origins")}>
        <input
          className={input}
          placeholder={t("apiTokens.originsPlaceholder")}
          value={origins}
          onChange={(e) => setOrigins(e.target.value)}
        />
      </Field>

      <Field label={t("apiTokens.expiresAt")}>
        <input
          className={input}
          type="date"
          value={expiresAt}
          onChange={(e) => setExpiresAt(e.target.value)}
        />
      </Field>

      <div className="flex items-start gap-3">
        <div className="pt-0.5">
          <Toggle
            checked={allowSecretLogin}
            disabled={busy}
            label={t("apiTokens.allowSecretLogin")}
            onChange={setAllowSecretLogin}
          />
        </div>
        <div className="min-w-0">
          <div className="text-sm font-medium text-slate-800 dark:text-slate-200">
            {t("apiTokens.allowSecretLogin")}
          </div>
          <div className="text-xs text-slate-400 dark:text-slate-500">
            {t("apiTokens.allowSecretLoginHint")}
          </div>
        </div>
      </div>

      <div className="flex gap-2">
        <button
          className={primaryButton}
          disabled={busy || !name.trim()}
          onClick={() => void submit()}
        >
          {t("apiTokens.create")}
        </button>
        <button
          className={ghostButton}
          disabled={busy}
          onClick={() => {
            reset();
            onCancel();
          }}
        >
          {t("apiTokens.cancel")}
        </button>
      </div>
    </section>
  );
}
