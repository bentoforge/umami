import type { ApiKeyView, CatalogueEntry } from "@bentoforge/umami-iam";
import { ChartBarIcon, TrashIcon } from "@heroicons/react/24/outline";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, DropdownMenu, errMsg, Field, formatDateTime, Loader, Toggle } from "../components";
import { RateLimitDetails } from "../ratelimit";
import { card, ghostButton, input, primaryButton, td, th } from "../ui";

/** Top-aligned cell: `td` bakes in `align-middle`, which a trailing `align-top` won't override. */
const tdTop = td.replace("align-middle", "align-top");

/** Own-tenant screen: manage service keys (M2M machine principals). Personal access tokens live in
 * the profile; this page is for tenant-owned keys exchanged at `POST /auth/token`. */
export function ServiceKeysPage() {
  const { client, me } = useUmami();
  const { t } = useTranslation();
  const tenantId = me?.user.tenantId ?? "";
  const [keys, setKeys] = useState<ApiKeyView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [freshSecret, setFreshSecret] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [scopeDefs, setScopeDefs] = useState<CatalogueEntry[]>([]);
  // The rate-limit panel is opened from the row's menu, so its state lives with the row: one key
  // at a time, which also keeps the table from growing several meters at once.
  const [meterFor, setMeterFor] = useState<string | null>(null);

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

  // Scope codes are for machines; a screen shows the catalogue's words for them.
  useEffect(() => {
    client
      .catalogue()
      .then((c) => setScopeDefs(c.scopes))
      .catch(() => setScopeDefs([]));
  }, [client]);

  const scopeLabel = (code: string) => scopeDefs.find((d) => d.code === code)?.name ?? code;

  const onDelete = async (key: ApiKeyView) => {
    if (!window.confirm(t("serviceKeys.deleteConfirm", { name: key.name }))) {
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
          {t("serviceKeys.title")}
        </h1>
        {!creating && (
          <button className={primaryButton} onClick={() => setCreating(true)}>
            {t("serviceKeys.new")}
          </button>
        )}
      </div>

      <Banner tone="error">{error}</Banner>

      {freshSecret && (
        <div className="rounded-lg border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950 p-3">
          <p className="text-xs text-emerald-700 dark:text-emerald-300 mb-1">
            {t("serviceKeys.secretOnce")}
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
          <p className="text-slate-500">{t("serviceKeys.empty")}</p>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={th}>{t("serviceKeys.name")}</th>
                {/* Each header names both of its lines, in the order the cell prints them —
                    otherwise the muted second line is a value without a question. */}
                <th className={th}>
                  <StackedHeader
                    main={t("serviceKeys.scopes")}
                    second={t("serviceKeys.allowedOrigins")}
                  />
                </th>
                <th className={th}>
                  <StackedHeader
                    main={t("serviceKeys.lastUsed")}
                    second={t("serviceKeys.expires")}
                  />
                </th>
                <th className={`${th} w-0`} />
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.keyId} className="border-b border-slate-100 dark:border-slate-700/50">
                  <td className={`${tdTop}`}>
                    <div className="font-medium text-slate-900 dark:text-white">{key.name}</div>
                    <div className="text-xs text-slate-400 font-mono">{key.keyId}</div>
                    {/* The override is on the key itself, so flagging it costs no extra request —
                        the meter behind the disclosure then shows the values it resolves to. */}
                    {key.rateLimit && (
                      <div className="mt-1 inline-block rounded bg-slate-100 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-slate-500 dark:bg-slate-700 dark:text-slate-300">
                        {t("rateLimits.override")}
                      </div>
                    )}
                    {meterFor === key.keyId && (
                      <div className="mt-2 max-w-md">
                        <RateLimitDetails target={{ kind: "apiKey", tenantId, keyId: key.keyId }} />
                      </div>
                    )}
                  </td>
                  <td className={tdTop}>
                    <div>{key.scopes.map(scopeLabel).join(", ") || "—"}</div>
                    {/* Muted, not smaller: grey already costs contrast, and shrinking it on top
                        is where readability goes. */}
                    <div className="text-slate-400">{key.allowedOrigins.join(", ") || "—"}</div>
                  </td>
                  <td className={`${tdTop} whitespace-nowrap`}>
                    <div>
                      {key.lastUsedAt ? formatDateTime(key.lastUsedAt) : t("serviceKeys.neverUsed")}
                    </div>
                    <div className="text-slate-400">
                      {key.expiresAt ? formatDateTime(key.expiresAt) : "—"}
                    </div>
                  </td>
                  <td className={`${tdTop} text-right`}>
                    <DropdownMenu
                      label={t("serviceKeys.menu")}
                      actions={[
                        {
                          label:
                            meterFor === key.keyId ? t("rateLimits.hide") : t("rateLimits.show"),
                          icon: ChartBarIcon,
                          onSelect: () =>
                            setMeterFor((open) => (open === key.keyId ? null : key.keyId)),
                        },
                        {
                          label: t("serviceKeys.delete"),
                          danger: true,
                          icon: TrashIcon,
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

/** A column header over a two-line cell: the main label, and the muted one below it. */
function StackedHeader({ main, second }: { main: string; second: string }) {
  return (
    <>
      <div>{main}</div>
      <div className="font-normal text-slate-400">{second}</div>
    </>
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
  const [defs, setDefs] = useState<CatalogueEntry[]>([]);
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
      .catalogue()
      .then((c) => setDefs(c.scopes))
      .catch(() => setDefs([]));
  }, [client]);

  // Assignable scopes with their config name/description; any assignable code the catalog no longer
  // defines still shows (labelled by its code) so it is never silently hidden.
  const scopeCatalog: CatalogueEntry[] = assignable.map(
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
      <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("serviceKeys.newKey")}</h2>

      <Field label={t("serviceKeys.name")}>
        <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
      </Field>

      <div>
        <div className="text-sm font-medium text-slate-800 dark:text-slate-200">
          {t("serviceKeys.scopes")}
        </div>
        {scopeCatalog.length === 0 ? (
          <p className="mt-1 text-xs text-slate-400">{t("serviceKeys.scopesEmpty")}</p>
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

      <Field label={t("serviceKeys.origins")}>
        <input
          className={input}
          placeholder={t("serviceKeys.originsPlaceholder")}
          value={origins}
          onChange={(e) => setOrigins(e.target.value)}
        />
      </Field>

      <Field label={t("serviceKeys.expiresAt")}>
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
            label={t("serviceKeys.allowSecretLogin")}
            onChange={setAllowSecretLogin}
          />
        </div>
        <div className="min-w-0">
          <div className="text-sm font-medium text-slate-800 dark:text-slate-200">
            {t("serviceKeys.allowSecretLogin")}
          </div>
          <div className="text-xs text-slate-400 dark:text-slate-500">
            {t("serviceKeys.allowSecretLoginHint")}
          </div>
        </div>
      </div>

      <div className="flex gap-2">
        <button
          className={primaryButton}
          disabled={busy || !name.trim()}
          onClick={() => void submit()}
        >
          {t("serviceKeys.create")}
        </button>
        <button
          className={ghostButton}
          disabled={busy}
          onClick={() => {
            reset();
            onCancel();
          }}
        >
          {t("serviceKeys.cancel")}
        </button>
      </div>
    </section>
  );
}
