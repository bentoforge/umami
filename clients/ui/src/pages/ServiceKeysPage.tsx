import type { ApiKeyView, CatalogueEntry } from "@bentoforge/umami-iam";
import { ListBulletIcon, TrashIcon } from "@heroicons/react/24/outline";
import type { TFunction } from "i18next";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, DropdownMenu, errMsg, Field, formatDateTime, Loader, Toggle } from "../components";
import { RateLimitDetails } from "../ratelimit";
import { card, ghostButton, input, primaryButton, td, th } from "../ui";

/** Token lifetimes offered when creating a key; empty means "whatever the server is configured for".
 *
 * A list rather than a number field: the useful answers are few, and a free-form value invites the
 * seconds/minutes mix-up that the server then refuses. Ordered short to long because short is the
 * safer choice — a longer lifetime is for a client that cannot renew, and it is also how long a
 * revoked key keeps working. */
const ACCESS_TTL_CHOICES = [1800, 3600, 14400, 28800, 86400] as const;

/** Whether the key's expiry has passed. The exchange refuses it from that moment on, so the date is
 * no longer a plan but a fact, and the screen has to say so rather than print a quiet date. */
function hasExpired(expiresAt: string | null | undefined): boolean {
  return expiresAt ? new Date(expiresAt).getTime() <= Date.now() : false;
}

/** Renders an expiry: muted when it is still ahead, and red plus named once it has passed — the
 * colour alone would be lost on anyone who cannot see it. */
function Expiry({ at }: { at: string | null | undefined }) {
  const { t } = useTranslation();
  if (!at) {
    return <>—</>;
  }
  if (!hasExpired(at)) {
    return <>{formatDateTime(at)}</>;
  }
  return (
    <span className="text-red-600 dark:text-red-400">
      {formatDateTime(at)} ({t("serviceKeys.expired")})
    </span>
  );
}

/** Current-tenant screen: manage service keys (M2M machine principals). Personal access tokens live
 * in the profile; this page is for tenant-owned keys exchanged at `POST /auth/token`. */
export function ServiceKeysPage() {
  const { client, me, activeTenantId } = useUmami();
  const { t } = useTranslation();
  // The tenant the token is scoped to, not the one the user belongs to. The server checks the path
  // id against the token's `tenant` claim, and switching tenants moves that claim while
  // `me.user.tenantId` stays on the user's home tenant — reading it here answers 403 on every call
  // this id feeds once someone has switched.
  const tenantId = activeTenantId ?? me?.user.tenantId ?? "";
  const [keys, setKeys] = useState<ApiKeyView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [freshSecret, setFreshSecret] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [scopeDefs, setScopeDefs] = useState<CatalogueEntry[]>([]);
  // The key whose details are open. The table answers "which keys are there and is this one still
  // in use"; everything else about a key — ids, scopes, origins, its rate limit — is one screen
  // deeper, because a row that carries all of it is a row nobody reads.
  const [detailsFor, setDetailsFor] = useState<string | null>(null);

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

  const selected = keys?.find((key) => key.keyId === detailsFor) ?? null;

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
        ) : selected ? (
          // A key the list no longer has (just deleted) drops back to the list on its own, because
          // `selected` is looked up in `keys` rather than kept as a second copy.
          <KeyDetails
            apiKey={selected}
            tenantId={tenantId}
            scopeLabel={scopeLabel}
            onBack={() => setDetailsFor(null)}
          />
        ) : keys.length === 0 ? (
          <p className="text-slate-500">{t("serviceKeys.empty")}</p>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={th}>{t("serviceKeys.name")}</th>
                <th className={th}>{t("serviceKeys.lastUsed")}</th>
                <th className={th}>{t("serviceKeys.expires")}</th>
                <th className={`${th} w-0`} />
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.keyId} className="border-b border-slate-100 dark:border-slate-700/50">
                  <td className={td}>
                    <button
                      className="font-medium text-slate-900 dark:text-white hover:underline"
                      onClick={() => setDetailsFor(key.keyId)}
                    >
                      {key.name}
                    </button>
                  </td>
                  <td className={`${td} whitespace-nowrap`}>
                    {key.lastUsedAt ? formatDateTime(key.lastUsedAt) : t("serviceKeys.neverUsed")}
                  </td>
                  <td className={`${td} whitespace-nowrap`}>
                    <Expiry at={key.expiresAt} />
                  </td>
                  <td className={`${td} text-right`}>
                    <DropdownMenu
                      label={t("serviceKeys.menu")}
                      actions={[
                        {
                          label: t("serviceKeys.details"),
                          icon: ListBulletIcon,
                          onSelect: () => setDetailsFor(key.keyId),
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

/** Everything about one key, as name/value pairs, in place of the list. */
function KeyDetails({
  apiKey,
  tenantId,
  scopeLabel,
  onBack,
}: {
  apiKey: ApiKeyView;
  tenantId: string;
  scopeLabel: (code: string) => string;
  onBack: () => void;
}) {
  const { t } = useTranslation();

  const rows: { label: string; value: ReactNode }[] = [
    { label: t("serviceKeys.name"), value: apiKey.name },
    {
      label: t("serviceKeys.keyId"),
      value: <span className="font-mono text-xs break-all">{apiKey.keyId}</span>,
    },
    { label: t("serviceKeys.scopes"), value: apiKey.scopes.map(scopeLabel).join(", ") || "—" },
    {
      label: t("serviceKeys.allowedOrigins"),
      // An empty list is not "none" but "every origin" — the opposite reading of a dash.
      value: apiKey.allowedOrigins.join(", ") || t("serviceKeys.anyOrigin"),
    },
    { label: t("serviceKeys.accessTtl"), value: accessTtlLabel(apiKey.accessTtlSecs, t) },
    {
      label: t("serviceKeys.loginMode"),
      value: apiKey.allowSecretLogin ? t("serviceKeys.modeSecret") : t("serviceKeys.modeHmac"),
    },
    {
      label: t("serviceKeys.lastUsed"),
      value: apiKey.lastUsedAt ? formatDateTime(apiKey.lastUsedAt) : t("serviceKeys.neverUsed"),
    },
    { label: t("serviceKeys.expires"), value: <Expiry at={apiKey.expiresAt} /> },
    { label: t("serviceKeys.created"), value: formatDateTime(apiKey.created) },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <h2 className="font-medium text-slate-800 dark:text-slate-200">{apiKey.name}</h2>
        <button className={ghostButton} onClick={onBack}>
          {t("serviceKeys.backToList")}
        </button>
      </div>

      {/* Label above, value below — the same shape as the meta box on a user or tenant, so a key
          reads like the rest of the admin rather than like a table that lost its header. */}
      <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-4">
        {rows.map((row) => (
          <div key={row.label}>
            <dt className="text-xs text-slate-400">{row.label}</dt>
            <dd className="text-sm text-slate-700 dark:text-slate-200">{row.value}</dd>
          </div>
        ))}
      </dl>

      <div className="max-w-md">
        <div className="mb-2 text-sm font-medium text-slate-800 dark:text-slate-200">
          {t("rateLimits.title")}
          {apiKey.rateLimit && (
            <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-slate-500 dark:bg-slate-700 dark:text-slate-300">
              {t("rateLimits.override")}
            </span>
          )}
        </div>
        <RateLimitDetails target={{ kind: "apiKey", tenantId, keyId: apiKey.keyId }} />
      </div>
    </div>
  );
}

/** Names a key's token lifetime the way the create form offers it; an unlisted value keeps its
 * seconds rather than being rounded into a lie. */
function accessTtlLabel(secs: number | null | undefined, t: TFunction): string {
  if (!secs) {
    return t("serviceKeys.accessTtlDefault");
  }
  if ((ACCESS_TTL_CHOICES as readonly number[]).includes(secs)) {
    return t(`serviceKeys.accessTtlOptions.${secs}`);
  }
  return t("serviceKeys.accessTtlSeconds", { count: secs });
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
  const [accessTtlSecs, setAccessTtlSecs] = useState("");
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
    setAccessTtlSecs("");
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
        accessTtlSecs: accessTtlSecs ? Number(accessTtlSecs) : undefined,
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
          <p className="mt-1 text-slate-400">{t("serviceKeys.scopesEmpty")}</p>
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
                    <div className="text-slate-400 dark:text-slate-500">{def.description}</div>
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

      <Field label={t("serviceKeys.accessTtl")}>
        <select
          className={input}
          value={accessTtlSecs}
          onChange={(e) => setAccessTtlSecs(e.target.value)}
        >
          <option value="">{t("serviceKeys.accessTtlDefault")}</option>
          {ACCESS_TTL_CHOICES.map((secs) => (
            <option key={secs} value={secs}>
              {t(`serviceKeys.accessTtlOptions.${secs}`)}
            </option>
          ))}
        </select>
        <div className="mt-1 text-slate-400 dark:text-slate-500">
          {t("serviceKeys.accessTtlHint")}
        </div>
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
          <div className="text-slate-400 dark:text-slate-500">
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
