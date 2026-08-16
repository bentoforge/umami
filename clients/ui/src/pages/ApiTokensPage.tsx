import { useCallback, useEffect, useState } from "react";
import type { ApiKeyView } from "umami-client";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, CheckboxTags, Field, errMsg } from "../components";
import { card, dangerButton, input, primaryButton, td, th } from "../ui";

/** Own-tenant screen: manage service keys (M2M machine principals). Personal access tokens live in
 * the profile; this page is for tenant-owned keys exchanged at `POST /auth/token`. */
export function ApiTokensPage() {
  const { client, me } = useUmami();
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
    if (!window.confirm(`Revoke key "${key.name}"? Anything using it stops working.`)) return;
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
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-white">API tokens</h1>
          <p className="text-sm text-slate-500">
            Service keys act as the tenant (M2M). Exchange one at <code>POST /auth/token</code> for a
            short-lived access token.
          </p>
        </div>
        <button className={primaryButton} onClick={() => setCreating((v) => !v)}>
          {creating ? "Cancel" : "New key"}
        </button>
      </div>

      <Banner tone="error">{error}</Banner>

      {freshSecret && (
        <div className="rounded-lg border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950 p-3">
          <p className="text-xs text-emerald-700 dark:text-emerald-300 mb-1">
            Copy this now — the secret is shown only once:
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
          onError={setError}
        />
      )}

      <section className={card + " overflow-x-auto"}>
        {keys === null ? (
          <p className="text-slate-500">Loading…</p>
        ) : keys.length === 0 ? (
          <p className="text-slate-500">No service keys.</p>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={th}>Name</th>
                <th className={th}>Scopes</th>
                <th className={th}>APIs</th>
                <th className={th}>Origins</th>
                <th className={th}>Last used</th>
                <th className={th}></th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.keyId} className="border-b border-slate-100 dark:border-slate-700/50">
                  <td className={td}>
                    <div className="font-medium text-slate-900 dark:text-white">{key.name}</div>
                    <div className="text-xs text-slate-400 font-mono">{key.keyId}</div>
                  </td>
                  <td className={td}>{key.scopes.join(", ") || "—"}</td>
                  <td className={td}>{key.apis.join(", ") || "—"}</td>
                  <td className={td}>{key.allowedOrigins.join(", ") || "any"}</td>
                  <td className={td}>
                    {key.lastUsedAt ? new Date(key.lastUsedAt).toLocaleString() : "never"}
                  </td>
                  <td className={td + " text-right whitespace-nowrap"}>
                    <button className={dangerButton} onClick={() => void onDelete(key)}>
                      Revoke
                    </button>
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
  onError,
}: {
  tenantId: string;
  onDone: (secret: string) => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>([]);
  const [assignable, setAssignable] = useState<string[]>([]);
  const [apis, setApis] = useState("");
  const [origins, setOrigins] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    client
      .assignableScopes(tenantId)
      .then((r) => setAssignable(r.codes))
      .catch(() => setAssignable([]));
  }, [client, tenantId]);

  const split = (text: string) =>
    text
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

  const submit = async () => {
    setBusy(true);
    onError("");
    try {
      const res = await client.createApiKey(tenantId, {
        name,
        scopes,
        apis: split(apis),
        allowedOrigins: split(origins),
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : undefined,
      });
      setName("");
      setScopes([]);
      setApis("");
      setOrigins("");
      setExpiresAt("");
      await onDone(res.apiKey);
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={card + " space-y-3"}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">New service key</h2>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Name">
          <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Target APIs (comma-separated, optional)">
          <input
            className={input}
            placeholder="empty = any audience (hardening only)"
            value={apis}
            onChange={(e) => setApis(e.target.value)}
          />
        </Field>
        <Field label="Scopes">
          <CheckboxTags
            options={assignable}
            selected={scopes}
            onChange={setScopes}
            empty="no scopes assignable"
          />
        </Field>
        <Field label="Allowed origins (comma-separated, optional)">
          <input
            className={input}
            placeholder="https://app.example.com"
            value={origins}
            onChange={(e) => setOrigins(e.target.value)}
          />
        </Field>
        <Field label="Expires at (optional)">
          <input
            className={input}
            type="date"
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
          />
        </Field>
      </div>
      <button className={primaryButton} disabled={busy || !name.trim()} onClick={() => void submit()}>
        Create key
      </button>
    </section>
  );
}
