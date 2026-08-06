import { useCallback, useEffect, useState } from "react";
import type { Tenant, TenantStatus } from "umami-client";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, Field, errMsg } from "../components";
import { card, dangerButton, ghostButton, input, primaryButton, td, th } from "../ui";

const STATUSES: TenantStatus[] = [
  "Lead",
  "Testing",
  "Onboarding",
  "Active",
  "Suspended",
  "Churned",
];

/** System-admin screen: list / create / edit / delete tenants. */
export function TenantsPage() {
  const { client, me } = useUmami();
  const [tenants, setTenants] = useState<Tenant[] | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);

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
    if (!window.confirm(`Delete tenant "${tenant.name}"? This only works when it has no users.`)) {
      return;
    }
    setError(null);
    setNotice(null);
    try {
      await client.deleteTenant(tenant.tenantId);
      setNotice(`Deleted "${tenant.name}".`);
      await load();
    } catch (err) {
      setError(errMsg(err));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">Tenants</h1>
        <input
          className={input + " max-w-xs"}
          placeholder="Search name, customer no., address…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button className={primaryButton} onClick={() => setCreating((v) => !v)}>
          {creating ? "Cancel" : "New tenant"}
        </button>
      </div>

      {error && <Banner tone="error">{error}</Banner>}
      {notice && <Banner tone="ok">{notice}</Banner>}
      {truncated && (
        <p className="text-xs text-amber-600 dark:text-amber-400">
          Showing the first 250 matches — refine your search to narrow the list.
        </p>
      )}

      {creating && (
        <CreateTenant
          onDone={async () => {
            setCreating(false);
            setNotice("Tenant created.");
            await load();
          }}
          onError={setError}
        />
      )}

      <section className={card + " overflow-x-auto"}>
        {tenants === null ? (
          <p className="text-slate-500">Loading…</p>
        ) : tenants.length === 0 ? (
          <p className="text-slate-500">No tenants.</p>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={th}>Name</th>
                <th className={th}>Status</th>
                <th className={th}>Plan</th>
                <th className={th}>Updated</th>
                <th className={th}></th>
              </tr>
            </thead>
            <tbody>
              {tenants.map((tenant) =>
                editing === tenant.tenantId ? (
                  <EditRow
                    key={tenant.tenantId}
                    tenant={tenant}
                    onCancel={() => setEditing(null)}
                    onSaved={async () => {
                      setEditing(null);
                      await load();
                    }}
                    onError={setError}
                  />
                ) : (
                  <tr
                    key={tenant.tenantId}
                    className="border-b border-slate-100 dark:border-slate-700/50"
                  >
                    <td className={td}>
                      <div className="font-medium text-slate-900 dark:text-white">
                        {tenant.name}
                        {tenant.tenantId === me?.user.tenantId && (
                          <span className="ml-2 rounded bg-brand/10 text-brand px-1.5 py-0.5 text-[10px] align-middle">
                            system
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-400 font-mono">{tenant.tenantId}</div>
                    </td>
                    <td className={td}>{tenant.status}</td>
                    <td className={td}>{tenant.plan}</td>
                    <td className={td}>{new Date(tenant.lastUpdated).toLocaleString()}</td>
                    <td className={td + " text-right whitespace-nowrap"}>
                      <button className={ghostButton} onClick={() => setEditing(tenant.tenantId)}>
                        Edit
                      </button>{" "}
                      <button className={dangerButton} onClick={() => void onDelete(tenant)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

function EditRow({
  tenant,
  onCancel,
  onSaved,
  onError,
}: {
  tenant: Tenant;
  onCancel: () => void;
  onSaved: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const [name, setName] = useState(tenant.name);
  const [plan, setPlan] = useState(tenant.plan);
  const [status, setStatus] = useState<TenantStatus>(tenant.status);
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    onError("");
    try {
      if (name !== tenant.name || plan !== tenant.plan) {
        await client.patchTenant(tenant.tenantId, { name, plan });
      }
      if (status !== tenant.status) {
        await client.patchStatus(tenant.tenantId, status);
      }
      await onSaved();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <tr className="border-b border-slate-100 dark:border-slate-700/50 bg-slate-50 dark:bg-slate-900/40">
      <td className={td}>
        <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
      </td>
      <td className={td}>
        <select
          className={input}
          value={status}
          onChange={(e) => setStatus(e.target.value as TenantStatus)}
        >
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </td>
      <td className={td}>
        <input className={input} value={plan} onChange={(e) => setPlan(e.target.value)} />
      </td>
      <td className={td}>—</td>
      <td className={td + " text-right whitespace-nowrap"}>
        <button className={primaryButton} disabled={saving} onClick={() => void save()}>
          Save
        </button>{" "}
        <button className={ghostButton} disabled={saving} onClick={onCancel}>
          Cancel
        </button>
      </td>
    </tr>
  );
}

function CreateTenant({
  onDone,
  onError,
}: {
  onDone: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const [name, setName] = useState("");
  const [ownerName, setOwnerName] = useState("");
  const [ownerUsername, setOwnerUsername] = useState("");
  const [ownerEmail, setOwnerEmail] = useState("");
  const [ownerPassword, setOwnerPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    onError("");
    try {
      await client.createTenant({
        name,
        owner: {
          name: ownerName,
          username: ownerUsername.trim() || undefined,
          email: ownerEmail.trim() || undefined,
          password: ownerPassword,
        },
      });
      setName("");
      setOwnerName("");
      setOwnerUsername("");
      setOwnerEmail("");
      setOwnerPassword("");
      await onDone();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={card + " space-y-3"}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">New tenant + owner</h2>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Tenant name">
          <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Owner name">
          <input className={input} value={ownerName} onChange={(e) => setOwnerName(e.target.value)} />
        </Field>
        <Field label="Owner username (defaults to email)">
          <input
            className={input}
            value={ownerUsername}
            onChange={(e) => setOwnerUsername(e.target.value)}
          />
        </Field>
        <Field label="Owner email (optional)">
          <input
            className={input}
            type="email"
            value={ownerEmail}
            onChange={(e) => setOwnerEmail(e.target.value)}
          />
        </Field>
        <Field label="Owner password">
          <input
            className={input}
            type="password"
            value={ownerPassword}
            onChange={(e) => setOwnerPassword(e.target.value)}
          />
        </Field>
      </div>
      <button className={primaryButton} disabled={busy} onClick={() => void submit()}>
        Create tenant
      </button>
    </section>
  );
}

