import type { CustomFieldDef, UserView } from "@bentoforge/umami-iam";
import { Fragment, useCallback, useEffect, useState } from "react";
import { useUmami } from "../auth/UmamiProvider";
import {
  Banner,
  CheckboxTags,
  CustomFieldsForm,
  errMsg,
  Field,
  formatFieldValue,
} from "../components";
import { card, dangerButton, ghostButton, input, primaryButton, td, th } from "../ui";

/** Own-tenant screen: list / create / edit / suspend / delete users. */
export function UsersPage() {
  const { client, me } = useUmami();
  const [users, setUsers] = useState<UserView[] | null>(null);
  const [defs, setDefs] = useState<CustomFieldDef[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [resetPw, setResetPw] = useState<{ user: string; pw: string } | null>(null);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);

  const myId = me?.user.userId;
  const tableDefs = defs.filter((d) => d.showInTable);
  const colCount = 4 + tableDefs.length;

  useEffect(() => {
    client
      .getCustomFields()
      .then((r) => setDefs(r.user))
      .catch(() => setDefs([]));
  }, [client]);

  const resetPassword = async (user: UserView) => {
    if (
      !window.confirm(`Reset password for "${user.username}"? A temporary one will be generated.`)
    )
      return;
    setError(null);
    setResetPw(null);
    try {
      const res = await client.resetPassword(user.userId);
      if (res.temporaryPassword) setResetPw({ user: user.username, pw: res.temporaryPassword });
    } catch (err) {
      setError(errMsg(err));
    }
  };

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await client.listUsers(query.trim() || undefined);
      setUsers(res.users);
      setTruncated(res.truncated);
    } catch (err) {
      setError(errMsg(err));
      setUsers([]);
    }
  }, [client, query]);

  // Debounced: reload as the search box changes.
  useEffect(() => {
    const handle = setTimeout(() => void load(), 250);
    return () => clearTimeout(handle);
  }, [load]);

  const setLocked = async (user: UserView, locked: boolean) => {
    setError(null);
    try {
      await client.patchUser(user.userId, { locked });
      await load();
    } catch (err) {
      setError(errMsg(err));
    }
  };

  const onDelete = async (user: UserView) => {
    if (!window.confirm(`Delete user "${user.email}"? This cannot be undone.`)) return;
    setError(null);
    setNotice(null);
    try {
      await client.deleteUser(user.userId);
      setNotice(`Deleted "${user.email}".`);
      await load();
    } catch (err) {
      setError(errMsg(err));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">Users</h1>
        <input
          className={`${input} max-w-xs`}
          placeholder="Search username, email, name…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button className={primaryButton} onClick={() => setCreating((v) => !v)}>
          {creating ? "Cancel" : "New user"}
        </button>
      </div>

      <Banner tone="error">{error}</Banner>
      <Banner tone="ok">{notice}</Banner>
      {resetPw && (
        <div className="rounded-lg border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950 p-3">
          <p className="text-xs text-emerald-700 dark:text-emerald-300 mb-1">
            Temporary password for <strong>{resetPw.user}</strong> — shown only once:
          </p>
          <code className="block break-all text-sm text-slate-900 dark:text-slate-100">
            {resetPw.pw}
          </code>
        </div>
      )}
      {truncated && (
        <p className="text-xs text-amber-600 dark:text-amber-400">
          Showing the first 250 matches — refine your search to narrow the list.
        </p>
      )}

      {creating && (
        <CreateUser
          defs={defs}
          onDone={async () => {
            setCreating(false);
            setNotice("User created.");
            await load();
          }}
          onError={setError}
        />
      )}

      <section className={`${card} overflow-x-auto`}>
        {users === null ? (
          <p className="text-slate-500">Loading…</p>
        ) : users.length === 0 ? (
          <p className="text-slate-500">No users.</p>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={th}>User</th>
                <th className={th}>Roles</th>
                <th className={th}>Locked</th>
                <th className={th}>Last seen</th>
                {tableDefs.map((def) => (
                  <th key={def.key} className={th}>
                    {def.label}
                  </th>
                ))}
                <th className={th}></th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <Fragment key={user.userId}>
                  <tr className="border-b border-slate-100 dark:border-slate-700/50">
                    <td className={td}>
                      <div className="font-medium text-slate-900 dark:text-white">
                        {user.username}
                        {user.userId === myId && (
                          <span className="ml-2 rounded bg-brand/10 text-brand px-1.5 py-0.5 text-[10px] align-middle">
                            you
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-400">{user.email ?? "—"}</div>
                    </td>
                    <td className={td}>{user.roles.join(", ") || "—"}</td>
                    <td className={td}>{user.locked ? "Locked" : "—"}</td>
                    <td className={td}>
                      {new Date(user.lastSeen).getTime() > 0
                        ? new Date(user.lastSeen).toLocaleString()
                        : "—"}
                    </td>
                    {tableDefs.map((def) => (
                      <td key={def.key} className={td}>
                        {formatFieldValue(user.customFields[def.key])}
                      </td>
                    ))}
                    <td className={`${td} text-right whitespace-nowrap`}>
                      <button
                        className={ghostButton}
                        onClick={() =>
                          setEditing((id) => (id === user.userId ? null : user.userId))
                        }
                      >
                        Edit
                      </button>{" "}
                      <button className={ghostButton} onClick={() => void resetPassword(user)}>
                        Reset pw
                      </button>{" "}
                      {user.locked ? (
                        <button className={ghostButton} onClick={() => void setLocked(user, false)}>
                          Unlock
                        </button>
                      ) : (
                        <button className={ghostButton} onClick={() => void setLocked(user, true)}>
                          Suspend
                        </button>
                      )}{" "}
                      <button
                        className={dangerButton}
                        disabled={user.userId === myId}
                        title={user.userId === myId ? "You cannot delete yourself" : undefined}
                        onClick={() => void onDelete(user)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                  {editing === user.userId && (
                    <tr className="border-b border-slate-100 dark:border-slate-700/50 bg-slate-50 dark:bg-slate-900/40">
                      <td className={td} colSpan={colCount}>
                        <EditUserPanel
                          user={user}
                          defs={defs}
                          onCancel={() => setEditing(null)}
                          onSaved={async () => {
                            setEditing(null);
                            await load();
                          }}
                          onError={setError}
                        />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

function EditUserPanel({
  user,
  defs,
  onCancel,
  onSaved,
  onError,
}: {
  user: UserView;
  defs: CustomFieldDef[];
  onCancel: () => void;
  onSaved: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const [roles, setRoles] = useState<string[]>(user.roles);
  const [assignable, setAssignable] = useState<string[]>([]);
  const [locked, setLocked] = useState<boolean>(user.locked);
  const [fields, setFields] = useState<Record<string, unknown>>({ ...user.customFields });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    client
      .assignableRoles(user.userId)
      .then((r) => setAssignable(r.codes))
      .catch(() => setAssignable([]));
  }, [client, user.userId]);

  const save = async () => {
    setSaving(true);
    onError("");
    try {
      await client.patchUser(user.userId, { roles, locked, customFields: fields });
      await onSaved();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-3 py-1">
      <div className="grid grid-cols-2 gap-3">
        <Field label="Roles">
          <CheckboxTags
            options={assignable}
            selected={roles}
            onChange={setRoles}
            empty="no roles assignable"
          />
        </Field>
        <Field label="Locked">
          <label className="inline-flex items-center gap-2 text-sm">
            <input type="checkbox" checked={locked} onChange={(e) => setLocked(e.target.checked)} />
            Locked
          </label>
        </Field>
        <CustomFieldsForm defs={defs} values={fields} onChange={setFields} />
      </div>
      <div>
        <button className={primaryButton} disabled={saving} onClick={() => void save()}>
          Save
        </button>{" "}
        <button className={ghostButton} disabled={saving} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function CreateUser({
  defs,
  onDone,
  onError,
}: {
  defs: CustomFieldDef[];
  onDone: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client, me } = useUmami();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [roles, setRoles] = useState<string[]>(["role:member"]);
  const [assignable, setAssignable] = useState<string[]>([]);
  const [fields, setFields] = useState<Record<string, unknown>>({});
  const [busy, setBusy] = useState(false);

  // Assignable roles are per-tenant; resolve via the caller's own id (same tenant as new users).
  useEffect(() => {
    if (!me) return;
    client
      .assignableRoles(me.user.userId)
      .then((r) => setAssignable(r.codes))
      .catch(() => setAssignable([]));
  }, [client, me]);

  const submit = async () => {
    setBusy(true);
    onError("");
    try {
      await client.createUser({
        username: username.trim() || undefined,
        email: email.trim() || undefined,
        password,
        roles,
        customFields: fields,
      });
      setUsername("");
      setEmail("");
      setPassword("");
      setRoles(["role:member"]);
      setFields({});
      await onDone();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">New user</h2>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Username (defaults to email)">
          <input className={input} value={username} onChange={(e) => setUsername(e.target.value)} />
        </Field>
        <Field label="Email (optional)">
          <input
            className={input}
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </Field>
        <Field label="Password">
          <input
            className={input}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </Field>
        <Field label="Roles">
          <CheckboxTags
            options={assignable}
            selected={roles}
            onChange={setRoles}
            empty="no roles assignable"
          />
        </Field>
        <CustomFieldsForm defs={defs} values={fields} onChange={setFields} />
      </div>
      <button className={primaryButton} disabled={busy} onClick={() => void submit()}>
        Create user
      </button>
    </section>
  );
}
