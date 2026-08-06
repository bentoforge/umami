import { useCallback, useEffect, useState } from "react";
import type { UserStatus, UserView } from "umami-client";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, Field, errMsg } from "../components";
import { card, dangerButton, ghostButton, input, primaryButton, td, th } from "../ui";

const STATUSES: UserStatus[] = ["Active", "Locked", "Invited"];

/** Own-tenant screen: list / create / edit / suspend / delete users. */
export function UsersPage() {
  const { client, me } = useUmami();
  const [users, setUsers] = useState<UserView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);

  const myId = me?.user.userId;

  const load = useCallback(async () => {
    setError(null);
    try {
      setUsers(await client.listUsers());
    } catch (err) {
      setError(errMsg(err));
      setUsers([]);
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  const setStatus = async (user: UserView, status: UserStatus) => {
    setError(null);
    try {
      await client.patchUser(user.userId, { status });
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
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">Users</h1>
        <button className={primaryButton} onClick={() => setCreating((v) => !v)}>
          {creating ? "Cancel" : "New user"}
        </button>
      </div>

      <Banner tone="error">{error}</Banner>
      <Banner tone="ok">{notice}</Banner>

      {creating && (
        <CreateUser
          onDone={async () => {
            setCreating(false);
            setNotice("User created.");
            await load();
          }}
          onError={setError}
        />
      )}

      <section className={card + " overflow-x-auto"}>
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
                <th className={th}>Status</th>
                <th className={th}>Last seen</th>
                <th className={th}></th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) =>
                editing === user.userId ? (
                  <EditRow
                    key={user.userId}
                    user={user}
                    onCancel={() => setEditing(null)}
                    onSaved={async () => {
                      setEditing(null);
                      await load();
                    }}
                    onError={setError}
                  />
                ) : (
                  <tr key={user.userId} className="border-b border-slate-100 dark:border-slate-700/50">
                    <td className={td}>
                      <div className="font-medium text-slate-900 dark:text-white">
                        {user.name}
                        {user.userId === myId && (
                          <span className="ml-2 rounded bg-brand/10 text-brand px-1.5 py-0.5 text-[10px] align-middle">
                            you
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-400">
                        {user.username}
                        {user.email ? ` · ${user.email}` : ""}
                      </div>
                    </td>
                    <td className={td}>{user.roles.join(", ") || "—"}</td>
                    <td className={td}>{user.status}</td>
                    <td className={td}>
                      {new Date(user.lastSeen).getTime() > 0
                        ? new Date(user.lastSeen).toLocaleString()
                        : "—"}
                    </td>
                    <td className={td + " text-right whitespace-nowrap"}>
                      <button className={ghostButton} onClick={() => setEditing(user.userId)}>
                        Edit
                      </button>{" "}
                      {user.status === "Locked" ? (
                        <button className={ghostButton} onClick={() => void setStatus(user, "Active")}>
                          Unlock
                        </button>
                      ) : (
                        <button className={ghostButton} onClick={() => void setStatus(user, "Locked")}>
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
  user,
  onCancel,
  onSaved,
  onError,
}: {
  user: UserView;
  onCancel: () => void;
  onSaved: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const [roles, setRoles] = useState(user.roles.join(", "));
  const [status, setStatus] = useState<UserStatus>(user.status);
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    onError("");
    try {
      await client.patchUser(user.userId, {
        roles: roles
          .split(",")
          .map((r) => r.trim())
          .filter(Boolean),
        status,
      });
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
        <div className="font-medium text-slate-900 dark:text-white">{user.name}</div>
        <div className="text-xs text-slate-400">
          {user.username}
          {user.email ? ` · ${user.email}` : ""}
        </div>
      </td>
      <td className={td}>
        <input
          className={input}
          value={roles}
          placeholder="owner, admin"
          onChange={(e) => setRoles(e.target.value)}
        />
      </td>
      <td className={td}>
        <select
          className={input}
          value={status}
          onChange={(e) => setStatus(e.target.value as UserStatus)}
        >
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
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

function CreateUser({
  onDone,
  onError,
}: {
  onDone: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [roles, setRoles] = useState("member");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    onError("");
    try {
      await client.createUser({
        name,
        username: username.trim() || undefined,
        email: email.trim() || undefined,
        password,
        roles: roles
          .split(",")
          .map((r) => r.trim())
          .filter(Boolean),
      });
      setName("");
      setUsername("");
      setEmail("");
      setPassword("");
      setRoles("member");
      await onDone();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={card + " space-y-3"}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">New user</h2>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Name">
          <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
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
        <Field label="Roles (comma-separated)">
          <input className={input} value={roles} onChange={(e) => setRoles(e.target.value)} />
        </Field>
      </div>
      <button className={primaryButton} disabled={busy} onClick={() => void submit()}>
        Create user
      </button>
    </section>
  );
}
