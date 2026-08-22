import type { CustomFieldDef, Salutation, UserView } from "@bentoforge/umami-iam";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import {
  Banner,
  CheckboxTags,
  CustomFieldsForm,
  DropdownMenu,
  errMsg,
  Field,
  formatDateTime,
  formatFieldValue,
  Loader,
} from "../components";
import { card, input, primaryButton, td, th } from "../ui";

/** Own-tenant screen: list / create / edit / suspend / delete users. */
export function UsersPage() {
  const { client, me } = useUmami();
  const { t } = useTranslation();
  const [users, setUsers] = useState<UserView[] | null>(null);
  const [defs, setDefs] = useState<CustomFieldDef[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [resetPw, setResetPw] = useState<{ user: string; pw: string } | null>(null);
  const [creating, setCreating] = useState(false);

  const myId = me?.user.userId;
  const tableDefs = defs.filter((d) => d.showInTable);

  useEffect(() => {
    client
      .getCustomFields()
      .then((r) => setDefs(r.user))
      .catch(() => setDefs([]));
  }, [client]);

  const resetPassword = async (user: UserView) => {
    if (!window.confirm(t("users.resetConfirm", { name: user.fullName || user.username }))) {
      return;
    }
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
    if (!window.confirm(t("users.deleteConfirm", { name: user.fullName || user.username }))) {
      return;
    }
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
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">{t("users.title")}</h1>
        <input
          className={`${input} max-w-xs`}
          placeholder={t("common.search")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button className={primaryButton} onClick={() => setCreating((v) => !v)}>
          {creating ? t("users.cancel") : t("users.new")}
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
          onDone={async (res) => {
            setCreating(false);
            setNotice("User created.");
            if (res.temporaryPassword) {
              setResetPw({ user: res.username, pw: res.temporaryPassword });
            }
            await load();
          }}
          onError={setError}
        />
      )}

      <section className={`${card} overflow-x-auto`}>
        {users === null ? (
          <Loader />
        ) : users.length === 0 ? (
          <p className="text-slate-500">{t("users.empty")}</p>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className={th}>{t("users.colName")}</th>
                {tableDefs.map((def) => (
                  <th key={def.code} className={th}>
                    {def.label}
                  </th>
                ))}
                <th className={th}>{t("users.colLastActive")}</th>
                <th className={th} />
                <th className={`${th} text-right`}>
                  <span className="sr-only">{t("users.actions")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => {
                const isSelf = user.userId === myId;
                const displayName = user.fullName || user.username;
                const sub = user.fullName ? user.username : (user.email ?? "");
                return (
                  <tr
                    key={user.userId}
                    className="border-b border-slate-100 dark:border-slate-700/50"
                  >
                    <td className={td}>
                      <Link
                        to={`/users/${encodeURIComponent(user.userId)}`}
                        className="font-medium text-primary hover:underline"
                      >
                        {displayName}
                      </Link>
                      {sub && <div className="text-xs text-slate-400">{sub}</div>}
                    </td>
                    {tableDefs.map((def) => (
                      <td key={def.code} className={td}>
                        {formatFieldValue(user.customFields[def.code])}
                      </td>
                    ))}
                    <td className={td}>{user.lastSeen ? formatDateTime(user.lastSeen) : "—"}</td>
                    <td className={td}>
                      <div className="flex flex-wrap gap-1">
                        {isSelf && <Tag tone="brand">{t("users.you")}</Tag>}
                        {user.locked && <Tag tone="danger">{t("users.locked")}</Tag>}
                        {user.passwordGenerated && <Tag>{t("users.generatedPassword")}</Tag>}
                        {user.mfaEnabled && <Tag>{t("users.twoFactor")}</Tag>}
                        {user.hasPasskey && <Tag>{t("users.passkey")}</Tag>}
                      </div>
                    </td>
                    <td className={`${td} text-right`}>
                      <DropdownMenu
                        label={t("users.actions")}
                        actions={[
                          {
                            label: t("users.resetPassword"),
                            onSelect: () => void resetPassword(user),
                          },
                          ...(isSelf
                            ? []
                            : [
                                {
                                  label: user.locked ? t("users.unlock") : t("users.lock"),
                                  onSelect: () => void setLocked(user, !user.locked),
                                },
                                {
                                  label: t("users.delete"),
                                  danger: true,
                                  onSelect: () => void onDelete(user),
                                },
                              ]),
                        ]}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

/** A small status pill for the user row (you / locked / generated-pw / 2FA / passkey). */
function Tag({
  tone = "neutral",
  children,
}: {
  tone?: "neutral" | "brand" | "danger";
  children: string;
}) {
  const cls =
    tone === "brand"
      ? "bg-brand/10 text-brand"
      : tone === "danger"
        ? "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300"
        : "bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300";
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ${cls}`}
    >
      {children}
    </span>
  );
}

function CreateUser({
  defs,
  onDone,
  onError,
}: {
  defs: CustomFieldDef[];
  onDone: (res: UserView & { temporaryPassword?: string | null }) => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client, me } = useUmami();
  const { t } = useTranslation();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [roles, setRoles] = useState<string[]>(["role:member"]);
  const [assignable, setAssignable] = useState<string[]>([]);
  const [fields, setFields] = useState<Record<string, unknown>>({});
  const [title, setTitle] = useState("");
  const [salutation, setSalutation] = useState<Salutation>("");
  const [firstname, setFirstname] = useState("");
  const [lastname, setLastname] = useState("");
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
      const res = await client.createUser({
        username: username.trim() || undefined,
        email: email.trim() || undefined,
        roles,
        title,
        salutation,
        firstname,
        lastname,
        customFields: fields,
      });
      setUsername("");
      setEmail("");
      setRoles(["role:member"]);
      setTitle("");
      setSalutation("");
      setFirstname("");
      setLastname("");
      setFields({});
      await onDone(res);
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("users.new")}</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label={t("users.username")}>
          <input className={input} value={username} onChange={(e) => setUsername(e.target.value)} />
        </Field>
        <Field label={t("users.email")}>
          <input
            className={input}
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </Field>
        <Field label={t("users.salutation")}>
          <select
            className={input}
            value={salutation}
            onChange={(e) => setSalutation(e.target.value as Salutation)}
          >
            <option value="">—</option>
            <option value="SIR">{t("users.salutationSir")}</option>
            <option value="MADAM">{t("users.salutationMadam")}</option>
          </select>
        </Field>
        <Field label={t("users.nameTitle")}>
          <input className={input} value={title} onChange={(e) => setTitle(e.target.value)} />
        </Field>
        <Field label={t("users.firstname")}>
          <input
            className={input}
            value={firstname}
            onChange={(e) => setFirstname(e.target.value)}
          />
        </Field>
        <Field label={t("users.lastname")}>
          <input className={input} value={lastname} onChange={(e) => setLastname(e.target.value)} />
        </Field>
        <CustomFieldsForm defs={defs} values={fields} onChange={setFields} />
        <Field label={t("users.rolesTitle")}>
          <CheckboxTags
            options={assignable}
            selected={roles}
            onChange={setRoles}
            empty={t("users.rolesEmpty")}
          />
        </Field>
      </div>
      <button className={primaryButton} disabled={busy} onClick={() => void submit()}>
        {t("users.create")}
      </button>
    </section>
  );
}
