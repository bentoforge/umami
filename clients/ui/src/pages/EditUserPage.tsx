import type {
  ApiKeyView,
  AuditEntry,
  CustomFieldDef,
  RoleDef,
  Salutation,
  SessionView,
  UserView,
} from "@bentoforge/umami-iam";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate, useParams } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import {
  AuditList,
  Banner,
  CustomFieldsForm,
  DropdownMenu,
  errMsg,
  Field,
  formatDateTime,
  formatFieldValue,
  Loader,
  Toggle,
} from "../components";
import { card, ghostButton, input, primaryButton, td, th } from "../ui";

/** Page size for the audit "load more" list. */
const AUDIT_PAGE = 10;

/** Per-user edit view: details (read + inline edit), roles, recent audit, sessions, read-only PATs,
 * a change-tracking metadata box, and an in-app Back. */
export function EditUserPage() {
  const { client, me } = useUmami();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { userId = "" } = useParams();

  const [user, setUser] = useState<UserView | null>(null);
  const [defs, setDefs] = useState<CustomFieldDef[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [resetPw, setResetPw] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);

  const reload = useCallback(async () => {
    setError(null);
    try {
      setUser(await client.getUser(userId));
    } catch (err) {
      setError(errMsg(err));
      setMissing(true);
    }
  }, [client, userId]);

  useEffect(() => {
    void reload();
  }, [reload]);

  useEffect(() => {
    client
      .getCustomFields()
      .then((r) => setDefs(r.user))
      .catch(() => setDefs([]));
  }, [client]);

  const isSelf = user?.userId === me?.user.userId;
  const name = () => user?.fullName || user?.username || "";

  const onReset = async () => {
    if (!user || !window.confirm(t("users.resetConfirm", { name: name() }))) {
      return;
    }
    setError(null);
    try {
      const res = await client.resetPassword(user.userId);
      if (res.temporaryPassword) {
        setResetPw(res.temporaryPassword);
      }
    } catch (err) {
      setError(errMsg(err));
    }
  };

  const onSetLocked = async (locked: boolean) => {
    if (!user) {
      return;
    }
    setError(null);
    try {
      await client.patchUser(user.userId, { locked });
      await reload();
    } catch (err) {
      setError(errMsg(err));
    }
  };

  const onDelete = async () => {
    if (!user || !window.confirm(t("users.deleteConfirm", { name: name() }))) {
      return;
    }
    try {
      await client.deleteUser(user.userId);
      navigate("/users");
    } catch (err) {
      setError(errMsg(err));
    }
  };

  const goBack = () => {
    const idx = (window.history.state as { idx?: number } | null)?.idx ?? 0;
    if (idx > 0) {
      navigate(-1);
    } else {
      navigate("/users");
    }
  };

  if (missing) {
    return (
      <div className="space-y-4">
        <Banner tone="error">{error ?? t("users.notFound")}</Banner>
        <button className={ghostButton} onClick={goBack}>
          {t("users.back")}
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
          {t("users.editTitle")}
        </h1>
        {user && (
          <DropdownMenu
            label={t("users.actions")}
            triggerLabel={t("common.moreActions")}
            actions={[
              { label: t("users.resetPassword"), onSelect: () => void onReset() },
              ...(isSelf
                ? []
                : [
                    {
                      label: user.locked ? t("users.unlock") : t("users.lock"),
                      onSelect: () => void onSetLocked(!user.locked),
                    },
                    { label: t("users.delete"), danger: true, onSelect: () => void onDelete() },
                  ]),
            ]}
          />
        )}
      </div>

      {error && <Banner tone="error">{error}</Banner>}
      {notice && <Banner tone="ok">{notice}</Banner>}
      {resetPw && (
        <div className="rounded-lg border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950 p-3">
          <p className="text-xs text-emerald-700 dark:text-emerald-300 mb-1">
            {t("users.resetPassword")} — <strong>{name()}</strong>:
          </p>
          <code className="block break-all text-sm text-slate-900 dark:text-slate-100">
            {resetPw}
          </code>
        </div>
      )}

      {user === null ? (
        <Loader />
      ) : (
        <>
          <DetailsCard
            user={user}
            defs={defs}
            onSaved={async () => {
              setNotice(t("users.saved"));
              await reload();
            }}
            onError={setError}
          />
          <RolesCard user={user} onChanged={reload} onError={setError} />
          <AuditCard userId={user.userId} />
          <SessionsCard user={user} onError={setError} />
          <PatsCard userId={user.userId} />
          <MetaBox user={user} />
        </>
      )}

      <button className={ghostButton} onClick={goBack}>
        {t("users.back")}
      </button>
    </div>
  );
}

/** Read-only details with an Edit toggle for the name parts + custom fields + lock. Username/email
 * are the login identity and stay read-only. */
function DetailsCard({
  user,
  defs,
  onSaved,
  onError,
}: {
  user: UserView;
  defs: CustomFieldDef[];
  onSaved: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [editing, setEditing] = useState(false);
  const [username, setUsername] = useState(user.username);
  const [email, setEmail] = useState(user.email ?? "");
  const [title, setTitle] = useState(user.title ?? "");
  const [salutation, setSalutation] = useState<Salutation>(user.salutation);
  const [firstname, setFirstname] = useState(user.firstname ?? "");
  const [lastname, setLastname] = useState(user.lastname ?? "");
  const [fields, setFields] = useState<Record<string, unknown>>({ ...user.customFields });
  const [saving, setSaving] = useState(false);

  const reset = useCallback(() => {
    setUsername(user.username);
    setEmail(user.email ?? "");
    setTitle(user.title ?? "");
    setSalutation(user.salutation);
    setFirstname(user.firstname ?? "");
    setLastname(user.lastname ?? "");
    setFields({ ...user.customFields });
  }, [user]);

  useEffect(() => reset(), [reset]);

  const cancel = () => {
    setEditing(false);
    reset();
  };

  const save = async () => {
    setSaving(true);
    onError("");
    try {
      await client.patchUser(user.userId, {
        username,
        email,
        title,
        salutation,
        firstname,
        lastname,
        customFields: fields,
      });
      setEditing(false);
      await onSaved();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className={`${card} space-y-4`}>
      <div className="flex items-center justify-between">
        <h2 className="font-medium text-slate-800 dark:text-slate-200">
          {t("users.detailsTitle")}
        </h2>
        {!editing && (
          <button className={ghostButton} onClick={() => setEditing(true)}>
            {t("users.edit")}
          </button>
        )}
      </div>

      {editing ? (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label={t("users.username")}>
              <input
                className={input}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
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
              <input
                className={input}
                value={lastname}
                onChange={(e) => setLastname(e.target.value)}
              />
            </Field>
            <CustomFieldsForm defs={defs} values={fields} onChange={setFields} />
          </div>
          <div className="flex gap-2">
            <button className={primaryButton} disabled={saving} onClick={() => void save()}>
              {t("users.save")}
            </button>
            <button className={ghostButton} disabled={saving} onClick={cancel}>
              {t("users.cancel")}
            </button>
          </div>
        </>
      ) : (
        <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
          <DetailRow label={t("users.username")}>{user.username}</DetailRow>
          <DetailRow label={t("users.email")}>{user.email ?? "—"}</DetailRow>
          <DetailRow label={t("users.name")}>
            {user.firstname || user.lastname ? user.fullName : "—"}
          </DetailRow>
          {defs.map((def) => (
            <DetailRow key={def.key} label={def.label}>
              {formatFieldValue(user.customFields[def.key])}
            </DetailRow>
          ))}
          <DetailRow label={t("users.locked")}>
            {user.locked ? t("users.yes") : t("users.no")}
          </DetailRow>
        </dl>
      )}
    </section>
  );
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-slate-800 dark:text-slate-200">{children}</dd>
    </>
  );
}

/** Assign/unassign the user's roles as a toggle list: a switch on the left, the role name in bold,
 * its description (or code) muted below. A role that is neither assigned nor currently assignable
 * (unmet feature gate) shows disabled. Each toggle persists immediately. */
function RolesCard({
  user,
  onChanged,
  onError,
}: {
  user: UserView;
  onChanged: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [defs, setDefs] = useState<RoleDef[]>([]);
  const [assignable, setAssignable] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    client
      .getConfig()
      .then((c) => setDefs(c.roles))
      .catch(() => setDefs([]));
  }, [client]);

  useEffect(() => {
    client
      .assignableRoles(user.userId)
      .then((r) => setAssignable(r.codes))
      .catch(() => setAssignable([]));
  }, [client, user.userId]);

  const toggle = async (code: string, assigned: boolean) => {
    const next = assigned ? user.roles.filter((r) => r !== code) : [...user.roles, code];
    setBusy(true);
    onError("");
    try {
      await client.patchUser(user.userId, { roles: next });
      await onChanged();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  // The catalog, plus any already-assigned code the catalog no longer defines (never hide a grant).
  const catalog: RoleDef[] = [
    ...defs,
    ...user.roles
      .filter((code) => !defs.some((d) => d.code === code))
      .map((code) => ({ code, name: code })),
  ];

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("users.rolesTitle")}</h2>
      {catalog.length === 0 ? (
        <span className="text-xs text-slate-400">{t("users.rolesEmpty")}</span>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
          {catalog.map((def) => {
            const assigned = user.roles.includes(def.code);
            const canToggle = assigned || assignable.includes(def.code);
            const subtitle = def.description || def.code;
            return (
              <li key={def.code} className="flex items-start gap-3 py-3">
                <div className="pt-0.5">
                  <Toggle
                    checked={assigned}
                    disabled={busy || !canToggle}
                    label={def.name}
                    onChange={() => void toggle(def.code, assigned)}
                  />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-slate-900 dark:text-white">
                    {def.name}
                  </div>
                  {subtitle && (
                    <div className="text-xs text-slate-400 dark:text-slate-500">{subtitle}</div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

/** The user's audit entries, paged newest-first with a "load more" button. */
function AuditCard({ userId }: { userId: string }) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    client
      .userAudit(userId, AUDIT_PAGE)
      .then((page) => {
        if (alive) {
          setEntries(page.entries);
          setCursor(page.nextCursor);
        }
      })
      .catch(() => {
        if (alive) {
          setEntries([]);
        }
      });
    return () => {
      alive = false;
    };
  }, [client, userId]);

  const loadMore = async () => {
    if (!cursor) {
      return;
    }
    setBusy(true);
    try {
      const page = await client.userAudit(userId, AUDIT_PAGE, cursor);
      setEntries((prev) => [...(prev ?? []), ...page.entries]);
      setCursor(page.nextCursor);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("users.auditTitle")}</h2>
      {entries === null ? (
        <Loader />
      ) : entries.length === 0 ? (
        <p className="text-sm text-slate-500">{t("users.noAudit")}</p>
      ) : (
        <>
          <AuditList entries={entries} />
          {cursor && (
            <button
              type="button"
              className="text-sm text-primary hover:underline disabled:opacity-50"
              disabled={busy}
              onClick={() => void loadMore()}
            >
              {t("common.loadMore")}
            </button>
          )}
        </>
      )}
    </section>
  );
}

/** The user's active sessions, with a force "log out everywhere". */
function SessionsCard({ user, onError }: { user: UserView; onError: (msg: string) => void }) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [sessions, setSessions] = useState<SessionView[] | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    client
      .userSessions(user.userId)
      .then(setSessions)
      .catch(() => setSessions([]));
  }, [client, user.userId]);

  useEffect(() => load(), [load]);

  const logoutAll = async () => {
    const name = user.fullName || user.username;
    if (!window.confirm(t("users.logoutAllConfirm", { name }))) {
      return;
    }
    setBusy(true);
    onError("");
    try {
      await client.logoutUser(user.userId);
      load();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={`${card} space-y-3`}>
      <div className="flex items-center justify-between gap-3">
        <h2 className="font-medium text-slate-800 dark:text-slate-200">
          {t("users.sessionsTitle")}
        </h2>
        {sessions && sessions.length > 0 && (
          <button className={ghostButton} disabled={busy} onClick={() => void logoutAll()}>
            {t("users.logoutAll")}
          </button>
        )}
      </div>
      {sessions === null ? (
        <Loader />
      ) : sessions.length === 0 ? (
        <p className="text-sm text-slate-500">{t("users.noSessions")}</p>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
          {sessions.map((session) => (
            <li key={session.sessionId} className="py-2">
              <div className="text-sm text-slate-800 dark:text-slate-200 truncate">
                {session.userAgent || "—"}
              </div>
              <div className="text-xs text-slate-400">
                {session.ip ? `${session.ip} · ` : ""}
                {formatDateTime(session.lastSeen)}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** Read-only list of the user's personal access tokens (requires `manage:users`). */
function PatsCard({ userId }: { userId: string }) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [pats, setPats] = useState<ApiKeyView[] | null>(null);

  useEffect(() => {
    client
      .listUserPats(userId)
      .then(setPats)
      .catch(() => setPats([]));
  }, [client, userId]);

  return (
    <section className={`${card} overflow-x-auto`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200 mb-3">
        {t("users.patsTitle")}
      </h2>
      {pats === null ? (
        <Loader />
      ) : pats.length === 0 ? (
        <p className="text-sm text-slate-500">{t("users.noPats")}</p>
      ) : (
        <table className="w-full border-collapse">
          <thead>
            <tr className="border-b border-slate-200 dark:border-slate-700">
              <th className={th}>Name</th>
              <th className={th}>APIs</th>
              <th className={th}>Status</th>
              <th className={th}>{t("users.created")}</th>
            </tr>
          </thead>
          <tbody>
            {pats.map((pat) => (
              <tr key={pat.keyId} className="border-b border-slate-100 dark:border-slate-700/50">
                <td className={td}>{pat.name}</td>
                <td className={td}>{pat.apis.join(", ") || "—"}</td>
                <td className={td}>{pat.status}</td>
                <td className={td}>{formatDateTime(pat.created)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

/** Muted gray change-tracking box: ID, last active, created. */
function MetaBox({ user }: { user: UserView }) {
  const { t } = useTranslation();
  const rows: { label: string; value: ReactNode }[] = [
    {
      label: t("users.id"),
      value: <span className="font-mono text-xs break-all">{user.userId}</span>,
    },
    {
      label: t("users.colLastActive"),
      value: user.lastSeen ? formatDateTime(user.lastSeen) : "—",
    },
    { label: t("users.lastUpdated"), value: formatDateTime(user.lastUpdated) },
    { label: t("users.created"), value: formatDateTime(user.created) },
  ];
  return (
    <section className="rounded border border-slate-200 dark:border-slate-700/50 bg-slate-200/60 dark:bg-slate-950/50 p-6">
      <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-3">
        {rows.map((row) => (
          <div key={row.label}>
            <dt className="text-xs text-slate-400">{row.label}</dt>
            <dd className="text-sm text-slate-600 dark:text-slate-300">{row.value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
