import type {
  ApiKeyView,
  AuditEntry,
  CustomFieldDef,
  Salutation,
  SessionView,
  UserView,
} from "@bentoforge/umami-iam";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate, useParams } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import {
  Banner,
  CheckboxTags,
  CustomFieldsForm,
  errMsg,
  Field,
  formatDateTime,
  formatFieldValue,
  Loader,
} from "../components";
import { card, ghostButton, input, primaryButton, td, th } from "../ui";

/** Per-user edit view: details (read + inline edit), roles, recent audit, sessions, read-only PATs,
 * a change-tracking metadata box, and an in-app Back. */
export function EditUserPage() {
  const { client } = useUmami();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { userId = "" } = useParams();

  const [user, setUser] = useState<UserView | null>(null);
  const [defs, setDefs] = useState<CustomFieldDef[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
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
      <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
        {t("users.editTitle")}
      </h1>

      {error && <Banner tone="error">{error}</Banner>}
      {notice && <Banner tone="ok">{notice}</Banner>}

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
  const [title, setTitle] = useState(user.title ?? "");
  const [salutation, setSalutation] = useState<Salutation>(user.salutation);
  const [firstname, setFirstname] = useState(user.firstname ?? "");
  const [lastname, setLastname] = useState(user.lastname ?? "");
  const [locked, setLocked] = useState(user.locked);
  const [fields, setFields] = useState<Record<string, unknown>>({ ...user.customFields });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setTitle(user.title ?? "");
    setSalutation(user.salutation);
    setFirstname(user.firstname ?? "");
    setLastname(user.lastname ?? "");
    setLocked(user.locked);
    setFields({ ...user.customFields });
  }, [user]);

  const cancel = () => {
    setEditing(false);
    setTitle(user.title ?? "");
    setSalutation(user.salutation);
    setFirstname(user.firstname ?? "");
    setLastname(user.lastname ?? "");
    setLocked(user.locked);
    setFields({ ...user.customFields });
  };

  const save = async () => {
    setSaving(true);
    onError("");
    try {
      await client.patchUser(user.userId, {
        title,
        salutation,
        firstname,
        lastname,
        locked,
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
          <div className="grid grid-cols-2 gap-3">
            <Field label={t("users.salutation")}>
              <select
                className={input}
                value={salutation}
                onChange={(e) => setSalutation(e.target.value as Salutation)}
              >
                <option value="">—</option>
                <option value="SIR">Sir</option>
                <option value="MADAM">Madam</option>
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
            <Field label={t("users.locked")}>
              <label className="inline-flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="h-4 w-4 accent-primary"
                  checked={locked}
                  onChange={(e) => setLocked(e.target.checked)}
                />
                {t("users.locked")}
              </label>
            </Field>
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
          <DetailRow label={t("users.salutation")}>{user.salutation || "—"}</DetailRow>
          <DetailRow label={t("users.nameTitle")}>{user.title ?? "—"}</DetailRow>
          <DetailRow label={t("users.firstname")}>{user.firstname ?? "—"}</DetailRow>
          <DetailRow label={t("users.lastname")}>{user.lastname ?? "—"}</DetailRow>
          {defs.map((def) => (
            <DetailRow key={def.key} label={def.label}>
              {formatFieldValue(user.customFields[def.key])}
            </DetailRow>
          ))}
          <DetailRow label={t("users.locked")}>{user.locked ? t("users.locked") : "—"}</DetailRow>
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

/** Assign/unassign the user's roles (chips). Each toggle persists immediately. */
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
  const [assignable, setAssignable] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    client
      .assignableRoles(user.userId)
      .then((r) => setAssignable(r.codes))
      .catch(() => setAssignable([]));
  }, [client, user.userId]);

  const change = async (roles: string[]) => {
    setBusy(true);
    onError("");
    try {
      await client.patchUser(user.userId, { roles });
      await onChanged();
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("users.rolesTitle")}</h2>
      <div className={busy ? "opacity-50 pointer-events-none" : ""}>
        <CheckboxTags
          options={assignable}
          selected={user.roles}
          onChange={(next) => void change(next)}
          empty={t("users.rolesEmpty")}
        />
      </div>
    </section>
  );
}

/** The user's most recent audit entries (last 5). */
function AuditCard({ userId }: { userId: string }) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);

  useEffect(() => {
    client
      .userAudit(userId, 5)
      .then(setEntries)
      .catch(() => setEntries([]));
  }, [client, userId]);

  const dot: Record<string, string> = {
    good: "bg-emerald-500",
    neutral: "bg-slate-400",
    bad: "bg-red-500",
  };

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("users.auditTitle")}</h2>
      {entries === null ? (
        <Loader />
      ) : entries.length === 0 ? (
        <p className="text-sm text-slate-500">{t("users.noAudit")}</p>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
          {entries.map((entry) => (
            <li key={entry.id} className="flex items-start gap-3 py-2">
              <span
                className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${dot[entry.severity] ?? dot.neutral}`}
              />
              <div className="min-w-0">
                <div className="text-sm text-slate-800 dark:text-slate-200">{entry.message}</div>
                <div className="text-xs text-slate-400">{formatDateTime(entry.timestamp)}</div>
              </div>
            </li>
          ))}
        </ul>
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
    { label: t("users.created"), value: formatDateTime(user.created) },
  ];
  return (
    <section className="rounded-2xl border border-slate-200 dark:border-slate-700/50 bg-slate-50 dark:bg-slate-800/40 p-6">
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
