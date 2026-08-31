import type {
  ApiKeyView,
  AuditEntry,
  Contact,
  CustomFieldDef,
  MessagingLink,
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
  ContactList,
  CustomFieldsForm,
  DropdownMenu,
  errMsg,
  Field,
  formatDateTime,
  formatFieldValue,
  Loader,
  MessagingLinkList,
  PatList,
  RoleToggleList,
  roleCatalog,
} from "../components";
import { RateLimitCard, RateLimitDisclosure } from "../ratelimit";
import { card, ghostButton, input, primaryButton } from "../ui";

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
  const [locales, setLocales] = useState<string[]>([]);
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
      .then((r) => {
        setDefs(r.user);
        setLocales(r.locales);
      })
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
            locales={locales}
            onSaved={async () => {
              setNotice(t("users.saved"));
              await reload();
            }}
            onError={setError}
          />
          <RolesCard user={user} onChanged={reload} onError={setError} />
          <AuditCard userId={user.userId} />
          <RateLimitCard
            target={{ kind: "user", userId: user.userId }}
            hint={t("rateLimits.userHint")}
          />
          <SessionsCard user={user} onError={setError} />
          <PatsCard userId={user.userId} />
          <ContactsCard userId={user.userId} />
          <MessagingLinksCard userId={user.userId} />
          <MetaBox user={user} />
        </>
      )}

      <button className={ghostButton} onClick={goBack}>
        {t("users.back")}
      </button>
    </div>
  );
}

/** Read-only details with an Edit toggle for the name parts + custom fields + lock. Username
 * are the login identity and stay read-only. */
function DetailsCard({
  user,
  defs,
  locales,
  onSaved,
  onError,
}: {
  user: UserView;
  defs: CustomFieldDef[];
  locales: string[];
  onSaved: () => Promise<void>;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [editing, setEditing] = useState(false);
  const [username, setUsername] = useState(user.username);
  const [title, setTitle] = useState(user.title ?? "");
  const [salutation, setSalutation] = useState<Salutation>(user.salutation);
  const [firstname, setFirstname] = useState(user.firstname ?? "");
  const [lastname, setLastname] = useState(user.lastname ?? "");
  const [locale, setLocale] = useState(user.locale ?? "");
  const [fields, setFields] = useState<Record<string, unknown>>({ ...user.customFields });
  const [saving, setSaving] = useState(false);

  const reset = useCallback(() => {
    setUsername(user.username);
    setTitle(user.title ?? "");
    setSalutation(user.salutation);
    setFirstname(user.firstname ?? "");
    setLastname(user.lastname ?? "");
    setLocale(user.locale ?? "");
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
        title,
        salutation,
        firstname,
        lastname,
        locale,
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
            <Field label={t("users.locale")}>
              <select className={input} value={locale} onChange={(e) => setLocale(e.target.value)}>
                <option value="">{t("users.localeAuto")}</option>
                {locales.map((code) => (
                  <option key={code} value={code}>
                    {t(`locale.${code}`, { defaultValue: code })}
                  </option>
                ))}
              </select>
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
          <DetailRow label={t("users.name")}>
            {user.firstname || user.lastname ? user.fullName : "—"}
          </DetailRow>
          {defs.map((def) => (
            <DetailRow key={def.code} label={def.label}>
              {formatFieldValue(user.customFields[def.code])}
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

/** The user's roles. Each toggle persists immediately. */
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

  const catalog = roleCatalog(defs, assignable, user.roles, t("users.roleUnknown"));

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("users.rolesTitle")}</h2>
      <RoleToggleList
        roles={catalog}
        selected={user.roles}
        onToggle={(code, assigned) => void toggle(code, assigned)}
        disabled={busy}
        canToggle={(code) => user.roles.includes(code) || assignable.includes(code)}
        empty={t("users.rolesEmpty")}
      />
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

/** Read-only list of the user's personal access tokens (same layout as the profile, no actions). */
function PatsCard({ userId }: { userId: string }) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [pats, setPats] = useState<ApiKeyView[] | null>(null);
  const [defs, setDefs] = useState<RoleDef[]>([]);

  useEffect(() => {
    client
      .listUserPats(userId)
      .then(setPats)
      .catch(() => setPats([]));
  }, [client, userId]);

  useEffect(() => {
    client
      .getConfig()
      .then((c) => setDefs(c.roles))
      .catch(() => setDefs([]));
  }, [client]);

  const roleLabel = (code: string) => defs.find((d) => d.code === code)?.name ?? code;

  // Read-only admin view: hide the whole card when the user has no PATs (nothing to show, and
  // there's no create affordance here) — keeps the edit screen uncluttered for apps that don't use
  // PATs. Also hidden while still loading.
  if (!pats || pats.length === 0) {
    return null;
  }
  return (
    <section className={card}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200 mb-3">{t("pats.title")}</h2>
      <PatList
        pats={pats}
        roleLabel={roleLabel}
        renderDetails={(pat) => (
          <RateLimitDisclosure target={{ kind: "userPat", userId, keyId: pat.keyId }} />
        )}
      />
    </section>
  );
}

/** Read-only list of the user's email addresses (requires `manage:users`; scoped to the caller's
 * tenant server-side). Hidden when the user has none, so the card is never an empty box. */
function ContactsCard({ userId }: { userId: string }) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [contacts, setContacts] = useState<Contact[] | null>(null);

  useEffect(() => {
    client
      .listUserContacts(userId)
      .then(setContacts)
      .catch(() => setContacts([]));
  }, [client, userId]);

  if (!contacts || contacts.length === 0) return null;
  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("contacts.title")}</h2>
      <ContactList contacts={contacts} />
    </section>
  );
}

/** Read-only list of the user's messaging (Telegram/WhatsApp) identity links (requires
 * `manage:users`; scoped to the caller's tenant). */
function MessagingLinksCard({ userId }: { userId: string }) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [links, setLinks] = useState<MessagingLink[] | null>(null);

  useEffect(() => {
    client
      .listUserMessagingLinks(userId)
      .then(setLinks)
      .catch(() => setLinks([]));
  }, [client, userId]);

  // Hide the card entirely when the user has no messaging links (or while loading) — read-only view.
  if (!links || links.length === 0) {
    return null;
  }
  return (
    <section className={card}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200 mb-3">
        {t("messaging.linksTitle")}
      </h2>
      <MessagingLinkList links={links} />
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
