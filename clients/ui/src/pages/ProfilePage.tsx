import type {
  ApiKeyView,
  AuditEntry,
  CustomFieldDef,
  MessagingCodeResponse,
  MessagingLink,
  RoleDef,
  Salutation,
  SessionView,
  TotpSetup,
} from "@bentoforge/umami-iam";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import {
  AuditList,
  Banner,
  CustomFieldsForm,
  errMsg,
  Field,
  formatDateTime,
  formatFieldValue,
  Loader,
  MessagingLinkList,
  PatList,
  Toggle,
} from "../components";
import { card, dangerButton, ghostButton, input, primaryButton } from "../ui";

/** Page size for the audit "load more" list. */
const AUDIT_PAGE = 10;

/** Profile: base data (editable), recent activity, sessions, security, and personal tokens. */
export function ProfilePage() {
  const { client, me } = useUmami();
  const { t } = useTranslation();

  if (!me) return null;

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-slate-900 dark:text-white">{t("profile.title")}</h1>
      <BaseDataCard />
      <AuditCard />
      <SessionsPanel />
      <SecurityCard />
      {client.hasPermission("manage:pat") && <PatsPanel />}
      {client.hasPermission("messaging:self") && <MessagingPanel />}
    </div>
  );
}

/** Self-service device management: the caller's active login sessions + "log out everywhere". */
function SessionsPanel() {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [sessions, setSessions] = useState<SessionView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      setSessions(await client.listSessions());
    } catch (err) {
      setError(errMsg(err));
      setSessions([]);
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  const revoke = async (session: SessionView) => {
    if (!window.confirm(t("sessions.revokeConfirm"))) {
      return;
    }
    setError(null);
    try {
      await client.deleteSession(session.sessionId);
      await load();
    } catch (err) {
      setError(errMsg(err));
    }
  };

  const logoutAll = async () => {
    if (!window.confirm(t("sessions.logoutAllConfirm"))) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await client.logoutAll();
      await load();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={`${card} space-y-3`}>
      <div className="flex items-center justify-between gap-3">
        <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("nav.sessions")}</h2>
        {sessions && sessions.length > 0 && (
          <button className={ghostButton} disabled={busy} onClick={() => void logoutAll()}>
            {t("sessions.logoutAll")}
          </button>
        )}
      </div>
      {error && <Banner tone="error">{error}</Banner>}
      {sessions === null ? (
        <Loader />
      ) : sessions.length === 0 ? (
        <p className="text-sm text-slate-500">{t("sessions.none")}</p>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
          {sessions.map((session) => (
            <li key={session.sessionId} className="flex items-center justify-between gap-3 py-3">
              <div className="min-w-0">
                <div className="text-sm font-medium text-slate-900 dark:text-white truncate">
                  {session.userAgent || t("sessions.unknownDevice")}
                  {session.current && (
                    <span className="ml-2 rounded bg-brand/10 text-brand px-1.5 py-0.5 text-[10px] align-middle">
                      {t("sessions.current")}
                    </span>
                  )}
                </div>
                <div className="text-xs text-slate-400">
                  {session.ip ? `${session.ip} · ` : ""}
                  {formatDateTime(session.lastSeen)}
                </div>
              </div>
              {!session.current && (
                <button className={dangerButton} onClick={() => void revoke(session)}>
                  {t("sessions.revoke")}
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** Messaging links: show the user's link code (regenerable) and their connected identities. */
function MessagingPanel() {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [code, setCode] = useState<MessagingCodeResponse | null>(null);
  const [links, setLinks] = useState<MessagingLink[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [c, l] = await Promise.all([client.getMessagingCode(), client.listMessagingLinks()]);
      setCode(c);
      setLinks(l.links);
    } catch (err) {
      setError(errMsg(err));
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  const regenerate = async () => {
    if (!window.confirm("Generate a new code? The old one stops working immediately.")) return;
    setBusy(true);
    setError(null);
    try {
      setCode(await client.regenerateMessagingCode());
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const unlink = async (link: MessagingLink) => {
    if (
      !window.confirm(
        t("messaging.deleteConfirm", { platform: link.platform, id: link.externalId }),
      )
    ) {
      return;
    }
    setError(null);
    try {
      await client.deleteMessagingLink(link.platform, link.externalId);
      await load();
    } catch (err) {
      setError(errMsg(err));
    }
  };

  return (
    <section className={`${card} space-y-4`}>
      <div>
        <h2 className="font-medium text-slate-800 dark:text-slate-200">Messaging</h2>
        <p className="text-sm text-slate-500">
          Give this code to the Telegram/WhatsApp bot (deep link or first message) to connect your
          account. It stays valid and can link several chats.
        </p>
      </div>

      <Banner tone="error">{error}</Banner>

      <div className="flex flex-wrap items-center gap-3">
        <code className="rounded-lg bg-slate-100 dark:bg-slate-900 px-3 py-2 text-lg font-mono tracking-widest text-slate-900 dark:text-white">
          {code?.code ?? "…"}
        </code>
        <button className={ghostButton} disabled={busy} onClick={() => void regenerate()}>
          Regenerate
        </button>
        {code?.telegramUrl && (
          <a className={ghostButton} href={code.telegramUrl} target="_blank" rel="noreferrer">
            Open in Telegram
          </a>
        )}
        {code?.whatsappUrl && (
          <a className={ghostButton} href={code.whatsappUrl} target="_blank" rel="noreferrer">
            Open in WhatsApp
          </a>
        )}
      </div>

      <div>
        <div className="text-xs text-slate-500 mb-1">{t("messaging.linksTitle")}</div>
        {links.length === 0 ? (
          <span className="text-xs text-slate-400">{t("messaging.empty")}</span>
        ) : (
          <MessagingLinkList links={links} onDelete={unlink} />
        )}
      </div>
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

/** Base data: read view (identity + name + tenant/roles + custom fields) with an Edit toggle that
 * turns the name parts and self-editable custom fields into inputs (patchMe). */
function BaseDataCard() {
  const { client, me, refreshMe } = useUmami();
  const { t } = useTranslation();
  const [defs, setDefs] = useState<CustomFieldDef[]>([]);
  const [editing, setEditing] = useState(false);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [title, setTitle] = useState("");
  const [salutation, setSalutation] = useState<Salutation>("");
  const [firstname, setFirstname] = useState("");
  const [lastname, setLastname] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  const canEdit = !client.hasPermission("self:readonly");

  useEffect(() => {
    client
      .getCustomFields()
      .then((schema) => setDefs(schema.user))
      .catch(() => setDefs([]));
  }, [client]);

  const reset = useCallback(() => {
    setValues((me?.user.customFields ?? {}) as Record<string, unknown>);
    setTitle(me?.user.title ?? "");
    setSalutation(me?.user.salutation ?? "");
    setFirstname(me?.user.firstname ?? "");
    setLastname(me?.user.lastname ?? "");
  }, [me?.user]);

  useEffect(() => reset(), [reset]);

  if (!me) return null;
  const u = me.user;
  const editableDefs = defs.filter((def) => def.selfEditable);

  const save = async () => {
    setSaving(true);
    setError(null);
    setOk(false);
    try {
      const customFields: Record<string, unknown> = {};
      for (const def of editableDefs) {
        customFields[def.code] = values[def.code];
      }
      await client.patchMe({ title, salutation, firstname, lastname, customFields });
      await refreshMe();
      setOk(true);
      setEditing(false);
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className={`${card} space-y-4`}>
      <div className="flex items-center justify-between">
        <h2 className="font-medium text-slate-800 dark:text-slate-200">
          {t("profile.detailsTitle")}
        </h2>
        {!editing && canEdit && (
          <button
            className={ghostButton}
            onClick={() => {
              setOk(false);
              setEditing(true);
            }}
          >
            {t("users.edit")}
          </button>
        )}
      </div>
      {error && <Banner tone="error">{error}</Banner>}
      {ok && <Banner tone="ok">{t("profile.saved")}</Banner>}

      {editing ? (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
            {editableDefs.length > 0 && (
              <CustomFieldsForm defs={editableDefs} values={values} onChange={setValues} />
            )}
          </div>
          <div className="flex gap-2">
            <button className={primaryButton} disabled={saving} onClick={() => void save()}>
              {t("users.save")}
            </button>
            <button
              className={ghostButton}
              disabled={saving}
              onClick={() => {
                reset();
                setEditing(false);
              }}
            >
              {t("users.cancel")}
            </button>
          </div>
        </>
      ) : (
        <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
          <DetailRow label={t("users.username")}>{u.username}</DetailRow>
          <DetailRow label={t("users.email")}>{u.email ?? "—"}</DetailRow>
          <DetailRow label={t("users.name")}>
            {u.firstname || u.lastname ? u.fullName : "—"}
          </DetailRow>
          {defs.map((def) => (
            <DetailRow key={def.code} label={def.label}>
              {formatFieldValue(u.customFields[def.code])}
            </DetailRow>
          ))}
        </dl>
      )}
    </section>
  );
}

/** The caller's own audit entries, paged newest-first with a "load more" button. */
function AuditCard() {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    client
      .myAudit(AUDIT_PAGE)
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
  }, [client]);

  const loadMore = async () => {
    if (!cursor) {
      return;
    }
    setBusy(true);
    try {
      const page = await client.myAudit(AUDIT_PAGE, cursor);
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

/** Security: three actions (change password / passkey / authenticator app). Password and TOTP
 * expand inline within the card; passkey enrols immediately. */
function SecurityCard() {
  const { client, me, refreshMe } = useUmami();
  const { t } = useTranslation();
  const [mode, setMode] = useState<"menu" | "password" | "totp">("menu");
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canPassword = !client.hasPermission("self:readonly");
  const mfaEnabled = me?.user.mfaEnabled ?? false;

  const enrolPasskey = async () => {
    setNotice(null);
    setError(null);
    try {
      await client.registerPasskey();
      await refreshMe();
      setNotice(t("dashboard.passkeyAdded"));
    } catch (err) {
      setError(errMsg(err));
    }
  };

  return (
    <section className={`${card} space-y-4`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">
        {t("profile.securityTitle")}
      </h2>
      {error && <Banner tone="error">{error}</Banner>}
      {notice && <Banner tone="ok">{notice}</Banner>}

      {mode === "menu" && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {canPassword && (
            <SecurityAction
              label={t("profile.changePassword")}
              desc={t("profile.changePasswordDesc")}
              onClick={() => {
                setNotice(null);
                setError(null);
                setMode("password");
              }}
            />
          )}
          <SecurityAction
            label={t("profile.passkey")}
            desc={t("profile.passkeyDesc")}
            onClick={() => void enrolPasskey()}
          />
          <SecurityAction
            label={t("profile.totp")}
            desc={t("profile.totpDesc")}
            badge={mfaEnabled ? t("profile.totpActive") : undefined}
            onClick={() => {
              setNotice(null);
              setError(null);
              setMode("totp");
            }}
          />
        </div>
      )}

      {mode === "password" && (
        <ChangePasswordForm
          onDone={(msg) => {
            setMode("menu");
            setNotice(msg);
          }}
          onCancel={() => setMode("menu")}
          onError={setError}
        />
      )}

      {mode === "totp" && (
        <TotpSection
          enabled={mfaEnabled}
          onDone={(msg) => {
            setMode("menu");
            setNotice(msg);
          }}
          onCancel={() => setMode("menu")}
          onError={setError}
        />
      )}
    </section>
  );
}

/** One column in the security menu: a full-width outline button + a description below. */
function SecurityAction({
  label,
  desc,
  onClick,
  badge,
}: {
  label: string;
  desc: string;
  onClick: () => void;
  badge?: string;
}) {
  return (
    <div className="space-y-2">
      <button
        type="button"
        className={`${ghostButton} w-full inline-flex items-center justify-center gap-2`}
        onClick={onClick}
      >
        {label}
        {badge && (
          <span className="rounded bg-brand/10 text-brand px-1.5 py-0.5 text-[10px]">{badge}</span>
        )}
      </button>
      <p className="text-xs text-slate-500">{desc}</p>
    </div>
  );
}

/** Inline password-change form (verifies the current password; logs out other sessions). */
function ChangePasswordForm({
  onDone,
  onCancel,
  onError,
}: {
  onDone: (msg: string) => void;
  onCancel: () => void;
  onError: (msg: string) => void;
}) {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (next !== confirm) {
      onError(t("profile.passwordMismatch"));
      return;
    }
    setBusy(true);
    onError("");
    try {
      await client.changePassword(current, next);
      onDone(t("profile.passwordChanged"));
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Field label={t("profile.currentPassword")}>
          <input
            className={input}
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
        </Field>
        <Field label={t("profile.newPassword")}>
          <input
            className={input}
            type="password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
          />
        </Field>
        <Field label={t("profile.confirmPassword")}>
          <input
            className={input}
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </Field>
      </div>
      <div className="flex gap-2">
        <button
          className={primaryButton}
          disabled={busy || !current || !next}
          onClick={() => void submit()}
        >
          {t("profile.changePassword")}
        </button>
        <button className={ghostButton} disabled={busy} onClick={onCancel}>
          {t("users.cancel")}
        </button>
      </div>
    </div>
  );
}

/** Inline TOTP setup / teardown. When enabled, offers a code-gated disable; otherwise fetches a
 * fresh secret to enrol and verify. */
function TotpSection({
  enabled,
  onDone,
  onCancel,
  onError,
}: {
  enabled: boolean;
  onDone: (msg: string) => void;
  onCancel: () => void;
  onError: (msg: string) => void;
}) {
  const { client, refreshMe } = useUmami();
  const { t } = useTranslation();
  const [setup, setSetup] = useState<TotpSetup | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (enabled) {
      return;
    }
    client
      .totpSetup()
      .then(setSetup)
      .catch((err) => onError(errMsg(err)));
    // onError is stable enough for this one-shot setup fetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, client]);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    onError("");
    try {
      await fn();
      await refreshMe();
      onDone(t("profile.saved"));
    } catch (err) {
      onError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      {enabled ? (
        <p className="text-sm text-slate-500">{t("profile.totpDisableHint")}</p>
      ) : (
        <>
          <p className="text-sm text-slate-500">{t("profile.totpSetupHint")}</p>
          <div>
            <div className="text-xs text-slate-500 mb-1">{t("profile.totpSecret")}</div>
            <code className="block break-all rounded bg-slate-100 dark:bg-slate-900 px-3 py-2 text-sm font-mono tracking-wider text-slate-900 dark:text-white">
              {setup?.secret ?? "…"}
            </code>
          </div>
        </>
      )}
      <div className="flex flex-wrap items-end gap-3">
        <Field label={t("profile.totpCode")}>
          <input
            className={`${input} max-w-40`}
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        </Field>
        {enabled ? (
          <button
            className={dangerButton}
            disabled={busy || code.length < 6}
            onClick={() => void run(() => client.totpDisable(code))}
          >
            {t("profile.totpDisable")}
          </button>
        ) : (
          <button
            className={primaryButton}
            disabled={busy || code.length < 6}
            onClick={() => void run(() => client.totpVerify(code))}
          >
            {t("profile.totpActivate")}
          </button>
        )}
        <button className={ghostButton} disabled={busy} onClick={onCancel}>
          {t("users.cancel")}
        </button>
      </div>
    </div>
  );
}

/** Personal access tokens for the current user: a list (name + roles/last-used/created) with a
 * per-row delete menu, plus a "new token" mode that captures a name and a role-inheritance toggle
 * list (no roles selected → all of the user's roles). The fresh secret is shown once on create. */
function PatsPanel() {
  const { client, me } = useUmami();
  const { t } = useTranslation();
  const [pats, setPats] = useState<ApiKeyView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [selectedRoles, setSelectedRoles] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [freshSecret, setFreshSecret] = useState<string | null>(null);
  const [defs, setDefs] = useState<RoleDef[]>([]);

  const load = useCallback(async () => {
    setError(null);
    try {
      setPats(await client.listMyPats());
    } catch (err) {
      setError(errMsg(err));
      setPats([]);
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    client
      .getConfig()
      .then((c) => setDefs(c.roles))
      .catch(() => setDefs([]));
  }, [client]);

  const roleLabel = (code: string) => defs.find((d) => d.code === code)?.name ?? code;

  // A PAT can only inherit the user's own roles — offer exactly those, with catalog name/description.
  const myRoles = me?.user.roles ?? [];
  const roleCatalog: RoleDef[] = myRoles.map(
    (code) => defs.find((d) => d.code === code) ?? { code, name: code },
  );

  const openCreate = () => {
    setCreating(true);
    setFreshSecret(null);
    setName("");
    setSelectedRoles([]);
  };

  const toggleRole = (code: string) => {
    setSelectedRoles((prev) =>
      prev.includes(code) ? prev.filter((r) => r !== code) : [...prev, code],
    );
  };

  const create = async () => {
    setBusy(true);
    setError(null);
    setFreshSecret(null);
    try {
      const res = await client.createMyPat({ name, roles: selectedRoles });
      setFreshSecret(res.apiKey);
      setCreating(false);
      await load();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (pat: ApiKeyView) => {
    if (!window.confirm(t("pats.deleteConfirm", { name: pat.name }))) {
      return;
    }
    setError(null);
    try {
      await client.deleteMyPat(pat.keyId);
      await load();
    } catch (err) {
      setError(errMsg(err));
    }
  };

  return (
    <section className={`${card} space-y-4`}>
      <div className="flex items-center justify-between gap-3">
        <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("pats.title")}</h2>
        {!creating && (
          <button className={primaryButton} onClick={openCreate}>
            {t("pats.new")}
          </button>
        )}
      </div>

      <Banner tone="error">{error}</Banner>

      {freshSecret && (
        <div className="rounded-lg border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950 p-3">
          <p className="text-xs text-emerald-700 dark:text-emerald-300 mb-1">
            {t("pats.secretOnce")}
          </p>
          <code className="block break-all text-sm text-slate-900 dark:text-slate-100">
            {freshSecret}
          </code>
        </div>
      )}

      {creating ? (
        <div className="space-y-4">
          <Field label={t("pats.name")}>
            <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
          </Field>

          <div>
            <div className="text-sm font-medium text-slate-800 dark:text-slate-200">
              {t("pats.rolesLabel")}
            </div>
            <p className="text-xs text-slate-500">{t("pats.rolesHint")}</p>
            {roleCatalog.length > 0 && (
              <ul className="mt-2 divide-y divide-slate-100 dark:divide-slate-700/50">
                {roleCatalog.map((def) => {
                  const checked = selectedRoles.includes(def.code);
                  return (
                    <li key={def.code} className="flex items-start gap-3 py-2">
                      <div className="pt-0.5">
                        <Toggle
                          checked={checked}
                          disabled={busy}
                          label={def.name}
                          onChange={() => toggleRole(def.code)}
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
                  );
                })}
              </ul>
            )}
          </div>

          <div className="flex gap-2">
            <button
              className={primaryButton}
              disabled={busy || !name.trim()}
              onClick={() => void create()}
            >
              {t("pats.create")}
            </button>
            <button className={ghostButton} disabled={busy} onClick={() => setCreating(false)}>
              {t("pats.cancel")}
            </button>
          </div>
        </div>
      ) : pats === null ? (
        <Loader />
      ) : pats.length === 0 ? (
        <p className="text-sm text-slate-500">{t("pats.empty")}</p>
      ) : (
        <PatList pats={pats} roleLabel={roleLabel} onDelete={revoke} />
      )}
    </section>
  );
}
