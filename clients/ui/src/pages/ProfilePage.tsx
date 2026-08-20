import type {
  ApiKeyView,
  CustomFieldDef,
  MessagingCodeResponse,
  MessagingLink,
  Salutation,
} from "@bentoforge/umami-iam";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, CustomFieldsForm, errMsg, Field, formatDateTime } from "../components";
import { card, dangerButton, ghostButton, input, primaryButton } from "../ui";

/** Profile tab: signed-in user, tenant, decoded permissions, passkey enrolment. */
export function ProfilePage() {
  const { t } = useTranslation();
  const { client, me } = useUmami();
  const [notice, setNotice] = useState<string | null>(null);
  const claims = client.getClaims();

  if (!me) return null;

  const onRegisterPasskey = async () => {
    setNotice(null);
    try {
      await client.registerPasskey();
      setNotice(t("dashboard.passkeyAdded"));
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="space-y-6">
      <section className={card}>
        <p className="text-sm text-slate-500">{t("dashboard.signedInAs")}</p>
        <p className="text-xl font-semibold text-slate-900 dark:text-white">{me.user.username}</p>
        <p className="text-slate-500">
          {me.user.username}
          {me.user.email ? ` · ${me.user.email}` : ""}
        </p>
        <dl className="mt-4 grid grid-cols-2 gap-3 text-sm">
          <div>
            <dt className="text-slate-500">{t("dashboard.tenant")}</dt>
            <dd className="text-slate-900 dark:text-white font-medium">
              {me.tenant?.name ?? me.user.tenantId}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">{t("dashboard.role")}</dt>
            <dd className="text-slate-900 dark:text-white font-medium">
              {me.user.roles.join(", ") || "—"}
            </dd>
          </div>
        </dl>
      </section>

      <section className={card}>
        <p className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
          {t("dashboard.permissions")}
        </p>
        <div className="flex flex-wrap gap-2">
          {(claims?.permissions ?? []).length === 0 && <span className="text-slate-400">—</span>}
          {(claims?.permissions ?? []).map((p) => (
            <span
              key={p}
              className="rounded-full bg-brand/10 text-brand px-3 py-1 text-xs font-medium"
            >
              {p}
            </span>
          ))}
        </div>
      </section>

      <section className={card}>
        <button onClick={() => void onRegisterPasskey()} className={ghostButton}>
          {t("dashboard.registerPasskey")}
        </button>
        {notice && <p className="mt-3 text-sm text-slate-600 dark:text-slate-300">{notice}</p>}
      </section>

      {!client.hasPermission("self:readonly") && <ProfileFieldsPanel />}
      {!client.hasPermission("self:readonly") && <ChangePasswordPanel />}
      {client.hasPermission("manage:pat") && <PatsPanel />}
      {client.hasPermission("messaging:self") && <MessagingPanel />}
    </div>
  );
}

/** Messaging links: show the user's link code (regenerable) and their connected identities. */
function MessagingPanel() {
  const { client } = useUmami();
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
    if (!window.confirm(`Unlink ${link.platform} identity "${link.externalId}"?`)) return;
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
        <div className="text-xs text-slate-500 mb-1">Connected identities</div>
        {links.length === 0 ? (
          <span className="text-xs text-slate-400">none yet</span>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {links.map((link) => (
              <li key={link.linkKey} className="flex items-center justify-between py-2">
                <div className="text-sm text-slate-800 dark:text-slate-200">
                  <span className="font-medium capitalize">{link.platform}</span>
                  <span className="text-slate-400"> · {link.externalId}</span>
                </div>
                <button className={dangerButton} onClick={() => void unlink(link)}>
                  Unlink
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

/** Self-service edit of the caller's own `selfEditable` custom fields (profile). Hidden entirely
 * when the deployment marks no user field self-editable. */
function ProfileFieldsPanel() {
  const { client, me, refreshMe } = useUmami();
  const { t } = useTranslation();
  const [defs, setDefs] = useState<CustomFieldDef[]>([]);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [title, setTitle] = useState("");
  const [salutation, setSalutation] = useState<Salutation>("");
  const [firstname, setFirstname] = useState("");
  const [lastname, setLastname] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        const schema = await client.getCustomFields();
        setDefs(schema.user.filter((def) => def.selfEditable));
      } catch (err) {
        setError(errMsg(err));
      }
    })();
  }, [client]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: seed the form once from the fetched profile
  useEffect(() => {
    setValues((me?.user.customFields ?? {}) as Record<string, unknown>);
    setTitle(me?.user.title ?? "");
    setSalutation(me?.user.salutation ?? "");
    setFirstname(me?.user.firstname ?? "");
    setLastname(me?.user.lastname ?? "");
  }, [me?.user.customFields]);

  const save = async () => {
    setBusy(true);
    setError(null);
    setOk(false);
    try {
      // Send only the self-editable keys — the server rejects anything else anyway.
      const customFields: Record<string, unknown> = {};
      for (const def of defs) {
        customFields[def.key] = values[def.key];
      }
      await client.patchMe({ title, salutation, firstname, lastname, customFields });
      await refreshMe();
      setOk(true);
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">Profile</h2>
      {me?.user.fullName && (
        <p className="text-sm text-slate-500">
          Name: <span className="text-slate-800 dark:text-slate-200">{me.user.fullName}</span>
        </p>
      )}
      {error && <Banner tone="error">{error}</Banner>}
      {ok && <Banner tone="ok">Profile updated.</Banner>}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="Salutation">
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
        <Field label="Title">
          <input className={input} value={title} onChange={(e) => setTitle(e.target.value)} />
        </Field>
        <Field label="First name">
          <input
            className={input}
            value={firstname}
            onChange={(e) => setFirstname(e.target.value)}
          />
        </Field>
        <Field label="Last name">
          <input className={input} value={lastname} onChange={(e) => setLastname(e.target.value)} />
        </Field>
      </div>
      {defs.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <CustomFieldsForm defs={defs} values={values} onChange={setValues} />
        </div>
      )}
      <button className={primaryButton} disabled={busy} onClick={() => void save()}>
        Save
      </button>
    </section>
  );
}

/** Self-service password change (verifies the current password; logs out other sessions). */
function ChangePasswordPanel() {
  const { client } = useUmami();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  const submit = async () => {
    setError(null);
    setOk(false);
    if (next !== confirm) {
      setError("New password and confirmation do not match.");
      return;
    }
    setBusy(true);
    try {
      await client.changePassword(current, next);
      setOk(true);
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={`${card} space-y-3`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">Change password</h2>
      {error && <Banner tone="error">{error}</Banner>}
      {ok && <Banner tone="ok">Password changed. Other sessions have been logged out.</Banner>}
      <div className="grid grid-cols-3 gap-3">
        <Field label="Current password">
          <input
            className={input}
            type="password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
        </Field>
        <Field label="New password">
          <input
            className={input}
            type="password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
          />
        </Field>
        <Field label="Confirm new password">
          <input
            className={input}
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </Field>
      </div>
      <button
        className={primaryButton}
        disabled={busy || !current || !next}
        onClick={() => void submit()}
      >
        Change password
      </button>
    </section>
  );
}

/** Personal access tokens: create (secret shown once), list, revoke — all for the current user. */
function PatsPanel() {
  const { client } = useUmami();
  const [pats, setPats] = useState<ApiKeyView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [roles, setRoles] = useState("");
  const [busy, setBusy] = useState(false);
  const [freshSecret, setFreshSecret] = useState<string | null>(null);

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

  const create = async () => {
    setBusy(true);
    setError(null);
    setFreshSecret(null);
    try {
      const res = await client.createMyPat({
        name,
        roles: roles
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      });
      setFreshSecret(res.apiKey);
      setName("");
      setRoles("");
      await load();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (pat: ApiKeyView) => {
    if (!window.confirm(`Revoke token "${pat.name}"? Anything using it stops working.`)) return;
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
      <div>
        <h2 className="font-medium text-slate-800 dark:text-slate-200">Personal access tokens</h2>
        <p className="text-sm text-slate-500">
          Long-lived credentials for CLIs/scripts that act as you. Exchange one at{" "}
          <code>POST /auth/token</code> for a short-lived token. Leave roles empty for all your
          roles, or list a subset to restrict the token.
        </p>
      </div>

      <Banner tone="error">{error}</Banner>

      {freshSecret && (
        <div className="rounded-lg border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950 p-3">
          <p className="text-xs text-emerald-700 dark:text-emerald-300 mb-1">
            Copy this now — it is shown only once:
          </p>
          <code className="block break-all text-sm text-slate-900 dark:text-slate-100">
            {freshSecret}
          </code>
        </div>
      )}

      <div className="flex flex-wrap items-end gap-3">
        <Field label="Name">
          <input className={input} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Roles (comma-separated, optional)">
          <input
            className={input}
            placeholder="role:admin, …"
            value={roles}
            onChange={(e) => setRoles(e.target.value)}
          />
        </Field>
        <button
          className={primaryButton}
          disabled={busy || !name.trim()}
          onClick={() => void create()}
        >
          Create token
        </button>
      </div>

      {pats && pats.length > 0 && (
        <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
          {pats.map((pat) => (
            <li key={pat.keyId} className="flex items-center justify-between py-2">
              <div>
                <div className="text-sm font-medium text-slate-900 dark:text-white">{pat.name}</div>
                <div className="text-xs text-slate-400">
                  {pat.roles.length ? `roles: ${pat.roles.join(", ")}` : "all your roles"} · created{" "}
                  {formatDateTime(pat.created)}
                  {pat.lastUsedAt ? ` · last used ${formatDateTime(pat.lastUsedAt)}` : ""}
                </div>
              </div>
              <button className={dangerButton} onClick={() => void revoke(pat)}>
                Revoke
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
