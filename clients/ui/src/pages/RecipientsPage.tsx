import type {
  CreateRecipientRequest,
  ExternalRecipient,
  RecipientsResponse,
  RecipientTypeView,
} from "@bentoforge/umami-iam";
import { PaperAirplaneIcon, TrashIcon } from "@heroicons/react/24/outline";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, DropdownMenu, errMsg, Field, formatDateTime, Loader, Tag } from "../components";
import { card, input, primaryButton, spanSixth, spanThird } from "../ui";

/** Own-tenant screen for external recipients: mailboxes with no login that receive notifications.
 *
 * Each row carries its own choice pickers, written on change, so a recipient's consent is always
 * visible in one place and never behind a second screen. The address is the one thing a row cannot
 * change: a different mailbox is a different recipient and starts with its own confirmation. */
export function RecipientsPage() {
  const { client, me, activeTenantId } = useUmami();
  const { t } = useTranslation();
  const tenantId = activeTenantId ?? me?.user.tenantId ?? "";
  const [data, setData] = useState<RecipientsResponse | null>(null);
  const [locales, setLocales] = useState<string[]>([]);
  const [defaultLocale, setDefaultLocale] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      setData(await client.listRecipients(tenantId));
    } catch (err) {
      setError(errMsg(err));
      setData({ recipients: [], types: [], verificationAvailable: false });
    }
  }, [client, tenantId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    client
      .getCustomFields()
      .then((r) => {
        setLocales(r.locales);
        setDefaultLocale(r.defaultLocale);
      })
      .catch(() => setLocales([]));
  }, [client]);

  const types = data?.types ?? [];

  const onCreate = async (request: CreateRecipientRequest) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const created = await client.createRecipient(tenantId, request);
      setNotice(
        created.verificationSent
          ? t("recipients.createdMailed", { address: created.address })
          : t("recipients.createdUnmailed", { address: created.address }),
      );
      setCreating(false);
      await load();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const onChoice = async (recipient: ExternalRecipient, code: string, value: string) => {
    setBusy(true);
    setError(null);
    try {
      const choices = { ...recipient.choices, [code]: value };
      await client.patchRecipient(tenantId, recipient.recipientId, { choices });
      await load();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const onResend = async (recipient: ExternalRecipient) => {
    setError(null);
    setNotice(null);
    try {
      const result = await client.resendRecipientConfirmation(tenantId, recipient.recipientId);
      setNotice(
        result.status === "already-confirmed"
          ? t("recipients.alreadyConfirmed")
          : t("recipients.resent", { address: recipient.address }),
      );
    } catch (err) {
      setError(errMsg(err));
    }
  };

  const onDelete = async (recipient: ExternalRecipient) => {
    if (!window.confirm(t("recipients.deleteConfirm", { address: recipient.address }))) {
      return;
    }
    setError(null);
    setNotice(null);
    try {
      await client.deleteRecipient(tenantId, recipient.recipientId);
      setNotice(t("recipients.deleted", { address: recipient.address }));
      await load();
    } catch (err) {
      setError(errMsg(err));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
            {t("recipients.title")}
          </h1>
          <p className="text-sm text-slate-500">{t("recipients.intro")}</p>
        </div>
        {types.length > 0 && (
          <button className={primaryButton} onClick={() => setCreating((v) => !v)}>
            {creating ? t("recipients.cancel") : t("recipients.new")}
          </button>
        )}
      </div>

      <Banner tone="error">{error}</Banner>
      <Banner tone="ok">{notice}</Banner>

      {data && !data.verificationAvailable && (
        <p className="text-xs text-amber-600 dark:text-amber-400">{t("recipients.noMail")}</p>
      )}

      {creating && (
        <CreateForm
          types={types}
          locales={locales}
          defaultLocale={defaultLocale}
          busy={busy}
          onSubmit={onCreate}
        />
      )}

      {data === null ? (
        <Loader />
      ) : types.length === 0 ? (
        <p className="text-sm text-slate-500">{t("recipients.noTypes")}</p>
      ) : data.recipients.length === 0 ? (
        <p className="text-sm text-slate-500">{t("recipients.empty")}</p>
      ) : (
        <ul className="space-y-3">
          {data.recipients.map((recipient) => (
            <li key={recipient.recipientId} className={`${card} space-y-3`}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 space-y-1">
                  <div className="flex flex-wrap items-center gap-2 text-sm font-medium text-slate-900 dark:text-white">
                    <span className="truncate">{recipient.displayName}</span>
                    <span className="text-slate-400">{recipient.address}</span>
                    {recipient.confirmed ? (
                      <Tag tone="info">{t("recipients.confirmed")}</Tag>
                    ) : (
                      <Tag tone="warn">{t("recipients.unconfirmed")}</Tag>
                    )}
                  </div>
                  <div className="text-slate-400">
                    {t("recipients.addedOn")}: {formatDateTime(recipient.created)} ·{" "}
                    {t(`locale.${recipient.locale}`, { defaultValue: recipient.locale })}
                  </div>
                </div>
                <DropdownMenu
                  label={t("recipients.menu")}
                  actions={[
                    ...(!recipient.confirmed && data.verificationAvailable
                      ? [
                          {
                            label: t("recipients.resend"),
                            icon: PaperAirplaneIcon,
                            onSelect: () => void onResend(recipient),
                          },
                        ]
                      : []),
                    {
                      label: t("recipients.delete"),
                      danger: true,
                      icon: TrashIcon,
                      onSelect: () => void onDelete(recipient),
                    },
                  ]}
                />
              </div>
              <ChoicePickers
                types={types}
                choices={recipient.choices}
                disabled={busy}
                onChange={(code, value) => void onChoice(recipient, code, value)}
              />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** One select per type open to recipients. The empty option is `off`: a recipient has no
 * "unset" state, because nobody ever showed it a default to follow. */
export function ChoicePickers({
  types,
  choices,
  disabled,
  onChange,
}: {
  types: RecipientTypeView[];
  choices: Record<string, string>;
  disabled?: boolean;
  onChange: (code: string, value: string) => void;
}) {
  const { t } = useTranslation();
  const labelFor = (type: RecipientTypeView, value: string) =>
    value === "off" || value === "on"
      ? t(`notifications.${value}`)
      : (type.cadences.find((c) => c.code === value)?.name ?? value);
  return (
    <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
      {types.map((type) => (
        <li key={type.code} className="flex flex-wrap items-center justify-between gap-3 py-2">
          <div className="min-w-0">
            <div className="text-sm font-medium text-slate-900 dark:text-white">{type.name}</div>
            {type.description && <div className="text-slate-400">{type.description}</div>}
          </div>
          <select
            className={`${input} w-auto`}
            value={choices[type.code] ?? "off"}
            disabled={disabled}
            onChange={(e) => onChange(type.code, e.target.value)}
          >
            {type.allowed.map((allowed) => (
              <option key={allowed} value={allowed}>
                {labelFor(type, allowed)}
              </option>
            ))}
          </select>
        </li>
      ))}
    </ul>
  );
}

function CreateForm({
  types,
  locales,
  defaultLocale,
  busy,
  onSubmit,
}: {
  types: RecipientTypeView[];
  locales: string[];
  defaultLocale: string;
  busy: boolean;
  onSubmit: (request: CreateRecipientRequest) => void;
}) {
  const { t } = useTranslation();
  const [address, setAddress] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [locale, setLocale] = useState(defaultLocale || locales[0] || "en");
  const [choices, setChoices] = useState<Record<string, string>>({});

  useEffect(() => {
    if (defaultLocale) setLocale(defaultLocale);
  }, [defaultLocale]);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({ address, displayName, locale, choices });
  };

  return (
    <form onSubmit={submit} className={`${card} space-y-4`}>
      <h2 className="font-medium text-slate-800 dark:text-slate-200">
        {t("recipients.createTitle")}
      </h2>
      <div className="grid grid-cols-12 gap-3">
        <Field label={t("recipients.address")} className={spanSixth}>
          <input
            className={input}
            type="email"
            required
            value={address}
            onChange={(e) => setAddress(e.target.value)}
          />
        </Field>
        <Field label={t("recipients.displayName")} className={spanThird}>
          <input
            className={input}
            required
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </Field>
        <Field label={t("recipients.locale")} className={spanSixth}>
          <select className={input} value={locale} onChange={(e) => setLocale(e.target.value)}>
            {locales.map((code) => (
              <option key={code} value={code}>
                {t(`locale.${code}`, { defaultValue: code })}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <div>
        <div className="text-sm text-slate-600 dark:text-slate-400">
          {t("recipients.choicesLabel")}
        </div>
        <ChoicePickers
          types={types}
          choices={choices}
          onChange={(code, value) => setChoices((c) => ({ ...c, [code]: value }))}
        />
      </div>
      <p className="text-xs text-slate-500">{t("recipients.consentHint")}</p>
      <button className={primaryButton} type="submit" disabled={busy}>
        {t("recipients.create")}
      </button>
    </form>
  );
}
