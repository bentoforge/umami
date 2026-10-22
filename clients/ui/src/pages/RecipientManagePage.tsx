import type { RecipientManageView } from "@bentoforge/umami-iam";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, errMsg, Loader } from "../components";
import { card, dangerButton, primaryButton } from "../ui";
import { ChoicePickers } from "./RecipientsPage";

/** What a recipient sees behind the link in every notification it receives: who is writing, what
 * it subscribed to, and the two ways out — change the choices, or leave altogether.
 *
 * Reachable **without a session** and without ever creating one: the token in the URL is the
 * recipient's own long-lived secret, sent to the server in the request body. */
export function RecipientManagePage() {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const [view, setView] = useState<RecipientManageView | null>(null);
  const [choices, setChoices] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [gone, setGone] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!token) {
      setError(t("recipientManage.missingToken"));
      return;
    }
    client
      .recipientManageView(token)
      .then((v) => {
        setView(v);
        setChoices(v.choices);
      })
      .catch((err) => setError(errMsg(err)));
  }, [client, token, t]);

  const save = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const v = await client.setRecipientChoices(token, choices);
      setView(v);
      setChoices(v.choices);
      setNotice(t("recipientManage.saved"));
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  const leave = async () => {
    if (!window.confirm(t("recipientManage.leaveConfirm"))) return;
    setBusy(true);
    setError(null);
    try {
      await client.unsubscribeRecipient(token);
      setGone(true);
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 dark:bg-slate-900 p-4">
      <section className={`${card} w-full max-w-lg space-y-4`}>
        <h1 className="text-lg font-medium text-slate-800 dark:text-slate-200">
          {t("recipientManage.title")}
        </h1>

        <Banner tone="error">{error}</Banner>
        <Banner tone="ok">{notice}</Banner>

        {gone ? (
          <p className="text-sm text-slate-600 dark:text-slate-300">{t("recipientManage.left")}</p>
        ) : view === null ? (
          !error && <Loader />
        ) : (
          <>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              {t("recipientManage.intro", { tenant: view.tenantName, name: view.displayName })}
            </p>
            {!view.confirmed && (
              <p className="text-xs text-amber-600 dark:text-amber-400">
                {t("recipientManage.unconfirmed")}
              </p>
            )}
            <ChoicePickers
              types={view.types}
              choices={choices}
              disabled={busy}
              onChange={(code, value) => setChoices((c) => ({ ...c, [code]: value }))}
            />
            <div className="flex flex-wrap items-center justify-between gap-3">
              <button className={primaryButton} disabled={busy} onClick={() => void save()}>
                {t("recipientManage.save")}
              </button>
              <button className={dangerButton} disabled={busy} onClick={() => void leave()}>
                {t("recipientManage.leave")}
              </button>
            </div>
          </>
        )}
      </section>
    </div>
  );
}
