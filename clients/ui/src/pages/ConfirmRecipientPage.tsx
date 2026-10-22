import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, errMsg, Loader } from "../components";
import { card } from "../ui";

/** Landing page for the link in a recipient's confirmation mail.
 *
 * Reachable **without a session**, like the contact confirmation: the reader is a mailbox nobody
 * logs in with, and the token in the URL is the proof. Renders standalone and ends with no
 * "continue" — the reader has no account here and nowhere in umami to go on to. */
export function ConfirmRecipientPage() {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const [state, setState] = useState<"working" | "ok" | "error">("working");
  const [tenantName, setTenantName] = useState("");
  const [error, setError] = useState<string | null>(null);
  // The token is single-use: React mounts effects twice in development, and a second POST would
  // consume nothing and report the link as invalid.
  const attempted = useRef(false);

  useEffect(() => {
    if (attempted.current) return;
    attempted.current = true;

    if (!token) {
      setError(t("confirmRecipient.missingToken"));
      setState("error");
      return;
    }
    client
      .confirmRecipient(token)
      .then((result) => {
        setTenantName(result.tenantName);
        setState("ok");
      })
      .catch((err) => {
        setError(errMsg(err));
        setState("error");
      });
  }, [client, token, t]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 dark:bg-slate-900 p-4">
      <section className={`${card} w-full max-w-md space-y-4 text-center`}>
        <h1 className="text-lg font-medium text-slate-800 dark:text-slate-200">
          {t("confirmRecipient.title")}
        </h1>

        {state === "working" && <Loader label={t("confirmRecipient.working")} />}

        {state === "ok" && (
          <p className="text-sm text-slate-600 dark:text-slate-300">
            {t("confirmRecipient.ok", { tenant: tenantName })}
          </p>
        )}

        {state === "error" && (
          <>
            <Banner tone="error">{error}</Banner>
            <p className="text-sm text-slate-500">{t("confirmRecipient.retryHint")}</p>
          </>
        )}
      </section>
    </div>
  );
}
