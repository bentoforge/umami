import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, errMsg, Loader } from "../components";
import { card, primaryButton } from "../ui";

/** Confirmation landing page for the link in a verification mail.
 *
 * Deliberately reachable **without a session** — the link is opened in a mail client, which is
 * regularly a different browser or device than the one that added the address. The token in the URL
 * is the proof; demanding a login here would lock out exactly the people reading mail on a phone.
 *
 * Renders standalone rather than inside the admin layout: a reader arriving from a mail has one
 * question ("did it work?"), and a full navigation chrome around the answer would only be noise. */
export function VerifyContactPage() {
  const { client, me } = useUmami();
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const [state, setState] = useState<"working" | "ok" | "error">("working");
  const [address, setAddress] = useState("");
  const [error, setError] = useState<string | null>(null);
  // The token is single-use: React 18 mounts effects twice in development, and a second POST would
  // consume nothing and report the link as invalid. Guard so the first attempt is the only one.
  const attempted = useRef(false);

  useEffect(() => {
    if (attempted.current) return;
    attempted.current = true;

    if (!token) {
      setError(t("verifyContact.missingToken"));
      setState("error");
      return;
    }
    client
      .verifyContact(token)
      .then((result) => {
        setAddress(result.address);
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
          {t("verifyContact.title")}
        </h1>

        {state === "working" && <Loader label={t("verifyContact.working")} />}

        {state === "ok" && (
          <>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              {t("verifyContact.ok", { address })}
            </p>
            <Link className={primaryButton} to="/profile">
              {t(me ? "verifyContact.toProfile" : "verifyContact.toSignIn")}
            </Link>
          </>
        )}

        {state === "error" && (
          <>
            <Banner tone="error">{error}</Banner>
            <p className="text-sm text-slate-500">{t("verifyContact.retryHint")}</p>
            <Link className={primaryButton} to="/profile">
              {t(me ? "verifyContact.toProfile" : "verifyContact.toSignIn")}
            </Link>
          </>
        )}
      </section>
    </div>
  );
}
