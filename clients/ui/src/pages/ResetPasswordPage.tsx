import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, errMsg, Field } from "../components";
import { card, input, primaryButton } from "../ui";

/** Landing page for the link in a password-recovery mail: pick a new password.
 *
 * Reachable **without a session** — the link arrives by mail and the token is the proof. It has to
 * be, since the whole point is that the user cannot sign in.
 *
 * Unlike the confirmation page this does *not* act on mount: the secret authorizes a password
 * change, and a change needs the new password first. So the token sits in state until the form is
 * submitted, and nothing is consumed by merely opening the link. */
export function ResetPasswordPage() {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (password !== repeat) {
      setError(t("resetPassword.mismatch"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await client.completeRecovery(token, password);
      setDone(true);
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 dark:bg-slate-900 p-4">
      <section className={`${card} w-full max-w-md space-y-4`}>
        <h1 className="text-lg font-medium text-slate-800 dark:text-slate-200">
          {t("resetPassword.title")}
        </h1>

        {!token && <Banner tone="error">{t("resetPassword.missingToken")}</Banner>}

        {done ? (
          <>
            <Banner tone="ok">{t("resetPassword.done")}</Banner>
            <p className="text-sm text-slate-500">{t("resetPassword.sessionsEnded")}</p>
            <Link className={primaryButton} to="/">
              {t("resetPassword.toSignIn")}
            </Link>
          </>
        ) : (
          <form onSubmit={onSubmit} className="space-y-4">
            <Field label={t("resetPassword.newPassword")}>
              <input
                className={input}
                type="password"
                required
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </Field>
            <Field label={t("resetPassword.repeat")}>
              <input
                className={input}
                type="password"
                required
                autoComplete="new-password"
                value={repeat}
                onChange={(e) => setRepeat(e.target.value)}
              />
            </Field>
            <Banner tone="error">{error}</Banner>
            <button className={primaryButton} type="submit" disabled={busy || !token}>
              {t("resetPassword.submit")}
            </button>
          </form>
        )}
      </section>
    </div>
  );
}
