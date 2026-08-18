import { UmamiError } from "@bentoforge/umami-iam";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";

export function LoginPage() {
  const { t } = useTranslation();
  const { client, refreshMe } = useUmami();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await client.login(username, password, mfaRequired ? totpCode : undefined);
      if (res.mfaRequired) {
        setMfaRequired(true);
        return;
      }
      await refreshMe();
    } catch (err) {
      setError(err instanceof UmamiError ? err.message : t("login.failed"));
    } finally {
      setBusy(false);
    }
  };

  const onPasskey = async () => {
    setBusy(true);
    setError(null);
    try {
      await client.loginWithPasskey(username);
      await refreshMe();
    } catch (err) {
      setError(err instanceof UmamiError ? err.message : t("login.failed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 dark:bg-slate-900 px-4">
      <div className="w-full max-w-sm rounded-2xl bg-white dark:bg-slate-800 shadow-xl p-8">
        {/* Theme-aware branding logo (config `branding.logoLight`/`logoDark`, else built-in). */}
        <picture className="flex justify-center mb-6">
          <source srcSet="/app/logo/dark" media="(prefers-color-scheme: dark)" />
          <img src="/app/logo/light" alt={t("app.title")} className="h-16 w-auto max-w-full" />
        </picture>
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-white mb-6">
          {t("login.heading")}
        </h1>
        <form onSubmit={onSubmit} className="space-y-4">
          <Field label={t("login.username")}>
            <input
              type="text"
              required
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className={inputClass}
            />
          </Field>
          <Field label={t("login.password")}>
            <input
              type="password"
              required
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={inputClass}
            />
          </Field>
          {mfaRequired && (
            <Field label={t("login.totp")}>
              <input
                inputMode="numeric"
                autoComplete="one-time-code"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                className={inputClass}
              />
              <p className="mt-1 text-xs text-slate-500">{t("login.mfaHint")}</p>
            </Field>
          )}
          {error && <p className="text-sm text-red-600">{error}</p>}
          <button type="submit" disabled={busy} className={primaryButtonClass}>
            {t("login.submit")}
          </button>
        </form>
        <button
          type="button"
          onClick={onPasskey}
          disabled={busy || !username}
          className={secondaryButtonClass}
        >
          {t("login.passkey")}
        </button>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
        {label}
      </span>
      {children}
    </label>
  );
}

const inputClass =
  "w-full rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 px-3 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand";
const primaryButtonClass =
  "w-full rounded-lg bg-brand hover:bg-brand-dark text-white font-medium py-2 transition disabled:opacity-50";
const secondaryButtonClass =
  "mt-3 w-full rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 font-medium py-2 transition hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50";
