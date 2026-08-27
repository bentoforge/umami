import { UmamiError } from "@bentoforge/umami-iam";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import { Logo } from "../components";

/**
 * Where to go after a successful login, from `?next=`.
 *
 * Only **same-origin absolute paths** are honoured. `next` arrives in a URL that anyone can hand
 * a user, so an unchecked value turns the login page into an open redirector — and one that runs
 * right after the user typed their password, which is the worst possible moment to bounce them
 * somewhere hostile.
 *
 * Rejected: anything with a scheme or authority (`https://evil.test`, `//evil.test`), and
 * backslash variants that some browsers normalise into `//`. The cross-origin case is served by
 * `GET /auth/authorize`, which has its own exact-match allow-list — `next` only ever points back
 * at umami itself.
 */
function safeNext(raw: string | null): string | null {
  if (!raw) {
    return null;
  }
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) {
    return null;
  }
  if (raw.includes("\\")) {
    return null;
  }
  return raw;
}

export function LoginPage() {
  const { t } = useTranslation();
  const { client, refreshMe } = useUmami();
  const [searchParams] = useSearchParams();
  // Set when an app sent the user here through /auth/authorize; the value points back at that
  // endpoint, which re-decides the redirect now that a session cookie exists.
  const next = safeNext(searchParams.get("next"));
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
      const res = await client.login(
        username,
        password,
        mfaRequired ? totpCode : undefined,
      );
      if (res.mfaRequired) {
        setMfaRequired(true);
        return;
      }
      await afterLogin();
    } catch (err) {
      setError(err instanceof UmamiError ? err.message : t("login.failed"));
    } finally {
      setBusy(false);
    }
  };

  /**
   * Hand control back to whoever sent us here, or fall through to the console.
   *
   * A full page assignment rather than a client-side navigation: `next` is a server route
   * (`/auth/authorize`), not a route of this SPA, and it answers with a 302 the browser has to
   * follow.
   */
  const afterLogin = async () => {
    if (next) {
      window.location.assign(next);
      return;
    }
    await refreshMe();
  };

  const onPasskey = async () => {
    setBusy(true);
    setError(null);
    try {
      await client.loginWithPasskey(username);
      await afterLogin();
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
        <div className="flex justify-center mb-6">
          <Logo className="h-16 w-auto max-w-full" alt={t("app.title")} />
        </div>
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-white mb-6">
          {t("login.heading")}
        </h1>
        <form onSubmit={onSubmit} className="space-y-4">
          {/*
            Two-step form: step one asks for username + password, step two for the
            one-time code. The username stays visible (read-only) so the password
            manager keeps the entry associated with this form.
          */}
          <Field label={t("login.username")}>
            <input
              type="text"
              required
              autoComplete="username"
              readOnly={mfaRequired}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className={mfaRequired ? readOnlyInputClass : inputClass}
            />
          </Field>
          {/*
            The password input is *removed* in the MFA step rather than hidden. As long
            as a fillable `current-password` field sits in the DOM, password managers
            keep treating step two as a password form and drop the one-time code into
            it. The value lives in React state, so the second submit still carries it.
          */}
          {!mfaRequired && (
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
          )}
          {mfaRequired && (
            <Field label={t("login.totp")}>
              <input
                type="text"
                inputMode="numeric"
                required
                autoFocus
                autoComplete="one-time-code"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                className={inputClass}
              />
              <p className="mt-1 text-xs text-slate-500">
                {t("login.mfaHint")}
              </p>
            </Field>
          )}
          {error && <p className="text-sm text-red-600">{error}</p>}
          <button type="submit" disabled={busy} className={primaryButtonClass}>
            {t("login.submit")}
          </button>
        </form>
        {!mfaRequired && (
          <button
            type="button"
            onClick={onPasskey}
            disabled={busy || !username}
            className={secondaryButtonClass}
          >
            {t("login.passkey")}
          </button>
        )}
      </div>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
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
  "w-full rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 px-3 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary";

/** Same box, visibly inert: the username in the MFA step is context, not an input. */
const readOnlyInputClass =
  "w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 px-3 py-2 text-slate-500 dark:text-slate-400 focus:outline-none";
const primaryButtonClass =
  "w-full rounded-lg bg-primary hover:bg-primary-dark text-white font-medium py-2 transition disabled:opacity-50";
const secondaryButtonClass =
  "mt-3 w-full rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 font-medium py-2 transition hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50";
