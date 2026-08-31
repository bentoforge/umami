import { UmamiError } from "@bentoforge/umami-iam";
import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import { Logo } from "../components";
import { errorBox } from "../ui";

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
  // Whether this deployment can mail at all. Asked before sign-in via the public capabilities
  // endpoint, so the recovery link is only offered when it leads somewhere.
  const [canRecover, setCanRecover] = useState(false);
  const [recoverMode, setRecoverMode] = useState(false);
  const [recoverSent, setRecoverSent] = useState(false);

  useEffect(() => {
    client
      .capabilities()
      .then((caps) => setCanRecover(caps.passwordRecovery))
      .catch(() => setCanRecover(false));
  }, [client]);

  const onForgot = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await client.forgotPassword(username.trim());
      // Always the same confirmation, because the server always answers the same way: showing
      // anything account-specific here would undo the point of that.
      setRecoverSent(true);
    } catch (err) {
      setError(err instanceof UmamiError ? err.message : t("login.failed"));
    } finally {
      setBusy(false);
    }
  };

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

  /**
   * Passkey autofill (conditional mediation).
   *
   * Started once on mount and then left pending: it resolves only if the user actually picks a
   * passkey out of the username field's autofill list. That list is the only place a passkey can
   * appear next to — and above — a saved password: how a password manager ranks its own
   * suggestions is not something a page can influence.
   *
   * `refreshMe` is deliberately not a dependency, for the same reason the provider's bootstrap
   * omits it: it is recreated on every render and would restart the ceremony each time. The
   * ref keeps the effect pointed at the current one.
   */
  const afterLoginRef = useRef<() => Promise<void>>(async () => {});
  const autofillRef = useRef<AbortController | null>(null);
  const autofillErrorRef = useRef<(err: unknown) => void>(() => {});

  const startAutofill = useCallback(() => {
    const controller = new AbortController();
    autofillRef.current = controller;
    client
      .loginWithPasskeyAutofill({ signal: controller.signal })
      .then((offered) => (offered ? afterLoginRef.current() : undefined))
      .catch((err) => autofillErrorRef.current(err));
  }, [client]);

  useEffect(() => {
    startAutofill();
    return () => autofillRef.current?.abort();
  }, [startAutofill]);

  afterLoginRef.current = afterLogin;

  /**
   * A login started from the autofill list has to fail just as visibly as one started from the
   * button. Only our own aborts stay silent — the effect cleanup on unmount, and the button
   * retiring the pending request before it opens the modal picker.
   *
   * Held in a ref rather than closed over by `startAutofill`, so `t` changing identity on a
   * language switch cannot restart the ceremony.
   */
  autofillErrorRef.current = (err: unknown) => {
    if (err instanceof DOMException && err.name === "AbortError") {
      return;
    }
    setError(err instanceof UmamiError ? err.message : t("login.failed"));
  };

  const onPasskey = async () => {
    // The autofill request from mount is still pending, and a browser rejects a second
    // concurrent `navigator.credentials.get()`. Retire it before opening the modal picker.
    autofillRef.current?.abort();
    autofillRef.current = null;
    setBusy(true);
    setError(null);
    try {
      // No username typed means a discoverable login: the authenticator picks the credential,
      // and with it the user. Hence no guard on the field being filled.
      await client.loginWithPasskey(username.trim() || undefined);
      await afterLogin();
    } catch (err) {
      setError(err instanceof UmamiError ? err.message : t("login.failed"));
      // Cancelled or failed: hand the passkey back to the username field, otherwise the
      // autofill offer stays gone until a reload.
      startAutofill();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-login-bg px-4">
      <div className="w-full max-w-sm rounded-2xl bg-login-card text-login-text shadow-xl p-8">
        {/* Theme-aware branding logo (config `branding.logoLight`/`logoDark`, else built-in). */}
        <div className="flex justify-center mb-6">
          <Logo className="h-16 w-auto max-w-full" />
        </div>
        <h1 className="text-2xl font-semibold mb-6">
          {t(recoverMode ? "login.recoverHeading" : "login.heading")}
        </h1>

        {recoverMode && (
          <div className="space-y-4">
            {recoverSent ? (
              <>
                <p className="text-sm text-login-text opacity-80">{t("login.recoverSent")}</p>
                <button
                  type="button"
                  className={secondaryButtonClass}
                  onClick={() => {
                    setRecoverMode(false);
                    setRecoverSent(false);
                  }}
                >
                  {t("login.recoverBack")}
                </button>
              </>
            ) : (
              <form onSubmit={onForgot} className="space-y-4">
                <p className="text-sm text-login-text opacity-80">{t("login.recoverHint")}</p>
                <Field label={t("login.recoverIdentifier")}>
                  <input
                    type="text"
                    required
                    autoFocus
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className={inputClass}
                  />
                </Field>
                {error && <p className={errorBox}>{error}</p>}
                <button type="submit" disabled={busy} className={primaryButtonClass}>
                  {t("login.recoverSubmit")}
                </button>
                <button
                  type="button"
                  className={secondaryButtonClass}
                  onClick={() => setRecoverMode(false)}
                >
                  {t("login.recoverBack")}
                </button>
              </form>
            )}
          </div>
        )}

        {!recoverMode && (
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
                // "webauthn" is what lets the browser put a passkey into this field's autofill
                // list; without it, conditional mediation has nothing to attach to.
                autoComplete="username webauthn"
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
                <p className="mt-1 text-xs text-login-text opacity-70">{t("login.mfaHint")}</p>
              </Field>
            )}
            {error && <p className={errorBox}>{error}</p>}
            <button type="submit" disabled={busy} className={primaryButtonClass}>
              {t("login.submit")}
            </button>
          </form>
        )}
        {!recoverMode && !mfaRequired && (
          <button
            type="button"
            onClick={onPasskey}
            disabled={busy}
            className={secondaryButtonClass}
          >
            {t("login.passkey")}
          </button>
        )}
        {!recoverMode && !mfaRequired && canRecover && (
          <button
            type="button"
            onClick={() => {
              setRecoverMode(true);
              setError(null);
            }}
            className="mt-4 w-full text-sm text-login-text opacity-70 hover:opacity-100 underline"
          >
            {t("login.forgot")}
          </button>
        )}
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="block text-sm font-medium text-login-text opacity-80 mb-1">{label}</span>
      {children}
    </label>
  );
}

const inputClass =
  "w-full rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 px-3 py-2 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary";

/** Same box, visibly inert: the username in the MFA step is context, not an input. */
const readOnlyInputClass =
  "w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 px-3 py-2 text-slate-500 dark:text-slate-400 focus:outline-none";
// Hover is element-level opacity rather than a second colour token: unlike a wash,
// it lands the same way whatever the button sits on.
const primaryButtonClass =
  "w-full rounded-lg bg-login-primary text-login-primary-text hover:opacity-90 font-medium py-2 transition disabled:opacity-50";
const secondaryButtonClass =
  "mt-3 w-full rounded-lg border border-login-secondary text-login-secondary-text hover:opacity-80 font-medium py-2 transition disabled:opacity-50";
