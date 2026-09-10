import { type MeResponse, UmamiClient } from "@bentoforge/umami-iam";
import {
  createContext,
  type ReactNode,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useLocation, useNavigate } from "react-router-dom";
import i18n from "../i18n/i18n";

interface AuthContextValue {
  client: UmamiClient;
  /** Current profile, or `null` when signed out. */
  me: MeResponse | null;
  /** `true` until the initial silent-refresh + `getMe` completes. */
  loading: boolean;
  /** The session ended while the app was open — the sign-in screen says so rather than staying mute. */
  sessionExpired: boolean;
  /** The tenant the current access token is scoped to (changes on switch-tenant). */
  activeTenantId: string | null;
  /** Display name of the active tenant, if known. */
  activeTenantName: string | null;
  /** Re-fetches the profile (call after login / passkey login). */
  refreshMe: () => Promise<void>;
  /** System-admin: re-scope the token to another tenant (ephemeral, no reload). */
  switchTenant: (tenantId: string, tenantName?: string) => Promise<void>;
  /** Clears the session and profile. */
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/** Access the shared `UmamiClient` and auth state. */
export function useUmami(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useUmami must be used within <UmamiProvider>");
  return value;
}

export function UmamiProvider({ baseUrl, children }: { baseUrl: string; children: ReactNode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [me, setMe] = useState<MeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [activeTenantId, setActiveTenantId] = useState<string | null>(null);
  const [activeTenantName, setActiveTenantName] = useState<string | null>(null);

  // Read by the expiry callback, which outlives the render that built it.
  const locationRef = useRef(location);
  locationRef.current = location;

  /**
   * Where the session died, for the jump back after signing in again.
   *
   * In memory, deliberately — not in `?next=`. That parameter is part of the hosted-login handoff
   * and travels in a URL anyone can hand a user, which is why `LoginPage` vets it and follows it
   * with a full page load. This value is neither: the router put it there, the router takes it
   * back, and it never reaches a URL for someone else to choose.
   */
  const returnTo = useRef<string | null>(null);

  /**
   * The session is over: drop the profile so `App` shows the sign-in screen.
   *
   * The alternative is what used to happen — the failed call's own error surfaced in whatever
   * banner the page had, the shell stayed up around a session that no longer existed, and the
   * sign-out only became visible on the next reload.
   */
  const client = useMemo(
    () =>
      new UmamiClient({
        baseUrl,
        onSessionExpired: () => {
          const at = `${locationRef.current.pathname}${locationRef.current.search}`;
          returnTo.current = at === "/" ? null : at;
          setSessionExpired(true);
          setMe(null);
          setActiveTenantId(null);
          setActiveTenantName(null);
        },
      }),
    [baseUrl],
  );

  const refreshMe = async () => {
    try {
      const profile = await client.getMe();
      // The language travels with the profile, so it has to be in place *before* the profile is
      // published. Everything that renders on the strength of `me` would otherwise render once in
      // the language guessed from the browser, and whatever does not re-render afterwards would
      // keep it — the header has no state of its own and so kept a German menu around an English
      // page. The browser's guess stands only while nobody has stated a preference.
      const preferred = profile.user.locale;
      if (preferred && preferred !== i18n.language) {
        await i18n.changeLanguage(preferred);
      }
      setMe(profile);
      // Both come from the session, not from an assumption about it: a switch is
      // durable, so a reload can land straight inside another tenant. The id is
      // the token's, and the name has to follow it — reading it off `tenant`
      // would name the user's own tenant while showing someone else's data.
      setActiveTenantId(client.getClaims()?.tenant ?? profile.user.tenantId);
      setActiveTenantName(profile.activeTenant?.name ?? profile.tenant?.name ?? null);
      setSessionExpired(false);
      const target = returnTo.current;
      returnTo.current = null;
      if (target) {
        navigate(target, { replace: true });
      }
    } catch {
      setMe(null);
      setActiveTenantId(null);
      setActiveTenantName(null);
    }
  };

  // Back to the start page, because the routes below it are tenant-scoped: `/users/:userId` names
  // a row the new tenant does not have, so a switch made from there answers with "no such user".
  // The start page is the one screen that is true in every tenant. `replace`, so going back does
  // not return to the route that just became meaningless.
  const switchTenant = async (tenantId: string, tenantName?: string) => {
    const active = await client.switchTenant(tenantId);
    setActiveTenantId(active);
    setActiveTenantName(tenantName ?? null);
    navigate("/", { replace: true });
  };

  const signOut = async () => {
    await client.logout();
    setMe(null);
    setSessionExpired(false);
    setActiveTenantId(null);
    setActiveTenantName(null);
  };

  // Mount-once bootstrap: refreshMe is intentionally omitted from the deps — it is recreated
  // every render, so including it would re-run this effect in a loop.
  // biome-ignore lint/correctness/useExhaustiveDependencies: intentional run-once bootstrap
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      // On load, try a silent refresh via the cookie; if it works, load the profile.
      const ok = await client.refresh().catch(() => false);
      if (!cancelled && ok) await refreshMe();
      if (!cancelled) setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [client]);

  return (
    <AuthContext.Provider
      value={{
        client,
        me,
        loading,
        sessionExpired,
        activeTenantId,
        activeTenantName,
        refreshMe,
        switchTenant,
        signOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
