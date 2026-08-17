import { type MeResponse, UmamiClient } from "@bentoforge/umami-iam";
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";

interface AuthContextValue {
  client: UmamiClient;
  /** Current profile, or `null` when signed out. */
  me: MeResponse | null;
  /** `true` until the initial silent-refresh + `getMe` completes. */
  loading: boolean;
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
  const client = useMemo(() => new UmamiClient({ baseUrl }), [baseUrl]);
  const [me, setMe] = useState<MeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTenantId, setActiveTenantId] = useState<string | null>(null);
  const [activeTenantName, setActiveTenantName] = useState<string | null>(null);

  const refreshMe = async () => {
    try {
      const profile = await client.getMe();
      setMe(profile);
      // A fresh login/refresh returns to the home tenant; sync the active-tenant view.
      setActiveTenantId(client.getClaims()?.tenant ?? profile.user.tenantId);
      setActiveTenantName(profile.tenant?.name ?? null);
    } catch {
      setMe(null);
      setActiveTenantId(null);
      setActiveTenantName(null);
    }
  };

  const switchTenant = async (tenantId: string, tenantName?: string) => {
    const active = await client.switchTenant(tenantId);
    setActiveTenantId(active);
    setActiveTenantName(tenantName ?? null);
  };

  const signOut = async () => {
    await client.logout();
    setMe(null);
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
