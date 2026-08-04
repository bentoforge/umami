import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { UmamiClient, type MeResponse } from "umami-client";

interface AuthContextValue {
  client: UmamiClient;
  /** Current profile, or `null` when signed out. */
  me: MeResponse | null;
  /** `true` until the initial silent-refresh + `getMe` completes. */
  loading: boolean;
  /** Re-fetches the profile (call after login / passkey login). */
  refreshMe: () => Promise<void>;
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

  const refreshMe = async () => {
    try {
      setMe(await client.getMe());
    } catch {
      setMe(null);
    }
  };

  const signOut = async () => {
    await client.logout();
    setMe(null);
  };

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
    <AuthContext.Provider value={{ client, me, loading, refreshMe, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}
