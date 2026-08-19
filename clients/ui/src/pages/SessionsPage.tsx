import { useState } from "react";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, errMsg } from "../components";
import { card, dangerButton } from "../ui";

/** Sessions — for now just "log out everywhere". A per-device session list needs a backend
 * `list sessions` endpoint (tracked separately); this is the slim first cut. */
export function SessionsPage() {
  const { client } = useUmami();
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const logoutAll = async () => {
    if (
      !window.confirm(
        "Alle Sitzungen abmelden? Andere Geräte verlieren beim nächsten Refresh den Zugang.",
      )
    ) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await client.logoutAll();
      setDone(true);
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-slate-900 dark:text-white">Sitzungen</h1>
      <section className={`${card} space-y-3`}>
        {error && <Banner tone="error">{error}</Banner>}
        {done && <Banner tone="ok">Alle Sitzungen wurden abgemeldet.</Banner>}
        <p className="text-sm text-slate-500">
          Meldet alle Sitzungen dieses Kontos ab (erhöht die <code>tokenVersion</code>) — andere
          Geräte verlieren beim nächsten Refresh den Zugang.
        </p>
        <button className={dangerButton} disabled={busy} onClick={() => void logoutAll()}>
          Alle Sitzungen abmelden
        </button>
      </section>
    </div>
  );
}
