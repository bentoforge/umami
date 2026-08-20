import type { SessionView } from "@bentoforge/umami-iam";
import { useCallback, useEffect, useState } from "react";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, errMsg, formatDateTime } from "../components";
import { card, dangerButton, ghostButton } from "../ui";

/** Sessions: list the caller's active login sessions (devices), revoke one, or log out everywhere. */
export function SessionsPage() {
  const { client } = useUmami();
  const [sessions, setSessions] = useState<SessionView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      setSessions(await client.listSessions());
    } catch (err) {
      setError(errMsg(err));
      setSessions([]);
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  const revoke = async (session: SessionView) => {
    if (
      !window.confirm(
        "Diese Sitzung abmelden? Das Gerät verliert beim nächsten Refresh den Zugang.",
      )
    ) {
      return;
    }
    setError(null);
    try {
      await client.deleteSession(session.sessionId);
      await load();
    } catch (err) {
      setError(errMsg(err));
    }
  };

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
      await load();
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
        {sessions === null ? (
          <p className="text-sm text-slate-500">Lädt…</p>
        ) : sessions.length === 0 ? (
          <p className="text-sm text-slate-500">Keine aktiven Sitzungen.</p>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {sessions.map((session) => (
              <li key={session.sessionId} className="flex items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-slate-900 dark:text-white truncate">
                    {session.userAgent || "Unbekanntes Gerät"}
                    {session.current && (
                      <span className="ml-2 rounded bg-brand/10 text-brand px-1.5 py-0.5 text-[10px] align-middle">
                        aktuelle Sitzung
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-400">
                    {session.ip ? `${session.ip} · ` : ""}zuletzt aktiv{" "}
                    {formatDateTime(session.lastSeen)}
                  </div>
                </div>
                {!session.current && (
                  <button className={dangerButton} onClick={() => void revoke(session)}>
                    Abmelden
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className={`${card} space-y-3`}>
        <p className="text-sm text-slate-500">
          Meldet <strong>alle</strong> Sitzungen dieses Kontos ab (erhöht die{" "}
          <code>tokenVersion</code>) — alle Geräte verlieren beim nächsten Refresh den Zugang.
        </p>
        <button className={ghostButton} disabled={busy} onClick={() => void logoutAll()}>
          Alle Sitzungen abmelden
        </button>
      </section>
    </div>
  );
}
