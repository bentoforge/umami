import type { Config } from "@bentoforge/umami-iam";
import { useCallback, useEffect, useState } from "react";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, errMsg } from "../components";
import { card, ghostButton, primaryButton } from "../ui";

/** Crude config editor: the whole document rendered as JSON in a textarea, saved back wholesale.
 * Save is version-checked server-side (optimistic concurrency) — a concurrent edit yields a 409. */
export function ConfigPage() {
  const { client } = useUmami();
  const [text, setText] = useState("");
  const [version, setVersion] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    setNotice(null);
    try {
      const config = await client.getConfig();
      setText(JSON.stringify(config, null, 2));
      setVersion(config.version);
    } catch (err) {
      setError(errMsg(err));
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async () => {
    setError(null);
    setNotice(null);

    let parsed: Config;
    try {
      parsed = JSON.parse(text) as Config;
    } catch (err) {
      setError(`Invalid JSON: ${errMsg(err)}`);
      return;
    }

    setSaving(true);
    try {
      const saved = await client.putConfig(parsed);
      setText(JSON.stringify(saved, null, 2));
      setVersion(saved.version);
      setNotice(`Saved. New version: ${saved.version}.`);
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-white">Config</h1>
          <p className="text-sm text-slate-500">
            Whole-document editor{version !== null && ` — loaded version ${version}`}. Saving writes
            the entire document; the server rejects the write if the version moved underneath you.
          </p>
        </div>
        <div className="flex gap-2">
          <button className={ghostButton} onClick={() => void load()} disabled={saving}>
            Reload
          </button>
          <button className={primaryButton} onClick={() => void save()} disabled={saving}>
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>

      <Banner tone="error">{error}</Banner>
      <Banner tone="ok">{notice}</Banner>

      <section className={card}>
        <textarea
          spellCheck={false}
          className="w-full h-[70vh] font-mono text-xs rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 p-3 focus:outline-none focus:ring-2 focus:ring-primary"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </section>
    </div>
  );
}
