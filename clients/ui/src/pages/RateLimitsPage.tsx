import type { RateLimitBlock } from "@bentoforge/umami-iam";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, errMsg, formatDateTime, Loader } from "../components";
import { formatDuration, policyLabelKey } from "../ratelimit";
import { card, ghostButton, input, td, th } from "../ui";

/** How far back the overview may look. The server clamps to 60 s … 7 days; these are the offered
 * steps, in seconds. */
const LOOKBACKS = [3600, 6 * 3600, 24 * 3600, 7 * 24 * 3600];

/** Policies the filter offers, in the order the server lists them. */
const POLICIES = ["perIp:login", "perIp:token", "login", "tokenExchange"];

/** Blocks fetched per request (the server caps this at 250). */
const LIMIT = 100;

/** Top-aligned cell: `td` bakes in `align-middle`, and a trailing `align-top` won't reliably win
 * the Tailwind cascade — so swap the class rather than append it. */
const tdTop = td.replace("align-middle", "align-top");

/**
 * Deployment-wide rate-limit overview (`view:ratelimits`): which IPs, accounts and keys tripped a
 * policy recently.
 *
 * Blocks only — a counter that never trips leaves no trace here, by design. Recording every
 * increment would mean an indexed write on every login and token exchange, funnelled into one
 * partition per policy; the overview would then cost more than the flood it is meant to reveal.
 */
export function RateLimitsPage() {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [blocks, setBlocks] = useState<RateLimitBlock[] | null>(null);
  const [since, setSince] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lookback, setLookback] = useState(LOOKBACKS[0]);
  const [policy, setPolicy] = useState("");

  const load = useCallback(async () => {
    setError(null);
    try {
      const page = await client.rateLimitBlocks({
        sinceSecs: lookback,
        limit: LIMIT,
        policy: policy || undefined,
      });
      setBlocks(page.blocks);
      setSince(page.since);
    } catch (err) {
      setError(errMsg(err));
      setBlocks([]);
    }
  }, [client, lookback, policy]);

  useEffect(() => {
    void load();
  }, [load]);

  const activeCount = blocks?.filter((block) => block.active).length ?? 0;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
          {t("rateLimits.pageTitle")}
        </h1>
        <div className="flex flex-wrap items-center gap-2">
          <select
            className={`${input} w-auto`}
            value={policy}
            aria-label={t("rateLimits.filterPolicy")}
            onChange={(e) => setPolicy(e.target.value)}
          >
            <option value="">{t("rateLimits.allPolicies")}</option>
            {POLICIES.map((code) => (
              <option key={code} value={code}>
                {t(policyLabelKey(code))}
              </option>
            ))}
          </select>
          <select
            className={`${input} w-auto`}
            value={lookback}
            aria-label={t("rateLimits.filterWindow")}
            onChange={(e) => setLookback(Number(e.target.value))}
          >
            {LOOKBACKS.map((secs) => (
              <option key={secs} value={secs}>
                {t("rateLimits.lastN", { duration: formatDuration(secs) })}
              </option>
            ))}
          </select>
          <button type="button" className={ghostButton} onClick={() => void load()}>
            {t("rateLimits.reload")}
          </button>
        </div>
      </div>

      <p className="text-sm text-slate-500">
        {t("rateLimits.overviewHint")}
        {since && <> {t("rateLimits.sinceHint", { at: formatDateTime(since) })}</>}
      </p>

      <Banner tone="error">{error}</Banner>

      <section className={`${card} overflow-x-auto`}>
        {blocks === null ? (
          <Loader />
        ) : blocks.length === 0 ? (
          <p className="text-slate-500">{t("rateLimits.noBlocks")}</p>
        ) : (
          <>
            <p className="mb-3 text-xs text-slate-400">
              {t("rateLimits.summary", { total: blocks.length, active: activeCount })}
            </p>
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-700">
                  <th className={`${th} w-0 align-bottom`}>
                    <span className="sr-only">{t("rateLimits.status")}</span>
                  </th>
                  <th className={`${th} align-bottom`}>{t("rateLimits.when")}</th>
                  <th className={`${th} align-bottom`}>{t("rateLimits.policyColumn")}</th>
                  <th className={`${th} align-bottom`}>{t("rateLimits.subject")}</th>
                  <th className={`${th} align-bottom`}>{t("rateLimits.until")}</th>
                </tr>
              </thead>
              <tbody>
                {blocks.map((block) => (
                  <tr
                    key={`${block.policy}|${block.subject}|${block.blockedAt}`}
                    className="border-b border-slate-100 dark:border-slate-700/50"
                  >
                    <td className={tdTop}>
                      <span
                        title={block.active ? t("rateLimits.active") : t("rateLimits.expired")}
                        className={`mt-1.5 inline-block h-2.5 w-2.5 shrink-0 rounded-full ${
                          block.active ? "bg-red-500" : "bg-slate-300 dark:bg-slate-600"
                        }`}
                      />
                    </td>
                    <td className={`${tdTop} whitespace-nowrap`}>
                      {formatDateTime(block.blockedAt)}
                    </td>
                    <td className={`${tdTop} whitespace-nowrap`}>
                      {t(policyLabelKey(block.policy))}
                    </td>
                    <td className={`${tdTop} font-mono text-xs break-all`}>{block.subject}</td>
                    <td className={`${tdTop} whitespace-nowrap`}>
                      <div>{formatDateTime(block.blockedUntil)}</div>
                      <div className="text-xs text-slate-400">
                        {block.active && block.retryAfter !== undefined
                          ? t("rateLimits.remaining", {
                              duration: formatDuration(block.retryAfter),
                            })
                          : t("rateLimits.expired")}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </section>
    </div>
  );
}
