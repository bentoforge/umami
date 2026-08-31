import type { RateLimitState, UmamiClient } from "@bentoforge/umami-iam";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useUmami } from "./auth/UmamiProvider";
import { Banner, errMsg, formatDateTime, Loader } from "./components";
import { card, ghostButton } from "./ui";

/** What a rate-limit readout is about. Declared as data rather than as a callback so the fetching
 * effect has a stable dependency — an inline `() => client.myRateLimit()` would change identity on
 * every render and re-fetch forever. */
export type RateLimitTarget =
  | { kind: "me" }
  | { kind: "user"; userId: string }
  | { kind: "apiKey"; tenantId: string; keyId: string }
  | { kind: "myPat"; keyId: string }
  | { kind: "userPat"; userId: string; keyId: string };

/** Fraction of the cap at which a meter starts warning. Below this the number is just a number. */
const WARN_AT = 0.8;

/** Fetches the states for one target — one switch, so the hook stays about lifecycle. */
function fetchStates(client: UmamiClient, target: RateLimitTarget): Promise<RateLimitState[]> {
  switch (target.kind) {
    case "me":
      return client.myRateLimit();
    case "user":
      return client.userRateLimit(target.userId);
    case "apiKey":
      return client.apiKeyRateLimit(target.tenantId, target.keyId);
    case "myPat":
      return client.myPatRateLimit(target.keyId);
    case "userPat":
      return client.userPatRateLimit(target.userId, target.keyId);
  }
}

/** Loads the states for one target, with a `reload` for the refresh buttons. */
export function useRateLimit(target: RateLimitTarget): {
  states: RateLimitState[] | null;
  error: string | null;
  reload: () => void;
} {
  const { client } = useUmami();
  const [states, setStates] = useState<RateLimitState[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The target is a plain object rebuilt on every render; its *contents* are what identify it.
  const key = JSON.stringify(target);
  // Ticket for the latest request, so a slow answer for a target we have since navigated away
  // from cannot overwrite the current one.
  const latest = useRef(0);

  const load = useCallback(async () => {
    const ticket = ++latest.current;
    setError(null);
    try {
      const loaded = await fetchStates(client, JSON.parse(key) as RateLimitTarget);
      if (ticket === latest.current) {
        setStates(loaded);
      }
    } catch (err) {
      if (ticket === latest.current) {
        setError(errMsg(err));
        setStates([]);
      }
    }
  }, [client, key]);

  useEffect(() => {
    void load();
  }, [load]);

  return { states, error, reload: () => void load() };
}

/** Duration in SI units — `h`, `min`, `s` read the same in every language the UI ships. */
export function formatDuration(seconds: number): string {
  const total = Math.max(0, Math.round(seconds));
  if (total < 60) {
    return `${total} s`;
  }
  const minutes = Math.floor(total / 60);
  if (minutes < 60) {
    const rest = total % 60;
    return rest ? `${minutes} min ${rest} s` : `${minutes} min`;
  }
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest ? `${hours} h ${rest} min` : `${hours} h`;
}

/** i18n key for a policy name — the wire values carry a colon, which i18next reads as a namespace
 * separator, so they cannot be interpolated into a key path as they are. */
export function policyLabelKey(policy: string): string {
  switch (policy) {
    case "login":
      return "rateLimits.policy.login";
    case "tokenExchange":
      return "rateLimits.policy.tokenExchange";
    case "perIp:login":
      return "rateLimits.policy.perIpLogin";
    case "perIp:token":
      return "rateLimits.policy.perIpToken";
    default:
      return "rateLimits.policy.unknown";
  }
}

/** One policy's live state: a count-vs-cap meter, when the window resets, and the block if there
 * is one. A disabled policy (`max === 0`) counts nothing, so it gets a note instead of a meter. */
export function RateLimitMeter({ state }: { state: RateLimitState }) {
  const { t } = useTranslation();
  const label = t(policyLabelKey(state.policy));

  if (state.max === 0) {
    return (
      <div className="space-y-1">
        <div className="flex items-baseline justify-between gap-3">
          <span className="text-sm font-medium text-slate-800 dark:text-slate-200">{label}</span>
          <span className="text-xs text-slate-400">{t("rateLimits.disabled")}</span>
        </div>
        <p className="text-xs text-slate-400">{t("rateLimits.disabledHint")}</p>
      </div>
    );
  }

  const blocked = !!state.blockedUntil;
  const ratio = Math.min(1, state.count / state.max);
  const bar = blocked
    ? "bg-red-500"
    : ratio >= WARN_AT
      ? "bg-amber-500"
      : "bg-emerald-500 dark:bg-emerald-400";

  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-sm font-medium text-slate-800 dark:text-slate-200">{label}</span>
        <span
          className={`font-mono text-sm tabular-nums ${
            blocked ? "text-red-600 dark:text-red-400" : "text-slate-600 dark:text-slate-300"
          }`}
        >
          {state.count} / {state.max}
        </span>
      </div>

      {/* Decorative: the "count / max" line above already carries the value as text, so the bar
          adds nothing for a screen reader and would only read out twice. */}
      <div
        aria-hidden="true"
        className="h-1.5 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700"
      >
        {/* Always paint a sliver for a non-zero count, so "1 of 300" is visible rather than empty. */}
        <div
          className={`h-full rounded-full ${bar}`}
          style={{ width: `${state.count === 0 ? 0 : Math.max(2, ratio * 100)}%` }}
        />
      </div>

      <div className="text-xs text-slate-400">
        {t("rateLimits.window", { window: formatDuration(state.windowSecs) })}
        {state.windowEndsAt && !blocked && (
          <> · {t("rateLimits.resets", { at: formatDateTime(state.windowEndsAt) })}</>
        )}
        {" · "}
        {t("rateLimits.blockFor", { duration: formatDuration(state.blockSecs) })}
      </div>

      {blocked && state.blockedUntil && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-xs text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-300">
          {t("rateLimits.blockedUntil", { at: formatDateTime(state.blockedUntil) })}
          {state.retryAfter !== undefined && <> · {formatDuration(state.retryAfter)}</>}
        </div>
      )}
    </div>
  );
}

/** The states for one target, with no chrome of its own — for embedding in an existing row. */
export function RateLimitDetails({ target }: { target: RateLimitTarget }) {
  const { t } = useTranslation();
  const { states, error } = useRateLimit(target);

  if (error) {
    return <p className="text-xs text-red-600 dark:text-red-400">{error}</p>;
  }
  if (states === null) {
    return <p className="text-xs text-slate-400">{t("common.loading")}</p>;
  }
  if (states.length === 0) {
    return <p className="text-xs text-slate-400">{t("rateLimits.none")}</p>;
  }
  return (
    <div className="space-y-3">
      {states.map((state) => (
        <RateLimitMeter key={state.policy} state={state} />
      ))}
    </div>
  );
}

/** The states for one target as a titled card with a refresh button — a page-level panel. */
export function RateLimitCard({ target, hint }: { target: RateLimitTarget; hint?: string }) {
  const { t } = useTranslation();
  const { states, error, reload } = useRateLimit(target);

  return (
    <section className={`${card} space-y-4`}>
      <div className="flex items-center justify-between gap-3">
        <h2 className="font-medium text-slate-800 dark:text-slate-200">{t("rateLimits.title")}</h2>
        <button type="button" className={ghostButton} onClick={reload}>
          {t("rateLimits.reload")}
        </button>
      </div>

      <Banner tone="error">{error}</Banner>
      {hint && <p className="text-sm text-slate-500">{hint}</p>}

      {states === null ? (
        <Loader />
      ) : states.length === 0 ? (
        !error && <p className="text-sm text-slate-500">{t("rateLimits.none")}</p>
      ) : (
        <div className="space-y-4">
          {states.map((state) => (
            <RateLimitMeter key={state.policy} state={state} />
          ))}
        </div>
      )}
    </section>
  );
}

/** A collapsed "show the rate limit" toggle for a table row or list item.
 *
 * The states are fetched by the child, which is mounted only once opened — so a list of fifty keys
 * costs nothing until someone actually looks at one. */
export function RateLimitDisclosure({ target }: { target: RateLimitTarget }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const panelId = useId();

  return (
    <div className="space-y-2">
      <button
        type="button"
        className="text-xs text-primary hover:underline"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((was) => !was)}
      >
        {open ? t("rateLimits.hide") : t("rateLimits.show")}
      </button>
      {open && (
        <div id={panelId} className="max-w-md">
          <RateLimitDetails target={target} />
        </div>
      )}
    </div>
  );
}
