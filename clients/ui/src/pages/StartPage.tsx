import type { AppCard, TaskCard } from "@bentoforge/umami-iam";
import { ArrowTopRightOnSquareIcon } from "@heroicons/react/24/outline";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import { Banner, errMsg } from "../components";
import { card } from "../ui";

/** Landing page — route `/app` (index). Two sections: the apps this deployment fronts (launch
 * cards, opened in a new tab) and umami's own account-hygiene tasks. Both come resolved and
 * per-user-gated from `GET /auth/me/home`, so this only lays them out. */
export function StartPage() {
  const { client } = useUmami();
  const { t } = useTranslation();
  const [apps, setApps] = useState<AppCard[]>([]);
  const [tasks, setTasks] = useState<TaskCard[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    client
      .home()
      .then((home) => {
        setApps(home.apps);
        setTasks(home.tasks);
      })
      .catch((err) => setError(errMsg(err)));
  }, [client]);

  return (
    <div className="space-y-8">
      <Banner tone="error">{error}</Banner>

      {apps.length > 0 && (
        <section className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {apps.map((app) => (
            <AppTile key={app.url} app={app} />
          ))}
        </section>
      )}

      {tasks.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
            {t("start.tasks")}
          </h2>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {tasks.map((task) => (
              <TaskTile key={task.url + task.label} task={task} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

/** A launch card for another service. Opens in a new tab — it leaves umami. */
function AppTile({ app }: { app: AppCard }) {
  return (
    <a
      href={app.url}
      target="_blank"
      rel="noopener noreferrer"
      className={`${card} group flex flex-col gap-1 transition hover:border-primary hover:shadow-sm`}
    >
      <div className="flex items-start justify-between gap-2">
        <h3 className="font-semibold text-slate-900 dark:text-white">{app.label}</h3>
        <ArrowTopRightOnSquareIcon className="h-4 w-4 shrink-0 text-slate-400 group-hover:text-primary" />
      </div>
      {app.description && <p className="text-sm text-slate-500">{app.description}</p>}
      <span className="mt-2 truncate font-mono text-xs text-slate-400">{app.url}</span>
    </a>
  );
}

/** An account-hygiene task. Links inside umami (same tab). An `important` task is highlighted —
 * the ring and left accent set it apart from the gentle nudges around it. */
function TaskTile({ task }: { task: TaskCard }) {
  const emphasis = task.important
    ? "border-amber-300 ring-1 ring-amber-300 dark:border-amber-500/50 dark:ring-amber-500/40"
    : "hover:border-primary";
  return (
    <Link
      to={task.url}
      className={`${card} flex flex-col gap-1 transition hover:shadow-sm ${emphasis}`}
    >
      <h3 className="font-semibold text-slate-900 dark:text-white">{task.label}</h3>
      <p className="text-sm text-slate-500">{task.description}</p>
    </Link>
  );
}
