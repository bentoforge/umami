/** Landing page — route `/app` (index), reachable via the logo and the "Start" nav item.
 *
 * It will hold several permission-gated sections (dashboards/shortcuts); intentionally empty for now.
 */
export function StartPage() {
  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-slate-900 dark:text-white">Start</h1>
      {/* Permission-gated sections go here. */}
    </div>
  );
}
