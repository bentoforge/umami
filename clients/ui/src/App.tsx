import { useUmami } from "./auth/UmamiProvider";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";

export function App() {
  const { me, loading } = useUmami();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-100 dark:bg-slate-900 text-slate-500">
        …
      </div>
    );
  }

  return me ? <DashboardPage /> : <LoginPage />;
}
