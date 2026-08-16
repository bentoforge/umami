import { Navigate, Route, Routes } from "react-router-dom";
import { useUmami } from "./auth/UmamiProvider";
import { AdminLayout } from "./pages/AdminLayout";
import { LoginPage } from "./pages/LoginPage";
import { ProfilePage } from "./pages/ProfilePage";
import { TenantsPage } from "./pages/TenantsPage";
import { UsersPage } from "./pages/UsersPage";
import { ApiTokensPage } from "./pages/ApiTokensPage";
import { AuditPage } from "./pages/AuditPage";
import { ConfigPage } from "./pages/ConfigPage";

export function App() {
  const { me, loading, client } = useUmami();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-100 dark:bg-slate-900 text-slate-500">
        …
      </div>
    );
  }

  if (!me) return <LoginPage />;

  const can = (permission: string) => client.hasPermission(permission);

  return (
    <Routes>
      <Route element={<AdminLayout />}>
        <Route index element={<ProfilePage />} />
        <Route
          path="tenants"
          element={can("admin:system") ? <TenantsPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="users"
          element={can("write:members") ? <UsersPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="api-tokens"
          element={can("write:members") ? <ApiTokensPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="audit"
          element={can("admin:tenant") ? <AuditPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="config"
          element={can("manage:config") ? <ConfigPage /> : <Navigate to="/" replace />}
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
