import { Navigate, Route, Routes } from "react-router-dom";
import { useUmami } from "./auth/UmamiProvider";
import { Loader } from "./components";
import { AdminLayout } from "./pages/AdminLayout";
import { ApiTokensPage } from "./pages/ApiTokensPage";
import { AuditPage } from "./pages/AuditPage";
import { ConfigPage } from "./pages/ConfigPage";
import { CreateTenantPage } from "./pages/CreateTenantPage";
import { EditTenantPage } from "./pages/EditTenantPage";
import { EditUserPage } from "./pages/EditUserPage";
import { LoginPage } from "./pages/LoginPage";
import { ProfilePage } from "./pages/ProfilePage";
import { SessionsPage } from "./pages/SessionsPage";
import { StartPage } from "./pages/StartPage";
import { TenantsPage } from "./pages/TenantsPage";
import { UsersPage } from "./pages/UsersPage";

export function App() {
  const { me, loading, client } = useUmami();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-100 dark:bg-slate-900">
        <Loader />
      </div>
    );
  }

  if (!me) return <LoginPage />;

  const can = (permission: string) => client.hasPermission(permission);

  return (
    <Routes>
      <Route element={<AdminLayout />}>
        <Route index element={<StartPage />} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="sessions" element={<SessionsPage />} />
        <Route
          path="tenants"
          element={can("manage:tenants") ? <TenantsPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="tenants/new"
          element={can("manage:tenants") ? <CreateTenantPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="tenants/:tenantId"
          element={can("manage:tenants") ? <EditTenantPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="users"
          element={can("manage:users") ? <UsersPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="users/:userId"
          element={can("manage:users") ? <EditUserPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="api-tokens"
          element={can("manage:service-keys") ? <ApiTokensPage /> : <Navigate to="/" replace />}
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
