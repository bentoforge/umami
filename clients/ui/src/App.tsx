import { Navigate, Route, Routes, useLocation } from "react-router-dom";
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
import { RateLimitsPage } from "./pages/RateLimitsPage";
import { ResetPasswordPage } from "./pages/ResetPasswordPage";
import { StartPage } from "./pages/StartPage";
import { TenantsPage } from "./pages/TenantsPage";
import { UsersPage } from "./pages/UsersPage";
import { VerifyContactPage } from "./pages/VerifyContactPage";

export function App() {
  const { me, loading, client } = useUmami();
  const { pathname } = useLocation();

  // Checked *above* the session gate: both links arrive by mail, and the mail client regularly
  // carries no umami session. The token in the URL is the proof — for the reset it has to be, since
  // the whole premise is that the user cannot sign in.
  if (pathname === "/verify-contact") return <VerifyContactPage />;
  if (pathname === "/reset-password") return <ResetPasswordPage />;

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
          element={can("view:audit") ? <AuditPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="rate-limits"
          element={can("view:ratelimits") ? <RateLimitsPage /> : <Navigate to="/" replace />}
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
