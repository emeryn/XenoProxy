/** Router and application providers. */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Navigate, Route, Routes } from 'react-router-dom';

import { ToastProvider } from '@/components/ui/Toast';
import { GroupsPage } from '@/features/admin/pages/GroupsPage';
import { PluginCatalogPage } from '@/features/admin/pages/PluginCatalogPage';
import { InstanceSettingsPage } from '@/features/admin/settings/SettingsPage';
import { AssistantPage } from '@/features/assistant/AssistantPage';
import { AuditPage } from '@/features/admin/pages/AuditPage';
import { PlaybooksPage } from '@/features/admin/pages/PlaybooksPage';
import { PluginPackagesPage } from '@/features/admin/pages/PluginPackagesPage';
import { UsersPage } from '@/features/admin/pages/UsersPage';
import { LoginPage } from '@/features/auth/pages/LoginPage';
import { SetupPage } from '@/features/auth/pages/SetupPage';
import { SettingsPage } from '@/features/auth/pages/SettingsPage';
import { DashboardPage } from '@/features/jobs/pages/DashboardPage';
import { JobDetailPage } from '@/features/jobs/pages/JobDetailPage';
import { JobsPage } from '@/features/jobs/pages/JobsPage';
import { NewScanPage } from '@/features/scan/pages/NewScanPage';
import { ApiError } from '@/lib/api-client';
import { AppShell } from './AppShell';
import { AuthProvider, useAuth } from './auth-context';
import { ErrorBoundary } from './ErrorBoundary';
import { HelpPage } from './HelpPage';
import { ThemeProvider } from './theme';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        // Authentication and authorization failures are final.
        if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
        return failureCount < 2;
      },
      refetchOnWindowFocus: false,
      staleTime: 15_000,
    },
  },
});

function RequirePermission({
  permission,
  children,
}: {
  permission: string;
  children: React.ReactNode;
}) {
  const { can } = useAuth();
  if (!can(permission)) return <Navigate to="/scan" replace />;
  return <>{children}</>;
}

function AuthenticatedRoutes() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center p-12 text-sm text-muted">
        Loading the workspace…
      </div>
    );
  }
  if (!user) return <LoginPage />;

  // The backend refuses almost every call while one of these is outstanding, so
  // the normal shell would render panels that all fail. The gate comes first.
  if (user.must_change_password || (user.mfa_required && !user.mfa_enabled)) {
    return <SetupPage />;
  }

  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<Navigate to="/scan" replace />} />
        <Route path="/scan" element={<NewScanPage />} />
        <Route path="/jobs" element={<JobsPage />} />
        <Route path="/jobs/:jobId" element={<JobDetailPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/help" element={<HelpPage />} />
        <Route path="/assistant" element={<AssistantPage />} />
        <Route
          path="/admin/plugins"
          element={
            <RequirePermission permission="analyzers:manage">
              <PluginCatalogPage />
            </RequirePermission>
          }
        />
        <Route
          path="/admin/settings"
          element={
            <RequirePermission permission="settings:manage">
              <InstanceSettingsPage />
            </RequirePermission>
          }
        />
        <Route
          path="/admin/playbooks"
          element={
            <RequirePermission permission="playbooks:manage">
              <PlaybooksPage />
            </RequirePermission>
          }
        />
        <Route
          path="/admin/plugin-packages"
          element={
            <RequirePermission permission="plugins:manage">
              <PluginPackagesPage />
            </RequirePermission>
          }
        />
        <Route
          path="/admin/groups"
          element={
            <RequirePermission permission="groups:manage">
              <GroupsPage />
            </RequirePermission>
          }
        />
        <Route
          path="/admin/users"
          element={
            <RequirePermission permission="users:manage">
              <UsersPage />
            </RequirePermission>
          }
        />
        <Route
          path="/admin/audit"
          element={
            <RequirePermission permission="audit:read">
              <AuditPage />
            </RequirePermission>
          }
        />
        <Route path="*" element={<Navigate to="/scan" replace />} />
      </Routes>
    </AppShell>
  );
}

export function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <ToastProvider>
            <AuthProvider>
              <AuthenticatedRoutes />
            </AuthProvider>
          </ToastProvider>
        </ThemeProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}
