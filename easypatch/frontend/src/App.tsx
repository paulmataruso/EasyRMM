import type { ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation, useSearchParams } from 'react-router';
import { useAuth, type AuthStage } from './auth/AuthContext';
import { AppLayout, AuthShell } from './components/Layout';
import { Button, ErrorState, Spinner } from './components/ui';
import {
  LoginPage,
  MfaSetupRequiredPage,
  MfaVerifyPage,
  PasswordChangeRequiredPage,
  ResetPasswordPage,
  safeReturnTo,
} from './pages/auth/AuthPages';
import { DashboardPage } from './pages/DashboardPage';
import { OrganizationsPage } from './pages/organizations/OrganizationsPage';
import { OrganizationDetailPage } from './pages/organizations/OrganizationDetailPage';
import { EndpointsPage } from './pages/endpoints/EndpointsPage';
import { EndpointDetailPage } from './pages/endpoints/EndpointDetailPage';
import { UpdatesPage } from './pages/updates/UpdatesPage';
import { UpdateDetailPage } from './pages/updates/UpdateDetailPage';
import { JobsPage } from './pages/jobs/JobsPage';
import { AlertsPage } from './pages/alerts/AlertsPage';
import { JobDetailPage } from './pages/jobs/JobDetailPage';
import { ReportsPage } from './pages/reports/ReportsPage';
import { DeployPage, LegacyAgentsRedirect } from './pages/agents/DeployPage';
import { ApprovalsPage } from './pages/agents/ApprovalsPage';
import { SettingsPage } from './pages/settings/SettingsPage';
import { AccountPage } from './pages/account/AccountPage';
import { NotFoundPage } from './pages/NotFoundPage';

const stageRoutes: Record<Exclude<AuthStage, 'loading' | 'error' | 'ready'>, string> = {
  anonymous: '/login',
  mfa: '/login/mfa',
  'mfa-setup': '/account/mfa-setup',
  'password-change': '/account/change-password',
};

function FullPageSpinner() {
  return (
    <div className="flex h-full items-center justify-center">
      <Spinner label="Loading EasyPatch…" />
    </div>
  );
}

function SessionError() {
  const { error, refresh } = useAuth();
  return (
    <AuthShell title="EasyPatch is unavailable">
      <ErrorState error={error} compact />
      <Button className="mt-2 w-full" onClick={() => void refresh()}>
        Try again
      </Button>
    </AuthShell>
  );
}

/** Renders children only in the given stage; otherwise routes to where the session needs to go. */
function Gate({ stage: required, children }: { stage: AuthStage; children: ReactNode }) {
  const { stage } = useAuth();
  const location = useLocation();
  const [params] = useSearchParams();

  if (stage === 'loading') return <FullPageSpinner />;
  if (stage === 'error') return <SessionError />;
  if (stage === required) return <>{children}</>;

  if (stage === 'ready') {
    return <Navigate to={safeReturnTo(params.get('returnTo'))} replace />;
  }

  const target = stageRoutes[stage];
  if (stage === 'anonymous' || stage === 'mfa') {
    // Preserve where the user was going.
    const current = required === 'ready' ? `${location.pathname}${location.search}` : params.get('returnTo');
    const returnTo = safeReturnTo(current);
    return <Navigate to={returnTo !== '/' ? `${target}?returnTo=${encodeURIComponent(returnTo)}` : target} replace />;
  }
  return <Navigate to={target} replace />;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<Gate stage="anonymous"><LoginPage /></Gate>} />
      <Route path="/login/mfa" element={<Gate stage="mfa"><MfaVerifyPage /></Gate>} />
      <Route path="/account/mfa-setup" element={<Gate stage="mfa-setup"><MfaSetupRequiredPage /></Gate>} />
      <Route path="/account/change-password" element={<Gate stage="password-change"><PasswordChangeRequiredPage /></Gate>} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />

      <Route element={<Gate stage="ready"><AppLayout /></Gate>}>
        <Route index element={<DashboardPage />} />
        <Route path="organizations" element={<OrganizationsPage />} />
        <Route path="organizations/:id" element={<OrganizationDetailPage />} />
        <Route path="endpoints" element={<EndpointsPage />} />
        <Route path="endpoints/:id" element={<EndpointDetailPage />} />
        <Route path="updates" element={<UpdatesPage />} />
        <Route path="updates/:guid" element={<UpdateDetailPage />} />
        <Route path="jobs" element={<JobsPage />} />
        <Route path="jobs/:id" element={<JobDetailPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="approvals" element={<ApprovalsPage />} />
        <Route path="deploy" element={<DeployPage />} />
        <Route path="agents" element={<LegacyAgentsRedirect />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="account" element={<AccountPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
