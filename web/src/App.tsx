import type { ReactNode } from "react";
import { Navigate, Route, Routes, useLocation, useSearchParams } from "react-router";
import { useAuth, type AuthStage } from "./auth/AuthContext";
import { AppLayout, AuthShell } from "./components/Layout";
import { Button, ErrorState, Spinner } from "./components/ui";
import {
  ForgotPasswordPage,
  LoginPage,
  MfaSetupRequiredPage,
  MfaVerifyPage,
  ResetPasswordPage,
  safeReturnTo,
  SetupPage,
} from "./pages/auth/AuthPages";
import { DashboardPage } from "./pages/DashboardPage";
import { OrganizationsPage } from "./pages/organizations/OrganizationsPage";
import { OrganizationDetailPage } from "./pages/organizations/OrganizationDetailPage";
import { SiteDetailPage } from "./pages/organizations/SiteDetailPage";
import { SettingsPage } from "./pages/settings/SettingsPage";
import { UserDetailPage } from "./pages/settings/UserDetailPage";
import { AccountPage } from "./pages/account/AccountPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { AddDevicesPage } from "./pages/devices/AddDevicesPage";
import { ApprovalsPage } from "./pages/devices/ApprovalsPage";
import { DevicesPage } from "./pages/devices/DevicesPage";
import { DeviceDetailPage } from "./pages/devices/DeviceDetailPage";
import { RemoteSessionPage } from "./pages/devices/RemoteSessionPage";
import { ScriptsPage } from "./pages/scripts/ScriptsPage";
import { ScriptDetailPage } from "./pages/scripts/ScriptDetailPage";
import { ScriptFormPage } from "./pages/scripts/ScriptFormPage";
import { JobsPage } from "./pages/jobs/JobsPage";
import { AlertsPage } from "./pages/alerts/AlertsPage";
import { ReportsPage } from "./pages/reports/ReportsPage";
import { JobDetailPage } from "./pages/jobs/JobDetailPage";
import { RunDetailPage } from "./pages/jobs/RunDetailPage";
import { useReloadWhenOutdated } from "./lib/consoleBuild";

const stageRoutes: Record<Exclude<AuthStage, "loading" | "error" | "ready">, string> = {
  setup: "/setup",
  anonymous: "/login",
  mfa: "/login/mfa",
  "mfa-setup": "/login/mfa-setup",
};

function FullPageSpinner() {
  return (
    <div className="flex h-full items-center justify-center">
      <Spinner label="Loading EasyRMM…" />
    </div>
  );
}

function SessionError() {
  const { error, refresh } = useAuth();
  return (
    <AuthShell title="EasyRMM is unavailable">
      <ErrorState error={error} compact />
      <Button className="mt-2 w-full" onClick={() => void refresh()}>
        Try again
      </Button>
    </AuthShell>
  );
}

/** Renders children only in the given stage; otherwise routes to where the session needs to go. */
function Gate({ stage: required, children }: { stage: AuthStage; children: ReactNode }) {
  const { stage, showingRecoveryCodes } = useAuth();
  const location = useLocation();
  const [params] = useSearchParams();

  if (stage === "loading") return <FullPageSpinner />;
  if (stage === "error") return <SessionError />;
  if (stage === required) return <>{children}</>;
  if (required === "mfa-setup" && stage === "ready" && showingRecoveryCodes) return <>{children}</>;

  if (stage === "ready") return <Navigate to={safeReturnTo(params.get("returnTo"))} replace />;

  const target = stageRoutes[stage];
  if (stage === "anonymous" || stage === "mfa") {
    // Preserve where the user was going.
    const current = required === "ready" ? `${location.pathname}${location.search}` : params.get("returnTo");
    const returnTo = safeReturnTo(current);
    return <Navigate to={returnTo !== "/" ? `${target}?returnTo=${encodeURIComponent(returnTo)}` : target} replace />;
  }
  return <Navigate to={target} replace />;
}

export function App() {
  useReloadWhenOutdated();
  return (
    <Routes>
      <Route path="/setup" element={<Gate stage="setup"><SetupPage /></Gate>} />
      <Route path="/login" element={<Gate stage="anonymous"><LoginPage /></Gate>} />
      <Route path="/login/mfa" element={<Gate stage="mfa"><MfaVerifyPage /></Gate>} />
      <Route path="/login/mfa-setup" element={<Gate stage="mfa-setup"><MfaSetupRequiredPage /></Gate>} />
      <Route path="/forgot-password" element={<Gate stage="anonymous"><ForgotPasswordPage /></Gate>} />
      {/* Reset and invitation links work whatever the browser's sign-in state. */}
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/welcome" element={<ResetPasswordPage invite />} />

      {/* Remote sessions take the whole window. */}
      <Route path="/devices/:id/remote/:kind" element={<Gate stage="ready"><RemoteSessionPage /></Gate>} />

      <Route element={<Gate stage="ready"><AppLayout /></Gate>}>
        <Route index element={<DashboardPage />} />
        <Route path="organizations" element={<OrganizationsPage />} />
        <Route path="organizations/:id" element={<OrganizationDetailPage />} />
        <Route path="sites/:id" element={<SiteDetailPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="devices/add" element={<AddDevicesPage />} />
        <Route path="devices/approvals" element={<ApprovalsPage />} />
        <Route path="devices/:id" element={<DeviceDetailPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="scripts" element={<ScriptsPage />} />
        <Route path="scripts/new" element={<ScriptFormPage />} />
        <Route path="scripts/:id" element={<ScriptDetailPage />} />
        <Route path="scripts/:id/edit" element={<ScriptFormPage />} />
        <Route path="jobs" element={<JobsPage />} />
        <Route path="jobs/:id" element={<JobDetailPage />} />
        <Route path="jobs/:jobId/runs/:runId" element={<RunDetailPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="users/:id" element={<UserDetailPage />} />
        <Route path="account" element={<AccountPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
