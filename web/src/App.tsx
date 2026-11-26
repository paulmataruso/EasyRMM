import { useEffect, type ComponentType, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation, useSearchParams } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { keyFor } from "./api/hooks";
import type { AuthOptions } from "./api/types";
import { useAuth, type AuthStage } from "./auth/AuthContext";
import { keyAvailability } from "./auth/webauthn";
import { AlertCard, AppLayout, AuthShell } from "./components/Layout";
import { Button, ErrorState, Spinner } from "./components/ui";
import {
  afterSignIn,
  ForgotPasswordPage,
  LoginPage,
  MfaSetupRequiredPage,
  MfaVerifyPage,
  PasskeyPromptPage,
  RecoverPage,
  ResetPasswordPage,
  safeReturnTo,
  SetupPage,
} from "./pages/auth/AuthPages";
import { useReloadWhenOutdated } from "./lib/consoleBuild";
import { lazyPage, PageFrame, type LazyPage } from "./lib/lazyPage";

// Pages are fetched when first shown (signing in needs none of them), so the console starts with less to load.
const pages: LazyPage[] = [];
function page(load: () => Promise<ComponentType>): LazyPage {
  const lazy = lazyPage(load);
  pages.push(lazy);
  return lazy;
}
const DashboardPage = page(() => import("./pages/DashboardPage").then((m) => m.DashboardPage));
const OrganizationsPage = page(() => import("./pages/organizations/OrganizationsPage").then((m) => m.OrganizationsPage));
const OrganizationDetailPage = page(() => import("./pages/organizations/OrganizationDetailPage").then((m) => m.OrganizationDetailPage));
const GroupDetailPage = page(() => import("./pages/organizations/GroupDetailPage").then((m) => m.GroupDetailPage));
const SiteDetailPage = page(() => import("./pages/organizations/SiteDetailPage").then((m) => m.SiteDetailPage));
const SettingsPage = page(() => import("./pages/settings/SettingsPage").then((m) => m.SettingsPage));
const UserDetailPage = page(() => import("./pages/settings/UserDetailPage").then((m) => m.UserDetailPage));
const AccountPage = page(() => import("./pages/account/AccountPage").then((m) => m.AccountPage));
const NotFoundPage = page(() => import("./pages/NotFoundPage").then((m) => m.NotFoundPage));
const AddDevicesPage = page(() => import("./pages/devices/AddDevicesPage").then((m) => m.AddDevicesPage));
const ApprovalsPage = page(() => import("./pages/devices/ApprovalsPage").then((m) => m.ApprovalsPage));
const DevicesPage = page(() => import("./pages/devices/DevicesPage").then((m) => m.DevicesPage));
const DeviceDetailPage = page(() => import("./pages/devices/DeviceDetailPage").then((m) => m.DeviceDetailPage));
const RemoteSessionPage = page(() => import("./pages/devices/RemoteSessionPage").then((m) => m.RemoteSessionPage));
const ScriptsPage = page(() => import("./pages/scripts/ScriptsPage").then((m) => m.ScriptsPage));
const ScriptDetailPage = page(() => import("./pages/scripts/ScriptDetailPage").then((m) => m.ScriptDetailPage));
const ScriptFormPage = page(() => import("./pages/scripts/ScriptFormPage").then((m) => m.ScriptFormPage));
const JobsPage = page(() => import("./pages/jobs/JobsPage").then((m) => m.JobsPage));
const AlertsPage = page(() => import("./pages/alerts/AlertsPage").then((m) => m.AlertsPage));
const FromEasyPatchPage = page(() => import("./pages/patching/FromEasyPatch").then((m) => m.FromEasyPatchPage));
const PatchingPage = page(() => import("./pages/patching/PatchingPage").then((m) => m.PatchingPage));
const PatchingDevicePage = page(() => import("./pages/patching/PatchingDevicePage").then((m) => m.PatchingDevicePage));
const UpdatePage = page(() => import("./pages/patching/UpdatePage").then((m) => m.UpdatePage));
const ReportsPage = page(() => import("./pages/reports/ReportsPage").then((m) => m.ReportsPage));
const JobDetailPage = page(() => import("./pages/jobs/JobDetailPage").then((m) => m.JobDetailPage));
const RunDetailPage = page(() => import("./pages/jobs/RunDetailPage").then((m) => m.RunDetailPage));

/** Fetches every page now. Tests call it so that pages render at once. */
export function preloadPages(): Promise<unknown> {
  return Promise.all([...pages, AlertCard].map((p) => p.preload()));
}

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
  const { stage, showingRecoveryCodes, session } = useAuth();
  const location = useLocation();
  const [params] = useSearchParams();
  const queryClient = useQueryClient();

  if (stage === "loading") return <FullPageSpinner />;
  if (stage === "error") return <SessionError />;
  if (stage === required) return <>{children}</>;
  if (required === "mfa-setup" && stage === "ready" && showingRecoveryCodes) return <>{children}</>;

  if (stage === "ready") {
    const returnTo = safeReturnTo(params.get("returnTo"));
    // A sign-in that just finished here may offer a passkey first. Decided here rather than only by the page:
    // the session renders before the page's own navigation, and this redirect would otherwise win.
    if (session && (required === "anonymous" || required === "mfa")) {
      const options = queryClient.getQueryData<AuthOptions>(keyFor("/auth/options"));
      return <Navigate to={afterSignIn(session, returnTo, keyAvailability(options?.webauthn))} replace />;
    }
    return <Navigate to={returnTo} replace />;
  }

  const target = stageRoutes[stage];
  if (stage === "anonymous" || stage === "mfa") {
    // Preserve where the user was going.
    const current = required === "ready" ? `${location.pathname}${location.search}` : params.get("returnTo");
    const returnTo = safeReturnTo(current);
    return <Navigate to={returnTo !== "/" ? `${target}?returnTo=${encodeURIComponent(returnTo)}` : target} replace />;
  }
  return <Navigate to={target} replace />;
}

/** Old links and bookmarks to /patching?deviceId= open the device's own patching page (ADR-0072). */
function PatchingRoute() {
  const [params] = useSearchParams();
  const deviceId = params.get("deviceId");
  // The Alerts tab's own device filter stays a filter of that tab.
  return deviceId && params.get("tab") !== "alerts" ? <Navigate to={`/patching/devices/${encodeURIComponent(deviceId)}`} replace /> : <PatchingPage />;
}

/** Old links and bookmarks to /sites/:id?groupId= open the group's own page (ADR-0072). */
function SiteRoute() {
  const [params] = useSearchParams();
  const groupId = params.get("groupId");
  return groupId ? <Navigate to={`/groups/${encodeURIComponent(groupId)}`} replace /> : <SiteDetailPage />;
}

/** /devices/add?siteId= opens that site's Install tab (ADR-0072). */
function AddDevicesRoute() {
  const [params] = useSearchParams();
  const siteId = params.get("siteId");
  return siteId ? <Navigate to={`/sites/${encodeURIComponent(siteId)}?tab=install`} replace /> : <AddDevicesPage />;
}

export function App() {
  useReloadWhenOutdated();
  return (
    <Routes>
      <Route path="/setup" element={<Gate stage="setup"><SetupPage /></Gate>} />
      <Route path="/login" element={<Gate stage="anonymous"><LoginPage /></Gate>} />
      <Route path="/login/mfa" element={<Gate stage="mfa"><MfaVerifyPage /></Gate>} />
      <Route path="/login/mfa-setup" element={<Gate stage="mfa-setup"><MfaSetupRequiredPage /></Gate>} />
      <Route path="/login/passkey" element={<Gate stage="ready"><PasskeyPromptPage /></Gate>} />
      <Route path="/forgot-password" element={<Gate stage="anonymous"><ForgotPasswordPage /></Gate>} />
      {/* Reset and invitation links work whatever the browser's sign-in state. */}
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/welcome" element={<ResetPasswordPage invite />} />
      <Route path="/recover" element={<RecoverPage />} />

      {/* Remote sessions take the whole window. */}
      <Route path="/devices/:id/remote/:kind" element={<Gate stage="ready"><PageFrame><RemoteSessionPage /></PageFrame></Gate>} />

      <Route element={<Gate stage="ready"><AppLayout /></Gate>}>
        <Route index element={<DashboardPage />} />
        <Route path="organizations" element={<OrganizationsPage />} />
        <Route path="organizations/:id" element={<OrganizationDetailPage />} />
        <Route path="sites/:id" element={<SiteRoute />} />
        <Route path="groups/:id" element={<GroupDetailPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="devices/add" element={<AddDevicesRoute />} />
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
        <Route path="patching" element={<PatchingRoute />} />
        <Route path="patching/devices/:id" element={<PatchingDevicePage />} />
        <Route path="patching/updates/:guid" element={<UpdatePage />} />
        <Route path="go/from-easypatch/:kind/:id" element={<FromEasyPatchPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="users/:id" element={<UserDetailPage />} />
        <Route path="account" element={<AccountPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
