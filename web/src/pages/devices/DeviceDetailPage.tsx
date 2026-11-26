import { Link, useParams } from "react-router";
import { AppWindow, ExternalLink, MoveRight, Play } from "lucide-react";
import { useState } from "react";
import { useApi, useList } from "../../api/hooks";
import type { AuditEntry, Device, DeviceRoles, JobRun, PatchStatus, RemoteKind } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { MenuButton } from "../../components/Menu";
import { DeviceStatusBadge, REMOTE_KIND_NAMES } from "../../components/StatusBadges";
import { useToast } from "../../components/Toast";
import { Alert, Button, Card, EmptyState, ErrorState, KeyValueList, PageHeader, Spinner, Tabs } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { MoveDialog } from "../../nav/MoveDialog";
import { RunStatusBadge } from "../scripts/parts";
import { RunScriptDialog } from "../scripts/RunScriptDialog";
import { cannotRunReason, isOpen } from "../scripts/scriptText";
import { HardwarePanel } from "./DeviceHardware";
import { HealthCard, PerformanceCard, useDeviceInventory } from "./DeviceHealth";
import { DeviceAlertsCard } from "../alerts/DeviceAlertsCard";
import { SoftwarePanel } from "./DeviceSoftware";
import { PatchesPanel } from "./DevicePatches";
import { HardeningPanel } from "./DeviceHardening";
import { PosturePanel } from "./PosturePanel";
import { WindowsHardeningPanel } from "../hardening/WindowsHardening";
import { AgentLogsPanel } from "./DeviceLogs";
import { DefenderPanel } from "./DeviceDefender";
import { platformName } from "./platform";
import { allowedKinds, KIND_ICONS, unavailableReason } from "./remote";
import { AgentLine } from "./agentUpdate";
import { RemovalBanner, RemoveDeviceButton } from "./deviceRemoval";
import { EasyRmmRepairCard, PatchingRepairCard, RemoteRepairCard, RepairButton } from "./remoteRepair";
import { openSessionWindow, sessionPath } from "./sessionWindow";
import { DeviceCompliance, useComplianceEnabled } from "../compliance/DeviceCompliance";
import { ModuleOff } from "./modules/ModuleTab";
import { DEVICE_MODULE_TABS, moduleTabState } from "./modules/moduleTabs";

/** The remote-access part of a device, in a few words, and what it means when that is not obvious. */
export function remoteAccessState(
  d: Pick<Device, "remoteAgent" | "remoteOnline" | "agent" | "platform">,
  enabled: boolean,
): { label: string; hint?: string } {
  if (!enabled) return { label: "Turned off on this server" };
  if (d.remoteAgent) return { label: d.remoteOnline ? "Connected" : "Not connected" };
  if (d.agent) {
    const status =
      d.platform === "windows" ? "“& \"$env:ProgramFiles\\EasyRMM\\Agent\\easyrmm-agent.exe\" status” in PowerShell as administrator" : "“sudo easyrmm-agent status”";
    return {
      label: "Not set up yet",
      hint: `The EasyRMM agent installs MeshAgent shortly after enrolling. If this lasts, run ${status} on the device.`,
    };
  }
  return { label: "Not installed" };
}

/** What is known about a MeshAgent that is not connected while its device checks in (ADR-0069). */
function NotConnected({ device: d }: { device: Device }) {
  const r = d.remote;
  return (
    <>
      The device is checking in, but its MeshAgent is not connected to MeshCentral
      {r?.reason === "not_connected" && r.since ? <> (since <span title={formatDateTime(r.since)}>{formatRelative(r.since)}</span>)</> : ""}. Remote sessions can
      start once it reconnects; this page checks every 30 seconds.
      {r?.host && r.reason === "other_server" && <span className="mt-1 block text-muted">Its settings name {r.host}.</span>}
      {r?.error && <span className="mt-1 block break-words text-muted">Last error on the device: {r.error}</span>}
      {d.canReconnectRemote && <span className="mt-1 block text-muted">Repair restarts MeshAgent and, if that does not help, puts it back in place.</span>}
    </>
  );
}

export function DeviceDetailPage() {
  const { id = "" } = useParams();
  const { can, canAt, session } = useAuth();
  const url = useUrlState();
  const device = useApi<Device>(`/devices/${id}`, undefined, { refetchInterval: 30_000 });
  const hasAgent = device.data?.agent != null;
  const inventory = useDeviceInventory(id, hasAgent);
  // The Patches tab shows once EasyPatch is set up (ADR-0030).
  const patching = useApi<PatchStatus>(can("patch.view") ? "/patching" : null, undefined, { staleTime: 60_000 });
  // Windows management modules (ADR-0073): the detected roles decide which module tabs are offered.
  const roles = useApi<DeviceRoles>(hasAgent && device.data?.platform === "windows" ? `/devices/${id}/roles` : null, undefined, { staleTime: 60_000 });
  const complianceOn = useComplianceEnabled(device.data);
  const [running, setRunning] = useState(false);
  const [moving, setMoving] = useState(false);
  const showHistory = can("audit.view");

  if (device.isPending) return <Spinner />;
  if (device.isError) return <ErrorState error={device.error} onRetry={() => void device.refetch()} />;
  const d = device.data;
  const atDevice = (p: Parameters<typeof can>[0]) => canAt(p, { organizationId: d.organizationId, siteId: d.siteId });
  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "hardware", label: "Hardware", hidden: !hasAgent },
    { id: "software", label: "Software", hidden: !hasAgent || !can("software.view") },
    { id: "patches", label: "Patches", hidden: !hasAgent || patching.data?.configured !== true },
    // Hardening covers Linux (ADR-0051) and Windows (ADR-0054); viewing its findings needs only device.view.
    { id: "hardening", label: "Hardening", hidden: !hasAgent || (d.platform !== "linux" && d.platform !== "windows") },
    // Agent logs (ADR-0069) need log.view: Technicians and above.
    { id: "logs", label: "Logs", hidden: !hasAgent || !can("log.view") },
    // Compliance (ADR-0078): hidden where the module is off or the viewer may not see its results.
    { id: "compliance", label: "Compliance", hidden: !hasAgent || (d.platform !== "linux" && d.platform !== "windows") || !complianceOn },
    ...DEVICE_MODULE_TABS.map((m) => ({ id: m.id, label: m.label, hidden: moduleTabState(m, roles.data, atDevice) !== "shown" })),
  ];
  const requested = url.get("tab");
  // A module that is off is not in the strip, but its URL says so instead of falling back to Overview.
  const offModule = DEVICE_MODULE_TABS.find((m) => m.id === requested && moduleTabState(m, roles.data, atDevice) === "off");
  const tab = offModule ? offModule.id : tabs.some((t) => t.id === requested && !t.hidden) ? requested : "overview";
  const showTab = (t: string) => url.set({ tab: t === "overview" ? null : t });
  const kinds = allowedKinds(d);
  const reason = unavailableReason(d);
  const remote = remoteAccessState(d, session?.features.remoteAccess === true);
  // Scripts are offered where the role runs them; the reason shows when the device itself cannot.
  const scriptReason = d.canRunScripts ? cannotRunReason(d) : null;
  const showRuns = can("job.view") && d.agent !== null;
  const showAlerts = can("alert.view");
  const side = hasAgent || showHistory || showRuns || showAlerts;

  return (
    <>
      <PageHeader
        breadcrumb={
          <>
            <Link to="/devices" className="hover:text-fg">
              Devices
            </Link>
            <span className="mx-1.5" aria-hidden>
              /
            </span>
            <Link to={`/sites/${d.siteId}`} className="hover:text-fg">
              {d.organizationName} / {d.siteName}
            </Link>
          </>
        }
        title={d.name}
        subtitle={d.osDescription || platformName(d.platform)}
        actions={
          <>
            {kinds.map((k, i) =>
              reason ? (
                <Button key={k} icon={KIND_ICONS[k]} disabled title={reason}>
                  {REMOTE_KIND_NAMES[k]}
                </Button>
              ) : (
                <SessionButton key={k} device={d} kind={k} primary={i === 0} />
              ),
            )}
            {d.canRunScripts && (
              <Button icon={<Play className="size-4" aria-hidden />} onClick={() => setRunning(true)} disabled={scriptReason !== null} title={scriptReason ?? undefined}>
                Run script
              </Button>
            )}
            <RepairButton device={d} />
            {can("device.edit") && (
              <Button icon={<MoveRight className="size-4" aria-hidden />} onClick={() => setMoving(true)}>
                Move to…
              </Button>
            )}
            <RemoveDeviceButton device={d} />
          </>
        }
      />

      <RemovalBanner device={d} />
      <MoveDialog devices={[d]} open={moving} onClose={() => setMoving(false)} />

      {kinds.length > 0 && reason && (
        <Alert tone="info" className="mb-5" title={reason}>
          {d.online ? <NotConnected device={d} /> : `Last seen ${formatRelative(d.lastSeenAt)}. Remote sessions can start again once the device reconnects; this page checks every 30 seconds.`}
        </Alert>
      )}

      <RemoteRepairCard device={d} />
      <PatchingRepairCard device={d} />
      <EasyRmmRepairCard device={d} />

      {hasAgent && <Tabs tabs={tabs} active={tab} onChange={showTab} />}

      {tab === "hardware" && (
        <div role="tabpanel" aria-labelledby="tab-hardware">
          {inventory.isPending ? (
            <Spinner />
          ) : inventory.isError ? (
            <ErrorState error={inventory.error} onRetry={() => void inventory.refetch()} />
          ) : (
            <HardwarePanel data={inventory.data} device={d} />
          )}
        </div>
      )}

      {tab === "software" && (
        <div role="tabpanel" aria-labelledby="tab-software">
          {inventory.isPending ? (
            <Spinner />
          ) : inventory.isError ? (
            <ErrorState error={inventory.error} onRetry={() => void inventory.refetch()} />
          ) : (
            <SoftwarePanel device={d} inventory={inventory.data.inventory} />
          )}
        </div>
      )}

      {tab === "patches" && (
        <div role="tabpanel" aria-labelledby="tab-patches">
          <PatchesPanel device={d} />
        </div>
      )}

      {tab === "hardening" && (
        <div role="tabpanel" aria-labelledby="tab-hardening">
          <PosturePanel deviceId={d.id} />
          {d.platform === "windows" ? <WindowsHardeningPanel device={d} /> : <HardeningPanel device={d} />}
        </div>
      )}

      {tab === "compliance" && (
        <div role="tabpanel" aria-labelledby="tab-compliance">
          <DeviceCompliance device={d} />
        </div>
      )}

      {tab === "logs" && (
        <div role="tabpanel" aria-labelledby="tab-logs">
          <AgentLogsPanel device={d} />
        </div>
      )}

      {offModule && (
        <div role="tabpanel" aria-label={offModule.label}>
          <ModuleOff device={d} label={roles.data?.roles.find((r) => r.module === offModule.module)?.label ?? offModule.label} />
        </div>
      )}

      {DEVICE_MODULE_TABS.map((m) =>
        tab === m.id && !offModule ? (
          <div key={m.id} role="tabpanel" aria-labelledby={`tab-${m.id}`}>
            <m.component device={d} />
          </div>
        ) : null,
      )}

      {tab === "overview" && (
      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3" role={hasAgent ? "tabpanel" : undefined} aria-labelledby={hasAgent ? "tab-overview" : undefined}>
        <div className={side ? "flex min-w-0 flex-col gap-5 xl:col-span-2" : "flex min-w-0 flex-col gap-5 xl:col-span-3"}>
        <Card title="Details">
          <KeyValueList
            items={[
              ["Status", <DeviceStatusBadge key="s" device={d} />],
              ["Last seen", d.online ? "Now" : <span title={formatDateTime(d.lastSeenAt)}>{formatRelative(d.lastSeenAt)}</span>],
              ["Hostname", d.hostname || "—"],
              ["Operating system", d.osDescription || platformName(d.platform)],
              [
                "Organization",
                <Link key="o" to={`/organizations/${d.organizationId}`} className="text-accent hover:underline">
                  {d.organizationName}
                </Link>,
              ],
              [
                "Site",
                <Link key="si" to={`/sites/${d.siteId}`} className="text-accent hover:underline">
                  {d.siteName}
                </Link>,
              ],
              ["Device group", d.deviceGroupName || <span className="text-muted">None</span>],
              ["EasyRMM agent", <AgentLine key="a" device={d} />],
              [
                "Remote access",
                <span key="r">
                  {remote.label}
                  {remote.hint && <span className="block text-xs text-muted">{remote.hint}</span>}
                </span>,
              ],
              ...(d.agent ? [["Enrolled", formatDateTime(d.agent.enrolledAt)] as [string, string]] : []),
              ["First seen", formatDateTime(d.createdAt)],
            ]}
          />
        </Card>
        {hasAgent && <PerformanceCard deviceId={d.id} />}
        {hasAgent && d.platform === "windows" && <DefenderPanel deviceId={d.id} />}
        </div>
        {side && (
          <div className="flex min-w-0 flex-col gap-5">
            {showAlerts && <DeviceAlertsCard deviceId={d.id} />}
            {hasAgent && <HealthCard query={inventory} online={d.online} windows={d.platform === "windows"} onShowAll={() => showTab("hardware")} />}
            {showRuns && <ScriptRuns deviceId={d.id} />}
            {showHistory && <SessionHistory deviceId={d.id} />}
          </div>
        )}
      </div>
      )}
      {d.canRunScripts && <RunScriptDialog open={running} onClose={() => setRunning(false)} device={d} />}
    </>
  );
}

/** The device's newest script runs; refreshes quickly while one is still going. */
function ScriptRuns({ deviceId }: { deviceId: string }) {
  const runs = useList<JobRun>("/job-runs", { deviceId }, { refetchInterval: (data) => (data?.items.some((r) => isOpen(r.status)) ? 4_000 : 60_000) });
  const recent = runs.items.slice(0, 8);
  return (
    <Card
      title="Scripts"
      padded={false}
      actions={
        <Link to="/jobs" className="text-xs text-accent hover:underline">
          All jobs
        </Link>
      }
    >
      {runs.isPending ? (
        <Spinner />
      ) : runs.isError ? (
        <ErrorState error={runs.error} onRetry={() => void runs.refetch()} compact />
      ) : recent.length === 0 ? (
        <EmptyState title="No scripts have run here" compact>
          Scripts run on this device are listed here with their results.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line">
          {recent.map((r) => (
            <li key={r.id}>
              <Link to={`/jobs/${r.jobId}/runs/${r.id}`} className="flex items-center justify-between gap-3 px-4 py-2.5 text-sm hover:bg-hover">
                <span className="min-w-0">
                  <span className="block truncate font-medium">{r.scriptName}</span>
                  <span className="text-xs text-muted" title={formatDateTime(r.createdAt)}>
                    {formatRelative(r.createdAt)}
                    {r.exitCode !== null && r.exitCode !== 0 && <> · exit code {r.exitCode}</>}
                  </span>
                </span>
                <RunStatusBadge status={r.status} cancelRequested={r.cancelRequested} />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** Starts a remote session in this tab (full-window) or in a browser window of its own. */
function SessionButton({ device, kind, primary }: { device: Device; kind: RemoteKind; primary: boolean }) {
  const toast = useToast();
  const name = REMOTE_KIND_NAMES[kind];
  return (
    <MenuButton
      variant={primary ? "primary" : "secondary"}
      icon={KIND_ICONS[kind]}
      label={`Open ${name}`}
      items={[
        { id: "tab", label: "In this tab", icon: <AppWindow className="size-4" aria-hidden />, to: sessionPath(device.id, kind) },
        {
          id: "window",
          label: "In a new window",
          icon: <ExternalLink className="size-4" aria-hidden />,
          onSelect: () => {
            if (!openSessionWindow(device.id, kind)) {
              toast.error("Your browser blocked the new window. Allow pop-ups for this site, or open the session in this tab.");
            }
          },
        },
      ]}
    >
      {name}
    </MenuButton>
  );
}

function SessionHistory({ deviceId }: { deviceId: string }) {
  const audit = useList<AuditEntry>("/audit", { deviceId, action: "device.remote_session", limit: 10 }, { refetchInterval: 60_000 });
  return (
    <Card
      title="Remote sessions"
      padded={false}
      actions={
        <Link to="/settings?tab=audit&action=device" className="text-xs text-accent hover:underline">
          Audit log
        </Link>
      }
    >
      {audit.isPending ? (
        <Spinner />
      ) : audit.isError ? (
        <ErrorState error={audit.error} onRetry={() => void audit.refetch()} compact />
      ) : audit.items.length === 0 ? (
        <EmptyState title="No sessions yet" compact>
          Every remote session started on this device is listed here.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line">
          {audit.items.map((e) => {
            const kind = typeof e.details?.kind === "string" ? (REMOTE_KIND_NAMES[e.details.kind as RemoteKind] ?? e.details.kind) : "Session";
            return (
              <li key={e.id} className="flex items-baseline justify-between gap-3 px-4 py-2.5 text-sm">
                <span className="min-w-0">
                  <span className="block truncate">{e.actorLabel || e.actorType}</span>
                  <span className="text-xs text-muted">
                    {kind}
                    {e.outcome === "denied" && <span className="text-warn"> · denied</span>}
                    {e.outcome === "failure" && <span className="text-danger"> · failed</span>}
                  </span>
                </span>
                <span className="shrink-0 text-xs text-muted" title={formatDateTime(e.occurredAt)}>
                  {formatRelative(e.occurredAt)}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}
