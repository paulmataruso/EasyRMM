import { Link, useParams } from "react-router";
import { AppWindow, ExternalLink, FolderOpen, MonitorPlay, SquareTerminal } from "lucide-react";
import type { ReactNode } from "react";
import { useApi, useList } from "../../api/hooks";
import type { AuditEntry, Device, RemoteKind } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { MenuButton } from "../../components/Menu";
import { DeviceStatusBadge, REMOTE_KIND_NAMES } from "../../components/StatusBadges";
import { useToast } from "../../components/Toast";
import { Alert, Button, Card, EmptyState, ErrorState, KeyValueList, PageHeader, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { DeviceTreeToggle } from "./DeviceTree";
import { platformName } from "./platform";
import { openSessionWindow, sessionPath } from "./sessionWindow";

const KIND_ICONS: Record<RemoteKind, ReactNode> = {
  desktop: <MonitorPlay className="size-4" aria-hidden />,
  terminal: <SquareTerminal className="size-4" aria-hidden />,
  files: <FolderOpen className="size-4" aria-hidden />,
};

/** The session kinds the caller may open on a device, in display order. */
export function allowedKinds(d: Pick<Device, "canDesktop" | "canTerminal" | "canFiles">): RemoteKind[] {
  return (["desktop", "terminal", "files"] as const).filter((k) => (k === "desktop" ? d.canDesktop : k === "terminal" ? d.canTerminal : d.canFiles));
}

/** Why sessions cannot start on a device right now, or null when they can. */
export function unavailableReason(d: Pick<Device, "remoteAgent" | "remoteOnline" | "online">): string | null {
  if (!d.remoteAgent) return "Remote access is not set up on this device.";
  if (!d.remoteOnline) return d.online ? "Remote access is not connected." : "The device is offline.";
  return null;
}

/** The remote-access part of a device, in a few words, and what it means when that is not obvious. */
export function remoteAccessState(d: Pick<Device, "remoteAgent" | "remoteOnline" | "agent">, enabled: boolean): { label: string; hint?: string } {
  if (!enabled) return { label: "Turned off on this server" };
  if (d.remoteAgent) return { label: d.remoteOnline ? "Connected" : "Not connected" };
  if (d.agent)
    return {
      label: "Not set up yet",
      hint: "The EasyRMM agent installs MeshAgent shortly after enrolling. If this lasts, run “easyrmm-agent status” on the device.",
    };
  return { label: "Not installed" };
}

export function DeviceDetailPage() {
  const { id = "" } = useParams();
  const { can, session } = useAuth();
  const device = useApi<Device>(`/devices/${id}`, undefined, { refetchInterval: 30_000 });
  const showHistory = can("audit.view");

  if (device.isPending) return <Spinner />;
  if (device.isError) return <ErrorState error={device.error} onRetry={() => void device.refetch()} />;
  const d = device.data;
  const kinds = allowedKinds(d);
  const reason = unavailableReason(d);
  const remote = remoteAccessState(d, session?.features.remoteAccess === true);

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
            <DeviceTreeToggle />
          </>
        }
      />

      {kinds.length > 0 && reason && (
        <Alert tone="info" className="mb-5" title={reason}>
          {d.online
            ? "The device is checking in, but its MeshAgent is not connected to MeshCentral. Remote sessions can start once it reconnects; this page checks every 30 seconds."
            : `Last seen ${formatRelative(d.lastSeenAt)}. Remote sessions can start again once the device reconnects; this page checks every 30 seconds.`}
        </Alert>
      )}

      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
        <Card title="Details" className={showHistory ? "xl:col-span-2" : "xl:col-span-3"}>
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
              [
                "EasyRMM agent",
                d.agent ? (
                  <span key="a">
                    {d.agent.version} <span className="text-muted">({d.agent.arch})</span>
                  </span>
                ) : (
                  <span className="text-muted">Not installed</span>
                ),
              ],
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
        {showHistory && <SessionHistory deviceId={d.id} />}
      </div>
    </>
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
