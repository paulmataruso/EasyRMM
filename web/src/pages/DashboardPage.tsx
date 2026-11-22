import { useState, type ReactNode } from "react";
import { Link } from "react-router";
import { Bell, Building2, FolderTree, MapPin, ScreenShare, Users } from "lucide-react";
import { useApi, useList, useOrganizations, useSites } from "../api/hooks";
import type { AlertEntry, AlertSummary, AuditEntry, Device, List, RecentConnection, User } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { actionLabel, auditTarget, OutcomeBadge, REMOTE_KIND_NAMES } from "../components/StatusBadges";
import { Button, Card, cx, Dot, EmptyState, ErrorState, PageHeader, Spinner, StatTile, TableWrap } from "../components/ui";
import { canQuickConnect, QuickConnectPanel } from "../nav/QuickConnect";
import { formatDateTime, formatNumber, formatRelative, plural } from "../lib/format";
import { AlertActions, useAlertAction } from "./alerts/AlertActions";
import { SeverityBadge, valueText } from "./alerts/alertText";

export function DashboardPage() {
  const { can, isSuperAdmin, session } = useAuth();
  const orgs = useOrganizations();
  const sites = useSites();
  const users = useApi<List<User>>(can("user.view") ? "/users" : null, { limit: 200 });
  const alerts = useApi<AlertSummary>(can("alert.view") ? "/alerts/summary" : null, undefined, { refetchInterval: 60_000 });
  const activeAlerts = alerts.data?.active ?? 0;

  const siteCount = sites.items.length;
  const groupCount = sites.items.reduce((n, s) => n + s.deviceGroupCount, 0);
  const orgsWithSites = new Set(sites.items.map((s) => s.organizationId)).size;
  const sitesWithGroups = sites.items.filter((s) => s.deviceGroupCount > 0).length;
  const userCount = users.data ? `${formatNumber(users.data.items.length)}${users.data.next ? "+" : ""}` : "—";
  const tiles = 3 + (can("alert.view") ? 1 : 0) + (can("user.view") ? 1 : 0);
  const connections = session?.features.remoteAccess === true && can("device.view");
  const left = activeAlerts > 0 || can("audit.view");

  return (
    <>
      <PageHeader title="Dashboard" subtitle={isSuperAdmin ? "Every organization on this server." : "The organizations and sites you have access to."} />

      <div className={cx("grid grid-cols-2 gap-3", TILE_COLUMNS[tiles])}>
        {can("alert.view") && (
          <StatTile
            label="Active alerts"
            value={alerts.data ? formatNumber(activeAlerts) : "—"}
            icon={<Bell className="size-4" aria-hidden />}
            hint={
              alerts.data
                ? activeAlerts > 0
                  ? `${alerts.data.critical > 0 ? `${formatNumber(alerts.data.critical)} critical` : plural(alerts.data.warning, "warning")} on ${plural(alerts.data.devices, "device")}`
                  : "Nothing needs attention"
                : undefined
            }
            to={<TileLink to="/alerts">View alerts</TileLink>}
          />
        )}
        <StatTile
          label="Organizations"
          value={orgs.isPending ? "—" : formatNumber(orgs.items.length)}
          icon={<Building2 className="size-4" aria-hidden />}
          to={<TileLink to="/organizations">View all</TileLink>}
        />
        <StatTile
          label="Sites"
          value={sites.isPending ? "—" : formatNumber(siteCount)}
          icon={<MapPin className="size-4" aria-hidden />}
          hint={sites.isPending ? undefined : `across ${plural(orgsWithSites, "organization")}`}
        />
        <StatTile
          label="Device groups"
          value={sites.isPending ? "—" : formatNumber(groupCount)}
          icon={<FolderTree className="size-4" aria-hidden />}
          hint={sites.isPending ? undefined : `in ${plural(sitesWithGroups, "site")}`}
        />
        {can("user.view") && (
          <StatTile
            label="Users"
            value={userCount}
            icon={<Users className="size-4" aria-hidden />}
            to={<TileLink to="/settings?tab=users">Manage users</TileLink>}
          />
        )}
      </div>

      {/* Side by side only where the activity table keeps all its columns; stacked, the connections come first. */}
      {(left || connections) && (
        <div className="mt-5 grid grid-cols-1 items-start gap-5 2xl:grid-cols-3">
          {left && (
            <div className={cx("flex min-w-0 flex-col gap-5", connections ? "2xl:col-span-2" : "2xl:col-span-3")}>
              {activeAlerts > 0 && <ActiveAlertsCard total={activeAlerts} />}
              <RecentActivity />
            </div>
          )}
          {connections && <RecentConnectionsCard className={left ? "max-2xl:order-first" : "2xl:col-span-3"} />}
        </div>
      )}
    </>
  );
}

/**
 * The devices the signed-in user most recently opened remote sessions on, from the audit log, each with quick connect.
 */
function RecentConnectionsCard({ className }: { className?: string }) {
  const recent = useList<RecentConnection>("/devices/recent-connections", undefined, { refetchInterval: 30_000 });
  const [connect, setConnect] = useState<{ device: Device; anchor: HTMLElement } | null>(null);
  return (
    <Card title="Recent connections" className={className} padded={false}>
      {recent.isPending ? (
        <Spinner />
      ) : recent.isError ? (
        <ErrorState error={recent.error} onRetry={() => void recent.refetch()} compact />
      ) : recent.items.length === 0 ? (
        <EmptyState title="No connections yet" icon={<ScreenShare className="size-8" aria-hidden />} compact>
          Devices you open a remote session on are listed here, ready to connect again.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line">
          {recent.items.map(({ device: d, kind, at }) => {
            const ready = canQuickConnect(d);
            const connecting = connect?.device.id === d.id;
            return (
              <li key={d.id} className="flex items-center gap-3 px-4 py-2.5">
                <Dot tone={d.remoteOnline ? "ok" : "neutral"} />
                <span className="min-w-0 flex-1">
                  <Link to={`/devices/${encodeURIComponent(d.id)}`} className="block truncate text-sm font-medium hover:text-accent">
                    {d.name}
                  </Link>
                  <span className="block truncate text-xs text-muted">
                    {REMOTE_KIND_NAMES[kind] ?? kind}, <span title={formatDateTime(at)}>{formatRelative(at)}</span> · {d.organizationName} / {d.siteName}
                  </span>
                </span>
                <span className="sr-only">{d.remoteOnline ? "online" : "offline"}</span>
                <Button
                  size="sm"
                  icon={<ScreenShare className="size-4" aria-hidden />}
                  aria-haspopup="dialog"
                  aria-expanded={connecting}
                  aria-label={`Connect to ${d.name}`}
                  disabled={!ready}
                  title={ready ? undefined : "You can no longer open sessions on this device."}
                  onClick={(e) => {
                    const anchor = e.currentTarget;
                    setConnect(connecting ? null : { device: d, anchor });
                  }}
                >
                  Connect
                </Button>
              </li>
            );
          })}
        </ul>
      )}
      {connect && (
        <QuickConnectPanel
          device={connect.device}
          anchor={connect.anchor}
          onClose={(returnFocus) => {
            const anchor = connect.anchor;
            setConnect(null);
            if (returnFocus) anchor.focus();
          }}
        />
      )}
    </Card>
  );
}

/** Literal classes, so Tailwind sees them: 3 to 5 tiles. */
const TILE_COLUMNS: Record<number, string> = { 3: "md:grid-cols-3", 4: "md:grid-cols-4", 5: "md:grid-cols-3 xl:grid-cols-5" };

const SHOWN_ALERTS = 6;

/** The most pressing active alerts: critical first, then the newest. */
function ActiveAlertsCard({ total }: { total: number }) {
  const list = useList<AlertEntry>("/alerts", { status: "active", limit: 50 }, { refetchInterval: 60_000 });
  const actions = useAlertAction();
  const shown = [...list.items].sort((a, b) => Number(b.severity === "critical") - Number(a.severity === "critical")).slice(0, SHOWN_ALERTS);
  return (
    <Card
      title="Needs attention"
      padded={false}
      actions={
        <Link to="/alerts" className="text-xs text-accent hover:underline">
          {total > shown.length ? `All ${formatNumber(total)} alerts` : "Alerts"}
        </Link>
      }
    >
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} compact />
      ) : (
        <ul className="divide-y divide-line">
          {shown.map((a) => (
            <li key={a.id} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-4 py-2.5 text-sm">
              <SeverityBadge severity={a.severity} />
              <span className="min-w-0 flex-1">
                <span className="font-medium">{a.name}</span>
                <span className="text-muted"> on </span>
                <Link to={`/devices/${a.deviceId}`} className="font-medium break-words hover:text-accent">
                  {a.deviceName}
                </Link>
                <span className="block text-xs text-muted">
                  {a.kind === "disk_health" && a.subjectLabel && <>{a.subjectLabel} · </>}
                  <span className="tabular-nums">{valueText(a)}</span> ·{" "}
                  <span title={formatDateTime(a.openedAt)}>opened {formatRelative(a.openedAt)}</span>
                  {a.status === "acknowledged" && " · acknowledged"}
                </span>
              </span>
              <AlertActions alert={a} actions={actions} />
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function TileLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className="text-xs text-accent hover:underline">
      {children}
    </Link>
  );
}

function RecentActivity({ className }: { className?: string }) {
  const { can } = useAuth();
  const allowed = can("audit.view");
  const audit = useList<AuditEntry>(allowed ? "/audit" : null, { limit: 10 }, { refetchInterval: 60_000 });
  if (!allowed) return null;
  return (
    <Card
      title="Recent activity"
      className={className}
      padded={false}
      actions={
        <Link to="/settings?tab=audit" className="text-xs text-accent hover:underline">
          Open audit log
        </Link>
      }
    >
      {audit.isPending ? (
        <Spinner />
      ) : audit.isError ? (
        <ErrorState error={audit.error} onRetry={() => void audit.refetch()} compact />
      ) : audit.items.length === 0 ? (
        <EmptyState title="No activity yet" compact>
          Sign-ins and changes to organizations, sites and users appear here.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>When</th>
                <th>User</th>
                <th>Action</th>
                <th>Target</th>
                <th className="text-right">Outcome</th>
              </tr>
            </thead>
            <tbody>
              {audit.items.map((e) => (
                <tr key={e.id}>
                  <td className="whitespace-nowrap text-muted" title={formatDateTime(e.occurredAt)}>
                    {formatRelative(e.occurredAt)}
                  </td>
                  <td className="max-w-48 truncate">{e.actorLabel || <span className="text-muted">{e.actorType}</span>}</td>
                  <td className="whitespace-nowrap">{actionLabel(e.action, e.details)}</td>
                  <td className="max-w-56 truncate text-muted">{auditTarget(e)}</td>
                  <td className="text-right">
                    <OutcomeBadge outcome={e.outcome} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Card>
  );
}
