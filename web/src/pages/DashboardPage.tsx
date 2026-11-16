import type { ReactNode } from "react";
import { Link } from "react-router";
import { Bell, Building2, CheckCircle2, Circle, FolderTree, MapPin, Users } from "lucide-react";
import { useApi, useList, useOrganizations, useSites } from "../api/hooks";
import type { AlertEntry, AlertSummary, AuditEntry, AuthOptions, List, User } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { actionLabel, auditTarget, OutcomeBadge } from "../components/StatusBadges";
import { buttonClasses, Card, cx, EmptyState, ErrorState, PageHeader, Spinner, StatTile, TableWrap } from "../components/ui";
import { formatDateTime, formatNumber, formatRelative, plural } from "../lib/format";
import { AlertActions, useAlertAction } from "./alerts/AlertActions";
import { SeverityBadge, valueText } from "./alerts/alertText";

export function DashboardPage() {
  const { can, isSuperAdmin } = useAuth();
  const orgs = useOrganizations();
  const sites = useSites();
  const users = useApi<List<User>>(can("user.view") ? "/users" : null, { limit: 200 });
  const options = useApi<AuthOptions>("/auth/options", undefined, { staleTime: 300_000 });
  const alerts = useApi<AlertSummary>(can("alert.view") ? "/alerts/summary" : null, undefined, { refetchInterval: 60_000 });
  const activeAlerts = alerts.data?.active ?? 0;

  const siteCount = sites.items.length;
  const groupCount = sites.items.reduce((n, s) => n + s.deviceGroupCount, 0);
  const orgsWithSites = new Set(sites.items.map((s) => s.organizationId)).size;
  const sitesWithGroups = sites.items.filter((s) => s.deviceGroupCount > 0).length;
  const userCount = users.data ? `${formatNumber(users.data.items.length)}${users.data.next ? "+" : ""}` : "—";

  const firstManaged = orgs.items.find((o) => o.canManage);
  const steps: Step[] = [];
  if (!orgs.isPending && !sites.isPending) {
    steps.push({
      done: orgs.items.length > 0,
      title: "Create an organization",
      detail: orgs.items.length > 0 ? `${plural(orgs.items.length, "organization")} so far.` : "Each customer you support is an organization.",
      action: can("org.create") && orgs.items.length === 0 ? <Link to="/organizations?new=1" className={buttonClasses("primary", "sm")}>New organization</Link> : null,
    });
    steps.push({
      done: siteCount > 0,
      title: "Add a site",
      detail: siteCount > 0 ? `${plural(siteCount, "site")} across your organizations.` : "Sites are the offices or locations inside an organization; devices belong to a site.",
      action:
        siteCount === 0 && firstManaged ? (
          <Link to={`/organizations/${firstManaged.id}?newSite=1`} className={buttonClasses("primary", "sm")}>
            Add site
          </Link>
        ) : null,
    });
    if (can("user.manage") && users.data) {
      const others = users.data.items.filter((u) => !u.isSelf).length;
      steps.push({
        done: others > 0,
        title: "Invite your team",
        detail: others > 0 ? `${plural(others, "other user")} can sign in.` : "Give technicians their own accounts and roles scoped to the organizations they support.",
        action: others === 0 ? <Link to="/settings?tab=users&invite=1" className={buttonClasses("primary", "sm")}>Invite user</Link> : null,
      });
    }
    if (isSuperAdmin && options.data) {
      steps.push({
        done: options.data.passwordResetAvailable,
        title: "Configure email delivery",
        detail: options.data.passwordResetAvailable
          ? "Invitations and password resets are emailed."
          : "Set the EASYRMM_SMTP_* settings on the server so invitations and password resets are emailed. Until then, EasyRMM gives you links to share yourself.",
        action: null,
      });
    }
  }
  const setupIncomplete = steps.some((s) => !s.done);
  const leftColumn = activeAlerts > 0 || setupIncomplete || can("audit.view");
  const tiles = 3 + (can("alert.view") ? 1 : 0) + (can("user.view") ? 1 : 0);

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

      <div className="mt-5 grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
        {leftColumn && (
          <div className="flex min-w-0 flex-col gap-5 xl:col-span-2">
            {activeAlerts > 0 && <ActiveAlertsCard total={activeAlerts} />}
            {setupIncomplete ? (
              <Card title="Get started" padded={false}>
                <ol className="divide-y divide-line">
                  {steps.map((s) => (
                    <SetupStep key={s.title} step={s} />
                  ))}
                </ol>
              </Card>
            ) : (
              <RecentActivity />
            )}
          </div>
        )}
        <OrganizationsCard className={leftColumn ? undefined : "xl:col-span-3"} />
      </div>

      {setupIncomplete && <RecentActivity className="mt-5" />}
    </>
  );
}

interface Step {
  done: boolean;
  title: string;
  detail: string;
  action: ReactNode;
}

function SetupStep({ step }: { step: Step }) {
  return (
    <li className="flex items-start gap-3 px-4 py-3">
      {step.done ? (
        <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-ok" aria-label="Done" />
      ) : (
        <Circle className="mt-0.5 size-4 shrink-0 text-subtle" aria-label="To do" />
      )}
      <div className="min-w-0 flex-1">
        <p className={cx("text-sm font-medium", step.done ? "text-muted" : "text-fg")}>{step.title}</p>
        <p className="text-xs text-muted">{step.detail}</p>
      </div>
      {step.action && <div className="shrink-0">{step.action}</div>}
    </li>
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

function OrganizationsCard({ className }: { className?: string }) {
  const orgs = useOrganizations();
  const shown = orgs.items.slice(0, 8);
  return (
    <Card
      title="Organizations"
      className={className}
      padded={false}
      actions={
        <Link to="/organizations" className="text-xs text-accent hover:underline">
          View all
        </Link>
      }
    >
      {orgs.isPending ? (
        <Spinner />
      ) : orgs.isError ? (
        <ErrorState error={orgs.error} onRetry={() => void orgs.refetch()} compact />
      ) : shown.length === 0 ? (
        <EmptyState title="No organizations yet" icon={<Building2 className="size-8" aria-hidden />} compact />
      ) : (
        <ul className="divide-y divide-line">
          {shown.map((o) => (
            <li key={o.id}>
              <Link to={`/organizations/${o.id}`} className="flex items-center justify-between gap-3 px-4 py-2.5 text-sm hover:bg-hover">
                <span className="truncate font-medium">{o.name}</span>
                <span className="shrink-0 text-xs text-muted tabular-nums">{plural(o.siteCount, "site")}</span>
              </Link>
            </li>
          ))}
          {orgs.items.length > shown.length && (
            <li className="px-4 py-2 text-xs text-muted">and {plural(orgs.items.length - shown.length, "more organization")}</li>
          )}
        </ul>
      )}
    </Card>
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
                  <td className="whitespace-nowrap">{actionLabel(e.action)}</td>
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
