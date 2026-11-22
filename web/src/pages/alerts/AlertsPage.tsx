import { useId, useMemo, useState } from "react";
import { Link } from "react-router";
import { BellRing, CheckCircle2, OctagonAlert, Plus } from "lucide-react";
import { useDeviceAlertCounts, useList } from "../../api/hooks";
import type { AlertEntry, AlertPolicy } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { DeviceScope, OrganizationSelect, SiteSelect } from "../../components/Filters";
import { Badge, Button, cx, EmptyState, ErrorState, Field, PageHeader, Select, Spinner, TableWrap, Tabs, Toolbar } from "../../components/ui";
import { formatDateTime, formatNumber, formatRelative, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { AlertActions, useAlertAction } from "./AlertActions";
import { AlertLink } from "./alertLink";
import { AlertFlashToggle, conditionText, DiskSubject, policyScope, resolutionText, risingHint, SeverityBadge, valueText } from "./alertText";
import { PolicyDialog, useCanWritePolicies } from "./PolicyDialog";

export function AlertsPage() {
  const url = useUrlState();
  const { can } = useAuth();
  const canWrite = useCanWritePolicies();
  const showPolicies = can("monitoring.view");
  const tab = url.get("tab") === "policies" && showPolicies ? "policies" : "alerts";
  const [editing, setEditing] = useState<AlertPolicy | "new" | null>(null);

  return (
    <>
      <PageHeader
        title="Alerts"
        subtitle={
          tab === "alerts"
            ? "What needs attention on the devices you support. Policies are checked every minute."
            : "Policies decide what raises an alert. Shared policies cover every device; organization and site policies cover only theirs."
        }
        actions={
          tab === "policies" ? (
            canWrite ? (
              <Button variant="primary" onClick={() => setEditing("new")}>
                <Plus className="size-4" aria-hidden />
                New policy
              </Button>
            ) : undefined
          ) : (
            <AlertFlashToggle />
          )
        }
      />
      <Tabs
        tabs={[
          { id: "alerts", label: "Alerts" },
          { id: "policies", label: "Policies", hidden: !showPolicies },
        ]}
        active={tab}
        onChange={(id) => url.set({ tab: id === "alerts" ? null : id, before: null })}
      />
      <div role="tabpanel" aria-labelledby={`tab-${tab}`}>
        {tab === "alerts" ? <AlertList /> : <PolicyList onEdit={setEditing} />}
      </div>
      <PolicyDialog open={editing !== null} onClose={() => setEditing(null)} policy={editing === "new" || editing === null ? undefined : editing} />
    </>
  );
}

type Show = "active" | "resolved" | "all";

function AlertList() {
  const url = useUrlState();
  const { can } = useAuth();
  const severityId = useId();
  const showId = useId();
  const show: Show = url.get("status") === "resolved" ? "resolved" : url.get("status") === "all" ? "all" : "active";
  const organizationId = url.get("organizationId");
  const siteId = url.get("siteId");
  const severity = url.get("severity");
  const deviceId = url.get("deviceId");
  const before = url.get("before");
  const list = useList<AlertEntry>(
    "/alerts",
    {
      status: show,
      organizationId: organizationId || undefined,
      siteId: siteId || undefined,
      severity: severity || undefined,
      deviceId: deviceId || undefined,
      before: before || undefined,
      limit: 100,
    },
    { keepPrevious: true, refetchInterval: 30_000 },
  );
  const actions = useAlertAction();
  // Whether each device has an active critical alert, whatever this page shows: one request for every row, shared
  // with the menu's alerts tree.
  const counts = useDeviceAlertCounts(true);
  const critical = useMemo(() => new Set(counts.items.filter((c) => c.critical > 0).map((c) => c.deviceId)), [counts.items]);
  const filtered = Boolean(organizationId || siteId || severity || deviceId);
  const anyActions = list.items.some((a) => a.canManage && a.status !== "resolved");

  return (
    <>
      <Toolbar>
        <Field label="Show" htmlFor={showId} className="min-w-36">
          <Select id={showId} value={show} onChange={(e) => url.set({ status: e.target.value === "active" ? null : e.target.value, before: null })}>
            <option value="active">Active alerts</option>
            <option value="resolved">Resolved alerts</option>
            <option value="all">All alerts</option>
          </Select>
        </Field>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null, deviceId: null, before: null })} />
        <SiteSelect organizationId={organizationId} value={siteId} onChange={(v) => url.set({ siteId: v, deviceId: null, before: null })} />
        <Field label="Severity" htmlFor={severityId} className="min-w-36">
          <Select id={severityId} value={severity} onChange={(e) => url.set({ severity: e.target.value, before: null })}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="warning">Warning</option>
          </Select>
        </Field>
        {deviceId && <DeviceScope deviceId={deviceId} clearLabel="Show alerts on every device" onClear={() => url.set({ deviceId: null, before: null })} />}
      </Toolbar>

      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.items.length === 0 ? (
        filtered ? (
          <EmptyState
            title="No alerts match these filters"
            action={<Button onClick={() => url.set({ organizationId: null, siteId: null, severity: null, deviceId: null, before: null })}>Clear filters</Button>}
          />
        ) : show === "active" ? (
          <EmptyState
            title="No active alerts"
            icon={<CheckCircle2 className="size-8 text-ok" aria-hidden />}
            action={can("monitoring.view") ? <Button onClick={() => url.set({ tab: "policies" })}>Review policies</Button> : undefined}
          >
            Every device you support is within its alert policies.
          </EmptyState>
        ) : (
          <EmptyState title="No resolved alerts" icon={<BellRing className="size-8" aria-hidden />}>
            Alerts that clear on their own or are resolved by hand are listed here.
          </EmptyState>
        )
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <th className="hidden w-px sm:table-cell">Severity</th>
                  <th>Alert</th>
                  <th>Device</th>
                  <th className="hidden md:table-cell">Latest</th>
                  <th className="hidden lg:table-cell">Opened</th>
                  <th className="hidden sm:table-cell">Status</th>
                  {anyActions && (
                    <th className="hidden sm:table-cell">
                      <span className="sr-only">Actions</span>
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {list.items.map((a) => (
                  <tr key={a.id}>
                    <td className="hidden sm:table-cell">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="min-w-40">
                      <div className="mb-1 sm:hidden">
                        <SeverityBadge severity={a.severity} />
                      </div>
                      <AlertLink id={a.id} label={`${a.name} on ${a.deviceName}, details`} title="Show the alert's details" className="font-medium break-words hover:text-accent">
                        {a.name}
                      </AlertLink>
                      <DiskSubject alert={a} />
                      <p className="text-xs text-muted">{conditionText(a)}</p>
                      {a.canManage && risingHint(a) && <p className="mt-0.5 max-w-md text-xs text-muted">{risingHint(a)}</p>}
                      <p className="mt-0.5 text-xs text-muted sm:hidden">
                        <StatusText alert={a} />
                      </p>
                      <AlertActions alert={a} actions={actions} align="start" className="mt-2 sm:hidden" />
                    </td>
                    <td className="min-w-32">
                      <DeviceName alert={a} critical={critical.has(a.deviceId)} />
                      <p className="text-xs break-words text-muted">
                        {a.organizationName} / {a.siteName}
                      </p>
                    </td>
                    <td className="hidden whitespace-nowrap tabular-nums md:table-cell">{valueText(a)}</td>
                    <td className="hidden whitespace-nowrap text-muted lg:table-cell" title={formatDateTime(a.openedAt)}>
                      {formatRelative(a.openedAt)}
                    </td>
                    <td className="hidden text-sm sm:table-cell">
                      <StatusText alert={a} />
                    </td>
                    {anyActions && (
                      <td className="hidden w-px sm:table-cell">
                        <AlertActions alert={a} actions={actions} nowrap />
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
            <span>
              {plural(list.items.length, "alert")}
              {before ? ", older page" : ", newest first"}
            </span>
            <span className="flex gap-1">
              {before && (
                <Button size="sm" variant="ghost" onClick={() => url.set({ before: null })}>
                  Newest
                </Button>
              )}
              {list.next && (
                <Button size="sm" variant="ghost" onClick={() => url.set({ before: list.next })}>
                  Older alerts
                </Button>
              )}
            </span>
          </div>
        </>
      )}
    </>
  );
}

/** The device's name, linked; it pulses in red, with the critical icon, while the device has an active critical alert. */
function DeviceName({ alert: a, critical }: { alert: AlertEntry; critical: boolean }) {
  return (
    <Link
      to={`/devices/${a.deviceId}`}
      title={critical ? `${a.deviceName} has an active critical alert` : undefined}
      aria-label={critical ? `${a.deviceName}, active critical alert` : undefined}
      className={cx("font-medium break-words", critical ? "alert-active-pulse rounded-sm hover:underline" : "hover:text-accent")}
    >
      {critical && <OctagonAlert className="mr-1 inline size-3.5 align-[-2px]" aria-hidden />}
      {a.deviceName}
    </Link>
  );
}

/** Open, acknowledged by whom, or how it resolved and when. */
function StatusText({ alert: a }: { alert: AlertEntry }) {
  if (a.status === "open") return <span className="font-medium text-fg">Open</span>;
  if (a.status === "acknowledged") {
    return (
      <span title={a.acknowledgedAt ? formatDateTime(a.acknowledgedAt) : undefined}>
        Acknowledged{a.acknowledgedBy ? <span className="text-muted"> by {a.acknowledgedBy}</span> : null}
      </span>
    );
  }
  return (
    <span className="text-muted" title={a.resolvedAt ? formatDateTime(a.resolvedAt) : undefined}>
      {resolutionText(a)}, {formatRelative(a.resolvedAt)}
    </span>
  );
}

function PolicyList({ onEdit }: { onEdit: (p: AlertPolicy | "new") => void }) {
  const url = useUrlState();
  const canWrite = useCanWritePolicies();
  const organizationId = url.get("organizationId");
  const list = useList<AlertPolicy>("/alert-policies", { organizationId: organizationId || undefined }, { keepPrevious: true });
  const anyEditable = list.items.some((p) => p.canEdit);

  return (
    <>
      <Toolbar>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v })} allLabel="Every policy" />
      </Toolbar>
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.items.length === 0 ? (
        <EmptyState
          title="No alert policies"
          icon={<BellRing className="size-8" aria-hidden />}
          action={
            canWrite ? (
              <Button variant="primary" onClick={() => onEdit("new")}>
                <Plus className="size-4" aria-hidden />
                New policy
              </Button>
            ) : undefined
          }
        >
          {canWrite
            ? "Add a policy to be alerted when devices go offline or run short of processor, memory or disk."
            : "Without policies, nothing raises an alert. An administrator adds them."}
        </EmptyState>
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <th>Policy</th>
                  <th className="hidden md:table-cell">Condition</th>
                  <th className="hidden lg:table-cell">Applies to</th>
                  <th className="hidden sm:table-cell">Severity</th>
                  <th className="hidden text-right sm:table-cell">Active alerts</th>
                  <th>State</th>
                  {anyEditable && (
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {list.items.map((p) => (
                  <tr key={p.id}>
                    <td className="min-w-44">
                      <p className="font-medium">{p.name}</p>
                      <div className="my-1 sm:hidden">
                        <SeverityBadge severity={p.severity} />
                      </div>
                      <p className="text-xs text-muted md:hidden">{conditionText(p)}</p>
                      <p className="text-xs text-muted lg:hidden">{policyScope(p)}</p>
                      {p.description && <p className="max-w-md text-xs text-muted">{p.description}</p>}
                    </td>
                    <td className="hidden md:table-cell">{conditionText(p)}</td>
                    <td className="hidden max-w-60 break-words lg:table-cell">
                      {p.level === "shared" ? <span className="text-muted">Every device</span> : policyScope(p)}
                    </td>
                    <td className="hidden sm:table-cell">
                      <SeverityBadge severity={p.severity} />
                    </td>
                    <td className="hidden text-right tabular-nums sm:table-cell">
                      {p.activeAlerts > 0 ? formatNumber(p.activeAlerts) : <span className="text-subtle">0</span>}
                    </td>
                    <td>{p.enabled ? <Badge tone="ok">On</Badge> : <Badge>Off</Badge>}</td>
                    {anyEditable && (
                      <td className="w-px text-right">
                        {p.canEdit && (
                          <Button size="sm" variant="ghost" onClick={() => onEdit(p)} aria-label={`Edit ${p.name}`}>
                            Edit
                          </Button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <p className="mt-2 text-xs text-muted">
            {plural(list.items.length, "policy", "policies")}, {plural(list.items.filter((p) => p.enabled).length, "turned on", "turned on")}.
          </p>
        </>
      )}
    </>
  );
}
