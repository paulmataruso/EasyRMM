import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { ArrowUpCircle, BellRing, CircleX, Download, ListChecks, Power, Radar, ServerOff, ShieldAlert, ShieldCheck, Trash2, Unlink, WifiOff } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation, useList } from "../../api/hooks";
import type { ComplianceStatus, PatchAlertCounts, PatchFleet, PatchJobView, PatchUnmatchedEndpoint } from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { OrganizationSelect } from "../../components/Filters";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, cx, Dot, EmptyState, ErrorState, Spinner, TableWrap, Toolbar, type Tone } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { COMPLIANCE, ComplianceBadge } from "./patchText";

/**
 * Patching → Overview: how up to date the devices are, what needs attention, worst first, each
 * with the list that shows it, organizations least up to date first, and EasyPatch endpoints no EasyRMM device is
 * linked to. Counted from the patching device list as the caller may see it, so site-level roles see their sites.
 */
export function PatchingOverview() {
  const url = useUrlState();
  const organizationId = url.get("organizationId");
  const fleet = useApi<PatchFleet>("/patching/devices", { organizationId: organizationId || undefined }, { keepPrevious: true, refetchInterval: 60_000 });
  const jobs = useList<PatchJobView>("/patching/jobs", { organizationId: organizationId || undefined, active: "true" }, { refetchInterval: 30_000 });
  const alerts = useApi<PatchAlertCounts>("/patching/alerts/summary", { organizationId: organizationId || undefined }, { refetchInterval: 60_000 });
  const t = useMemo(() => (fleet.data ? tally(fleet.data) : null), [fleet.data]);

  return (
    <>
      <Toolbar>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v })} />
      </Toolbar>
      {fleet.isPending ? (
        <Spinner />
      ) : fleet.isError ? (
        <ErrorState error={fleet.error} onRetry={() => void fleet.refetch()} />
      ) : t && t.devices === 0 && fleet.data.unmatched.length === 0 ? (
        <Card>
          <EmptyState title="No devices to patch yet" icon={<ShieldCheck className="size-8" aria-hidden />}>
            Devices show here once EasyRMM has created their organization in the patching engine, or once their EasyRMM agent reports an
            EasyPatch agent.
          </EmptyState>
        </Card>
      ) : (
        t && (
          <>
            {fleet.data.errors.map((e) => (
              <Alert key={e} tone="danger" className="mb-4" title="The patching engine could not be read">
                {e}
              </Alert>
            ))}
            <div className="mb-5 grid items-start gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
              <Compliance t={t} organizationId={organizationId} />
              <Attention
                t={t}
                unmatched={fleet.data.unmatched.length}
                activeJobs={jobs.items.length}
                alerts={alerts.data}
                organizationId={organizationId}
              />
            </div>
            {t.orgs.length > 1 && <Organizations orgs={t.orgs} />}
            <Unmatched fleet={fleet.data} />
            {fleet.data.truncated && <p className="mt-2 text-xs text-muted">Counted over the first {plural(t.devices, "device")}: choose an organization to count the rest.</p>}
            <p className="mt-2 text-xs text-muted">From the patching engine, refreshed every minute.</p>
          </>
        )
      )}
    </>
  );
}

interface OrgTally {
  id: string;
  name: string;
  devices: number;
  /** Devices EasyPatch reports on. */
  reporting: number;
  upToDate: number;
  failed: number;
  exploited: number;
  missing: number;
}

interface Tally {
  devices: number;
  reporting: number;
  status: Record<ComplianceStatus, number>;
  exploited: number;
  offline: number;
  outdated: number;
  unlinked: number;
  missingUpdates: number;
  orgs: OrgTally[];
}

function tally(fleet: PatchFleet): Tally {
  const status: Record<ComplianceStatus, number> = { Compliant: 0, MissingUpdates: 0, FailedUpdates: 0, RebootRequired: 0, ScanStale: 0, NeverScanned: 0 };
  const t: Tally = { devices: 0, reporting: 0, status, exploited: 0, offline: 0, outdated: 0, unlinked: 0, missingUpdates: 0, orgs: [] };
  const orgs = new Map<string, OrgTally>();
  for (const d of fleet.devices) {
    let o = orgs.get(d.organizationId);
    if (!o) {
      o = { id: d.organizationId, name: d.organizationName, devices: 0, reporting: 0, upToDate: 0, failed: 0, exploited: 0, missing: 0 };
      orgs.set(d.organizationId, o);
    }
    t.devices++;
    o.devices++;
    const e = d.endpoint;
    if (!e) {
      t.unlinked++;
      continue;
    }
    t.reporting++;
    o.reporting++;
    status[e.complianceStatus] = (status[e.complianceStatus] ?? 0) + 1;
    if (e.complianceStatus === "Compliant") o.upToDate++;
    if (e.failedCount > 0) o.failed++;
    if (e.missingRequiredCount > 0) o.missing++;
    if (e.knownExploitedMissingCount > 0) {
      t.exploited++;
      o.exploited++;
    }
    if (!e.isOnline) t.offline++;
    if (e.agentOutdated) t.outdated++;
    t.missingUpdates += e.missingTotalCount;
  }
  // Least up to date first; organizations EasyPatch reports nothing for last.
  t.orgs = [...orgs.values()].sort((a, b) => share(a) - share(b) || b.devices - a.devices || a.name.localeCompare(b.name));
  return t;
}

/** The share of reporting devices that are up to date, from 0 to 1; 2 when none report (sorted last). */
function share(o: Pick<OrgTally, "reporting" | "upToDate">): number {
  return o.reporting === 0 ? 2 : o.upToDate / o.reporting;
}

function percent(o: Pick<OrgTally, "reporting" | "upToDate">): number {
  return Math.floor((o.upToDate / o.reporting) * 100);
}

/** A link to the device list, filtered, keeping the organization chosen here. */
function devicesLink(filter: Record<string, string>, organizationId: string): string {
  const q = new URLSearchParams({ tab: "devices", ...filter });
  if (organizationId) q.set("organizationId", organizationId);
  return `/patching?${q.toString()}`;
}

// The bar's order keeps amber and red apart: side by side they are hard to tell apart even with full color vision.
// Out-of-date and never-run scans share one segment: both mean what is missing is not known.
const SEGMENTS: { statuses: ComplianceStatus[]; tone: Tone; label: string }[] = [
  { statuses: ["Compliant"], tone: "ok", label: COMPLIANCE.Compliant.label },
  { statuses: ["MissingUpdates"], tone: "warn", label: COMPLIANCE.MissingUpdates.label },
  { statuses: ["RebootRequired"], tone: "info", label: COMPLIANCE.RebootRequired.label },
  { statuses: ["FailedUpdates"], tone: "danger", label: COMPLIANCE.FailedUpdates.label },
  { statuses: ["ScanStale", "NeverScanned"], tone: "neutral", label: "Not scanned recently" },
];

const FILL: Record<Tone, string> = {
  ok: "bg-ok",
  warn: "bg-warn",
  info: "bg-info",
  danger: "bg-danger",
  neutral: "bg-subtle",
  accent: "bg-accent",
};

/** The share of devices up to date, and how the others stand, as a bar with its legend. */
function Compliance({ t, organizationId }: { t: Tally; organizationId: string }) {
  const legend: ComplianceStatus[] = ["Compliant", "MissingUpdates", "RebootRequired", "FailedUpdates", "ScanStale", "NeverScanned"];
  const segments = SEGMENTS.map((s) => ({ ...s, count: s.statuses.reduce((n, st) => n + t.status[st], 0) })).filter((s) => s.count > 0);
  return (
    <Card title="Up to date">
      {t.reporting === 0 ? (
        <p className="text-sm text-muted">The patching engine reports on none of these devices yet.</p>
      ) : (
        <>
          <p className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-2xl font-semibold text-fg tabular-nums">{percent({ reporting: t.reporting, upToDate: t.status.Compliant })}%</span>
            <span className="text-sm text-muted">
              of {plural(t.reporting, "device")} the patching engine reports on
              {t.unlinked > 0 && <>, besides {t.unlinked.toLocaleString()} not patched from EasyRMM</>}
            </span>
          </p>
          <div
            role="img"
            aria-label={segments.map((s) => `${s.label}: ${s.count.toLocaleString()}`).join(", ")}
            className="mt-3 flex h-2.5 gap-0.5 overflow-hidden rounded-full"
          >
            {segments.map((s) => (
              <div key={s.label} className={cx("h-full first:rounded-l-full last:rounded-r-full", FILL[s.tone])} style={{ flexGrow: s.count, flexBasis: 0 }} title={`${s.label}: ${s.count.toLocaleString()}`} />
            ))}
          </div>
          <ul className="mt-3 grid grid-cols-1 gap-x-4 gap-y-1.5 text-sm sm:grid-cols-2">
            {legend.map((st) => (
              <li key={st} className="flex items-center gap-2">
                <Dot tone={COMPLIANCE[st].tone} />
                {t.status[st] > 0 ? (
                  <Link to={devicesLink({ compliance: st }, organizationId)} className="min-w-0 truncate rounded-sm hover:text-accent">
                    {COMPLIANCE[st].label}
                  </Link>
                ) : (
                  <span className="min-w-0 truncate text-muted">{COMPLIANCE[st].label}</span>
                )}
                <span className="ml-auto font-medium text-fg tabular-nums">{t.status[st].toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
}

interface AttentionRow {
  key: string;
  tone: Tone;
  icon: ReactNode;
  count: number;
  /** What the count is of, said for one and for several. */
  text: (n: number) => string;
  to?: string;
  action?: string;
  /** The count is where a list stopped: there may be more. */
  more?: boolean;
}

/** The most jobs the job list returns. */
const JOB_LIST_MAX = 200;

const TEXT: Record<Tone, string> = {
  ok: "text-ok",
  warn: "text-warn",
  info: "text-info",
  danger: "text-danger",
  neutral: "text-muted",
  accent: "text-accent",
};

/** What needs attention, worst first; only what has a count. */
function Attention({ t, unmatched, activeJobs, alerts, organizationId }: {
  t: Tally;
  unmatched: number;
  activeJobs: number;
  /** Missing while they load, or when EasyPatch could not count them. */
  alerts?: PatchAlertCounts;
  organizationId: string;
}) {
  const icon = (I: typeof ShieldAlert) => <I className="size-4" aria-hidden />;
  const show = "Show devices";
  const all: AttentionRow[] = [
    {
      key: "alerts",
      tone: alerts && alerts.critical > 0 ? "danger" : "warn",
      icon: icon(BellRing),
      count: alerts?.open ?? 0,
      more: alerts?.capped,
      text: (n) => (n === 1 ? "patching alert is open" : "patching alerts are open"),
      to: `/patching?${new URLSearchParams({ tab: "alerts", ...(organizationId ? { organizationId } : {}) }).toString()}`,
      action: "Show alerts",
    },
    {
      key: "exploited",
      tone: "danger",
      icon: icon(ShieldAlert),
      count: t.exploited,
      text: (n) => (n === 1 ? "device misses updates for vulnerabilities exploited in the wild" : "devices miss updates for vulnerabilities exploited in the wild"),
      to: `/patching?${new URLSearchParams({ tab: "updates", exploited: "true", ...(organizationId ? { organizationId } : {}) }).toString()}`,
      action: "Show the updates",
    },
    {
      key: "failed",
      tone: "danger",
      icon: icon(CircleX),
      count: t.status.FailedUpdates,
      text: (n) => (n === 1 ? "device has updates that failed to install" : "devices have updates that failed to install"),
      to: devicesLink({ compliance: "FailedUpdates" }, organizationId),
      action: show,
    },
    {
      key: "missing",
      tone: "warn",
      icon: icon(Download),
      count: t.status.MissingUpdates,
      text: (n) => (n === 1 ? "device misses required updates" : "devices miss required updates"),
      to: devicesLink({ compliance: "MissingUpdates" }, organizationId),
      action: show,
    },
    {
      key: "restart",
      tone: "info",
      icon: icon(Power),
      count: t.status.RebootRequired,
      text: (n) => (n === 1 ? "device needs a restart to finish installing" : "devices need a restart to finish installing"),
      to: devicesLink({ compliance: "RebootRequired" }, organizationId),
      action: show,
    },
    {
      key: "stale",
      tone: "neutral",
      icon: icon(Radar),
      count: t.status.ScanStale,
      text: (n) => (n === 1 ? "device has not scanned as often as its policy asks" : "devices have not scanned as often as their policy asks"),
      to: devicesLink({ compliance: "ScanStale" }, organizationId),
      action: show,
    },
    {
      key: "never",
      tone: "neutral",
      icon: icon(Radar),
      count: t.status.NeverScanned,
      text: (n) => (n === 1 ? "device has never scanned" : "devices have never scanned"),
      to: devicesLink({ compliance: "NeverScanned" }, organizationId),
      action: show,
    },
    {
      key: "outdated",
      tone: "warn",
      icon: icon(ArrowUpCircle),
      count: t.outdated,
      text: (n) => (n === 1 ? "device runs an out-of-date EasyPatch agent" : "devices run an out-of-date EasyPatch agent"),
    },
    {
      key: "offline",
      tone: "neutral",
      icon: icon(WifiOff),
      count: t.offline,
      text: (n) => (n === 1 ? "device's EasyPatch agent is offline" : "devices' EasyPatch agents are offline"),
    },
    {
      key: "unlinked",
      tone: "neutral",
      icon: icon(Unlink),
      count: t.unlinked,
      text: (n) => (n === 1 ? "device is not patched from EasyRMM" : "devices are not patched from EasyRMM"),
      to: devicesLink({ compliance: "unlinked" }, organizationId),
      action: show,
    },
    {
      key: "unmatched",
      tone: "neutral",
      icon: icon(ServerOff),
      count: unmatched,
      text: (n) => (n === 1 ? "patching engine endpoint has no EasyRMM device" : "patching engine endpoints have no EasyRMM device"),
      to: "#unmatched",
      action: "Show them",
    },
    {
      key: "jobs",
      tone: "info",
      icon: icon(ListChecks),
      count: activeJobs,
      more: activeJobs >= JOB_LIST_MAX,
      text: (n) => (n === 1 ? "patch job is queued or running" : "patch jobs are queued or running"),
      to: "/patching?tab=jobs",
      action: "Show jobs",
    },
  ];
  const rows = all.filter((r) => r.count > 0);

  return (
    <Card title="Needs attention" padded={false}>
      {rows.length === 0 ? (
        <EmptyState title="Nothing needs attention" icon={<ShieldCheck className="size-8" aria-hidden />} compact>
          Every device the patching engine reports on is up to date, scanned and online.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line">
          {rows.map((r) => (
            <li key={r.key} className="flex items-center gap-3 px-4 py-2.5 text-sm">
              <span className={cx("shrink-0", TEXT[r.tone])}>{r.icon}</span>
              <span className="w-12 shrink-0 text-right text-base font-semibold text-fg tabular-nums">
                {r.count.toLocaleString()}
                {r.more && "+"}
              </span>
              <span className="min-w-0 flex-1">{r.text(r.count)}</span>
              {r.to &&
                (r.to.startsWith("#") ? (
                  <a href={r.to} className="shrink-0 rounded-sm text-xs font-medium text-accent hover:underline">
                    {r.action}
                  </a>
                ) : (
                  <Link to={r.to} className="shrink-0 rounded-sm text-xs font-medium text-accent hover:underline">
                    {r.action}
                  </Link>
                ))}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** A compliance share as a bar; its tone follows how far from up to date it is, and the number says it too. */
function ComplianceBar({ o }: { o: OrgTally }) {
  if (o.reporting === 0) return <span className="text-xs text-muted">No reports yet</span>;
  const p = percent(o);
  const tone: Tone = p >= 90 ? "ok" : p >= 70 ? "warn" : "danger";
  return (
    <div className="flex items-center gap-2">
      <div
        role="meter"
        aria-label={`${o.name}: devices up to date`}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={p}
        aria-valuetext={`${p}%, ${o.upToDate} of ${o.reporting}`}
        className="h-2 w-24 shrink-0 overflow-hidden rounded-full bg-neutral-soft sm:w-32"
      >
        <div className={cx("h-full rounded-full", FILL[tone])} style={{ width: `${p}%` }} />
      </div>
      <span className="text-sm font-medium text-fg tabular-nums">{p}%</span>
    </div>
  );
}

function Organizations({ orgs }: { orgs: OrgTally[] }) {
  return (
    <Card title="Organizations, least up to date first" padded={false} className="mb-5">
      <TableWrap className="rounded-none border-0">
        <table className="table-base">
          <thead>
            <tr>
              <th>Organization</th>
              <th>Up to date</th>
              <th className="hidden text-right sm:table-cell">Devices</th>
              <th className="hidden text-right md:table-cell">Missing required</th>
              <th className="hidden text-right md:table-cell">Failed</th>
              <th className="hidden text-right lg:table-cell">Exploited</th>
            </tr>
          </thead>
          <tbody>
            {orgs.map((o) => (
              <tr key={o.id}>
                <td>
                  <Link to={devicesLink({}, o.id)} className="rounded-sm font-medium hover:text-accent">
                    {o.name}
                  </Link>
                </td>
                <td>
                  <ComplianceBar o={o} />
                </td>
                <td className="hidden text-right tabular-nums sm:table-cell">{o.devices.toLocaleString()}</td>
                <td className="hidden text-right tabular-nums md:table-cell">{o.missing.toLocaleString()}</td>
                <td className={cx("hidden text-right tabular-nums md:table-cell", o.failed > 0 && "text-danger")}>{o.failed.toLocaleString()}</td>
                <td className={cx("hidden text-right tabular-nums lg:table-cell", o.exploited > 0 && "text-danger")}>{o.exploited.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Card>
  );
}

/** EasyPatch endpoints with no EasyRMM device, with what to do about them. */
function Unmatched({ fleet }: { fleet: PatchFleet }) {
  if (fleet.unmatched.length === 0) return null;
  const removable = fleet.unmatched.some((e) => e.canRemove || e.removal);
  return (
    <Card id="unmatched" title={`In the patching engine, with no EasyRMM device (${fleet.unmatched.length.toLocaleString()})`} padded={false} className="mb-5 scroll-mt-4">
      <div className="border-b border-line px-4 py-3">
        <p className="max-w-3xl text-sm text-muted">
          The patching engine patches these endpoints, but no EasyRMM device is linked to them, so they show only here. Install EasyRMM's agent on each machine, in
          the same organization: EasyRMM links the device to the EasyPatch agent already there when their host names match, and the device's Patches tab says why
          when it cannot. Remove an endpoint whose computer is gone.{" "}
          <Link to="/devices/add" className="font-medium text-accent hover:underline">
            Add a device
          </Link>
        </p>
      </div>
      <TableWrap className="rounded-none border-0">
        <table className="table-base">
          <thead>
            <tr>
              <th>Endpoint</th>
              <th className="hidden sm:table-cell">Status</th>
              <th className="hidden md:table-cell">Organization / site</th>
              <th className="hidden lg:table-cell">Last check-in</th>
              {removable && (
                <th>
                  <span className="sr-only">Remove</span>
                </th>
              )}
            </tr>
          </thead>
          <tbody>
            {fleet.unmatched.map((e) => (
              <tr key={e.id}>
                <td>
                  <span className="font-medium">{e.hostname}</span>
                  <p className="max-w-64 truncate text-xs text-muted">{e.operatingSystem || e.platform}</p>
                </td>
                <td className="hidden sm:table-cell">
                  <ComplianceBadge status={e.complianceStatus} />
                </td>
                <td className="hidden text-muted md:table-cell">
                  {e.organizationName}
                  {e.siteName && <> / {e.siteName}</>}
                </td>
                <td className="hidden whitespace-nowrap text-muted lg:table-cell">
                  {e.lastCheckInAt ? <span title={formatDateTime(e.lastCheckInAt)}>{formatRelative(e.lastCheckInAt)}</span> : "Never"}
                </td>
                {removable && (
                  <td className="text-right">
                    <RemoveEndpoint endpoint={e} />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Card>
  );
}

/**
 * Removes an endpoint no EasyRMM device is linked to, such as a computer decommissioned before its device was (ADR-0050):
 * its EasyPatch agent uninstalls itself and the patching engine stops patching it.
 */
function RemoveEndpoint({ endpoint: e }: { endpoint: PatchUnmatchedEndpoint }) {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const remove = useApiMutation(() => api.post<PatchUnmatchedEndpoint>(`/patching/endpoints/${e.id}/remove`), {
    invalidate: ["/patching/devices"],
    onSuccess: () => {
      setOpen(false);
      toast.success(`${e.hostname}'s EasyPatch agent uninstalls itself the next time it checks in.`);
    },
  });
  if (e.removal) {
    return (
      <Badge
        tone={e.removal.error ? "danger" : "warn"}
        icon={<Dot tone={e.removal.error ? "danger" : "warn"} />}
        title={
          e.removal.error ||
          `Asked ${formatRelative(e.removal.requestedAt)}. The patching engine stops patching the endpoint once its agent has uninstalled itself, or after 7 days.`
        }
      >
        {e.removal.state === "uninstalling" ? "Uninstalling" : "Removing"}
      </Badge>
    );
  }
  if (!e.canRemove) return null;
  return (
    <>
      <Button size="sm" variant="ghost" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={() => setOpen(true)}>
        Remove
      </Button>
      <ConfirmDialog
        open={open}
        onClose={() => setOpen(false)}
        onConfirm={() => remove.mutate(undefined)}
        title={`Remove ${e.hostname}?`}
        confirmLabel="Remove endpoint"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        <p className="text-left">
          The next time {e.hostname} checks in, its EasyPatch agent uninstalls itself, and the patching engine stops patching it. If it does not check in
          within 7 days, the engine stops patching it anyway. The engine keeps its patch history.
        </p>
      </ConfirmDialog>
    </>
  );
}
