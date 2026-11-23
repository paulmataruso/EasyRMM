import { useEffect, useId, useMemo, useState } from "react";
import { Link, useLocation } from "react-router";
import { Download, ListChecks, PackagePlus, Power, Radar, ShieldCheck } from "lucide-react";
import { useApi, useList } from "../../api/hooks";
import type { PatchFleet, PatchFleetDevice, PatchJobView, PatchStatus } from "../../api/types";
import { DeviceScope, GroupSelect, SearchInput } from "../../components/Filters";
import { Alert, Button, Card, cx, EmptyState, ErrorState, Field, PageHeader, Segmented, Select, Spinner, TableWrap, Tabs, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { AgentInstallDialog, InstallDialog, RestartDialog, useScan } from "./PatchDialogs";
import { PatchJobDialog } from "./PatchJobDialog";
import {
  activityText,
  COMPLIANCE,
  COMPLIANCE_ORDER,
  ComplianceBadge,
  InstallLine,
  isActiveJob,
  jobOutcome,
  jobTypeLabel,
  LinkBadge,
  NoPatchingEngine,
  PatchJobBadge,
  requester,
} from "./patchText";
import { PatchingOverview } from "./PatchingOverview";
import { ALERT_FILTERS, PatchAlerts } from "./PatchAlerts";
import { JOB_FILTERS, PatchJobs } from "./PatchJobs";
import { PatchUpdates } from "./PatchUpdates";

/**
 * Patching across organizations, through the patching engine (ADR-0038): what needs attention, which devices miss updates, every
 * update across them, scans and installs on many devices at once, the jobs that carry them out, and installing the
 * EasyPatch agent where it is missing (ADR-0031).
 */
const TABS = [
  { id: "overview", label: "Overview" },
  { id: "devices", label: "Devices" },
  { id: "updates", label: "Updates" },
  { id: "jobs", label: "Jobs" },
  { id: "alerts", label: "Alerts" },
] as const;

type PatchingTab = (typeof TABS)[number]["id"];

const CLEARED = {
  q: null,
  compliance: null,
  category: null,
  state: null,
  exploited: null,
  sort: null,
  page: null,
  active: null,
  ...JOB_FILTERS,
  ...ALERT_FILTERS,
};

export function PatchingPage() {
  const url = useUrlState();
  const status = useApi<PatchStatus>("/patching", undefined, {
    staleTime: 30_000,
  });
  const tab = TABS.find((t) => t.id === url.get("tab"))?.id ?? "overview";
  const jobId = url.get("job") || null;
  // Why a link from EasyPatch opened here instead of the page it named (FromEasyPatchPage).
  const notice = (useLocation().state as { notice?: string } | null)?.notice;

  return (
    <>
      <PageHeader
        title="Patching"
        subtitle="Operating system and application updates on the devices EasyRMM patches, read from the patching engine as you look."
      />
      {notice && (
        <Alert tone="info" className="mb-4" title="Opened from a patching engine link">
          {notice}
        </Alert>
      )}
      {status.isPending ? (
        <Spinner />
      ) : status.isError ? (
        <ErrorState error={status.error} onRetry={() => void status.refetch()} />
      ) : !status.data.configured ? (
        <Card>
          <NoPatchingEngine />
        </Card>
      ) : (
        <>
          <Tabs
            active={tab}
            // Each tab has its own filters; the organization and site chosen in the sidebar carry over.
            onChange={(t) => url.set({ tab: t === "overview" ? null : t, ...CLEARED })}
            tabs={[...TABS]}
          />
          {tab !== "devices" && (url.get("groupId") || url.get("deviceId")) && (
            <p className="mb-3 text-sm text-muted">
              The patching engine counts updates, jobs and alerts for a whole site, so this tab shows the site of the {url.get("deviceId") ? "device" : "group"} you chose.
              The Devices tab narrows to it.
            </p>
          )}
          <div role="tabpanel" aria-labelledby={`tab-${tab}`}>
            {tab === "overview" ? (
              <PatchingOverview />
            ) : tab === "devices" ? (
              <Fleet status={status.data} />
            ) : tab === "updates" ? (
              <PatchUpdates />
            ) : tab === "jobs" ? (
              <PatchJobs onJob={(id) => url.set({ job: id })} />
            ) : (
              <PatchAlerts />
            )}
          </div>
          <PatchJobDialog jobId={jobId} onClose={() => url.set({ job: null })} onJob={(id) => url.set({ job: id })} />
        </>
      )}
    </>
  );
}

function ComplianceSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const id = useId();
  return (
    <Field label="Status" htmlFor={id} className="min-w-44">
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Every status</option>
        {COMPLIANCE_ORDER.map((c) => (
          <option key={c} value={c}>
            {COMPLIANCE[c].label}
          </option>
        ))}
        <option value="unlinked">Not patched from EasyRMM</option>
      </Select>
    </Field>
  );
}

/** The devices of linked organizations and every device with an EasyPatch agent. */
function Fleet({ status }: { status: PatchStatus }) {
  const url = useUrlState();
  const q = url.get("q");
  const organizationId = url.get("organizationId");
  const siteId = url.get("siteId");
  const groupId = url.get("groupId");
  const deviceId = url.get("deviceId");
  const compliance = url.get("compliance");
  const filtered = Boolean(q || organizationId || siteId || groupId || deviceId || compliance);
  const params = {
    q: q || undefined,
    organizationId: organizationId || undefined,
    siteId: siteId || undefined,
    groupId: groupId || undefined,
    deviceId: deviceId || undefined,
    compliance: compliance || undefined,
  };
  const fleet = useApi<PatchFleet>("/patching/devices", params, {
    keepPrevious: true,
    refetchInterval: 60_000,
  });

  return (
    <>
      <Toolbar>
        <SearchInput value={q} onChange={(v) => url.set({ q: v })} placeholder="Name or hostname" className="max-w-xs" />
        <GroupSelect siteId={siteId} value={groupId} onChange={(v) => url.set({ groupId: v, deviceId: null })} />
        {deviceId && <DeviceScope deviceId={deviceId} clearLabel="Show every device" onClear={() => url.set({ deviceId: null })} />}
        <ComplianceSelect value={compliance} onChange={(v) => url.set({ compliance: v })} />
      </Toolbar>
      {fleet.isPending ? (
        <Spinner />
      ) : fleet.isError ? (
        <ErrorState error={fleet.error} onRetry={() => void fleet.refetch()} />
      ) : (
        <>
          {fleet.data.errors.map((e) => (
            <Alert key={e} tone="danger" className="mb-4" title="The patching engine could not be read">
              {e}
            </Alert>
          ))}
          {fleet.data.devices.length === 0 ? (
            <Card>
              <EmptyState title={filtered ? "No devices match these filters" : "No devices to patch yet"} icon={<ShieldCheck className="size-8" aria-hidden />}>
                {!filtered &&
                  "Devices show here once EasyRMM has created their organization in the patching engine, or once their EasyRMM agent reports an EasyPatch agent."}
              </EmptyState>
            </Card>
          ) : (
            <FleetTable devices={fleet.data.devices} status={status} />
          )}
          {fleet.data.truncated && (
            <p className="mt-2 text-xs text-muted">Showing the first {plural(fleet.data.devices.length, "device")}. Filter to see the rest.</p>
          )}
        </>
      )}
    </>
  );
}

function FleetTable({ devices, status }: { devices: PatchFleetDevice[]; status: PatchStatus }) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [installing, setInstalling] = useState(false);
  const [agentInstalling, setAgentInstalling] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const { scan, dialog } = useScan();
  // Linked devices can be scanned and patched; devices without an EasyPatch agent can be given one.
  const selectable = useMemo(
    () => devices.filter((d) => d.canManage && (d.link === "linked" || d.link === "none")),
    [devices],
  );

  // Devices that leave the list, or can no longer be acted on, leave the selection.
  useEffect(() => {
    setSelected((prev) => {
      const ids = new Set(selectable.map((d) => d.deviceId));
      const next = new Set([...prev].filter((id) => ids.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [selectable]);

  const chosen = selectable.filter((d) => selected.has(d.deviceId));
  const toPatch = chosen.filter((d) => d.link === "linked");
  const agentless = chosen.filter((d) => d.link === "none");
  // With both kinds chosen, each action says how many devices it acts on.
  const mixed = toPatch.length > 0 && agentless.length > 0;
  const all = selectable.length > 0 && chosen.length === selectable.length;
  const toggle = (id: string, on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  const counts = useMemo(() => {
    const c = { patched: 0, behind: 0, unlinked: 0 };
    for (const d of devices) {
      if (!d.endpoint) c.unlinked++;
      else if (d.endpoint.complianceStatus === "Compliant") c.patched++;
      else c.behind++;
    }
    return c;
  }, [devices]);
  const showSelect = selectable.length > 0;

  return (
    <>
      <Card
        padded={false}
        title={
          chosen.length > 0 ? (
            `${chosen.length.toLocaleString()} selected`
          ) : (
            <span>
              {plural(devices.length, "device")}
              <span className="ml-2 text-xs font-normal text-muted">
                {counts.patched.toLocaleString()} up to date · {counts.behind.toLocaleString()} need attention
                {counts.unlinked > 0 && <> · {counts.unlinked.toLocaleString()} not patched from EasyRMM</>}
              </span>
            </span>
          )
        }
        actions={
          chosen.length > 0 && (
            <div className="flex flex-wrap items-center justify-end gap-2">
              {toPatch.length > 0 && (
                <>
                  <Button
                    size="sm"
                    icon={<Radar className="size-3.5" aria-hidden />}
                    loading={scan.isPending}
                    onClick={() =>
                      scan.mutate(
                        toPatch.map((d) => d.deviceId),
                        { onSuccess: () => setSelected(new Set()) },
                      )
                    }
                  >
                    {mixed ? `Scan ${toPatch.length.toLocaleString()}` : "Scan"}
                  </Button>
                  <Button size="sm" icon={<Power className="size-3.5" aria-hidden />} onClick={() => setRestarting(true)}>
                    {mixed ? `Restart ${toPatch.length.toLocaleString()}…` : "Restart…"}
                  </Button>
                  <Button size="sm" variant="primary" icon={<Download className="size-3.5" aria-hidden />} onClick={() => setInstalling(true)}>
                    {mixed ? `Install updates on ${toPatch.length.toLocaleString()}…` : "Install updates…"}
                  </Button>
                </>
              )}
              {agentless.length > 0 && (
                <Button
                  size="sm"
                  variant={toPatch.length > 0 ? "secondary" : "primary"}
                  icon={<PackagePlus className="size-3.5" aria-hidden />}
                  onClick={() => setAgentInstalling(true)}
                >
                  {mixed ? `Install EasyPatch agent on ${agentless.length.toLocaleString()}…` : "Install EasyPatch agent…"}
                </Button>
              )}
            </div>
          )
        }
      >
        {scan.error && <p className="border-b border-line px-4 py-2 text-sm text-danger">{scan.error.message}</p>}
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                {showSelect && (
                  <th className="w-10">
                    <input
                      type="checkbox"
                      aria-label="Select every device you can act on"
                      checked={all}
                      ref={(el) => {
                        if (el) el.indeterminate = chosen.length > 0 && !all;
                      }}
                      onChange={(e) => setSelected(e.target.checked ? new Set(selectable.map((d) => d.deviceId)) : new Set())}
                    />
                  </th>
                )}
                <th>Device</th>
                <th className="hidden sm:table-cell">Status</th>
                <th className="hidden md:table-cell">Missing</th>
                <th className="hidden lg:table-cell">Last scan</th>
                <th className="hidden xl:table-cell">EasyPatch agent</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => {
                const e = d.endpoint;
                const can = selectable.includes(d);
                return (
                  <tr key={d.deviceId} className={cx(selected.has(d.deviceId) && "bg-accent-soft/40")}>
                    {showSelect && (
                      <td className="align-top">
                        {can && (
                          <input
                            type="checkbox"
                            aria-label={`Select ${d.name}`}
                            checked={selected.has(d.deviceId)}
                            onChange={(ev) => toggle(d.deviceId, ev.target.checked)}
                          />
                        )}
                      </td>
                    )}
                    <td className="align-top">
                      <Link to={`/devices/${d.deviceId}?tab=patches`} className="rounded-sm font-medium hover:text-accent">
                        {d.name}
                      </Link>
                      <p className="max-w-52 truncate text-xs text-muted sm:max-w-64">
                        {d.organizationName} / {d.siteName}
                      </p>
                      <div className="mt-1.5 sm:hidden">
                        {e ? <ComplianceBadge status={e.complianceStatus} /> : <LinkBadge link={d.link} reason={d.reason} />}
                        <InstallLine install={d.install} link={d.link} />
                      </div>
                    </td>
                    <td className="hidden align-top sm:table-cell">
                      {e ? <ComplianceBadge status={e.complianceStatus} /> : <LinkBadge link={d.link} reason={d.reason} />}
                      {!e && d.reason && <p className="mt-1 max-w-sm text-xs text-muted">{d.reason}</p>}
                      <InstallLine install={d.install} link={d.link} />
                      {activityText(e?.currentActivity) && <p className="mt-1 text-xs text-muted">{activityText(e?.currentActivity)}</p>}
                    </td>
                    <td className="hidden align-top md:table-cell">
                      {e?.lastScanAt ? (
                        <span className="tabular-nums">
                          {e.missingTotalCount.toLocaleString()}
                          {e.missingRequiredCount > 0 && <span className="text-xs text-muted"> ({e.missingRequiredCount.toLocaleString()} required)</span>}
                          {e.failedCount > 0 && <span className="block text-xs text-danger">{plural(e.failedCount, "failed")}</span>}
                          {e.knownExploitedMissingCount > 0 && (
                            <span className="block text-xs text-danger">{e.knownExploitedMissingCount.toLocaleString()} exploited in the wild</span>
                          )}
                        </span>
                      ) : (
                        <span className="text-subtle">—</span>
                      )}
                    </td>
                    <td className="hidden align-top whitespace-nowrap text-muted lg:table-cell">
                      {e?.lastScanAt ? <span title={formatDateTime(e.lastScanAt)}>{formatRelative(e.lastScanAt)}</span> : e ? "Never" : "—"}
                      {e?.rebootPending && <span className="block text-xs text-info">Restart pending</span>}
                    </td>
                    <td className="hidden align-top text-muted xl:table-cell">
                      {e ? (
                        <>
                          {e.isOnline ? (
                            "Online"
                          ) : e.lastCheckInAt ? (
                            <span title={formatDateTime(e.lastCheckInAt)}>Seen {formatRelative(e.lastCheckInAt)}</span>
                          ) : (
                            "Never seen"
                          )}
                          <span className="block text-xs">
                            {e.agentVersion}
                            {e.agentOutdated && <span className="text-warn"> · out of date</span>}
                          </span>
                        </>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      </Card>
      <InstallDialog
        open={installing}
        onClose={() => setInstalling(false)}
        devices={toPatch.map((d) => ({ id: d.deviceId, name: d.name }))}
        onDone={() => setSelected(new Set())}
      />
      <RestartDialog
        open={restarting}
        onClose={() => setRestarting(false)}
        devices={toPatch.map((d) => ({ id: d.deviceId, name: d.name }))}
        pendingOnly={toPatch.some((d) => d.endpoint?.rebootPending)}
        onDone={() => setSelected(new Set())}
      />
      <AgentInstallDialog
        open={agentInstalling}
        onClose={() => setAgentInstalling(false)}
        devices={agentless.map((d) => ({ id: d.deviceId, name: d.name }))}
        onDone={() => setSelected(new Set())}
      />
      {dialog}
      <p className="mt-2 text-xs text-muted">
        From the patching engine, refreshed every minute. Scans and installs start when each device next checks in with the patching engine; the EasyPatch
        agent installs at its next check-in with EasyRMM.
      </p>
    </>
  );
}
