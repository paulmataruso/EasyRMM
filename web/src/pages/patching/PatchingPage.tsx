import { useEffect, useId, useMemo, useState } from "react";
import { Link } from "react-router";
import { Download, ListChecks, PackagePlus, Power, Radar, ShieldCheck } from "lucide-react";
import { useApi, useList } from "../../api/hooks";
import type { DeviceGroup, PatchFleet, PatchFleetDevice, PatchJobView, PatchStatus } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { OrganizationSelect, SearchInput, SiteSelect } from "../../components/Filters";
import { Alert, Button, Card, cx, EmptyState, ErrorState, Field, PageHeader, Segmented, Select, Spinner, TableWrap, Tabs, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { AgentInstallDialog, InstallDialog, PatchJobDialog, RestartDialog, useScan } from "./PatchDialogs";
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
  OpenEasyPatch,
  PatchJobBadge,
  requester,
} from "./patchText";

/**
 * Patching across organizations, through EasyPatch (ADR-0030): which devices miss updates, scans and installs on
 * many devices at once, the jobs that carry them out, and installing the EasyPatch agent where it is missing
 * (ADR-0031).
 */
export function PatchingPage() {
  const url = useUrlState();
  const { can } = useAuth();
  const status = useApi<PatchStatus>("/patching", undefined, {
    staleTime: 30_000,
  });
  const tab = url.get("tab") === "jobs" ? "jobs" : "devices";
  const jobId = url.get("job") || null;

  return (
    <>
      <PageHeader
        title="Patching"
        subtitle="Operating system and application updates on the devices EasyPatch patches, read from EasyPatch as you look."
        actions={status.data?.consoleUrl && <OpenEasyPatch to={{ list: tab === "jobs" ? "jobs" : "endpoints" }} />}
      />
      {status.isPending ? (
        <Spinner />
      ) : status.isError ? (
        <ErrorState error={status.error} onRetry={() => void status.refetch()} />
      ) : !status.data.configured ? (
        <Card>
          <EmptyState
            title="EasyPatch is not set up"
            icon={<ShieldCheck className="size-8" aria-hidden />}
            action={
              can("settings.manage") ? (
                <Link to="/settings?tab=easypatch" className="font-medium text-accent hover:underline">
                  Set up EasyPatch
                </Link>
              ) : undefined
            }
          >
            {can("settings.manage")
              ? "Connect EasyRMM to your EasyPatch server with an API token, then link organizations. Devices with the EasyPatch agent then show here."
              : "A super administrator connects EasyRMM to EasyPatch in Settings. Devices with the EasyPatch agent then show here."}
          </EmptyState>
        </Card>
      ) : (
        <>
          {!status.data.canOperate && (
            <Alert tone="info" className="mb-4" title="Read-only">
              EasyRMM's EasyPatch API token can only read, so scans and installs are off. A super administrator can replace it with an Operator token in
              Settings → EasyPatch.
            </Alert>
          )}
          <Tabs
            active={tab}
            onChange={(t) => url.set({ tab: t === "devices" ? null : t })}
            tabs={[
              { id: "devices", label: "Devices" },
              { id: "jobs", label: "Jobs" },
            ]}
          />
          <div role="tabpanel" aria-labelledby={`tab-${tab}`}>
            {tab === "devices" ? <Fleet status={status.data} /> : <Jobs onJob={(id) => url.set({ job: id })} />}
          </div>
          <PatchJobDialog jobId={jobId} onClose={() => url.set({ job: null })} onJob={(id) => url.set({ job: id })} />
        </>
      )}
    </>
  );
}

function GroupSelect({ siteId, value, onChange }: { siteId: string; value: string; onChange: (v: string) => void }) {
  const id = useId();
  const groups = useList<DeviceGroup>(siteId ? `/sites/${siteId}/device-groups` : null, undefined, { staleTime: 30_000 });
  if (!siteId || groups.items.length === 0) return null;
  return (
    <Field label="Device group" htmlFor={id} className="min-w-40">
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)} className="max-w-56">
        <option value="">Every group</option>
        {groups.items.map((g) => (
          <option key={g.id} value={g.id}>
            {g.name}
          </option>
        ))}
      </Select>
    </Field>
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
  const compliance = url.get("compliance");
  const filtered = Boolean(q || organizationId || siteId || groupId || compliance);
  const params = {
    q: q || undefined,
    organizationId: organizationId || undefined,
    siteId: siteId || undefined,
    groupId: groupId || undefined,
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
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null, groupId: null })} />
        <SiteSelect organizationId={organizationId} value={siteId} onChange={(v) => url.set({ siteId: v, groupId: null })} className="max-w-64" />
        <GroupSelect siteId={siteId} value={groupId} onChange={(v) => url.set({ groupId: v })} />
        <ComplianceSelect value={compliance} onChange={(v) => url.set({ compliance: v })} />
      </Toolbar>
      {fleet.isPending ? (
        <Spinner />
      ) : fleet.isError ? (
        <ErrorState error={fleet.error} onRetry={() => void fleet.refetch()} />
      ) : (
        <>
          {fleet.data.errors.map((e) => (
            <Alert key={e} tone="danger" className="mb-4" title="EasyPatch could not be read">
              {e}
            </Alert>
          ))}
          {fleet.data.devices.length === 0 ? (
            <Card>
              <EmptyState title={filtered ? "No devices match these filters" : "No devices to patch yet"} icon={<ShieldCheck className="size-8" aria-hidden />}>
                {!filtered &&
                  "Devices show here once their organization is linked to an EasyPatch organization, or once their EasyRMM agent reports an EasyPatch agent."}
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
    () => devices.filter((d) => d.canManage && status.canOperate && (d.link === "linked" || d.link === "none")),
    [devices, status.canOperate],
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
  const toRestart = toPatch.filter((d) => d.endpoint?.rebootPending);
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
                  {toRestart.length > 0 && (
                    <Button size="sm" icon={<Power className="size-3.5" aria-hidden />} onClick={() => setRestarting(true)}>
                      {toRestart.length < chosen.length ? `Restart ${toRestart.length.toLocaleString()}…` : "Restart…"}
                    </Button>
                  )}
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
        canSchedule={status.canSchedule}
        onDone={() => setSelected(new Set())}
      />
      <RestartDialog
        open={restarting}
        onClose={() => setRestarting(false)}
        devices={toRestart.map((d) => ({ id: d.deviceId, name: d.name }))}
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
        From EasyPatch, refreshed every minute. Scans and installs start when each device next checks in with EasyPatch; the EasyPatch agent installs at its
        next check-in with EasyRMM.
      </p>
    </>
  );
}

/** Recent EasyPatch jobs of the devices the caller may see; refreshes quickly while any is running. */
function Jobs({ onJob }: { onJob: (id: string) => void }) {
  const url = useUrlState();
  const organizationId = url.get("organizationId");
  const which = url.get("active") === "false" ? "all" : "active";
  const jobs = useList<PatchJobView>(
    "/patching/jobs",
    {
      organizationId: organizationId || undefined,
      active: which === "active" ? "true" : undefined,
    },
    {
      keepPrevious: true,
      refetchInterval: (data) => (data?.items.some(isActiveJob) ? 4_000 : 30_000),
    },
  );
  return (
    <>
      <Toolbar>
        <Segmented
          label="Jobs to show"
          className="self-end"
          value={which}
          onChange={(v) => url.set({ active: v === "all" ? "false" : null })}
          options={[
            { value: "active", label: "Still running" },
            { value: "all", label: "All recent" },
          ]}
        />
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v })} />
      </Toolbar>
      {jobs.isPending ? (
        <Spinner />
      ) : jobs.isError ? (
        <ErrorState error={jobs.error} onRetry={() => void jobs.refetch()} />
      ) : jobs.items.length === 0 ? (
        <Card>
          <EmptyState title={which === "active" ? "No patch jobs running" : "No patch jobs yet"} icon={<ListChecks className="size-8" aria-hidden />} compact>
            Scans and installs started here, from a device, or by EasyPatch's own schedules show here while they run.
          </EmptyState>
        </Card>
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>Job</th>
                <th>Status</th>
                <th className="hidden md:table-cell">Result</th>
                <th className="hidden lg:table-cell">Requested by</th>
                <th className="hidden sm:table-cell">Started</th>
              </tr>
            </thead>
            <tbody>
              {jobs.items.map((j) => (
                <tr key={j.id} className="cursor-pointer" onClick={() => onJob(j.id)}>
                  <td>
                    <button type="button" className="rounded-sm text-left font-medium hover:text-accent" onClick={(e) => (e.stopPropagation(), onJob(j.id))}>
                      {jobTypeLabel(j.type)}
                    </button>
                    <p className="text-xs text-muted">{j.deviceName}</p>
                  </td>
                  <td>
                    <PatchJobBadge job={j} />
                    {j.progressMessage && isActiveJob(j) && <p className="mt-1 max-w-xs truncate text-xs text-muted">{j.progressMessage}</p>}
                  </td>
                  <td className="hidden text-muted md:table-cell">
                    {j.errorMessage ? <span className="text-danger">{j.errorMessage}</span> : jobOutcome(j) || "—"}
                  </td>
                  <td className="hidden max-w-56 truncate text-muted lg:table-cell">{requester(j.requestedBy)}</td>
                  <td className="hidden whitespace-nowrap text-muted sm:table-cell" title={formatDateTime(j.createdAt)}>
                    {formatRelative(j.createdAt)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </>
  );
}
