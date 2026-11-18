import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Download, PackagePlus, Power, Radar } from "lucide-react";
import { useApi, useList } from "../../api/hooks";
import type { Device, DevicePatching, PatchHistoryEntry, PatchJob, PatchPage, PatchUpdate } from "../../api/types";
import { Alert, Badge, Button, Card, cx, EmptyState, ErrorState, KeyValueList, Segmented, Spinner, TableWrap } from "../../components/ui";
import { formatDate, formatDateTime, formatRelative, formatSize, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import { AgentInstallDialog, InstallDialog, PatchJobDialog, RestartDialog, useScan } from "../patching/PatchDialogs";
import {
  categoryLabel,
  ComplianceBadge,
  EasyPatchLink,
  easyPatchHref,
  PATCH_VIEW_TAB,
  INSTALLABLE,
  installText,
  isActiveJob,
  jobOutcome,
  jobTypeLabel,
  LinkBadge,
  maintenanceText,
  PatchJobBadge,
  requester,
  UpdateStateBadge,
} from "../patching/patchText";

type View = "available" | "installed" | "history" | "jobs";

/** A device's updates through EasyPatch (ADR-0030): what is missing and installed, history, jobs, and the actions. */
export function PatchesPanel({ device }: { device: Device }) {
  const p = useApi<DevicePatching>(`/patching/devices/${device.id}`, undefined, { refetchInterval: 30_000 });
  if (p.isPending) return <Spinner />;
  if (p.isError) return <ErrorState error={p.error} onRetry={() => void p.refetch()} />;
  const d = p.data;
  if (d.link !== "linked") return <NotLinked patching={d} device={device} />;
  return <Linked patching={d} device={device} />;
}

function NotLinked({ patching: d, device }: { patching: DevicePatching; device: Device }) {
  const [installing, setInstalling] = useState(false);
  const title = d.link === "pending" ? "Checking this device's EasyPatch agent" : d.link === "none" ? "No EasyPatch agent" : "Not patched from EasyRMM";
  // EasyRMM's agent can install the EasyPatch agent on Windows and Linux (ADR-0031).
  const canInstall = d.link === "none" && d.canManage && device.agent !== null && (device.platform === "windows" || device.platform === "linux");
  const running = d.install?.state === "waiting" || d.install?.state === "sent";
  const install = d.install && d.link !== "linked" ? installText(d.install) : null;
  return (
    <Card>
      <EmptyState
        title={title}
        icon={<LinkBadge link={d.link} />}
        action={
          canInstall &&
          !running && (
            <Button variant="primary" icon={<PackagePlus className="size-4" aria-hidden />} onClick={() => setInstalling(true)}>
              {d.install?.state === "failed" ? "Try the install again…" : "Install EasyPatch agent…"}
            </Button>
          )
        }
      >
        {d.link === "none" &&
          (!device.agent
            ? "EasyRMM finds the EasyPatch agent through its own agent, which this device does not have."
            : canInstall
              ? "The EasyRMM agent has not reported an EasyPatch agent on this device. EasyRMM can install it and enroll it with your EasyPatch server."
              : "The EasyRMM agent has not reported an EasyPatch agent on this device. Install the EasyPatch agent and enroll it with your EasyPatch server; the EasyRMM agent reports it with its next inventory, within an hour.")}
        {d.link === "pending" && "EasyRMM is making sure the EasyPatch endpoint the device reports is this device. This takes up to a minute."}
        {d.link === "unlinked" && (
          <>
            {d.reason}
            <span className="mt-2 block">EasyRMM checks again every 15 minutes, and as soon as the device reports something new.</span>
          </>
        )}
        {install && d.install && (
          <div className="mt-4 rounded-md border border-line px-3 py-2.5 text-left" role="status">
            <p className={cx("font-medium", install.tone === "danger" ? "text-danger" : install.tone === "ok" ? "text-ok" : "text-fg")}>{install.label}</p>
            {install.detail && <p className="mt-0.5 break-words">{install.detail}</p>}
            <p className="mt-1 text-xs text-subtle">
              {d.install.automatic ? "Started by the organization's automatic installs" : `Requested by ${d.install.requestedBy || "a removed user"}`}{" "}
              {formatRelative(d.install.requestedAt)}
              {d.install.attempts > 1 && ` · attempt ${d.install.attempts.toLocaleString()}`}
            </p>
          </div>
        )}
      </EmptyState>
      <AgentInstallDialog open={installing} onClose={() => setInstalling(false)} devices={[{ id: device.id, name: device.name }]} />
    </Card>
  );
}

function Linked({ patching: d, device }: { patching: DevicePatching; device: Device }) {
  const url = useUrlState();
  const view = (["available", "installed", "history", "jobs"] as View[]).find((v) => v === url.get("patches")) ?? "available";
  const [installing, setInstalling] = useState<{ id: string; title: string }[] | "all" | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [restarting, setRestarting] = useState(false);
  const { scan, dialog } = useScan();
  const e = d.endpoint;
  const target = [{ id: device.id, name: device.name }];

  return (
    <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
      <div className="flex min-w-0 flex-col gap-4 xl:col-span-2">
        {d.error && (
          <Alert tone="danger" title="EasyPatch could not be read">
            {d.error}
          </Alert>
        )}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Segmented
            label="Updates to show"
            value={view}
            onChange={(v) => url.set({ patches: v === "available" ? null : v })}
            options={[
              {
                value: "available",
                label: e?.summary.lastScanAt ? `To install (${e.summary.missingTotalCount.toLocaleString()})` : "To install",
              },
              { value: "installed", label: "Installed" },
              { value: "history", label: "History" },
              { value: "jobs", label: "Jobs" },
            ]}
          />
          {d.canManage && (
            <div className="flex flex-wrap gap-2">
              {e?.summary.rebootPending && (
                <Button icon={<Power className="size-4" aria-hidden />} onClick={() => setRestarting(true)}>
                  Restart…
                </Button>
              )}
              <Button icon={<Radar className="size-4" aria-hidden />} loading={scan.isPending} onClick={() => scan.mutate([device.id])}>
                Scan now
              </Button>
              <Button
                variant="primary"
                icon={<Download className="size-4" aria-hidden />}
                onClick={() => setInstalling("all")}
                disabled={e?.summary.missingTotalCount === 0}
              >
                Install updates…
              </Button>
            </div>
          )}
        </div>
        {scan.error && (
          <Alert tone="danger" title="The scan did not start">
            {scan.error.message}
          </Alert>
        )}
        {view === "available" && <Available deviceId={device.id} canManage={d.canManage} scanned={!!e?.summary.lastScanAt} onInstall={setInstalling} />}
        {view === "installed" && <Installed deviceId={device.id} />}
        {view === "history" && <History deviceId={device.id} />}
        {view === "jobs" && <Jobs deviceId={device.id} onOpen={setJobId} />}
      </div>
      <div className="flex min-w-0 flex-col gap-5">
        <Summary patching={d} view={view} />
        {d.policy && <PolicyCard patching={d} />}
      </div>
      <InstallDialog
        open={installing !== null}
        onClose={() => setInstalling(null)}
        devices={target}
        updates={installing === "all" || installing === null ? undefined : installing}
        canSchedule={d.canSchedule}
        onDone={() => url.set({ patches: "jobs" })}
      />
      <RestartDialog open={restarting} onClose={() => setRestarting(false)} devices={target} onDone={() => url.set({ patches: "jobs" })} />
      <PatchJobDialog jobId={jobId} onClose={() => setJobId(null)} onJob={setJobId} />
      {dialog}
    </div>
  );
}

function When({ at, never = "Never" }: { at: string | null | undefined; never?: string }) {
  return at ? <span title={formatDateTime(at)}>{formatRelative(at)}</span> : <span className="text-muted">{never}</span>;
}

function Summary({ patching: d, view }: { patching: DevicePatching; view: View }) {
  const e = d.endpoint;
  if (!e) {
    return (
      <Card title="Patch status">
        <LinkBadge link="linked" />
      </Card>
    );
  }
  const s = e.summary;
  const items: [string, ReactNode][] = [
    ["Status", <ComplianceBadge key="c" status={s.complianceStatus} />],
    [
      "Missing",
      !s.lastScanAt ? (
        <span key="m" className="text-muted">
          Known after the first scan
        </span>
      ) : (
        <span key="m">
          {plural(s.missingTotalCount, "update")}
          {s.missingRequiredCount > 0 && <span className="text-muted">, {s.missingRequiredCount.toLocaleString()} required</span>}
          {s.missingDeferredCount > 0 && (
            <span className="block text-xs text-muted">{s.missingDeferredCount.toLocaleString()} held back by the policy's delay</span>
          )}
          {s.knownExploitedMissingCount > 0 && (
            <span className="block text-xs text-danger">
              {s.knownExploitedMissingCount === 1
                ? "1 fixes a vulnerability exploited in the wild"
                : `${s.knownExploitedMissingCount.toLocaleString()} fix vulnerabilities exploited in the wild`}
            </span>
          )}
        </span>
      ),
    ],
  ];
  if (s.failedCount > 0)
    items.push([
      "Failed",
      <span key="f" className="text-danger">
        {plural(s.failedCount, "update")}
      </span>,
    ]);
  items.push([
    "Last scan",
    <span key="s">
      <When at={s.lastScanAt} />
      {e.lastScanError && <span className="block text-xs text-danger">{e.lastScanError}</span>}
    </span>,
  ]);
  if (s.rebootPending) {
    items.push([
      "Restart",
      <span key="r">
        Pending
        {e.rebootPendingSince && (
          <>
            {" "}
            since <When at={e.rebootPendingSince} />
          </>
        )}
        {e.rebootReasons && e.rebootReasons.length > 0 && <span className="block text-xs text-muted">{e.rebootReasons.join(", ")}</span>}
      </span>,
    ]);
  }
  items.push([
    "EasyPatch agent",
    <span key="a">
      {s.agentVersion}
      {s.agentOutdated && <span className="text-warn"> · out of date</span>}
      <span className="block text-xs text-muted">
        {s.isOnline ? (
          "Online"
        ) : (
          <>
            Last seen <When at={s.lastCheckInAt} never="never" />
          </>
        )}
      </span>
    </span>,
  ]);
  items.push([
    "In EasyPatch",
    <span key="o">
      <span className="block">
        {s.organizationName} / {s.siteName}
      </span>
      <EasyPatchLink to={{ device: d.deviceId, tab: PATCH_VIEW_TAB[view] }} className="mt-0.5 text-xs">
        Open in EasyPatch
      </EasyPatchLink>
    </span>,
  ]);
  return (
    <Card title="Patch status">
      <KeyValueList narrow items={items} />
    </Card>
  );
}

function PolicyCard({ patching: d }: { patching: DevicePatching }) {
  const p = d.policy!;
  const items: [string, ReactNode][] = [
    ["Automatic installs", maintenanceText(p)],
    ["Scans", `Every ${p.scanIntervalMinutes % 60 === 0 ? plural(p.scanIntervalMinutes / 60, "hour") : plural(p.scanIntervalMinutes, "minute")}`],
  ];
  if (p.allowedCategories && p.allowedCategories.length > 0) items.push(["Categories", p.allowedCategories.map(categoryLabel).join(", ")]);
  if (p.installDelayDays > 0 || p.securityInstallDelayDays > 0) {
    items.push(["Delay", `${plural(p.securityInstallDelayDays, "day")} for security updates, ${plural(p.installDelayDays, "day")} for others`]);
  }
  return (
    <Card title="EasyPatch policy">
      <KeyValueList narrow items={items} />
      <p className="mt-3 border-t border-line pt-3 text-xs text-muted">
        Policies are set in EasyPatch, for its organization, site or this endpoint.{" "}
        <EasyPatchLink to={{ device: d.deviceId, tab: "policy" }}>Change in EasyPatch</EasyPatchLink>
      </p>
    </Card>
  );
}

/** An update: its title opens it in EasyPatch, with its vulnerabilities, the other devices that miss it and its hold. */
function UpdateTitle({ u }: { u: PatchUpdate }) {
  return (
    <>
      <a href={easyPatchHref({ update: u.updateGuid })} className="block rounded-sm font-medium break-words hover:text-accent" title="Open in EasyPatch">
        {u.title}
      </a>
      <span className="text-xs text-muted">
        {u.kbNumber && <>KB{u.kbNumber.replace(/^KB/i, "")} · </>}
        {u.package && u.package.installedVersion && (
          <>
            {u.package.installedVersion} → {u.package.version} ·{" "}
          </>
        )}
        {categoryLabel(u.category)}
        {u.msrcSeverity && <> · {u.msrcSeverity}</>}
        {u.sizeBytes ? <> · {formatSize(u.sizeBytes)}</> : null}
        {u.rebootLikely && <> · may need a restart</>}
      </span>
      {u.knownExploited && (
        <Badge tone="danger" className="mt-1">
          Exploited in the wild
        </Badge>
      )}
    </>
  );
}

function Available({
  deviceId,
  canManage,
  scanned,
  onInstall,
}: {
  deviceId: string;
  canManage: boolean;
  scanned: boolean;
  onInstall: (u: { id: string; title: string }[]) => void;
}) {
  const updates = useList<PatchUpdate>(`/patching/devices/${deviceId}/updates`, undefined, {
    refetchInterval: (data) => (data?.items.some((u) => u.activeJob) ? 5_000 : 60_000),
  });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const installable = useMemo(() => updates.items.filter((u) => INSTALLABLE.includes(u.state) && !u.isExcluded && !u.activeJob), [updates.items]);
  useEffect(() => {
    setSelected((prev) => {
      const ids = new Set(installable.map((u) => u.updateGuid));
      const next = new Set([...prev].filter((id) => ids.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [installable]);

  if (updates.isPending) return <Spinner />;
  if (updates.isError) return <ErrorState error={updates.error} onRetry={() => void updates.refetch()} />;
  if (updates.items.length === 0) {
    return (
      <Card>
        {scanned ? (
          <EmptyState title="Nothing to install" compact>
            The last scan found no missing updates. Scans run on the policy's schedule, or now with Scan now.
          </EmptyState>
        ) : (
          <EmptyState title="Not scanned yet" compact>
            EasyPatch lists missing updates after the device's first scan. Scans run on the policy's schedule, or now with Scan now.
          </EmptyState>
        )}
      </Card>
    );
  }
  const chosen = installable.filter((u) => selected.has(u.updateGuid));
  const select = canManage && installable.length > 0;
  const all = chosen.length === installable.length;
  return (
    <Card
      padded={false}
      title={chosen.length > 0 ? `${chosen.length.toLocaleString()} selected` : plural(updates.items.length, "update")}
      actions={
        chosen.length > 0 ? (
          <Button size="sm" variant="primary" onClick={() => onInstall(chosen.map((u) => ({ id: u.updateGuid, title: u.title })))}>
            Install selected…
          </Button>
        ) : (
          <EasyPatchLink to={{ device: deviceId, tab: "updates" }} className="text-xs">
            Exclude in EasyPatch
          </EasyPatchLink>
        )
      }
    >
      <TableWrap className="rounded-none border-0">
        <table className="table-base">
          <thead>
            <tr>
              {select && (
                <th className="w-10">
                  <input
                    type="checkbox"
                    aria-label="Select every update that can be installed"
                    checked={all}
                    ref={(el) => {
                      if (el) el.indeterminate = chosen.length > 0 && !all;
                    }}
                    onChange={(ev) => setSelected(ev.target.checked ? new Set(installable.map((u) => u.updateGuid)) : new Set())}
                  />
                </th>
              )}
              <th>Update</th>
              <th>State</th>
              <th className="hidden md:table-cell">Released</th>
            </tr>
          </thead>
          <tbody>
            {updates.items.map((u) => (
              <tr key={u.updateGuid} className={cx(selected.has(u.updateGuid) && "bg-accent-soft/40")}>
                {select && (
                  <td className="align-top">
                    {installable.includes(u) && (
                      <input
                        type="checkbox"
                        aria-label={`Select ${u.title}`}
                        checked={selected.has(u.updateGuid)}
                        onChange={(ev) =>
                          setSelected((prev) => {
                            const next = new Set(prev);
                            if (ev.target.checked) next.add(u.updateGuid);
                            else next.delete(u.updateGuid);
                            return next;
                          })
                        }
                      />
                    )}
                  </td>
                )}
                <td className="align-top">
                  <UpdateTitle u={u} />
                </td>
                <td className="align-top">
                  {u.activeJob ? (
                    <Badge tone="info">
                      {u.activeJob.itemStatus}
                      {u.activeJob.installPercent !== null
                        ? ` · ${u.activeJob.installPercent}%`
                        : u.activeJob.downloadPercent !== null
                          ? ` · ${u.activeJob.downloadPercent}%`
                          : ""}
                    </Badge>
                  ) : (
                    <UpdateStateBadge state={u.state} />
                  )}
                  {u.isRequired && <span className="mt-1 block text-xs text-muted">Required</span>}
                  {u.state === "Failed" && u.errorMessage && <span className="mt-1 block max-w-xs text-xs text-danger">{u.errorMessage}</span>}
                  {u.deferredUntil && <span className="mt-1 block text-xs text-muted">Held until {formatDate(u.deferredUntil)}</span>}
                  {u.holdReason && <span className="mt-1 block max-w-xs text-xs text-muted">{u.holdReason}</span>}
                </td>
                <td className="hidden align-top whitespace-nowrap text-muted md:table-cell">{u.releaseDate ? formatDate(u.releaseDate) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Card>
  );
}

function Installed({ deviceId }: { deviceId: string }) {
  const updates = useList<PatchUpdate>(`/patching/devices/${deviceId}/installed`, undefined, { staleTime: 60_000 });
  if (updates.isPending) return <Spinner />;
  if (updates.isError) return <ErrorState error={updates.error} onRetry={() => void updates.refetch()} />;
  if (updates.items.length === 0) {
    return (
      <Card>
        <EmptyState title="No installed updates recorded" compact>
          EasyPatch lists updates it has seen installed here after a scan.
        </EmptyState>
      </Card>
    );
  }
  return (
    <TableWrap>
      <table className="table-base">
        <thead>
          <tr>
            <th>Update</th>
            <th className="hidden sm:table-cell">Installed</th>
          </tr>
        </thead>
        <tbody>
          {updates.items.map((u) => (
            <tr key={u.updateGuid}>
              <td>
                <UpdateTitle u={u} />
              </td>
              <td className="hidden whitespace-nowrap text-muted sm:table-cell">{u.installedAt ? formatDateTime(u.installedAt) : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

function Pager({ page, total, size, onPage }: { page: number; total: number; size: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / size));
  if (pages <= 1) return null;
  return (
    <div className="mt-2 flex items-center justify-between text-xs text-muted">
      <span>
        Page {page} of {pages.toLocaleString()}
      </span>
      <span className="flex gap-2">
        <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          Newer
        </Button>
        <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          Older
        </Button>
      </span>
    </div>
  );
}

function History({ deviceId }: { deviceId: string }) {
  const [page, setPage] = useState(1);
  const h = useApi<PatchPage<PatchHistoryEntry>>(`/patching/devices/${deviceId}/history`, { page: String(page) }, { keepPrevious: true, staleTime: 60_000 });
  if (h.isPending) return <Spinner />;
  if (h.isError) return <ErrorState error={h.error} onRetry={() => void h.refetch()} />;
  if (h.data.items.length === 0) {
    return (
      <Card>
        <EmptyState title="No update history" compact>
          The device's own record of updates installed and removed shows here once EasyPatch has read it.
        </EmptyState>
      </Card>
    );
  }
  return (
    <>
      <TableWrap>
        <table className="table-base">
          <thead>
            <tr>
              <th>Update</th>
              <th>Result</th>
              <th className="hidden sm:table-cell">When</th>
            </tr>
          </thead>
          <tbody>
            {h.data.items.map((e) => (
              <tr key={e.id}>
                <td>
                  <span className="block break-words">{e.title}</span>
                  <span className="text-xs text-muted">{e.operation}</span>
                </td>
                <td>
                  <Badge tone={e.result === "Succeeded" ? "ok" : e.result === "Failed" || e.result === "Aborted" ? "danger" : "neutral"}>{e.result}</Badge>
                  {e.errorDescription && <span className="mt-1 block max-w-xs text-xs text-danger">{e.errorDescription}</span>}
                </td>
                <td className="hidden whitespace-nowrap text-muted sm:table-cell">{formatDateTime(e.date)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      <Pager page={page} total={h.data.totalCount} size={h.data.pageSize || 50} onPage={setPage} />
    </>
  );
}

function Jobs({ deviceId, onOpen }: { deviceId: string; onOpen: (id: string) => void }) {
  const [page, setPage] = useState(1);
  const jobs = useApi<PatchPage<PatchJob>>(
    `/patching/devices/${deviceId}/jobs`,
    { page: String(page) },
    {
      keepPrevious: true,
      refetchInterval: (data) => (data?.items.some(isActiveJob) ? 4_000 : 30_000),
    },
  );
  if (jobs.isPending) return <Spinner />;
  if (jobs.isError) return <ErrorState error={jobs.error} onRetry={() => void jobs.refetch()} />;
  if (jobs.data.items.length === 0) {
    return (
      <Card>
        <EmptyState title="No patch jobs yet" compact>
          Scans and installs on this device, started here or by EasyPatch's schedules, show here.
        </EmptyState>
      </Card>
    );
  }
  return (
    <>
      <TableWrap>
        <table className="table-base">
          <thead>
            <tr>
              <th>Job</th>
              <th>Status</th>
              <th className="hidden md:table-cell">Requested</th>
            </tr>
          </thead>
          <tbody>
            {jobs.data.items.map((j) => (
              <tr key={j.id} className="cursor-pointer" onClick={() => onOpen(j.id)}>
                <td>
                  <button type="button" className="rounded-sm text-left font-medium hover:text-accent" onClick={(ev) => (ev.stopPropagation(), onOpen(j.id))}>
                    {jobTypeLabel(j.type)}
                  </button>
                  <span className="block text-xs text-muted">
                    {j.errorMessage ? <span className="text-danger">{j.errorMessage}</span> : jobOutcome(j) || j.trigger}
                  </span>
                </td>
                <td>
                  <PatchJobBadge job={j} />
                </td>
                <td className="hidden text-muted md:table-cell">
                  <span title={formatDateTime(j.createdAt)}>{formatRelative(j.createdAt)}</span>
                  <span className="block max-w-56 truncate text-xs">{requester(j.requestedBy)}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      <Pager page={page} total={jobs.data.totalCount} size={jobs.data.pageSize || 50} onPage={setPage} />
    </>
  );
}
