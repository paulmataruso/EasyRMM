import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Ban, CircleSlash, Download, PackageMinus, PackagePlus, Power, Radar, Undo2 } from "lucide-react";
import { useApi, useList } from "../../api/hooks";
import { PATCH_AGENT_CAN, type Device, type DevicePatching, type PatchHistoryEntry, type PatchJob, type PatchPage, type PatchUpdate } from "../../api/types";
import { Alert, Badge, Button, Card, cx, EmptyState, ErrorState, KeyValueList, Segmented, Spinner, TableWrap } from "../../components/ui";
import { formatDate, formatDateTime, formatRelative, formatSize, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";
import {
  AgentInstallDialog,
  InstallDialog,
  PatchJobDialog,
  RestartDialog,
  StopPatchingDialog,
  useAllowPatching,
  useScan,
} from "../patching/PatchDialogs";
import {
  categoryLabel,
  ComplianceBadge,
  INSTALLABLE,
  installText,
  isActiveJob,
  jobOutcome,
  jobTypeLabel,
  LinkBadge,
  maintenanceText,
  Pager,
  PatchJobBadge,
  requester,
  UpdateStateBadge,
} from "../patching/patchText";
import { AgentUpdateDialog, ExcludeDialog, MessageDialog, RemoveUpdateDialog, SessionSummary, useInclude } from "./PatchActionDialogs";
import { PolicyView, restartScheduleText } from "./PatchPolicyView";

type View = "available" | "installed" | "history" | "jobs" | "policy";

/** A device's updates through EasyPatch (ADR-0030): what is missing and installed, history, jobs, and the actions. */
export function PatchesPanel({ device }: { device: Device }) {
  const p = useApi<DevicePatching>(`/patching/devices/${device.id}`, undefined, { refetchInterval: 30_000 });
  if (p.isPending) return <Spinner />;
  if (p.isError) return <ErrorState error={p.error} onRetry={() => void p.refetch()} />;
  const d = p.data;
  if (d.stopped) return <Stopped patching={d} stopped={d.stopped} device={device} />;
  if (d.link !== "linked") return <NotLinked patching={d} device={device} />;
  return <Linked patching={d} device={device} />;
}

/** Patching stopped for the device (ADR-0040): its EasyPatch agent removed, or being removed, and none installed. */
function Stopped({ patching: d, stopped, device }: { patching: DevicePatching; stopped: NonNullable<DevicePatching["stopped"]>; device: Device }) {
  const allow = useAllowPatching();
  const removal = d.removal?.reason === "opted_out" ? d.removal : undefined;
  return (
    <Card>
      <EmptyState
        title="Patching stopped"
        icon={<CircleSlash className="size-6 text-muted" aria-hidden />}
        action={
          d.canManage && (
            <Button variant="primary" loading={allow.isPending} onClick={() => allow.mutate([device.id])}>
              Allow patching again
            </Button>
          )
        }
      >
        Stopped by {stopped.by || "a removed user"} <span title={formatDateTime(stopped.at)}>{formatRelative(stopped.at)}</span>.{" "}
        {!removal
          ? "EasyRMM installs no EasyPatch agent on this device, automatically or when asked."
          : removal.state === "pending"
            ? "EasyRMM is about to have the EasyPatch agent uninstall itself."
            : "The EasyPatch agent is uninstalling itself. One that has not within a week is cut off from patching instead."}
        {removal?.error && <span className="mt-2 block text-danger">{removal.error}</span>}
      </EmptyState>
    </Card>
  );
}

function NotLinked({ patching: d, device }: { patching: DevicePatching; device: Device }) {
  const [installing, setInstalling] = useState(false);
  const [stopping, setStopping] = useState(false);
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
            <div className="flex flex-wrap justify-center gap-2">
              <Button variant="primary" icon={<PackagePlus className="size-4" aria-hidden />} onClick={() => setInstalling(true)}>
                {d.install?.state === "failed" ? "Try the install again…" : "Install EasyPatch agent…"}
              </Button>
              {/* Before automatic installs reach a device that must not be patched. */}
              <Button onClick={() => setStopping(true)}>Stop patching…</Button>
            </div>
          )
        }
      >
        {d.link === "none" &&
          (!device.agent
            ? "EasyRMM finds the EasyPatch agent through its own agent, which this device does not have."
            : canInstall
              ? "The EasyRMM agent has not reported an EasyPatch agent on this device. EasyRMM can install it and enroll it in the patching engine."
              : "The EasyRMM agent has not reported an EasyPatch agent on this device. On Windows and Linux, someone who manages patching here can have EasyRMM install it; the EasyRMM agent reports it with its next inventory, within an hour.")}
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
      <StopPatchingDialog open={stopping} onClose={() => setStopping(false)} devices={[{ id: device.id, name: device.name }]} />
    </Card>
  );
}

/** What the device's EasyPatch agent can do, as it reports it. */
function agentCan(d: DevicePatching, what: string): boolean {
  return (d.endpoint?.agentCapabilities ?? []).includes(what);
}

/** Updates the policy excludes everywhere by KB, which cannot be included again on one device. */
function policyExcludes(d: DevicePatching, u: PatchUpdate): boolean {
  const kbs = new Set((d.policy?.excludedKbs ?? []).map((k) => k.toUpperCase().replace(/^KB/, "")));
  return [u.kbNumber, ...(u.kbNumbers ?? [])].some((k) => k && kbs.has(k.toUpperCase().replace(/^KB/, "")));
}

/** Windows updates the device's agent can remove: not a Linux package, and nothing working on it. */
function removable(d: DevicePatching, device: Device, u: PatchUpdate): boolean {
  return d.canManage && device.platform === "windows" && agentCan(d, PATCH_AGENT_CAN.uninstallUpdates) && !u.package && !u.activeJob;
}

function Linked({ patching: d, device }: { patching: DevicePatching; device: Device }) {
  const url = useUrlState();
  const view = (["available", "installed", "history", "jobs", "policy"] as View[]).find((v) => v === url.get("patches")) ?? "available";
  const [installing, setInstalling] = useState<{ id: string; title: string }[] | "all" | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [restarting, setRestarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [excluding, setExcluding] = useState<PatchUpdate | null>(null);
  const [removing, setRemoving] = useState<PatchUpdate | null>(null);
  const [messaging, setMessaging] = useState(false);
  const [updatingAgent, setUpdatingAgent] = useState(false);
  const { scan, dialog } = useScan();
  const e = d.endpoint;
  const target = [{ id: device.id, name: device.name }];
  const toJobs = () => url.set({ patches: "jobs" });

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
            onChange={(v) => url.set({ patches: v === "available" ? null : v, policy: null })}
            options={[
              {
                value: "available",
                label: e?.summary.lastScanAt ? `To install (${e.summary.missingTotalCount.toLocaleString()})` : "To install",
              },
              { value: "installed", label: "Installed" },
              { value: "history", label: "History" },
              { value: "jobs", label: "Jobs" },
              ...(d.policy ? [{ value: "policy" as const, label: "Policy" }] : []),
            ]}
          />
          {d.canManage && (
            <div className="flex flex-wrap gap-2">
              {(e?.summary.rebootPending || agentCan(d, PATCH_AGENT_CAN.restart)) && (
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
        {view === "available" && (
          <Available
            patching={d}
            device={device}
            scanned={!!e?.summary.lastScanAt}
            onInstall={setInstalling}
            onExclude={setExcluding}
            onRemove={setRemoving}
          />
        )}
        {view === "installed" && <Installed patching={d} device={device} onRemove={setRemoving} />}
        {view === "history" && <History deviceId={device.id} />}
        {view === "jobs" && <Jobs deviceId={device.id} onOpen={setJobId} />}
        {view === "policy" && <PolicyView patching={d} device={device} />}
      </div>
      <div className="flex min-w-0 flex-col gap-5">
        <Summary
          patching={d}
          device={device}
          view={view}
          onOpenJob={setJobId}
          onMessage={() => setMessaging(true)}
          onUpdateAgent={() => setUpdatingAgent(true)}
        />
        {d.policy && view !== "policy" && <PolicyCard patching={d} onMore={() => url.set({ patches: "policy" })} />}
        {d.canManage && (
          <Card title="Patching this device">
            <p className="text-sm text-muted">For a device that must not be patched, stopping removes the EasyPatch agent and keeps it off.</p>
            <Button className="mt-3" variant="danger-ghost" size="sm" onClick={() => setStopping(true)}>
              Stop patching…
            </Button>
          </Card>
        )}
      </div>
      <InstallDialog
        open={installing !== null}
        onClose={() => setInstalling(null)}
        devices={target}
        updates={installing === "all" || installing === null ? undefined : installing}
        canSchedule={d.canSchedule}
        preview
        onDone={toJobs}
      />
      <RestartDialog open={restarting} onClose={() => setRestarting(false)} devices={target} pendingOnly={Boolean(e?.summary.rebootPending)} onDone={toJobs} />
      <StopPatchingDialog open={stopping} onClose={() => setStopping(false)} devices={target} />
      <ExcludeDialog device={device} update={excluding} onClose={() => setExcluding(null)} />
      <RemoveUpdateDialog device={device} update={removing} onClose={() => setRemoving(null)} onDone={toJobs} />
      {e && <MessageDialog open={messaging} onClose={() => setMessaging(false)} device={device} endpoint={e} />}
      {e && <AgentUpdateDialog open={updatingAgent} onClose={() => setUpdatingAgent(false)} device={device} endpoint={e} />}
      <PatchJobDialog jobId={jobId} onClose={() => setJobId(null)} onJob={setJobId} />
      {dialog}
    </div>
  );
}

function When({ at, never = "Never" }: { at: string | null | undefined; never?: string }) {
  return at ? <span title={formatDateTime(at)}>{formatRelative(at)}</span> : <span className="text-muted">{never}</span>;
}

const RESTART_SOURCES: Record<string, string> = {
  Installed: "installed, takes effect at the restart",
  WindowsUpdate: "Windows Update lists it as waiting",
  Servicing: "a pending Windows servicing package",
};

/** What a pending restart is for: the updates waiting for it, and what else Windows has queued. */
function RestartFor({ patching: d }: { patching: DevicePatching }) {
  const e = d.endpoint!;
  const r = e.restart;
  const updates = r?.updates ?? [];
  const packages = r?.servicingPackages ?? [];
  const files = r?.fileOperationCount ?? 0;
  return (
    <>
      {updates.length > 0 && (
        <ul className="mt-1 space-y-0.5 text-xs text-muted">
          {updates.map((u) => (
            <li key={`${u.updateGuid ?? ""}-${u.title}`} className="break-words">
              <span className="text-fg">{u.title}</span> · {RESTART_SOURCES[u.source] ?? u.source}
            </li>
          ))}
        </ul>
      )}
      {packages.length > 0 && <span className="mt-1 block text-xs text-muted">{plural(packages.length, "servicing package")} waiting</span>}
      {files > 0 && <span className="mt-1 block text-xs text-muted">{plural(files, "file")} to change at the restart</span>}
      {e.rebootReasons && e.rebootReasons.length > 0 && <span className="mt-1 block text-xs text-muted">{e.rebootReasons.join(", ")}</span>}
    </>
  );
}

/** The agent's version and whether it can update itself, as EasyPatch plans it. */
function AgentLine({ patching: d, onUpdate }: { patching: DevicePatching; onUpdate: () => void }) {
  const e = d.endpoint!;
  const s = e.summary;
  const u = e.agentUpdate;
  let hint: ReactNode = null;
  if (!u?.supported) hint = s.agentOutdated ? <span className="text-warn">A newer version exists; this agent must be reinstalled once to get it</span> : null;
  else if (u.availableVersion) hint = u.automaticUpdates ? `Updating itself to ${u.availableVersion}` : `${u.availableVersion} available`;
  else if (u.code === "agent_up_to_date") hint = u.automaticUpdates ? "Up to date, updates itself" : "Up to date";
  else hint = <span className="text-warn">{u.message || "It cannot update itself"}</span>;
  return (
    <span>
      {s.agentVersion}
      <span className="block text-xs text-muted">
        {s.isOnline ? (
          "Online"
        ) : (
          <>
            Last seen <When at={s.lastCheckInAt} never="never" />
          </>
        )}
      </span>
      {hint && <span className="block text-xs text-muted">{hint}</span>}
      {d.canManage && u?.supported && u.availableVersion && (
        <Button size="sm" className="mt-2" onClick={onUpdate}>
          Update agent…
        </Button>
      )}
    </span>
  );
}

function Summary({
  patching: d,
  device,
  view,
  onOpenJob,
  onMessage,
  onUpdateAgent,
}: {
  patching: DevicePatching;
  device: Device;
  view: View;
  onOpenJob: (id: string) => void;
  onMessage: () => void;
  onUpdateAgent: () => void;
}) {
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
  if (e.activeJob) {
    const j = e.activeJob;
    items.push([
      "Working on",
      <span key="j">
        <button type="button" className="rounded-sm text-left font-medium hover:text-accent" onClick={() => onOpenJob(j.id)}>
          {jobTypeLabel(j.type)}
        </button>
        <span className="mt-1 block">
          <PatchJobBadge job={j} />
        </span>
      </span>,
    ]);
  }
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
        <RestartFor patching={d} />
      </span>,
    ]);
  }
  if (device.platform === "windows") {
    const canMessage = d.canManage && agentCan(d, PATCH_AGENT_CAN.notifyUser);
    items.push([
      "Users",
      <span key="u">
        <SessionSummary endpoint={e} platform={device.platform} />
        {canMessage && (
          <Button size="sm" className="mt-2 block" onClick={onMessage}>
            Message users…
          </Button>
        )}
      </span>,
    ]);
  }
  items.push(["EasyPatch agent", <AgentLine key="a" patching={d} onUpdate={onUpdateAgent} />]);
  return (
    <Card title="Patch status">
      <KeyValueList narrow items={items} />
    </Card>
  );
}

function PolicyCard({ patching: d, onMore }: { patching: DevicePatching; onMore: () => void }) {
  const p = d.policy!;
  const items: [string, ReactNode][] = [
    ["Automatic installs", maintenanceText(p)],
    ["Scans", `Every ${p.scanIntervalMinutes % 60 === 0 ? plural(p.scanIntervalMinutes / 60, "hour") : plural(p.scanIntervalMinutes, "minute")}`],
  ];
  if (p.allowedCategories && p.allowedCategories.length > 0) items.push(["Categories", p.allowedCategories.map(categoryLabel).join(", ")]);
  if (p.installDelayDays > 0 || p.securityInstallDelayDays > 0) {
    items.push(["Delay", `${plural(p.securityInstallDelayDays, "day")} for security updates, ${plural(p.installDelayDays, "day")} for others`]);
  }
  if (p.restartSchedule?.enabled) items.push(["Restarts", restartScheduleText(p.restartSchedule)]);
  return (
    <Card
      title="Patch policy"
      actions={
        <Button size="sm" variant="ghost" onClick={onMore}>
          Whole policy
        </Button>
      }
    >
      <KeyValueList narrow items={items} />
    </Card>
  );
}

/** An update: its title, with its KB number or package version. */
function UpdateTitle({ u }: { u: PatchUpdate }) {
  return (
    <>
      <span className="block font-medium break-words">{u.title}</span>
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
  patching: d,
  device,
  scanned,
  onInstall,
  onExclude,
  onRemove,
}: {
  patching: DevicePatching;
  device: Device;
  scanned: boolean;
  onInstall: (u: { id: string; title: string }[]) => void;
  onExclude: (u: PatchUpdate) => void;
  onRemove: (u: PatchUpdate) => void;
}) {
  const deviceId = device.id;
  const canManage = d.canManage;
  const { include, isPending: including, variables: includingId } = useInclude(device);
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
        chosen.length > 0 && (
          <Button size="sm" variant="primary" onClick={() => onInstall(chosen.map((u) => ({ id: u.updateGuid, title: u.title })))}>
            Install selected…
          </Button>
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
              {canManage && (
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              )}
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
                  {u.isExcluded && policyExcludes(d, u) && <span className="mt-1 block text-xs text-muted">By the policy's excluded KBs</span>}
                </td>
                <td className="hidden align-top whitespace-nowrap text-muted md:table-cell">{u.releaseDate ? formatDate(u.releaseDate) : "—"}</td>
                {canManage && (
                  <td className="text-right align-top whitespace-nowrap">
                    {u.isExcluded ? (
                      !policyExcludes(d, u) && (
                        <Button
                          size="sm"
                          variant="ghost"
                          aria-label={`Include ${u.title}`}
                          icon={<Undo2 className="size-3.5" aria-hidden />}
                          loading={including && includingId === u.updateGuid}
                          onClick={() => include(u.updateGuid)}
                        >
                          <span className="hidden sm:inline">Include</span>
                        </Button>
                      )
                    ) : (u.state === "Missing" || u.state === "Failed") && !u.activeJob ? (
                      <Button size="sm" variant="ghost" icon={<Ban className="size-3.5" aria-hidden />} aria-label={`Exclude ${u.title}…`} onClick={() => onExclude(u)}>
                        <span className="hidden sm:inline">Exclude…</span>
                      </Button>
                    ) : (
                      u.state === "PendingReboot" &&
                      removable(d, device, u) && (
                        <Button size="sm" variant="ghost" icon={<PackageMinus className="size-3.5" aria-hidden />} aria-label={`Remove ${u.title}…`} onClick={() => onRemove(u)}>
                          <span className="hidden sm:inline">Remove…</span>
                        </Button>
                      )
                    )}
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

function Installed({ patching: d, device, onRemove }: { patching: DevicePatching; device: Device; onRemove: (u: PatchUpdate) => void }) {
  const updates = useList<PatchUpdate>(`/patching/devices/${device.id}/installed`, undefined, { staleTime: 60_000 });
  const canRemove = updates.items.some((u) => removable(d, device, u));
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
            {canRemove && (
              <th>
                <span className="sr-only">Actions</span>
              </th>
            )}
          </tr>
        </thead>
        <tbody>
          {updates.items.map((u) => (
            <tr key={u.updateGuid}>
              <td>
                <UpdateTitle u={u} />
              </td>
              <td className="hidden whitespace-nowrap text-muted sm:table-cell">{u.installedAt ? formatDateTime(u.installedAt) : "—"}</td>
              {canRemove && (
                <td className="text-right whitespace-nowrap">
                  {removable(d, device, u) && (
                    <Button size="sm" variant="ghost" icon={<PackageMinus className="size-3.5" aria-hidden />} aria-label={`Remove ${u.title}…`} onClick={() => onRemove(u)}>
                      <span className="hidden sm:inline">Remove…</span>
                    </Button>
                  )}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
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
      <Pager page={page} total={h.data.totalCount} size={h.data.pageSize || 50} onPage={setPage} previous="Newer" next="Older" />
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
      <Pager page={page} total={jobs.data.totalCount} size={jobs.data.pageSize || 50} onPage={setPage} previous="Newer" next="Older" />
    </>
  );
}
