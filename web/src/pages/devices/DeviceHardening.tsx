import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { ScanSearch, ShieldCheck } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { keyFor, useApi, useList } from "../../api/hooks";
import type { Device, DeviceHardening, HardeningModule, HardeningPorts, HardeningState, JobRun } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Badge, Button, Card, cx, EmptyState, ErrorState, KeyValueList, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { RunStatusBadge } from "../scripts/parts";
import { isOpen } from "../scripts/scriptText";
import { HardeningCheckDialog } from "./HardeningCheckDialog";
import { HardeningStateBadge } from "./hardeningParts";
import { containerName, distributionName, MODULES, moduleInfo, summarize, SUPPORT } from "./hardeningText";

/** How many of the device's hardening runs the Checks card lists. */
const SHOWN_RUNS = 6;

/**
 * A Linux device's hardening (ADR-0051): what the last check of each module found, the platform as the latest check
 * read it, and the device's hardening runs. Viewing needs device.view; checking needs script.run (canCheckHardening).
 */
export function HardeningPanel({ device }: { device: Device }) {
  const { can } = useAuth();
  const [checking, setChecking] = useState(false);
  const viewJobs = can("job.view");
  const runs = useList<JobRun>(viewJobs ? "/job-runs" : null, { deviceId: device.id, kind: "hardening" }, {
    refetchInterval: (data) => (data?.items.some((r) => isOpen(r.status)) ? 4_000 : 30_000),
  });
  const running = runs.items.some((r) => isOpen(r.status));
  const path = `/devices/${device.id}/hardening`;
  const h = useApi<DeviceHardening>(path, undefined, { refetchInterval: 60_000 });
  useReadAgainWhenDone(running, path);

  if (h.isPending) return <Spinner />;
  if (h.isError) return <ErrorState error={h.error} onRetry={() => void h.refetch()} />;
  const d = h.data;
  const checkButton = (variant: "primary" | "secondary") =>
    device.canCheckHardening && (
      <Button variant={variant} icon={<ScanSearch className="size-4" aria-hidden />} onClick={() => setChecking(true)}>
        Run check…
      </Button>
    );
  const showRuns = viewJobs && (runs.isError || runs.items.length > 0);
  const side = d.platform !== null || showRuns;

  return (
    <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
      <div className={cx("flex min-w-0 flex-col gap-4", side ? "xl:col-span-2" : "xl:col-span-3")}>
        {d.checkedAt && d.modules.length > 0 ? (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <Overview modules={d.modules} checkedAt={d.checkedAt} />
              {checkButton("secondary")}
            </div>
            <Modules hardening={d} checkedAt={d.checkedAt} viewJobs={viewJobs} />
          </>
        ) : (
          <Card>
            <EmptyState title={running ? "Checking hardening" : "Not checked yet"} icon={<ShieldCheck className="size-8" aria-hidden />} action={!running && checkButton("primary")}>
              {running
                ? "The EasyRMM agent is running the check. Its findings show here, module by module, when it reports."
                : `A check reads this device's SSH, firewall, kernel and other settings through the EasyRMM agent, and changes nothing. Its findings show here, module by module.${
                    device.canCheckHardening ? "" : " Someone who runs scripts on this device can start one."
                  }`}
            </EmptyState>
          </Card>
        )}
      </div>
      {side && (
        <div className="flex min-w-0 flex-col gap-5">
          {d.platform && d.checkedAt && <LastCheck hardening={d} platform={d.platform} checkedAt={d.checkedAt} runs={runs.items} viewJobs={viewJobs} />}
          {showRuns && <Checks runs={runs} deviceId={device.id} />}
        </div>
      )}
      {device.canCheckHardening && <HardeningCheckDialog open={checking} onClose={() => setChecking(false)} device={device} />}
    </div>
  );
}

/** A check's findings are recorded with its result: once the device's last run ends, they are read again. */
function useReadAgainWhenDone(running: boolean, path: string) {
  const client = useQueryClient();
  const was = useRef(running);
  useEffect(() => {
    if (was.current && !running) void client.invalidateQueries({ queryKey: keyFor(path) });
    was.current = running;
  }, [running, path, client]);
}

function When({ at }: { at: string }) {
  return <span title={formatDateTime(at)}>{formatRelative(at)}</span>;
}

/** The findings in a few words: "9 of 12 in place, checked 3 hours ago". */
function Overview({ modules, checkedAt }: { modules: HardeningModule[]; checkedAt: string }) {
  const states: Partial<Record<HardeningState, number>> = {};
  for (const m of modules) states[m.state] = (states[m.state] ?? 0) + 1;
  const s = summarize({ checkedAt, states });
  return (
    <p className="flex flex-wrap items-center gap-2 text-sm text-muted">
      <Badge tone={s.tone} title={s.title} className="tabular-nums">
        {s.label}
      </Badge>
      <span>
        Checked <When at={checkedAt} />
      </span>
    </p>
  );
}

function Modules({ hardening: d, checkedAt, viewJobs }: { hardening: DeviceHardening; checkedAt: string; viewJobs: boolean }) {
  const checked = new Set(d.modules.map((m) => m.module));
  const unchecked = MODULES.filter((m) => !checked.has(m.id));
  return (
    <Card title="Modules" padded={false}>
      <ul className="divide-y divide-line">
        {d.modules.map((m) => (
          <ModuleItem key={m.module} module={m} earlier={Date.parse(m.checkedAt) < Date.parse(checkedAt)} viewJobs={viewJobs} />
        ))}
      </ul>
      {unchecked.length > 0 && (
        <p className="border-t border-line px-4 py-2.5 text-xs text-muted">Not checked yet: {unchecked.map((m) => m.name).join(", ")}.</p>
      )}
    </Card>
  );
}

function ModuleItem({ module: m, earlier, viewJobs }: { module: HardeningModule; earlier: boolean; viewJobs: boolean }) {
  const info = moduleInfo(m.module);
  const missing = m.missing ?? [];
  const changes = m.changes ?? [];
  return (
    <li className="px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1">
        <h3 className="text-sm font-medium">{info.name}</h3>
        <HardeningStateBadge state={m.state} />
      </div>
      {m.reason && <p className="mt-1 text-sm break-words text-muted">{m.reason}</p>}
      {(missing.length > 0 || changes.length > 0) && (
        <div className="mt-2.5 grid grid-cols-1 gap-x-6 gap-y-2.5 md:grid-cols-2">
          {missing.length > 0 && <Findings title="Missing" items={missing} />}
          {changes.length > 0 && <Findings title="Apply would change" items={changes} />}
        </div>
      )}
      {m.ports && <Ports ports={m.ports} />}
      {earlier && (
        <p className="mt-2 text-xs text-muted">
          From an earlier check, <When at={m.checkedAt} />
          {viewJobs && m.jobId && (
            <>
              {" · "}
              <Link to={`/jobs/${m.jobId}`} className="text-accent hover:underline">
                View the job
              </Link>
            </>
          )}
        </p>
      )}
    </li>
  );
}

function Findings({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="min-w-0">
      <h4 className="text-xs font-medium text-muted">{title}</h4>
      <ul className="mt-1 list-disc space-y-0.5 pl-4 text-sm break-words marker:text-subtle">
        {items.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ul>
    </div>
  );
}

function PortList({ ports }: { ports: string[] | undefined }) {
  if (!ports || ports.length === 0) return <span className="text-muted">None</span>;
  return <span className="font-mono text-xs break-words">{ports.join(", ")}</span>;
}

/** The firewall's ports: what it would leave open, what Docker publishes past it, and services whose ports are unknown. */
function Ports({ ports }: { ports: HardeningPorts }) {
  const items: [ReactNode, ReactNode][] = [
    ["TCP", <PortList key="t" ports={ports.tcp} />],
    ["UDP", <PortList key="u" ports={ports.udp} />],
  ];
  if (ports.docker && ports.docker.length > 0) {
    items.push([
      "Through Docker",
      <span key="d">
        <PortList ports={ports.docker} />
        <span className="mt-0.5 block text-xs text-muted">Docker publishes these with its own rules, which the firewall does not filter.</span>
      </span>,
    ]);
  }
  if (ports.unknown && ports.unknown.length > 0) {
    items.push([
      "Ports unknown",
      <span key="k">
        <PortList ports={ports.unknown} />
        <span className="mt-0.5 block text-xs text-muted">
          These start at boot but are not running, so their ports are unknown and would be cut off when they start. Start them and check again to have
          their ports listed.
        </span>
      </span>,
    ]);
  }
  return (
    <div className="mt-3">
      <h4 className="text-xs font-medium text-muted">Ports the firewall would leave open</h4>
      <KeyValueList narrow className="mt-1.5" items={items} />
    </div>
  );
}

/** When the latest check ran and by which job, and the platform as it read it, with what EasyRMM supports there. */
function LastCheck({ hardening: d, platform: p, checkedAt, runs, viewJobs }: {
  hardening: DeviceHardening;
  platform: NonNullable<DeviceHardening["platform"]>;
  checkedAt: string;
  runs: JobRun[];
  viewJobs: boolean;
}) {
  const support = SUPPORT[p.support] ?? { label: p.support, tone: "neutral" as const, title: "" };
  const container = containerName(p.container);
  // The job's name, from the device's runs when the latest is among them.
  const jobName = runs.find((r) => r.jobId === d.jobId)?.scriptName;
  const items: [ReactNode, ReactNode][] = [
    ["Checked", <When key="c" at={checkedAt} />],
    [
      "Job",
      !d.jobId ? (
        <span key="j" className="text-muted">
          No longer kept
        </span>
      ) : viewJobs ? (
        <Link key="j" to={`/jobs/${d.jobId}`} className="text-accent hover:underline">
          {jobName ?? "View the job"}
        </Link>
      ) : (
        <span key="j" className="text-muted">
          Not visible to your role
        </span>
      ),
    ],
    ["Distribution", distributionName(p)],
    [
      "Support",
      <span key="s">
        <Badge tone={support.tone}>{support.label}</Badge>
        <span className="mt-1 block text-xs text-muted">{support.title}</span>
      </span>,
    ],
  ];
  if (container) {
    items.push([
      "Container",
      <span key="ct">
        {container}
        <span className="mt-1 block text-xs text-muted">
          The kernel, its modules, audit, SELinux or AppArmor, shared memory and the clock belong to the host, so those modules do not apply here.
        </span>
      </span>,
    ]);
  }
  return (
    <Card title="Last check">
      <KeyValueList narrow items={items} />
    </Card>
  );
}

/** The device's hardening runs, newest first; refreshed quickly while one is still going. */
function Checks({ runs, deviceId }: { runs: ReturnType<typeof useList<JobRun>>; deviceId: string }) {
  return (
    <Card
      title="Checks"
      padded={false}
      actions={
        <Link to={`/jobs?kind=hardening&deviceId=${encodeURIComponent(deviceId)}`} className="text-xs text-accent hover:underline">
          All hardening jobs
        </Link>
      }
    >
      {runs.isError ? (
        <ErrorState error={runs.error} onRetry={() => void runs.refetch()} compact />
      ) : (
        <ul className="divide-y divide-line">
          {runs.items.slice(0, SHOWN_RUNS).map((r) => (
            <li key={r.id}>
              <Link to={`/jobs/${r.jobId}/runs/${r.id}`} className="flex items-center justify-between gap-3 px-4 py-2.5 text-sm hover:bg-hover">
                <span className="min-w-0">
                  <span className="block truncate font-medium" title={r.scriptName}>
                    {r.scriptName}
                  </span>
                  <span className="text-xs text-muted">
                    <When at={r.createdAt} />
                  </span>
                  {r.error && <span className="line-clamp-2 block text-xs break-words text-danger">{r.error}</span>}
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
