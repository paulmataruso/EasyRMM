import { useRef, useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { CircleStop, RotateCcw } from "lucide-react";
import { api } from "../../api/client";
import { auditedRead, useApi, useApiMutation, usePrefetch } from "../../api/hooks";
import type { HardeningJob, Job, JobArguments, JobRun, Script, SoftwareAction } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, Card, ErrorState, KeyValueList, Mono, PageHeader, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useRowKeys } from "../../lib/rowKeys";
import { CodeView, JobStateBadge, RunStatusBadge, StatusBreakdown } from "../scripts/parts";
import { RunScriptDialog } from "../scripts/RunScriptDialog";
import { formatElapsed, formatSeconds, runElapsed, SHELL_NAMES } from "../scripts/scriptText";
import { SoftwareDialog } from "../software/SoftwareDialog";
import { MANAGERS, VERBS } from "../software/softwareText";

/** Refresh every few seconds until every run has ended. */
const OPEN_INTERVAL = 3_000;

/**
 * A library script job's argument values, for a caller who may read them. Each read is audited, so they are asked for
 * once while the page is open, apart from the job (ADR-0063); the details and Run again share the one request.
 */
function useJobArguments(j: Job) {
  const readable = j.kind === "script" && (j.argCount ?? 0) > 0 && j.canViewArguments === true;
  return useApi<JobArguments>(readable ? `/jobs/${j.id}/arguments` : null, undefined, auditedRead(["job-arguments", j.id]));
}

export function JobDetailPage() {
  const { id = "" } = useParams();
  const toast = useToast();
  const job = useApi<Job>(`/jobs/${id}`, undefined, { refetchInterval: (d) => (d && !d.finished ? OPEN_INTERVAL : false) });
  const [stopping, setStopping] = useState(false);
  const stop = useApiMutation(() => api.post<Job>(`/jobs/${id}/cancel`), {
    invalidate: ["/jobs", "/job-runs"],
    onSuccess: () => {
      setStopping(false);
      toast.success("Stopping the job. Runs still waiting are canceled; running scripts stop within seconds on online devices.");
    },
  });

  if (job.isPending) return <Spinner />;
  if (job.isError) return <ErrorState error={job.error} onRetry={() => void job.refetch()} />;
  const j = job.data;
  const runs = j.runs ?? [];
  const stoppable = j.canCancel && !j.finished;

  return (
    <>
      <PageHeader
        breadcrumb={
          <Link to="/jobs" className="hover:text-fg">
            Jobs
          </Link>
        }
        title={j.scriptName}
        subtitle={
          <>
            Started by {j.createdBy} <span title={formatDateTime(j.createdAt)}>{formatRelative(j.createdAt)}</span> on {plural(j.total, "device")}
          </>
        }
        actions={
          <>
            {stoppable && (
              <Button variant="danger-ghost" icon={<CircleStop className="size-4" aria-hidden />} onClick={() => setStopping(true)}>
                Stop job
              </Button>
            )}
            <RunAgain job={j} />
          </>
        }
      />

      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
        <div className="flex min-w-0 flex-col gap-5 xl:col-span-2">
          <Card title="Devices" padded={false}>
            <RunsTable jobId={j.id} runs={runs} />
          </Card>
          <Card title="Script as run">
            {j.software && (
              <p className="mb-3 text-sm text-muted">
                EasyRMM&rsquo;s own script for {j.software.manager === "system" ? "the Linux package manager" : MANAGERS[j.software.manager].label}. The
                package reaches it as an argument, never as script text.
              </p>
            )}
            {j.hardening && (
              <p className="mb-3 text-sm text-muted">
                EasyRMM&rsquo;s own hardening script. The modules and options reach it as arguments, never as script text. A check changes nothing on the
                device.
              </p>
            )}
            <CodeView code={j.body ?? ""} label="Script as run" />
          </Card>
        </div>
        <Card title="Details">
          <KeyValueList
            narrow
            items={[
              ["Status", <JobStateBadge key="s" job={j} />],
              ["Progress", <StatusBreakdown key="p" job={j} />],
              ...(j.software ? softwareDetails(j.software) : j.hardening ? hardeningDetails(j.hardening) : scriptDetails(j, <ScriptArguments key="a" job={j} />)),
              ["Timeout", formatSeconds(j.timeoutSeconds)],
              ...(!j.finished ? [["Waits until", formatDateTime(j.expiresAt)] as [string, string]] : []),
              ["Started", formatDateTime(j.createdAt)],
              ["SHA-256", <Mono key="h">{j.sha256}</Mono>],
            ]}
          />
        </Card>
      </div>

      <ConfirmDialog
        open={stopping}
        onClose={() => setStopping(false)}
        onConfirm={() => stop.mutate()}
        title="Stop this job?"
        confirmLabel="Stop job"
        tone="danger"
        loading={stop.isPending}
        error={stop.error}
      >
        Runs still waiting for a device are canceled at once. Running scripts are stopped on their devices, within seconds when the device is online. Runs that
        already finished keep their results.
      </ConfirmDialog>
    </>
  );
}

type Row = [string, ReactNode];

/** What a library script job ran. */
function scriptDetails(j: Job, args: ReactNode): Row[] {
  return [
    [
      "Script",
      j.scriptId ? (
        <Link key="sc" to={`/scripts/${j.scriptId}`} className="text-accent hover:underline">
          {j.scriptName}
        </Link>
      ) : (
        <span key="sc">
          {j.scriptName} <span className="text-muted">(deleted from the library)</span>
        </span>
      ),
    ],
    ["Shell", SHELL_NAMES[j.shell] ?? j.shell],
    ["Arguments", args],
  ];
}

/** A script job's arguments: none, hidden without job.view_sensitive, or the values. */
function ScriptArguments({ job }: { job: Job }) {
  const args = useJobArguments(job);
  const count = job.argCount ?? 0;
  if (count === 0) return <span className="text-muted">None</span>;
  if (!job.canViewArguments) {
    return (
      <span className="text-muted">
        {plural(count, "argument")}. Hidden: needs permission to see job arguments (<code className="font-mono text-xs">job.view_sensitive</code>).
      </span>
    );
  }
  if (args.isPending) return <span className="text-muted">Loading…</span>;
  if (args.isError) return <ErrorState error={args.error} onRetry={() => void args.refetch()} />;
  return (
    <ol className="flex flex-wrap gap-1">
      {args.data.args.map((a, i) => (
        <li key={i}>
          <Mono className="whitespace-pre-wrap">{a === "" ? " " : a}</Mono>
        </li>
      ))}
    </ol>
  );
}

/** What a software job asked for (ADR-0028). */
function softwareDetails(sw: SoftwareAction): Row[] {
  return [
    ["Action", VERBS[sw.action]],
    ["Package", <Mono key="pkg">{sw.package}</Mono>],
    ...(sw.version ? [["Version", <Mono key="v">{sw.version}</Mono>] as Row] : []),
    ["Package manager", MANAGERS[sw.manager].label],
  ];
}

/** What a hardening job asked for (ADR-0051). */
function hardeningDetails(h: HardeningJob): Row[] {
  const o = h.options;
  const switches = [
    o.rootPasswordOff && "Root's password sign-in to SSH off",
    o.passwordOff && "Password sign-in to SSH off",
    o.epel && "fail2ban from EPEL",
  ].filter((s): s is string => Boolean(s));
  const lists: [string, string[] | undefined][] = [
    ["TCP ports kept open", o.allowTcp],
    ["UDP ports kept open", o.allowUdp],
    ["Never banned", o.trusted],
  ];
  return [
    ["Hardening", "Check"],
    [
      "Modules",
      <ol key="m" className="flex flex-wrap gap-1">
        {h.modules.map((m) => (
          <li key={m}>
            <Mono>{m}</Mono>
          </li>
        ))}
      </ol>,
    ],
    ...lists
      .filter(([, v]) => v && v.length > 0)
      .map(([label, v]) => [label, <Mono key={label}>{v!.join(", ")}</Mono>] as Row),
    ...(switches.length > 0 ? [["Options", switches.join("; ")] as Row] : []),
  ];
}

/** Runs the same script on the same devices with the same arguments, after checking them in the dialog. Hardening has no dialog yet. */
function RunAgain({ job }: { job: Job }) {
  if (job.hardening) return null;
  return job.software ? <SoftwareAgain job={job} software={job.software} /> : <ScriptAgain job={job} />;
}

/** Asks for the same software action on the same devices. */
function SoftwareAgain({ job, software }: { job: Job; software: SoftwareAction }) {
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  if (!can("software.manage")) return null;
  return (
    <>
      <Button icon={<RotateCcw className="size-4" aria-hidden />} onClick={() => setOpen(true)}>
        Run again
      </Button>
      <SoftwareDialog
        open={open}
        onClose={() => setOpen(false)}
        preset={{ ...software, deviceIds: (job.runs ?? []).map((r) => r.deviceId), timeoutSeconds: job.timeoutSeconds }}
      />
    </>
  );
}

function ScriptAgain({ job }: { job: Job }) {
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  // The script may be gone, or out of the caller's reach; then there is nothing to offer.
  const script = useApi<Script>(job.scriptId && can("script.run") ? `/scripts/${job.scriptId}` : null);
  const args = useJobArguments(job);
  if (!script.data?.canRun) return null;
  // Running it without the arguments it had would run something else: not offered until they are read, nor where hidden.
  const preset = (job.argCount ?? 0) === 0 ? [] : args.data?.args;
  if (!preset) return null;
  return (
    <>
      <Button icon={<RotateCcw className="size-4" aria-hidden />} onClick={() => setOpen(true)}>
        Run again
      </Button>
      <RunScriptDialog
        open={open}
        onClose={() => setOpen(false)}
        script={script.data}
        preset={{ deviceIds: (job.runs ?? []).map((r) => r.deviceId), args: preset, timeoutSeconds: job.timeoutSeconds, sha256: job.sha256 }}
      />
    </>
  );
}

function RunsTable({ jobId, runs }: { jobId: string; runs: JobRun[] }) {
  const navigate = useNavigate();
  const prefetch = usePrefetch();
  const ref = useRef<HTMLDivElement>(null);
  useRowKeys(ref, (link) => link.dataset.id && prefetch(`/job-runs/${link.dataset.id}`));
  if (runs.length === 0) return <p className="px-4 py-6 text-center text-sm text-muted">None of this job&rsquo;s devices are in organizations or sites you can see.</p>;
  return (
    <div ref={ref} className="overflow-x-auto">
      <table className="table-base">
        <thead>
          <tr>
            <th>Device</th>
            <th>Status</th>
            <th className="hidden sm:table-cell">Exit code</th>
            <th className="hidden md:table-cell">Took</th>
            <th className="hidden lg:table-cell">Finished</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((r) => {
            const to = `/jobs/${jobId}/runs/${r.id}`;
            const took = runElapsed(r);
            return (
              <tr key={r.id} className="cursor-pointer" onClick={() => navigate(to)} onMouseEnter={() => prefetch(`/job-runs/${r.id}`)}>
                <td>
                  <Link
                    to={to}
                    className="rounded-sm font-medium hover:text-accent"
                    data-row-link
                    data-id={r.id}
                    onClick={(e) => e.stopPropagation()}
                    onFocus={() => prefetch(`/job-runs/${r.id}`)}
                  >
                    {r.deviceName}
                  </Link>
                  <p className="max-w-52 truncate text-xs text-muted">
                    {r.organizationName} / {r.siteName}
                  </p>
                </td>
                <td>
                  <RunStatusBadge status={r.status} cancelRequested={r.cancelRequested} />
                </td>
                <td className="hidden font-mono text-xs tabular-nums sm:table-cell">{r.exitCode ?? <span className="font-sans text-sm text-muted">—</span>}</td>
                <td className="hidden whitespace-nowrap text-muted tabular-nums md:table-cell">{took === null ? "—" : formatElapsed(took)}</td>
                <td className="hidden whitespace-nowrap text-muted lg:table-cell" title={formatDateTime(r.finishedAt)}>
                  {r.finishedAt ? formatRelative(r.finishedAt) : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
