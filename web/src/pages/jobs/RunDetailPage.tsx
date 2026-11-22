import { useState } from "react";
import { Link, useParams } from "react-router";
import type { UseQueryResult } from "@tanstack/react-query";
import { CircleStop, Download, Trash2 } from "lucide-react";
import { api, API_BASE } from "../../api/client";
import { auditedRead, useApi, useApiMutation } from "../../api/hooks";
import type { JobRun, JobRunOutput, RunStatus } from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Button, buttonClasses, Card, ErrorState, KeyValueList, PageHeader, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { OutputView, RunStatusBadge } from "../scripts/parts";
import { formatElapsed, HELD_SENT_TEXT, HELD_TEXT, isOpen, programNote, programText, runElapsed } from "../scripts/scriptText";

const ERROR_TONE: Partial<Record<RunStatus, "danger" | "warn" | "info">> = {
  failed: "danger",
  timed_out: "warn",
  lost: "warn",
  expired: "warn",
  canceled: "info",
};

/** What is happening with a run, in a sentence, while it has not finished. */
function waitingFor(r: JobRun): string | null {
  if (r.status === "queued" && r.held) return `${HELD_TEXT[r.held]} It is waited for until ${formatDateTime(r.expiresAt)}.`;
  if (r.status === "queued") return `Waiting for ${r.deviceName} to pick it up. Offline devices are waited for until ${formatDateTime(r.expiresAt)}.`;
  if (r.status === "sent" && r.held) return `${HELD_SENT_TEXT[r.held]} It is waited for until ${formatDateTime(r.expiresAt)}.`;
  if (r.status === "sent") return `${r.deviceName} has the script and is about to start it.`;
  if (r.status === "running") {
    return r.cancelRequested
      ? `Stopping: ${r.deviceName} stops the script the next time it checks in.`
      : "Running. Output is sent when the script ends; this page updates on its own.";
  }
  return null;
}

/** The program the agent started, with its path, as the agent reported it (ADR-0064). */
function RunProgramText({ run }: { run: JobRun }) {
  const text = programText(run);
  if (!text) return <>—</>;
  const p = run.program;
  const note = programNote(p);
  return (
    <>
      <span className={p ? undefined : "text-muted"}>{text}</span>
      {note && <span className="block text-xs text-warn">{note}</span>}
      {p && <span className="block font-mono text-xs break-all text-muted">{p.path}</span>}
    </>
  );
}

/** Whether a finished run has output the caller may read: then the page asks for it, once. */
function hasOutput(r: JobRun | undefined): boolean {
  return Boolean(r?.canViewOutput && !isOpen(r.status) && !r.outputRemovedAt && (r.stdoutBytes ?? 0) + (r.stderrBytes ?? 0) > 0);
}

export function RunDetailPage() {
  const { runId = "" } = useParams();
  const toast = useToast();
  const run = useApi<JobRun>(`/job-runs/${runId}`, undefined, { refetchInterval: (d) => (d && isOpen(d.status) ? 2_000 : false) });
  // Each read of the output is audited, so it is asked for once, apart from the run (ADR-0063). Once the run says
  // the output was removed, the query is left and dropped.
  const output = useApi<JobRunOutput>(hasOutput(run.data) ? `/job-runs/${runId}/output` : null, undefined, auditedRead(["job-output", runId]));
  const [stopping, setStopping] = useState(false);
  const [removing, setRemoving] = useState(false);
  const stop = useApiMutation(() => api.post<JobRun>(`/job-runs/${runId}/cancel`), {
    invalidate: ["/jobs", "/job-runs"],
    onSuccess: (r) => {
      setStopping(false);
      toast.success(r.status === "canceled" ? "Canceled before it started." : "Stopping the script on the device.");
    },
  });
  const remove = useApiMutation(() => api.del<JobRun>(`/job-runs/${runId}/output`), {
    invalidate: ["/job-runs"],
    onSuccess: () => {
      setRemoving(false);
      toast.success("The run's output was removed.");
    },
  });

  if (run.isPending) return <Spinner />;
  if (run.isError) return <ErrorState error={run.error} onRetry={() => void run.refetch()} />;
  const r = run.data;
  const took = runElapsed(r);
  const open = isOpen(r.status);
  const waiting = waitingFor(r);
  // The server says whether this caller may remove output at the run's site.
  const removable = hasOutput(r) && Boolean(r.canRemoveOutput);
  // The run as JSON, with both streams: for a finished run whose output the caller may read and was not removed (ADR-0064).
  const downloadable = Boolean(r.canViewOutput) && !open && !r.outputRemovedAt;

  return (
    <>
      <PageHeader
        breadcrumb={
          <>
            <Link to="/jobs" className="hover:text-fg">
              Jobs
            </Link>
            <span className="mx-1.5" aria-hidden>
              /
            </span>
            <Link to={`/jobs/${r.jobId}`} className="hover:text-fg">
              {r.scriptName}
            </Link>
          </>
        }
        title={r.deviceName}
        subtitle={
          <>
            {r.scriptName}, started by {r.job?.createdBy ?? "someone"} <span title={formatDateTime(r.createdAt)}>{formatRelative(r.createdAt)}</span>
          </>
        }
        actions={
          r.canCancel && (
            <Button variant="danger-ghost" icon={<CircleStop className="size-4" aria-hidden />} onClick={() => setStopping(true)}>
              Stop run
            </Button>
          )
        }
      />

      {waiting && (
        <Alert tone={r.held ? "warn" : "info"} className="mb-5">
          <span role="status">{waiting}</span>
        </Alert>
      )}
      {!open && r.error && (
        <Alert tone={ERROR_TONE[r.status] ?? "info"} className="mb-5">
          {r.error}
        </Alert>
      )}

      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
        <Card
          title="Output"
          className="min-w-0 xl:col-span-2"
          actions={
            (downloadable || removable) && (
              <div className="flex items-center gap-1.5">
                {downloadable && (
                  <a href={outputDownload(r.id, "json")} download className={buttonClasses("secondary", "sm")}>
                    <Download className="size-3.5" aria-hidden />
                    Download run
                  </a>
                )}
                {removable && (
                  <Button size="sm" variant="danger-ghost" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={() => setRemoving(true)}>
                    Remove output
                  </Button>
                )}
              </div>
            )
          }
        >
          <RunOutput run={r} open={open} output={output} />
        </Card>
        <Card title="Details">
          <KeyValueList
            narrow
            items={[
              ["Status", <RunStatusBadge key="s" status={r.status} cancelRequested={r.cancelRequested} />],
              ["Exit code", r.exitCode === null ? "—" : <span className="font-mono text-xs tabular-nums">{r.exitCode}</span>],
              ["Program", <RunProgramText key="p" run={r} />],
              [
                "Device",
                <Link key="d" to={`/devices/${r.deviceId}`} className="text-accent hover:underline">
                  {r.deviceName}
                </Link>,
              ],
              [
                "Site",
                <Link key="si" to={`/sites/${r.siteId}`} className="text-accent hover:underline">
                  {r.organizationName} / {r.siteName}
                </Link>,
              ],
              ["Queued", formatDateTime(r.createdAt)],
              ["Delivered", r.sentAt ? `${formatDateTime(r.sentAt)}${r.deliveries > 1 ? ` (${r.deliveries} times)` : ""}` : "—"],
              ["Started", formatDateTime(r.startedAt)],
              ["Finished", formatDateTime(r.finishedAt)],
              ["Took", took === null ? "—" : formatElapsed(took)],
            ]}
          />
        </Card>
      </div>

      <ConfirmDialog
        open={stopping}
        onClose={() => setStopping(false)}
        onConfirm={() => stop.mutate()}
        title={`Stop the run on ${r.deviceName}?`}
        confirmLabel="Stop run"
        tone="danger"
        loading={stop.isPending}
        error={stop.error}
      >
        {r.status === "running"
          ? "The script is stopped on the device, within seconds when it is online. Whatever it already changed stays changed."
          : "It has not started, so it is canceled at once and never runs."}
      </ConfirmDialog>
      <ConfirmDialog
        open={removing}
        onClose={() => setRemoving(false)}
        onConfirm={() => remove.mutate()}
        title="Remove this run's output?"
        confirmLabel="Remove output"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        The output is emptied for everyone, and the audit log records that you removed it. Backups made before keep it.
      </ConfirmDialog>
    </>
  );
}

/** The Output card's content: hidden, removed, empty, or what the run printed. */
function RunOutput({ run: r, open, output }: { run: JobRun; open: boolean; output: UseQueryResult<JobRunOutput> }) {
  if (open) return <p className="text-sm text-muted">The device sends the script&rsquo;s output when it ends.</p>;
  if (!r.canViewOutput) {
    return (
      <p className="text-sm text-muted">
        Hidden: needs permission to see job output (<code className="font-mono text-xs">job.view_sensitive</code>).
      </p>
    );
  }
  if (r.outputRemovedAt) {
    return (
      <p className="text-sm text-muted">
        The output was removed <span title={formatDateTime(r.outputRemovedAt)}>{formatRelative(r.outputRemovedAt)}</span>, by retention or by someone who
        could read it.
      </p>
    );
  }
  if (!hasOutput(r)) {
    return (
      <div className="flex flex-col gap-4">
        <OutputView title="Standard output" text="" truncated={false} emptyLabel="Nothing was written to standard output." />
        <OutputView title="Standard error" text="" truncated={false} emptyLabel="Nothing was written to standard error." />
      </div>
    );
  }
  if (output.isPending) return <Spinner label="Loading output…" />;
  if (output.isError) return <ErrorState error={output.error} onRetry={() => void output.refetch()} />;
  const o = output.data;
  return (
    <div className="flex flex-col gap-4">
      <OutputView
        title="Standard output"
        text={o.stdout}
        truncated={o.stdoutTruncated}
        emptyLabel="Nothing was written to standard output."
        download={outputDownload(r.id, "stdout")}
      />
      <OutputView
        title="Standard error"
        text={o.stderr}
        truncated={o.stderrTruncated}
        emptyLabel="Nothing was written to standard error."
        download={outputDownload(r.id, "stderr")}
      />
      <p className="text-xs text-muted">Opening or downloading a run&rsquo;s output is recorded in the audit log, each time.</p>
    </div>
  );
}

/** Where the server sends a run's stream, or the run as JSON, as a file (ADR-0064). */
function outputDownload(runId: string, what: "stdout" | "stderr" | "json"): string {
  return `${API_BASE}/job-runs/${encodeURIComponent(runId)}/output?download=${what}`;
}
