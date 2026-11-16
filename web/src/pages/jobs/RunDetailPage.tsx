import { useState } from "react";
import { Link, useParams } from "react-router";
import { CircleStop } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { JobRun, RunStatus } from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Button, Card, ErrorState, KeyValueList, PageHeader, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { OutputView, RunStatusBadge } from "../scripts/parts";
import { formatElapsed, isOpen, runElapsed } from "../scripts/scriptText";

const ERROR_TONE: Partial<Record<RunStatus, "danger" | "warn" | "info">> = {
  failed: "danger",
  timed_out: "warn",
  lost: "warn",
  expired: "warn",
  canceled: "info",
};

/** What is happening with a run, in a sentence, while it has not finished. */
function waitingFor(r: JobRun): string | null {
  if (r.status === "queued") return `Waiting for ${r.deviceName} to pick it up. Offline devices are waited for until ${formatDateTime(r.expiresAt)}.`;
  if (r.status === "sent") return `${r.deviceName} has the script and is about to start it.`;
  if (r.status === "running") {
    return r.cancelRequested
      ? `Stopping: ${r.deviceName} stops the script the next time it checks in.`
      : "Running. Output is sent when the script ends; this page updates on its own.";
  }
  return null;
}

export function RunDetailPage() {
  const { runId = "" } = useParams();
  const toast = useToast();
  const run = useApi<JobRun>(`/job-runs/${runId}`, undefined, { refetchInterval: (d) => (d && isOpen(d.status) ? 2_000 : false) });
  const [stopping, setStopping] = useState(false);
  const stop = useApiMutation(() => api.post<JobRun>(`/job-runs/${runId}/cancel`), {
    invalidate: ["/jobs", "/job-runs"],
    onSuccess: (r) => {
      setStopping(false);
      toast.success(r.status === "canceled" ? "Canceled before it started." : "Stopping the script on the device.");
    },
  });

  if (run.isPending) return <Spinner />;
  if (run.isError) return <ErrorState error={run.error} onRetry={() => void run.refetch()} />;
  const r = run.data;
  const took = runElapsed(r);
  const open = isOpen(r.status);
  const waiting = waitingFor(r);

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
        <Alert tone="info" className="mb-5">
          <span role="status">{waiting}</span>
        </Alert>
      )}
      {!open && r.error && (
        <Alert tone={ERROR_TONE[r.status] ?? "info"} className="mb-5">
          {r.error}
        </Alert>
      )}

      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
        <Card title="Output" className="min-w-0 xl:col-span-2">
          {open ? (
            <p className="text-sm text-muted">The device sends the script&rsquo;s output when it ends.</p>
          ) : (
            <div className="flex flex-col gap-4">
              <OutputView title="Standard output" text={r.stdout} truncated={r.stdoutTruncated} emptyLabel="Nothing was written to standard output." />
              <OutputView title="Standard error" text={r.stderr} truncated={r.stderrTruncated} emptyLabel="Nothing was written to standard error." />
            </div>
          )}
        </Card>
        <Card title="Details">
          <KeyValueList
            narrow
            items={[
              ["Status", <RunStatusBadge key="s" status={r.status} cancelRequested={r.cancelRequested} />],
              ["Exit code", r.exitCode === null ? "—" : <span className="font-mono text-xs tabular-nums">{r.exitCode}</span>],
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
    </>
  );
}
