import { useEffect, useId, useState } from "react";
import { Link } from "react-router";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { PatchActionInput, PatchActionResult, PatchJobDetail } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, ErrorState, InlineError, Input, KeyValueList, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { categoryLabel, isActiveJob, jobOutcome, jobTypeLabel, PatchJobBadge, requester } from "./patchText";

/** What the patching views refresh after an action. */
export const PATCH_KEYS = ["/patching", "/audit"];

export interface PatchTarget {
  id: string;
  name: string;
}

/** The outcome of a scan or install, said in a toast; devices that did not start are listed in a dialog. */
function useOutcome() {
  const toast = useToast();
  const [result, setResult] = useState<PatchActionResult | null>(null);
  const report = (verb: string, r: PatchActionResult) => {
    if (r.succeeded > 0) toast.success(`${verb} on ${plural(r.succeeded, "device")}.`);
    if (r.failed > 0) setResult(r);
  };
  const dialog = <ResultDialog result={result} onClose={() => setResult(null)} />;
  return { report, dialog };
}

function ResultDialog({ result, onClose }: { result: PatchActionResult | null; onClose: () => void }) {
  const failed = result?.results.filter((r) => !r.ok) ?? [];
  return (
    <Dialog
      open={result !== null}
      onClose={onClose}
      title={`${plural(failed.length, "device")} did not start`}
      description={result && result.succeeded > 0 ? `${plural(result.succeeded, "other device")} did.` : undefined}
      footer={<Button onClick={onClose}>Close</Button>}
    >
      <ul className="divide-y divide-line rounded-md border border-line">
        {failed.map((r) => (
          <li key={r.deviceId} className="px-3 py-2.5 text-sm">
            <Link to={`/devices/${r.deviceId}?tab=patches`} className="font-medium hover:text-accent">
              {r.deviceName}
            </Link>
            <p className="text-muted">{r.message || "EasyPatch did not say why."}</p>
          </li>
        ))}
      </ul>
    </Dialog>
  );
}

/** Scans devices for updates at once. */
export function useScan() {
  const outcome = useOutcome();
  const scan = useApiMutation((ids: string[]) => api.post<PatchActionResult>("/patching/scan", { deviceIds: ids }), {
    invalidate: PATCH_KEYS,
    onSuccess: (r) => outcome.report("Scan started", r),
  });
  return { scan, dialog: outcome.dialog };
}

/** A datetime-local value for a time, in the browser's zone. */
function localInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Tonight at 22:00, or tomorrow's if that has passed. */
function tonight(now = new Date()): Date {
  const d = new Date(now);
  d.setHours(22, 0, 0, 0);
  if (d.getTime() - now.getTime() < 15 * 60_000) d.setDate(d.getDate() + 1);
  return d;
}

/**
 * Installs updates on devices: every eligible update, or chosen ones on one device. Where EasyPatch can schedule
 * (scheduled-installs), the install can wait for a time.
 */
export function InstallDialog({
  open,
  onClose,
  devices,
  updates,
  canSchedule,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  devices: PatchTarget[];
  /** Chosen updates (one device only); every eligible update when absent. */
  updates?: { id: string; title: string }[];
  canSchedule: boolean;
  onDone?: () => void;
}) {
  const outcome = useOutcome();
  const [when, setWhen] = useState<"now" | "later">("now");
  const [at, setAt] = useState(() => localInput(tonight()));
  const whenId = useId();
  useEffect(() => {
    if (open) {
      setWhen("now");
      setAt(localInput(tonight()));
    }
  }, [open]);

  const install = useApiMutation((body: PatchActionInput) => api.post<PatchActionResult>("/patching/install", body), {
    invalidate: PATCH_KEYS,
    onSuccess: (r) => {
      outcome.report(when === "later" ? "Install scheduled" : "Install started", r);
      onClose();
      onDone?.();
    },
  });
  useEffect(() => {
    if (open) install.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when the dialog opens, not when the mutation changes
  }, [open]);

  const scheduledAt = when === "later" && at ? new Date(at) : null;
  const badTime = scheduledAt !== null && Number.isNaN(scheduledAt.getTime());
  const what = updates ? plural(updates.length, "chosen update") : "every update its policy allows";
  const where = devices.length === 1 ? devices[0]!.name : plural(devices.length, "device");

  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={updates ? `Install ${plural(updates.length, "update")} on ${where}` : `Install updates on ${where}`}
        description={`EasyPatch installs ${what}, downloading what it needs. Updates that need a restart finish at the next one, which the device's EasyPatch policy may schedule.`}
        footer={
          <>
            <Button onClick={onClose} disabled={install.isPending}>
              Cancel
            </Button>
            <Button
              variant="primary"
              loading={install.isPending}
              disabled={badTime || (when === "later" && !at)}
              onClick={() =>
                install.mutate({
                  deviceIds: devices.map((d) => d.id),
                  updateIds: updates?.map((u) => u.id),
                  scheduledAt: scheduledAt && !badTime ? scheduledAt.toISOString() : undefined,
                })
              }
            >
              {when === "later" ? "Schedule install" : "Install now"}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {updates && (
            <ul className="max-h-40 list-disc space-y-0.5 overflow-y-auto pl-5 text-sm">
              {updates.map((u) => (
                <li key={u.id} className="break-words">
                  {u.title}
                </li>
              ))}
            </ul>
          )}
          {canSchedule ? (
            <fieldset className="space-y-2" aria-describedby={whenId}>
              <legend className="text-xs font-medium text-muted">When</legend>
              <label className="flex items-center gap-2 text-sm">
                <input type="radio" name="when" checked={when === "now"} onChange={() => setWhen("now")} className="size-4 accent-accent" />
                Now
              </label>
              <label className="flex flex-wrap items-center gap-2 text-sm">
                <input type="radio" name="when" checked={when === "later"} onChange={() => setWhen("later")} className="size-4 accent-accent" />
                At
                <Input
                  type="datetime-local"
                  aria-label="Install at"
                  value={at}
                  min={localInput(new Date())}
                  onChange={(e) => {
                    setAt(e.target.value);
                    setWhen("later");
                  }}
                  className="w-auto"
                />
              </label>
              <p id={whenId} className="text-xs text-subtle">
                Your time zone ({Intl.DateTimeFormat().resolvedOptions().timeZone}). Up to 31 days ahead; the device must be online then.
              </p>
            </fieldset>
          ) : (
            <p className="text-xs text-muted">
              Installs start when each device next checks in with EasyPatch. Installing at a later time needs an EasyPatch server with scheduled installs.
            </p>
          )}
          <InlineError error={install.error} fields={["scheduledAt", "updateIds", "deviceIds"]} />
        </div>
      </Dialog>
      {outcome.dialog}
    </>
  );
}

/** One EasyPatch job: its updates and what happened, refreshing while it runs; cancellable where the caller may. */
export function PatchJobDialog({ jobId, onClose }: { jobId: string | null; onClose: () => void }) {
  const toast = useToast();
  const job = useApi<PatchJobDetail>(jobId ? `/patching/jobs/${jobId}` : null, undefined, {
    refetchInterval: (data) => (data && !isActiveJob(data.summary) ? false : 4_000),
  });
  const cancel = useApiMutation(() => api.post<PatchJobDetail>(`/patching/jobs/${jobId}/cancel`), {
    invalidate: PATCH_KEYS,
    onSuccess: (j) => toast.success(isActiveJob(j.summary) ? "Asked the device to stop." : "Job cancelled."),
  });
  useEffect(() => {
    cancel.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when another job opens
  }, [jobId]);
  const d = job.data;
  const s = d?.summary;
  const outcome = s ? jobOutcome(s) : "";

  return (
    <Dialog
      open={jobId !== null}
      onClose={onClose}
      size="lg"
      title={s ? `${jobTypeLabel(s.type)} on ${d.deviceName}` : "Patch job"}
      footer={
        <>
          {d?.canManage && s && isActiveJob(s) && !s.cancelRequested && (
            <Button variant="danger-ghost" loading={cancel.isPending} onClick={() => cancel.mutate()}>
              Cancel job
            </Button>
          )}
          <Button onClick={onClose}>Close</Button>
        </>
      }
    >
      {job.isPending ? (
        <Spinner />
      ) : job.isError ? (
        <ErrorState error={job.error} onRetry={() => void job.refetch()} compact />
      ) : (
        s && (
          <div className="space-y-4">
            <InlineError error={cancel.error} />
            {s.errorMessage && (
              <Alert tone="danger" title="EasyPatch reported an error">
                {s.errorMessage}
                {s.errorCode && <span className="block text-xs text-muted">{s.errorCode}</span>}
              </Alert>
            )}
            <KeyValueList
              narrow
              items={[
                ["Status", <PatchJobBadge key="s" job={s} />],
                ...(s.progressMessage && isActiveJob(s) ? [["Now", s.progressMessage] as [string, string]] : []),
                ...(outcome ? [["Result", outcome] as [string, string]] : []),
                ...(d.notBefore ? [["Starts", formatDateTime(d.notBefore)] as [string, string]] : []),
                [
                  "Requested",
                  <span key="r">
                    {formatDateTime(s.createdAt)} <span className="text-muted">by {requester(s.requestedBy)}</span>
                  </span>,
                ],
                ...(s.completedAt ? [["Finished", formatDateTime(s.completedAt)] as [string, string]] : []),
                ...(s.rebootRequired ? [["Restart", "Needed to finish"] as [string, string]] : []),
              ]}
            />
            {d.items.length > 0 && (
              <div>
                <h3 className="mb-1.5 text-xs font-medium text-muted">Updates</h3>
                <ul className="divide-y divide-line rounded-md border border-line">
                  {d.items.map((it) => (
                    <li key={it.updateGuid} className="flex items-start justify-between gap-3 px-3 py-2 text-sm">
                      <span className="min-w-0">
                        <span className="block break-words">{it.title}</span>
                        <span className="text-xs text-muted">
                          {categoryLabel(it.category)}
                          {it.skipReason && ` · ${it.skipReason}`}
                          {it.errorMessage && <span className="text-danger"> · {it.errorMessage}</span>}
                        </span>
                      </span>
                      <Badge tone={it.status === "Succeeded" ? "ok" : it.status === "Failed" ? "danger" : "neutral"}>
                        {it.status}
                        {it.installPercent !== null && it.status === "Installing" ? ` · ${it.installPercent}%` : ""}
                        {it.downloadPercent !== null && it.status === "Downloading" ? ` · ${it.downloadPercent}%` : ""}
                      </Badge>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {d.events.length > 0 && (
              <div>
                <h3 className="mb-1.5 text-xs font-medium text-muted">Events</h3>
                <ol className="space-y-1 text-sm">
                  {d.events.map((e) => (
                    <li key={e.id} className="flex gap-3">
                      <span className="shrink-0 text-xs whitespace-nowrap text-muted tabular-nums" title={formatDateTime(e.createdAt)}>
                        {formatRelative(e.createdAt)}
                      </span>
                      <span className={e.severity === "Error" ? "text-danger" : e.severity === "Warning" ? "text-warn" : undefined}>{e.message}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        )
      )}
    </Dialog>
  );
}
