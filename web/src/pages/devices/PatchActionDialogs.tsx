import { useEffect, useId, useState } from "react";
import { MessageSquare } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import { PATCH_AGENT_CAN, type Device, type PatchActionResult, type PatchEndpointDetail, type PatchMessagePreset, type PatchUpdate } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Button, cx, Field, InlineError, Input, Spinner, TextField } from "../../components/ui";
import { plural } from "../../lib/format";
import { PATCH_KEYS } from "../patching/PatchDialogs";

// What a device's Patches tab does beyond scans, installs and restarts: exclusions, removing an
// update, messages to users and agent updates. EasyRMM checks patch.manage on the device; EasyPatch refuses what the
// device's agent cannot do, and the refusal is shown in the dialog.

const MAX_REASON = 500;

/** The one device's outcome of an action, or null when it went through. */
function refusal(r: PatchActionResult): string | null {
  const first = r.results[0];
  return r.failed > 0 ? first?.message || "The patching engine did not say why." : null;
}

/** Keeps an update off the device: EasyPatch no longer installs it there, automatically or with every update. */
export function ExcludeDialog({ device, update, onClose }: { device: Device; update: PatchUpdate | null; onClose: () => void }) {
  const toast = useToast();
  const [reason, setReason] = useState("");
  const exclude = useApiMutation(
    (vars: { updateId: string; reason: string }) => api.post<void>(`/patching/devices/${device.id}/exclusions`, vars),
    {
      invalidate: PATCH_KEYS,
      onSuccess: () => {
        toast.success(`Excluded on ${device.name}.`);
        onClose();
      },
    },
  );
  const reset = exclude.reset;
  useEffect(() => {
    if (update) {
      setReason("");
      reset();
    }
  }, [update, reset]);
  return (
    <Dialog
      open={update !== null}
      onClose={onClose}
      size="sm"
      title={`Exclude this update on ${device.name}?`}
      footer={
        <>
          <Button onClick={onClose} disabled={exclude.isPending}>
            Cancel
          </Button>
          <Button variant="primary" loading={exclude.isPending} onClick={() => update && exclude.mutate({ updateId: update.updateGuid, reason: reason.trim() })}>
            Exclude update
          </Button>
        </>
      }
    >
      {update && (
        <div className="flex flex-col gap-3 text-sm">
          <p>
            <strong className="font-medium break-words">{update.title}</strong> is not installed on {device.name}, automatically or with every update,
            and no longer counts against its patch status.{" "}
            {update.package
              ? "This version only: a newer version of the package is a new update."
              : "To keep a KB off every device, the policy excludes it instead."}
          </p>
          <TextField
            label="Reason (optional)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={MAX_REASON}
            placeholder="Breaks the line-of-business app"
            error={fieldError(exclude.error, "reason")}
          />
          <InlineError error={exclude.error} fields={["reason"]} />
        </div>
      )}
    </Dialog>
  );
}

/** Lets EasyPatch install an update excluded on the device again; a refusal is said in a toast. */
export function useInclude(device: Pick<Device, "id" | "name">) {
  const toast = useToast();
  const m = useApiMutation((updateId: string) => api.del(`/patching/devices/${device.id}/exclusions/${updateId}`), {
    invalidate: PATCH_KEYS,
    onSuccess: () => toast.success(`Included again on ${device.name}.`),
  });
  return { ...m, include: (updateId: string) => m.mutate(updateId, { onError: (e) => toast.error(e.message) }) };
}

/** Has the device uninstall an installed Windows update. The agent never restarts the computer for it. */
export function RemoveUpdateDialog({ device, update, onClose, onDone }: { device: Device; update: PatchUpdate | null; onClose: () => void; onDone?: () => void }) {
  const toast = useToast();
  const [block, setBlock] = useState(true);
  const [reason, setReason] = useState("");
  const [refused, setRefused] = useState<string | null>(null);
  const remove = useApiMutation(
    (vars: { updateId: string; block: boolean; reason: string }) =>
      api.post<PatchActionResult>(`/patching/devices/${device.id}/updates/${vars.updateId}/remove`, { block: vars.block, reason: vars.reason }),
    {
      invalidate: PATCH_KEYS,
      onSuccess: (r) => {
        const why = refusal(r);
        if (why) return setRefused(why);
        toast.success(`Removal queued on ${device.name}.`);
        onClose();
        onDone?.();
      },
    },
  );
  const reset = remove.reset;
  useEffect(() => {
    if (update) {
      setBlock(true);
      setReason("");
      setRefused(null);
      reset();
    }
  }, [update, reset]);
  const blockId = useId();
  return (
    <Dialog
      open={update !== null}
      onClose={onClose}
      title={`Remove this update from ${device.name}?`}
      footer={
        <>
          <Button onClick={onClose} disabled={remove.isPending}>
            Cancel
          </Button>
          <Button
            variant="danger"
            loading={remove.isPending}
            onClick={() => update && remove.mutate({ updateId: update.updateGuid, block, reason: block ? reason.trim() : "" })}
          >
            Remove update
          </Button>
        </>
      }
    >
      {update && (
        <div className="flex flex-col gap-4 text-sm">
          <p>
            <strong className="font-medium break-words">{update.title}</strong>
          </p>
          <p className="text-muted">
            The agent uses Windows Update’s own uninstall where the update supports it, and otherwise has DISM remove its package, as Microsoft documents
            for cumulative updates. It never restarts the computer: when Windows needs a restart to finish, the job says so. Windows does not let some
            updates be removed, such as servicing stack updates; the job then fails and nothing changes.
          </p>
          <div>
            <label className="flex items-start gap-2">
              <input type="checkbox" className="mt-0.5 size-4 accent-accent" checked={block} onChange={(e) => setBlock(e.target.checked)} aria-describedby={blockId} />
              <span>Exclude it on {device.name}</span>
            </label>
            <p id={blockId} className="mt-1 pl-6 text-xs text-subtle">
              The patching engine then does not install it again. Windows Update can still offer it if the computer also updates outside EasyRMM.
            </p>
          </div>
          {block && (
            <TextField
              label="Reason (optional)"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={MAX_REASON}
              placeholder="Breaks printing"
              error={fieldError(remove.error, "reason")}
            />
          )}
          {refused && (
            <Alert tone="danger" title="The patching engine refused the removal">
              {refused}
            </Alert>
          )}
          <InlineError error={remove.error} fields={block ? ["reason"] : []} />
        </div>
      )}
    </Dialog>
  );
}

/** Who is signed in to the device, and whether the EasyPatch icon can reach them. */
export function SessionSummary({ endpoint, platform }: { endpoint: PatchEndpointDetail; platform: Device["platform"] }) {
  const users = endpoint.signedInUsers;
  const trays = endpoint.trayConnectedSessions ?? 0;
  if (users === null) return <span className="text-muted">Unknown until the agent reports</span>;
  if (users === 0) return <span>Nobody is signed in</span>;
  const who = plural(users, "user");
  if (platform !== "windows" || !(endpoint.agentCapabilities ?? []).includes(PATCH_AGENT_CAN.tray)) {
    return <span>{who} signed in</span>;
  }
  return (
    <span>
      {who} signed in
      <span className={cx("block text-xs", trays < users ? "text-warn" : "text-muted")}>
        {trays === users
          ? "The EasyPatch icon is running in every session"
          : `The EasyPatch icon is running in ${trays.toLocaleString()} of ${plural(users, "session")}`}
      </span>
    </span>
  );
}

/** A datetime-local value for a time, in the browser's zone. */
function localInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Shows one of EasyPatch's preset messages to the people signed in to a Windows device, from the EasyPatch icon. */
export function MessageDialog({ open, onClose, device, endpoint }: { open: boolean; onClose: () => void; device: Device; endpoint: PatchEndpointDetail }) {
  const toast = useToast();
  const presets = useApi<{ items: PatchMessagePreset[] }>(open ? "/patching/messages" : null, undefined, { staleTime: 3_600_000 });
  const [preset, setPreset] = useState("SaveYourWork");
  const [at, setAt] = useState("");
  const [refused, setRefused] = useState<string | null>(null);
  const atId = useId();
  const send = useApiMutation((body: { deviceIds: string[]; preset: string; restartAt?: string }) => api.post<PatchActionResult>("/patching/notify", body), {
    invalidate: PATCH_KEYS,
    onSuccess: (r) => {
      const why = refusal(r);
      if (why) return setRefused(why);
      toast.success(`Message sent to ${device.name}. It shows at the agent's next check-in.`);
      onClose();
    },
  });
  const reset = send.reset;
  useEffect(() => {
    if (!open) return;
    const soon = new Date(Date.now() + 3_600_000);
    soon.setMinutes(0, 0, 0);
    setPreset("SaveYourWork");
    setAt(localInput(soon));
    setRefused(null);
    reset();
  }, [open, reset]);

  const chosen = presets.data?.items.find((p) => p.preset === preset);
  const restartAt = chosen?.needsRestartTime && at ? new Date(at) : null;
  const badTime = !!chosen?.needsRestartTime && (!restartAt || Number.isNaN(restartAt.getTime()) || restartAt.getTime() <= Date.now());
  const atText = restartAt && !Number.isNaN(restartAt.getTime()) ? restartAt.toLocaleString([], { weekday: "long", hour: "numeric", minute: "2-digit" }) : "…";
  const nobody = endpoint.signedInUsers === 0;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Message the users of ${device.name}`}
      description="A notification from the EasyPatch icon in the corner of their screen. Only these preset messages can be sent."
      footer={
        <>
          <Button onClick={onClose} disabled={send.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            icon={<MessageSquare className="size-4" aria-hidden />}
            loading={send.isPending}
            disabled={!chosen || badTime}
            onClick={() =>
              send.mutate({ deviceIds: [device.id], preset, restartAt: chosen?.needsRestartTime && restartAt ? restartAt.toISOString() : undefined })
            }
          >
            Send message
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4 text-sm">
        <p className={cx(nobody ? "text-warn" : "text-muted")}>
          <SessionSummary endpoint={endpoint} platform={device.platform} />
        </p>
        {presets.isPending ? (
          <Spinner />
        ) : presets.isError ? (
          <InlineError error={presets.error} />
        ) : (
          <fieldset className="flex flex-col gap-2">
            <legend className="sr-only">Message</legend>
            {presets.data.items.map((p) => (
              <label
                key={p.preset}
                className={cx(
                  "flex cursor-pointer gap-3 rounded-md border px-3 py-2",
                  p.preset === preset ? "border-accent bg-accent-soft" : "border-line hover:bg-hover",
                )}
              >
                <input type="radio" name="preset" className="mt-1 size-4 accent-accent" checked={p.preset === preset} onChange={() => setPreset(p.preset)} />
                <span className="min-w-0">
                  <span className="block font-medium">{p.title}</span>
                  <span className="block text-xs text-muted">{p.needsRestartTime ? p.body.replace("{time}", atText) : p.body}</span>
                </span>
              </label>
            ))}
          </fieldset>
        )}
        {chosen?.needsRestartTime && (
          <Field
            label="Restart time the message names"
            htmlFor={atId}
            hint={`Your time zone (${Intl.DateTimeFormat().resolvedOptions().timeZone}). The message only names the time: restart the device with Restart….`}
            error={fieldError(send.error, "restartAt")}
          >
            <Input
              id={atId}
              type="datetime-local"
              value={at}
              min={localInput(new Date())}
              onChange={(e) => setAt(e.target.value)}
              aria-invalid={fieldError(send.error, "restartAt") ? true : undefined}
              className="w-auto self-start"
            />
          </Field>
        )}
        {refused && (
          <Alert tone="danger" title="The patching engine did not send the message">
            {refused}
          </Alert>
        )}
        <InlineError error={send.error} fields={chosen?.needsRestartTime ? ["restartAt"] : []} />
      </div>
    </Dialog>
  );
}

/** Has the device's EasyPatch agent update itself to the newest package EasyPatch hosts whose signature it accepts. */
export function AgentUpdateDialog({ open, onClose, device, endpoint }: { open: boolean; onClose: () => void; device: Device; endpoint: PatchEndpointDetail }) {
  const toast = useToast();
  const [refused, setRefused] = useState<string | null>(null);
  const update = useApiMutation((ids: string[]) => api.post<PatchActionResult>("/patching/agent-update", { deviceIds: ids }), {
    invalidate: PATCH_KEYS,
    onSuccess: (r) => {
      const why = refusal(r);
      if (why) return setRefused(why);
      toast.success(`Agent update queued on ${device.name}.`);
      onClose();
    },
  });
  const reset = update.reset;
  useEffect(() => {
    if (open) {
      setRefused(null);
      reset();
    }
  }, [open, reset]);
  const to = endpoint.agentUpdate?.availableVersion;
  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="sm"
      title={`Update the EasyPatch agent on ${device.name}?`}
      footer={
        <>
          <Button onClick={onClose} disabled={update.isPending}>
            Cancel
          </Button>
          <Button variant="primary" loading={update.isPending} onClick={() => update.mutate([device.id])}>
            Update agent
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        <p>
          From {endpoint.summary.agentVersion} to {to || "the newest version"}. At its next check-in the agent downloads the package, checks its release
          signature and installs it. A package whose signature the agent does not accept is not installed.
        </p>
        {refused && (
          <Alert tone="danger" title="The patching engine refused the update">
            {refused}
          </Alert>
        )}
        <InlineError error={update.error} />
      </div>
    </Dialog>
  );
}
