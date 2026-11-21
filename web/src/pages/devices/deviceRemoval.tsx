import { Trash2 } from "lucide-react";
import { type ReactNode, useState } from "react";
import { useNavigate } from "react-router";
import { api } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { Device, DeviceRemovalResult } from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Button } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";

// Removing a device (ADR-0050): its agent uninstalls itself, with MeshAgent and the EasyPatch agent, and confirms; the
// device is deleted then. One that cannot confirm is removed by force.

/** What removing deletes, said once in each dialog. */
const DELETES = "Its alerts, inventory, metrics and script history are deleted with it; the audit log keeps what happened.";

function useRemoval(d: Device) {
  const toast = useToast();
  const navigate = useNavigate();
  const gone = () => {
    toast.success(`Removed ${d.name}.`);
    void navigate("/devices", { replace: true });
  };
  const request = useApiMutation(() => api.post<DeviceRemovalResult>(`/devices/${d.id}/removal`), {
    invalidate: (r) => (r.status === "removed" ? ["/devices"] : [`/devices/${d.id}`, "/devices"]),
    onSuccess: (r) => (r.status === "removed" ? gone() : toast.success(`${d.name} uninstalls its agents the next time it checks in.`)),
  });
  const cancel = useApiMutation(() => api.del<Device>(`/devices/${d.id}/removal`), {
    invalidate: [`/devices/${d.id}`, "/devices"],
    onSuccess: () => toast.success(`${d.name} stays in EasyRMM.`),
  });
  const force = useApiMutation(() => api.del(`/devices/${d.id}`), { invalidate: ["/devices"], onSuccess: gone });
  return { request, cancel, force };
}

/** The device page's button that asks for the device's removal. */
export function RemoveDeviceButton({ device: d }: { device: Device }) {
  const [open, setOpen] = useState(false);
  const { request } = useRemoval(d);
  if (!d.canRemove || d.removal) return null;
  const agent = d.agent !== null;
  return (
    <>
      <Button icon={<Trash2 className="size-4" aria-hidden />} onClick={() => setOpen(true)}>
        Remove
      </Button>
      <ConfirmDialog
        open={open}
        onClose={() => setOpen(false)}
        onConfirm={() => request.mutate(undefined, { onSuccess: () => setOpen(false) })}
        title={`Remove ${d.name}?`}
        confirmLabel={agent ? "Remove device" : "Remove now"}
        tone="danger"
        loading={request.isPending}
        error={request.error}
      >
        {agent ? (
          <div className="space-y-2">
            <p>
              The next time {d.name} checks in, its EasyRMM agent uninstalls itself, with MeshAgent and the EasyPatch agent, and confirms. EasyRMM removes the
              device then.
            </p>
            <p className="text-muted">{DELETES}</p>
          </div>
        ) : (
          <div className="space-y-2">
            <p>
              {d.name} has no EasyRMM agent, so it is removed now. If its MeshAgent is connected, MeshCentral uninstalls it; MeshCentral forgets the device
              either way.
            </p>
            <p className="text-muted">{DELETES}</p>
          </div>
        )}
      </ConfirmDialog>
    </>
  );
}

/** Where a device's removal stands, with what can be done about it. */
export function RemovalBanner({ device: d }: { device: Device }) {
  const [forcing, setForcing] = useState(false);
  const { request, cancel, force } = useRemoval(d);
  const r = d.removal;
  if (!r) return null;
  const failed = r.error !== "";
  const asked = <span title={formatDateTime(r.requestedAt)}>{formatRelative(r.requestedAt)}</span>;
  let title: string;
  let body: ReactNode;
  if (failed) {
    title = "The agent could not uninstall itself";
    body = (
      <>
        <span className="block break-words">{r.error}</span>
        <span className="mt-1 block text-muted">
          The device keeps working as before. Ask again once the problem is fixed, or remove the device anyway.
        </span>
      </>
    );
  } else if (r.sentAt) {
    title = "The agent is uninstalling itself";
    body = (
      <>
        Asked {asked}; {d.name} got the instruction <span title={formatDateTime(r.sentAt)}>{formatRelative(r.sentAt)}</span>. EasyRMM removes the device once
        the agent confirms.
      </>
    );
  } else {
    title = "Waiting for the agent to check in";
    body = (
      <>
        Asked {asked}. {d.name} gets the instruction to uninstall itself the next time it checks in
        {d.online ? ", within a minute." : <>; it was last seen <span title={formatDateTime(d.lastSeenAt)}>{formatRelative(d.lastSeenAt)}</span>.</>}
      </>
    );
  }
  const busy = request.isPending || cancel.isPending || force.isPending;
  return (
    <Alert tone={failed ? "danger" : "warn"} className="mb-5" title={title}>
      {body}
      {d.canRemove && (
        <span className="mt-2.5 flex flex-wrap gap-2">
          {failed && (
            <Button size="sm" onClick={() => request.mutate(undefined)} loading={request.isPending} disabled={busy}>
              Ask again
            </Button>
          )}
          <Button size="sm" variant="danger" onClick={() => setForcing(true)} disabled={busy}>
            {failed ? "Remove anyway" : "Remove now"}
          </Button>
          <Button size="sm" onClick={() => cancel.mutate(undefined)} loading={cancel.isPending} disabled={busy}>
            Keep the device
          </Button>
        </span>
      )}
      {(request.error ?? cancel.error) && <span className="mt-1.5 block text-xs text-danger">{(request.error ?? cancel.error)?.message}</span>}
      <ConfirmDialog
        open={forcing}
        onClose={() => setForcing(false)}
        onConfirm={() => force.mutate(undefined)}
        title={`Remove ${d.name} without its agent?`}
        confirmLabel="Remove anyway"
        tone="danger"
        loading={force.isPending}
        error={force.error}
      >
        <div className="space-y-2">
          <p>
            EasyRMM removes the device now. If its agent checks in within 90 days, it is told to uninstall itself then, and MeshCentral forgets the device
            either way.
          </p>
          <p className="text-muted">{DELETES}</p>
        </div>
      </ConfirmDialog>
    </Alert>
  );
}
