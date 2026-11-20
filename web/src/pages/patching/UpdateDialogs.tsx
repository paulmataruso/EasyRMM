import { useEffect, useId, useState } from "react";
import { api, fieldError } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { PatchActionResult, PatchHold, PatchUpdateView } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Button, InlineError, SelectField, TextareaField, TextField } from "../../components/ui";
import { plural } from "../../lib/format";
import { PATCH_KEYS, useOutcome } from "./PatchDialogs";

// What Patching → Updates → an update does: install it or remove it across devices, and hold
// it. EasyRMM checks patch.manage on each device, and patch.configure for holds; EasyPatch says what became of each
// device.

const MAX_REASON = 500;

/** The organization and site the update page counts over; installing or removing "everywhere" means there. */
export interface UpdateScopeIds {
  organizationId: string;
  siteId: string;
}

/** The request's scope: only what is chosen (the server reads an empty id as a malformed one). */
function scopeBody(s: UpdateScopeIds): { organizationId?: string; siteId?: string } {
  return { ...(s.organizationId ? { organizationId: s.organizationId } : {}), ...(s.siteId ? { siteId: s.siteId } : {}) };
}

/**
 * Installs the update on the devices chosen, or on every device in scope where it is missing or failed. Devices where
 * the caller may not install are reported, not left out silently.
 */
export function FleetInstallDialog({ open, onClose, view, scope, deviceIds, missing, onDone }: {
  open: boolean;
  onClose: () => void;
  view: PatchUpdateView;
  scope: UpdateScopeIds;
  /** Devices chosen; empty: every device in scope that misses it. */
  deviceIds: string[];
  /** Devices in scope where it is missing or failed. */
  missing: number;
  onDone?: () => void;
}) {
  const outcome = useOutcome();
  const install = useApiMutation(
    (ids: string[]) =>
      api.post<PatchActionResult>(`/patching/updates/${view.summary.updateGuid}/install`, ids.length > 0 ? { deviceIds: ids } : { all: true, ...scopeBody(scope) }),
    {
      invalidate: PATCH_KEYS,
      onSuccess: (r) => {
        outcome.report("Install started", r);
        onClose();
        onDone?.();
      },
    },
  );
  const reset = install.reset;
  useEffect(() => {
    if (open) reset();
  }, [open, reset]);
  const some = deviceIds.length > 0;
  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={some ? `Install on ${plural(deviceIds.length, "device")}?` : `Install wherever it is missing?`}
        description="The patching engine installs it, downloading what it needs. Updates that need a restart finish at the next one, which the device's patch policy may schedule."
        footer={
          <>
            <Button onClick={onClose} disabled={install.isPending}>
              Cancel
            </Button>
            <Button variant="primary" loading={install.isPending} onClick={() => install.mutate(deviceIds)}>
              {some ? `Install on ${plural(deviceIds.length, "device")}` : "Install"}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3 text-sm">
          <p className="font-medium break-words">{view.summary.title}</p>
          {!some && (
            <p className="text-muted">
              On the {plural(missing, "device")} in this view where it is missing or failed, except where it is excluded. Patching engine endpoints with
              no EasyRMM device are left out; devices where you may not install updates are listed afterwards.
            </p>
          )}
          {view.holds.length > 0 && (
            <Alert tone="warn" title="It is on hold">
              Installing it by hand installs it anyway; the hold keeps it out of scheduled installs only.
            </Alert>
          )}
          <InlineError error={install.error} />
        </div>
      </Dialog>
      {outcome.dialog}
    </>
  );
}

/**
 * Removes the update from every device in scope where it is installed (Windows only: EasyPatch refuses Linux and
 * macOS per device), and by default excludes it there so it is not installed again.
 */
export function FleetRemoveDialog({ open, onClose, view, scope, installed, onDone }: {
  open: boolean;
  onClose: () => void;
  view: PatchUpdateView;
  scope: UpdateScopeIds;
  /** Devices in scope where it is installed or waits for a restart. */
  installed: number;
  onDone?: () => void;
}) {
  const outcome = useOutcome();
  const [block, setBlock] = useState(true);
  const [reason, setReason] = useState("");
  const remove = useApiMutation(
    (vars: { block: boolean; reason: string }) =>
      api.post<PatchActionResult>(`/patching/updates/${view.summary.updateGuid}/remove`, { all: true, ...scopeBody(scope), ...vars }),
    {
      invalidate: PATCH_KEYS,
      onSuccess: (r) => {
        outcome.report("Removal queued", r);
        onClose();
        onDone?.();
      },
    },
  );
  const reset = remove.reset;
  useEffect(() => {
    if (open) {
      setBlock(true);
      setReason("");
      reset();
    }
  }, [open, reset]);
  const blockId = useId();
  return (
    <>
      <Dialog
        open={open}
        onClose={onClose}
        title={`Remove it from ${plural(installed, "device")}?`}
        footer={
          <>
            <Button onClick={onClose} disabled={remove.isPending}>
              Cancel
            </Button>
            <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate({ block, reason: block ? reason.trim() : "" })}>
              Remove update
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4 text-sm">
          <p className="font-medium break-words">{view.summary.title}</p>
          <p className="text-muted">
            On every device in this view where it is installed or waits for a restart. The agent uses Windows Update’s own uninstall where the update
            supports it, and otherwise has DISM remove its package. It never restarts the computer. Windows does not let some updates be removed; those
            jobs fail and nothing changes. The patching engine removes updates from Windows only: other devices are listed afterwards.
          </p>
          <div>
            <label className="flex items-start gap-2">
              <input type="checkbox" className="mt-0.5 size-4 accent-accent" checked={block} onChange={(e) => setBlock(e.target.checked)} aria-describedby={blockId} />
              <span>Exclude it on these devices</span>
            </label>
            <p id={blockId} className="mt-1 pl-6 text-xs text-subtle">
              The patching engine then does not install it there again. To keep it off devices it is not on yet, hold it.
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
          <InlineError error={remove.error} fields={block ? ["reason"] : []} />
        </div>
      </Dialog>
      {outcome.dialog}
    </>
  );
}

/** Holds the update in one organization, or in every one (super administrators). */
export function HoldDialog({ open, onClose, view, organizationId }: {
  open: boolean;
  onClose: () => void;
  view: PatchUpdateView;
  /** The organization the page is scoped to, chosen first when the update can be held there. */
  organizationId: string;
}) {
  const toast = useToast();
  const held = new Set(view.holds.map((h) => h.organizationId ?? ""));
  const choices = [
    ...(view.canHoldEverywhere && !held.has("") ? [{ id: "", name: "Every organization" }] : []),
    ...view.holdIn.filter((o) => !held.has(o.id)),
  ];
  const first = choices.find((o) => o.id === organizationId)?.id ?? choices[0]?.id ?? "";
  const [org, setOrg] = useState(first);
  const [reason, setReason] = useState("");
  const hold = useApiMutation(
    (vars: { organizationId: string; reason: string }) =>
      api.post<PatchHold>(`/patching/updates/${view.summary.updateGuid}/holds`, {
        ...(vars.organizationId ? { organizationId: vars.organizationId } : {}),
        reason: vars.reason,
      }),
    {
      invalidate: PATCH_KEYS,
      onSuccess: (h) => {
        toast.success(h.organizationId ? `On hold in ${h.organizationName}.` : "On hold in every organization.");
        onClose();
      },
    },
  );
  const reset = hold.reset;
  useEffect(() => {
    if (open) {
      setOrg(first);
      setReason("");
      reset();
    }
    // The choice resets when the dialog opens, not when the update refreshes behind it.
  }, [open, reset]);
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Hold this update?"
      description="Scheduled installs and installs of every missing update leave it out until the hold is released. Installing it by hand still installs it."
      footer={
        <>
          <Button onClick={onClose} disabled={hold.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={hold.isPending}
            disabled={choices.length === 0 || reason.trim() === ""}
            onClick={() => hold.mutate({ organizationId: org, reason: reason.trim() })}
          >
            Hold update
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4 text-sm">
        <p className="font-medium break-words">{view.summary.title}</p>
        {choices.length === 0 ? (
          <Alert tone="info">It is already on hold everywhere you may hold it.</Alert>
        ) : (
          <>
            <SelectField label="Hold it in" value={org} onChange={(e) => setOrg(e.target.value)} error={fieldError(hold.error, "organizationId")}>
              {choices.map((o) => (
                <option key={o.id || "every"} value={o.id}>
                  {o.name}
                </option>
              ))}
            </SelectField>
            <TextareaField
              label="Why"
              required
              rows={3}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={MAX_REASON}
              placeholder="Breaks the line-of-business app; waiting for the vendor"
              hint="Shown with the hold, wherever it is listed."
              error={fieldError(hold.error, "reason")}
            />
          </>
        )}
        <InlineError error={hold.error} fields={["organizationId", "reason"]} />
      </div>
    </Dialog>
  );
}

/** Releases a hold: scheduled installs include the update again. */
export function ReleaseHoldDialog({ hold, guid, onClose }: { hold: PatchHold | null; guid: string; onClose: () => void }) {
  const toast = useToast();
  const release = useApiMutation((id: string) => api.post<PatchHold>(`/patching/updates/${guid}/holds/${id}/release`, {}), {
    invalidate: PATCH_KEYS,
    onSuccess: () => {
      toast.success("Hold released.");
      onClose();
    },
  });
  const reset = release.reset;
  useEffect(() => {
    if (hold) reset();
  }, [hold, reset]);
  return (
    <Dialog
      open={hold !== null}
      onClose={onClose}
      title={hold?.organizationId ? `Release the hold in ${hold.organizationName}?` : "Release the hold in every organization?"}
      description="Scheduled installs and installs of every missing update include it again."
      footer={
        <>
          <Button onClick={onClose} disabled={release.isPending}>
            Cancel
          </Button>
          <Button variant="primary" loading={release.isPending} onClick={() => hold && release.mutate(hold.id)}>
            Release hold
          </Button>
        </>
      }
    >
      <InlineError error={release.error} />
    </Dialog>
  );
}
