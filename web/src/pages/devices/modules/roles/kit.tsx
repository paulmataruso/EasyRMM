import { useState, type FormEvent, type ReactNode } from "react";
import type { Device } from "../../../../api/types";
import { ConfirmDialog, Dialog } from "../../../../components/Dialog";
import { Button, InlineError, TextField } from "../../../../components/ui";
import { confirmText, useWinmodChange } from "../winmod";

export type Change = ReturnType<typeof useWinmodChange>;

/** What a change asks the server: the action's short name, its parameters, and whether it needs the typed confirmation. */
export interface Op {
  /** "<module>.<action>". */
  action: string;
  params: Record<string, unknown>;
  /** A tier 2 or 3 action carries `device` and is confirmed with "<action>:<computer's name>". */
  confirmed: boolean;
}

/** Sends an Op: the computer's name goes in `device` and in the confirmation, as the server compares it (ADR-0073). */
export function send(change: Change, device: Device, op: Op, onSuccess: () => void) {
  change.mutate(
    {
      action: op.action,
      params: op.confirmed ? { device: device.name, ...op.params } : op.params,
      confirm: op.confirmed ? confirmText(op.action, device.name) : undefined,
    },
    { onSuccess },
  );
}

/**
 * Asks before a change. `typed` makes the person type the computer's name (tier 2 and 3); a tier 3 action also
 * triggers the console's step-up, which the API client handles.
 */
export function ActionDialog({
  title,
  children,
  label,
  op,
  device,
  change,
  onClose,
  danger = false,
  typed = true,
}: {
  title: string;
  children: ReactNode;
  label: string;
  op: Op;
  device: Device;
  change: Change;
  onClose: () => void;
  danger?: boolean;
  typed?: boolean;
}) {
  return (
    <ConfirmDialog
      open
      onClose={onClose}
      title={title}
      confirmLabel={label}
      tone={danger ? "danger" : "primary"}
      confirmText={typed ? device.name : undefined}
      loading={change.isPending}
      error={change.error}
      onConfirm={() => send(change, device, op, onClose)}
    >
      {children}
    </ConfirmDialog>
  );
}

/** A form in a dialog whose submit sends an Op. */
export function FormDialog({
  title,
  description,
  children,
  label,
  build,
  valid,
  device,
  change,
  onClose,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  label: string;
  build: () => Op;
  valid: boolean;
  device: Device;
  change: Change;
  onClose: () => void;
}) {
  const [typedName, setTypedName] = useState("");
  const op = build();
  function submit(e: FormEvent) {
    e.preventDefault();
    send(change, device, op, onClose);
  }
  const needsName = op.confirmed;
  return (
    <Dialog open onClose={onClose} title={title} description={description}>
      <form onSubmit={submit} className="flex flex-col gap-3">
        {children}
        {needsName && (
          <TextField
            label={
              <>
                Type the computer&apos;s name, <strong>{device.name}</strong>, to confirm
              </>
            }
            value={typedName}
            onChange={(e) => setTypedName(e.target.value)}
            autoComplete="off"
          />
        )}
        <InlineError error={change.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose} disabled={change.isPending}>Cancel</Button>
          <Button type="submit" variant="primary" loading={change.isPending} disabled={!valid || (needsName && typedName.trim().toLowerCase() !== device.name.toLowerCase())}>
            {label}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
