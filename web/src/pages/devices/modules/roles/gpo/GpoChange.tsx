import { useState, type FormEvent, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../../../../../api/client";
import type { Device } from "../../../../../api/types";
import { Dialog } from "../../../../../components/Dialog";
import { Alert, Button, InlineError, TextField, TextareaField } from "../../../../../components/ui";
import { confirmText, useWinmodChange } from "../../winmod";
import { APPROVAL_CODE, MODULE, SENSITIVITY_TEXT } from "./gpoText";
import type { GpoRequest } from "./types";

/** What a change sends: the short action name, its parameters (the reason is added), and how it is confirmed. */
export interface GpoOp {
  /** "gpo_rename", "link_add", ... (the module's name is added). */
  action: string;
  params: Record<string, unknown>;
  /** The name a person types to confirm a destructive action (a GPO's name); the server compares it. */
  confirmSubject?: string;
  /** What the approver sees as the change's subject. */
  subject?: string;
}

/**
 * A change dialog (ADR-0083 section 7): a typed reason, the typed name of the GPO for a destructive action, the Default
 * policies' extra confirmation, and, when the server says a second person must approve, a request to send. The step-up is
 * asked for by the API client. The versions the page read the GPO at go with the change, so the script refuses if someone
 * else changed it meanwhile.
 */
export function GpoChangeDialog({
  device,
  title,
  description,
  children,
  label,
  op,
  valid = true,
  danger = false,
  defaultName,
  onClose,
}: {
  device: Device;
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  label: string;
  op: GpoOp;
  valid?: boolean;
  danger?: boolean;
  /** Set for a Default policy: its name must be typed in full. */
  defaultName?: string;
  onClose: () => void;
}) {
  const client = useQueryClient();
  const change = useWinmodChange(device.id, MODULE);
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const [defaultTyped, setDefaultTyped] = useState("");
  const [requested, setRequested] = useState<GpoRequest | null>(null);
  const [askError, setAskError] = useState<unknown>(null);
  const [asking, setAsking] = useState(false);
  const reasonOk = reason.trim().length >= 10 && reason.trim().length <= 500;
  const typedOk = op.confirmSubject === undefined || typed.trim().toLowerCase() === op.confirmSubject.toLowerCase();
  const defaultOk = defaultName === undefined || defaultTyped === defaultName;
  const params = { ...op.params, reason: reason.trim(), ...(defaultName ? { confirmName: defaultTyped } : {}) };
  const action = `${MODULE}.${op.action}`;
  const needsApproval = change.error instanceof ApiError && change.error.code === APPROVAL_CODE;

  function submit(e: FormEvent) {
    e.preventDefault();
    change.mutate(
      { action, params, confirm: op.confirmSubject !== undefined ? confirmText(action, op.confirmSubject) : undefined },
      {
        onSuccess: () => {
          void client.invalidateQueries({ predicate: (q) => q.queryKey.includes("gpo") });
          onClose();
        },
      },
    );
  }

  async function ask() {
    setAsking(true);
    setAskError(null);
    try {
      setRequested(await api.post<GpoRequest>(`/devices/${device.id}/gpo/requests`, { action, params, subject: op.subject ?? "" }));
      void client.invalidateQueries({ predicate: (q) => q.queryKey.includes("gpo") });
    } catch (err) {
      setAskError(err);
    } finally {
      setAsking(false);
    }
  }

  if (requested) {
    return (
      <Dialog open onClose={onClose} title="Sent for approval">
        <p className="text-sm">
          A second administrator who may edit Group Policy must approve this change within 24 hours. It runs when they do, under
          their name, and the audit log records both of you. It is in the Approvals list.
        </p>
        <div className="flex justify-end pt-3">
          <Button variant="primary" onClick={onClose}>
            Close
          </Button>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog open onClose={onClose} title={title} description={description}>
      <form onSubmit={submit} className="flex flex-col gap-3">
        {children}
        <TextareaField
          label="Why"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          hint="Required, 10 to 500 characters. It goes in the audit log."
          rows={2}
          maxLength={500}
          required
        />
        {defaultName !== undefined && (
          <TextField
            label={
              <>
                This is a Default policy. Type its name, <strong>{defaultName}</strong>, in full to confirm
              </>
            }
            value={defaultTyped}
            onChange={(e) => setDefaultTyped(e.target.value)}
            autoComplete="off"
          />
        )}
        {op.confirmSubject !== undefined && (
          <TextField
            label={
              <>
                Type <strong>{op.confirmSubject}</strong> to confirm
              </>
            }
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            autoComplete="off"
          />
        )}
        <Alert tone="info">A change asks you to confirm it is you (a second factor). A backup of the GPO is taken first and kept.</Alert>
        {needsApproval ? (
          <Alert tone="warn" title="A second person must approve this">
            {change.error instanceof ApiError ? change.error.message : ""} It touches{" "}
            {SENSITIVITY_TEXT[sensitivityOf(change.error)] ?? "something that reaches many computers"}.
            <div className="mt-2">
              <Button size="sm" variant="primary" loading={asking} disabled={!reasonOk || !defaultOk} onClick={() => void ask()}>
                Ask for approval
              </Button>
            </div>
            <InlineError error={askError} />
          </Alert>
        ) : (
          <InlineError error={change.error} />
        )}
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose} disabled={change.isPending}>
            Cancel
          </Button>
          <Button type="submit" variant={danger ? "danger" : "primary"} loading={change.isPending} disabled={!valid || !reasonOk || !typedOk || !defaultOk}>
            {label}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

// The server's message names why; the console picks the wording from it.
function sensitivityOf(error: unknown): string {
  const m = error instanceof Error ? error.message : "";
  if (m.includes("Default policy")) return "default_policy";
  if (m.includes("domain root")) return "sensitive_link";
  return "organization";
}
