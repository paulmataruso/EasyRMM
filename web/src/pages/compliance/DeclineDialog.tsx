import { useState, type FormEvent } from "react";
import { api, fieldError } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { FixItem } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, InlineError, SelectField, TextField, TextareaField } from "../../components/ui";

/** Sets an item aside with a reason (ADR-0078, section 6, rule 9): accepted as a risk, or deferred until a date. It stays in the queue. */
export function DeclineDialog({ item, organizationId, onClose }: { item: FixItem | null; organizationId: string; onClose: () => void }) {
  return (
    <Dialog open={item !== null} onClose={onClose} title="Set this item aside" description={item ? `${item.title} on ${item.deviceName}. It stays in the queue, with your reason.` : undefined}>
      {item && <Form item={item} organizationId={organizationId} onClose={onClose} />}
    </Dialog>
  );
}

const tomorrow = () => new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString().slice(0, 10);

function Form({ item, organizationId, onClose }: { item: FixItem; organizationId: string; onClose: () => void }) {
  const toast = useToast();
  const [kind, setKind] = useState<"accepted_risk" | "deferred">("accepted_risk");
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState(tomorrow());
  const decline = useApiMutation(
    () =>
      api.post(`/organizations/${organizationId}/compliance/fixes/${item.id}/decline`, {
        kind,
        reason: reason.trim(),
        ...(kind === "deferred" ? { expiresAt: new Date(`${until}T12:00:00Z`).toISOString() } : {}),
      }),
    {
      invalidate: [`/organizations/${organizationId}/compliance`, "/devices"],
      onSuccess: () => {
        toast.success("Set aside.");
        onClose();
      },
    },
  );
  function submit(e: FormEvent) {
    e.preventDefault();
    decline.mutate(undefined);
  }
  return (
    <form onSubmit={submit} noValidate className="flex flex-col gap-3.5">
      <SelectField label="Why" value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
        <option value="accepted_risk">Accept the risk</option>
        <option value="deferred">Defer until a date</option>
      </SelectField>
      {kind === "deferred" && <TextField label="Comes back on" type="date" value={until} onChange={(e) => setUntil(e.target.value)} error={fieldError(decline.error, "expiresAt")} />}
      <TextareaField label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} rows={3} error={fieldError(decline.error, "reason")} />
      <InlineError error={decline.error} fields={["kind", "reason", "expiresAt"]} />
      <div className="flex justify-end gap-2 border-t border-line pt-3">
        <Button onClick={onClose} disabled={decline.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" loading={decline.isPending} disabled={reason.trim() === ""}>
          Set aside
        </Button>
      </div>
    </form>
  );
}
