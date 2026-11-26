import { useState, type FormEvent } from "react";
import { ShieldCheck, Undo2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { FixItem } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, InlineError, TextField } from "../../components/ui";
import { bulkProblem, TIERS } from "./complianceText";

/** What the dialog does with its items: agree to the fix, put it back, or approve what someone else agreed to. */
export type FixAct = "apply" | "undo" | "approve";

const FIELDS = ["agreed", "typed", "itemIds"];

const TITLES: Record<FixAct, string> = { apply: "Apply fix", undo: "Undo fix", approve: "Approve fix" };

/**
 * The agreement a fix is made under (ADR-0078, section 6). It shows our warning for the item's tier, what the person
 * should check first (the preconditions), and every computer it is made on, and records nothing until the person agrees.
 * A change of tier 3 is one computer at a time: the computer's name is typed, and the server then asks for a second
 * factor (the console's step-up dialog), which is why that is not asked here.
 */
export function FixDialog({ act, items, organizationId, onClose }: { act: FixAct | null; items: FixItem[]; organizationId: string; onClose: () => void }) {
  return (
    <Dialog open={act !== null && items.length > 0} onClose={onClose} size="lg" title={act ? TITLES[act] : ""} description={act ? describe(act, items) : undefined}>
      {act && items.length > 0 && <Form act={act} items={items} organizationId={organizationId} onClose={onClose} />}
    </Dialog>
  );
}

function describe(act: FixAct, items: FixItem[]): string {
  const where = items.length === 1 ? `on ${items[0]!.deviceName}` : `on ${items.length} computers`;
  return act === "undo" ? `Put back what the fix changed ${where}.` : act === "approve" ? `A second person approves the change ${where}.` : `One setting is changed ${where}.`;
}

function Form({ act, items, organizationId, onClose }: { act: FixAct; items: FixItem[]; organizationId: string; onClose: () => void }) {
  const toast = useToast();
  const [agreed, setAgreed] = useState(false);
  const [typed, setTyped] = useState("");
  const first = items[0]!;
  const tier = first.tier;
  const warning = first.warning;
  const problem = bulkProblem(items);
  const dangerous = tier === "T3" || first.requiresTyped;
  const needsApproval = act === "apply" && items.every((i) => i.requiresApproval);
  const base = `/organizations/${organizationId}/compliance/fixes`;
  const run = useApiMutation(
    () => {
      const body = { agreed, ...(dangerous ? { typed: typed.trim() } : {}) };
      return act === "apply" ? api.post(`${base}/apply`, { itemIds: items.map((i) => i.id), ...body }) : api.post(`${base}/${first.id}/${act}`, body);
    },
    {
      invalidate: [`/organizations/${organizationId}/compliance`, "/devices"],
      onSuccess: () => {
        toast.success(
          needsApproval ? "Agreed to. The fix waits for a second person to approve it." : act === "undo" ? "Undoing the change. The result shows here when the agent reports." : "Applying the change. The result shows here when the agent reports.",
        );
        onClose();
      },
    },
  );
  const canSubmit = agreed && problem === null && (!dangerous || typed.trim() !== "");

  function submit(e: FormEvent) {
    e.preventDefault();
    run.mutate(undefined);
  }

  const preconditions = [...new Set(items.flatMap((i) => i.preconditions))];
  return (
    <form onSubmit={submit} noValidate className="flex flex-col gap-3.5">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge tone={TIERS[tier].tone} title={TIERS[tier].title}>
          {TIERS[tier].label}
        </Badge>
        <span className="font-medium">{items.length === 1 ? first.title : `${first.title}${new Set(items.map((i) => i.controlId)).size > 1 ? " and others" : ""}`}</span>
      </div>

      <ul aria-label="Computers" className="max-h-40 divide-y divide-line overflow-auto rounded-md border border-line">
        {items.map((i) => (
          <li key={i.id} className="px-3 py-2 text-sm">
            <span className="font-medium">{i.deviceName}</span>
            {items.some((o) => o.controlId !== i.controlId) && <span className="ml-2 text-muted">{i.title}</span>}
            {i.applyBlocked !== "" && <span className="block text-warn">{i.applyBlocked}</span>}
          </li>
        ))}
      </ul>

      {warning ? (
        <Alert tone={tier === "T3" ? "danger" : tier === "T2" ? "warn" : "info"} title={warning.title}>
          {warning.paragraphs.map((p) => (
            <span key={p} className="mt-1 block first:mt-0">
              {p}
            </span>
          ))}
          {act === "undo" && <span className="mt-1 block">{warning.undoNote}</span>}
        </Alert>
      ) : (
        <Alert tone="warn" title="No warning text">
          This control has no warning text, so it cannot be agreed to.
        </Alert>
      )}

      {preconditions.length > 0 && (
        <div className="text-sm">
          <p className="font-medium">Check before you agree</p>
          <ul className="ml-5 list-disc text-muted">
            {preconditions.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </div>
      )}

      {act === "apply" && items.length === 1 && first.undoKind === "none" && <Alert tone="danger">This change cannot be undone from here.</Alert>}
      {needsApproval && <Alert tone="info">This organization wants a second person to approve fixes of this tier. Your agreement is recorded, and nothing changes on the computer until they approve.</Alert>}
      {problem && <Alert tone="warn">{problem}</Alert>}

      {dangerous && (
        <TextField
          label={`Type ${first.deviceName} to confirm`}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          autoComplete="off"
          error={fieldError(run.error, "typed")}
        />
      )}
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-0.5 size-4 accent-accent" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
        <span>
          I have read the warning{act === "undo" ? "" : " and what this change can break"}.
          {items.length > 1 ? ` Each computer is agreed to on its own and recorded with its own agreement.` : ""}
        </span>
      </label>
      <InlineError error={run.error} fields={FIELDS} />
      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line pt-3">
        <Button onClick={onClose} disabled={run.isPending}>
          Cancel
        </Button>
        <Button
          type="submit"
          variant={act === "undo" ? "secondary" : "danger"}
          disabled={!canSubmit || !warning}
          loading={run.isPending}
          icon={act === "undo" ? <Undo2 className="size-4" aria-hidden /> : <ShieldCheck className="size-4" aria-hidden />}
        >
          {act === "undo" ? "Undo" : act === "approve" ? "Approve" : "Apply"}
        </Button>
      </div>
    </form>
  );
}
