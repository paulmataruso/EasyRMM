import { useState } from "react";
import { api } from "../../../api/client";
import { useApi, useApiMutation } from "../../../api/hooks";
import type { AssessmentDetail, PoamBoard, PoamItem } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { useToast } from "../../../components/Toast";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, InlineError, Spinner, TextField } from "../../../components/ui";
import { DETERMINATION_WORDS, POAM_NOTE, POAM_STATUS } from "./cmmcText";

const COLUMNS: { id: PoamItem["status"]; label: string }[] = [
  { id: "draft", label: "Draft" },
  { id: "open", label: "Open" },
  { id: "in_progress", label: "In progress" },
  { id: "closed", label: "Closed" },
];

/**
 * The plan-of-action board. A failing requirement becomes a draft item with its point value, whether the rule lets it be on
 * a plan of action at all, and its 180 days. A person confirms a draft; an item the rule does not allow cannot be opened.
 */
export function PoamBoardView({ organizationId, assessment, base }: { organizationId: string; assessment: AssessmentDetail; base: string }) {
  const { canAt } = useAuth();
  const toast = useToast();
  const board = useApi<PoamBoard>(`${base}/poam`);
  const mayEdit = canAt("compliance.edit", { organizationId }) && assessment.state === "draft";
  const gen = useApiMutation(() => api.post<{ drafted: number }>(`${base}/poam/generate`), {
    invalidate: [base],
    onSuccess: (r) => toast.success(`${r.drafted} draft item(s) made.`),
  });
  if (board.isPending) return <Spinner />;
  if (board.isError) return <ErrorState error={board.error} onRetry={() => void board.refetch()} />;
  const items = board.data.items;
  return (
    <Card
      title="Plan of action and milestones"
      actions={
        mayEdit && (
          <Button loading={gen.isPending} onClick={() => gen.mutate(undefined)}>
            Draft items for what is not met
          </Button>
        )
      }
    >
      <Alert tone="info">{POAM_NOTE}</Alert>
      <InlineError error={gen.error} />
      {items.length === 0 ? (
        <EmptyState title="No items yet" compact>
          Items are drafted for requirements that are not met.
        </EmptyState>
      ) : (
        <div className="mt-3 grid gap-3 lg:grid-cols-4">
          {COLUMNS.map((c) => (
            <section key={c.id} aria-label={c.label} className="flex flex-col gap-2">
              <h3 className="text-xs font-semibold text-muted">
                {c.label} ({items.filter((i) => i.status === c.id).length})
              </h3>
              {items
                .filter((i) => i.status === c.id)
                .map((i) => (
                  <Item key={i.id} item={i} base={base} mayEdit={mayEdit} />
                ))}
            </section>
          ))}
        </div>
      )}
    </Card>
  );
}

function Item({ item, base, mayEdit }: { item: PoamItem; base: string; mayEdit: boolean }) {
  const [title, setTitle] = useState("");
  const [due, setDue] = useState("");
  const [weakness, setWeakness] = useState(item.weakness);
  const update = useApiMutation((patch: Record<string, unknown>) => api.put(`${base}/poam/${item.id}`, patch), { invalidate: [base] });
  const add = useApiMutation(() => api.post(`${base}/poam/${item.id}/milestones`, { title: title.trim(), ...(due ? { due } : {}) }), {
    invalidate: [base],
    onSuccess: () => {
      setTitle("");
      setDue("");
    },
  });
  const done = useApiMutation((v: { id: string; done: boolean }) => api.put(`${base}/poam/milestones/${v.id}`, { done: v.done }), { invalidate: [base] });
  const next = item.status === "draft" ? "open" : item.status === "open" ? "in_progress" : item.status === "in_progress" ? "closed" : null;
  return (
    <article className="rounded-md border border-line p-2 text-sm">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono text-xs">{item.nistId}</span>
        <Badge tone={POAM_STATUS[item.status].tone}>{item.points} pt</Badge>
        {item.overdue && <Badge tone="danger">Past 180 days</Badge>}
        {!item.eligible && <Badge tone="danger">Not allowed on a plan</Badge>}
        {item.requirementStatus === "met" && <Badge tone={DETERMINATION_WORDS.met.tone}>Now met</Badge>}
      </div>
      <p className="font-medium">{item.title}</p>
      <p className="text-xs text-muted">{item.eligibilityReason}</p>
      <p className="text-xs text-muted">Closes by {item.closesBy}</p>
      {mayEdit ? (
        <TextField label="What is wrong" value={weakness} onChange={(e) => setWeakness(e.target.value)} onBlur={() => weakness !== item.weakness && update.mutate({ weakness })} />
      ) : (
        <p className="mt-1">{item.weakness}</p>
      )}
      <ul className="mt-1 flex flex-col gap-1">
        {item.milestones.map((m) => (
          <li key={m.id} className="flex items-center gap-2">
            <input type="checkbox" aria-label={`Done: ${m.title}`} className="size-4 accent-accent" disabled={!mayEdit} checked={m.done} onChange={(e) => done.mutate({ id: m.id, done: e.target.checked })} />
            <span className={m.done ? "text-muted line-through" : ""}>
              {m.title}
              {m.due ? ` (${m.due})` : ""}
            </span>
          </li>
        ))}
      </ul>
      {mayEdit && (
        <>
          <div className="mt-2 flex flex-wrap items-end gap-2">
            <TextField label="New step" value={title} onChange={(e) => setTitle(e.target.value)} />
            <TextField label="Due" type="date" value={due} onChange={(e) => setDue(e.target.value)} />
            <Button disabled={title.trim() === ""} loading={add.isPending} onClick={() => add.mutate(undefined)}>
              Add
            </Button>
          </div>
          <div className="mt-2 flex gap-2">
            {next && item.eligible && (
              <Button variant="primary" loading={update.isPending} onClick={() => update.mutate({ status: next })}>
                {next === "open" ? "Confirm" : next === "in_progress" ? "Start" : "Close"}
              </Button>
            )}
            {!item.eligible && item.status === "draft" && (
              <Button variant="ghost" loading={update.isPending} onClick={() => update.mutate({ status: "closed" })}>
                Close
              </Button>
            )}
          </div>
        </>
      )}
      <InlineError error={update.error ?? add.error ?? done.error} />
    </article>
  );
}
