import { useState, type FormEvent } from "react";
import { api, fieldError } from "../../../api/client";
import { useApiMutation, useList } from "../../../api/hooks";
import type { Assessment } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { useToast } from "../../../components/Toast";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, InlineError, Spinner, TextField } from "../../../components/ui";
import { formatRelative } from "../../../lib/format";
import { AssessmentView } from "./AssessmentView";
import { STATE_WORDS } from "./cmmcText";

/**
 * The CMMC workspace (ADR-0078, slice C5; ADR-0072 puts it in the organization's Compliance tab): the assessments, each
 * with its scope, requirements, plan of action, system security plan, evidence and exports. It is an aid for the people
 * who do the assessment, and it posts nothing anywhere.
 */
export function CmmcWorkspace({ organizationId }: { organizationId: string }) {
  const { canAt } = useAuth();
  const canEdit = canAt("compliance.edit", { organizationId });
  const list = useList<Assessment>(`/organizations/${organizationId}/compliance/assessments`);
  const [open, setOpen] = useState<string | null>(null);
  if (open) return <AssessmentView organizationId={organizationId} assessmentId={open} onBack={() => setOpen(null)} />;
  return (
    <Card title="CMMC assessments">
      <p className="mb-3 text-sm text-muted">
        Record the scope, say how each requirement is implemented, attach evidence, keep a plan of action and write the system security plan. The score is shown as a
        range until every requirement is assessed.
      </p>
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} compact />
      ) : list.items.length === 0 ? (
        <EmptyState title="No assessment yet" compact>
          {canEdit ? "Start one below." : "Someone who may edit compliance records can start one."}
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line rounded-md border border-line" aria-label="Assessments">
          {list.items.map((a) => (
            <li key={a.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2.5">
              <div>
                <button type="button" className="font-medium text-accent hover:underline" onClick={() => setOpen(a.id)}>
                  {a.title}
                </button>
                <div className="text-xs text-muted">
                  {a.framework} · started {formatRelative(a.createdAt)}
                  {a.supersedes ? " · from an earlier approved assessment" : ""}
                </div>
              </div>
              <Badge tone={STATE_WORDS[a.state].tone} title={STATE_WORDS[a.state].hint}>
                {STATE_WORDS[a.state].label}
              </Badge>
            </li>
          ))}
        </ul>
      )}
      {canEdit && <NewAssessment organizationId={organizationId} onCreated={setOpen} />}
    </Card>
  );
}

function NewAssessment({ organizationId, onCreated }: { organizationId: string; onCreated: (id: string) => void }) {
  const toast = useToast();
  const [title, setTitle] = useState("");
  const create = useApiMutation((t: string) => api.post<Assessment>(`/organizations/${organizationId}/compliance/assessments`, { title: t.trim(), framework: "cmmc-l2" }), {
    invalidate: [`/organizations/${organizationId}/compliance/assessments`],
    onSuccess: (a) => {
      toast.success("Assessment started.");
      setTitle("");
      onCreated(a.id);
    },
  });
  function submit(e: FormEvent) {
    e.preventDefault();
    create.mutate(title);
  }
  return (
    <form onSubmit={submit} noValidate className="mt-4 flex flex-wrap items-end gap-3 border-t border-line pt-4">
      <TextField label="Title for a new assessment" value={title} onChange={(e) => setTitle(e.target.value)} error={fieldError(create.error, "title")} className="min-w-64" />
      <Button type="submit" variant="primary" loading={create.isPending} disabled={title.trim() === ""}>
        Start an assessment
      </Button>
      <InlineError error={create.error} fields={["title"]} />
      <Alert tone="info" className="basis-full">
        The Level 2 framework is used: the 110 requirements of NIST SP 800-171 Revision 2, under their CMMC practice ids.
      </Alert>
    </form>
  );
}
