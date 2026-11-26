import { useState } from "react";
import { api } from "../../../api/client";
import { useApi, useApiMutation } from "../../../api/hooks";
import type { Assessment, AssessmentDetail } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { useToast } from "../../../components/Toast";
import { Alert, Badge, Button, Card, ErrorState, InlineError, Spinner, Tabs } from "../../../components/ui";
import { EvidenceLibrary } from "./EvidenceLibrary";
import { ExportsPanel } from "./ExportsPanel";
import { PoamBoardView } from "./PoamBoardView";
import { RequirementsView } from "./RequirementsView";
import { ScopeEditor } from "./ScopeEditor";
import { ScoreCard } from "./ScoreCard";
import { SspEditor } from "./SspEditor";
import { STATE_WORDS } from "./cmmcText";

const TABS = [
  { id: "requirements", label: "Requirements" },
  { id: "scope", label: "Scope" },
  { id: "poam", label: "Plan of action" },
  { id: "ssp", label: "System security plan" },
  { id: "evidence", label: "Evidence" },
  { id: "exports", label: "Exports" },
];

/** One assessment: its state and workflow, the score range, and the tabs of the workspace. */
export function AssessmentView({ organizationId, assessmentId, onBack }: { organizationId: string; assessmentId: string; onBack: () => void }) {
  const base = `/organizations/${organizationId}/compliance/assessments/${assessmentId}`;
  const { canAt } = useAuth();
  const toast = useToast();
  const [tab, setTab] = useState("requirements");
  const detail = useApi<AssessmentDetail>(base);
  const canEdit = canAt("compliance.edit", { organizationId });
  const canApprove = canAt("compliance.approve", { organizationId });
  const move = useApiMutation((to: string) => api.post<Assessment>(`${base}/transition`, { to }), {
    invalidate: [`/organizations/${organizationId}/compliance/assessments`],
    onSuccess: (a) => toast.success(`The assessment is now ${STATE_WORDS[a.state].label.toLowerCase()}.`),
  });
  const newDraft = useApiMutation(() => api.post<Assessment>(`${base}/new-draft`), {
    invalidate: [`/organizations/${organizationId}/compliance/assessments`],
    onSuccess: () => {
      toast.success("A new draft was made from this assessment.");
      onBack();
    },
  });
  if (detail.isPending) return <Spinner />;
  if (detail.isError) return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />;
  const a = detail.data;
  const st = STATE_WORDS[a.state];
  return (
    <div className="flex flex-col gap-4">
      <Card
        title={
          <span className="flex flex-wrap items-center gap-2">
            <button type="button" className="text-sm font-normal text-accent hover:underline" onClick={onBack}>
              All assessments
            </button>
            <span>{a.title}</span>
            <Badge tone={st.tone} title={st.hint}>
              {st.label}
            </Badge>
          </span>
        }
        actions={
          <div className="flex flex-wrap gap-2">
            {a.state === "draft" && canEdit && (
              <Button variant="primary" loading={move.isPending} onClick={() => move.mutate("in_review")}>
                Send for review
              </Button>
            )}
            {a.state === "in_review" && canEdit && (
              <Button loading={move.isPending} onClick={() => move.mutate("draft")}>
                Back to draft
              </Button>
            )}
            {a.state === "in_review" && canApprove && (
              <Button variant="primary" loading={move.isPending} onClick={() => move.mutate("approved")}>
                Approve and freeze
              </Button>
            )}
            {a.state === "approved" && canApprove && (
              <Button loading={move.isPending} onClick={() => move.mutate("archived")}>
                Archive
              </Button>
            )}
            {a.frozen && canEdit && (
              <Button variant="primary" loading={newDraft.isPending} onClick={() => newDraft.mutate(undefined)}>
                Start a new draft from this
              </Button>
            )}
          </div>
        }
      >
        <p className="text-sm text-muted">{st.hint}</p>
        <InlineError error={move.error ?? newDraft.error} />
        <ScoreCard detail={a} />
        <Alert tone="info" className="mt-3">
          {a.disclaimer}
        </Alert>
      </Card>
      <Tabs tabs={TABS} active={tab} onChange={setTab} />
      {tab === "requirements" && <RequirementsView organizationId={organizationId} assessment={a} base={base} />}
      {tab === "scope" && <ScopeEditor organizationId={organizationId} assessment={a} base={base} />}
      {tab === "poam" && <PoamBoardView organizationId={organizationId} assessment={a} base={base} />}
      {tab === "ssp" && <SspEditor assessment={a} base={base} />}
      {tab === "evidence" && <EvidenceLibrary organizationId={organizationId} assessment={a} />}
      {tab === "exports" && <ExportsPanel base={base} />}
    </div>
  );
}
