import { useMemo, useState } from "react";
import { useList } from "../../../api/hooks";
import type { AssessmentDetail, RequirementRow } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { useToast } from "../../../components/Toast";
import { api } from "../../../api/client";
import { useApiMutation } from "../../../api/hooks";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, InlineError, Segmented, Spinner, TableWrap } from "../../../components/ui";
import { RequirementPanel } from "./RequirementPanel";
import { DETERMINATION_WORDS } from "./cmmcText";

type Filter = "all" | "not_met" | "not_assessed" | "met";

/** The per-requirement view: every requirement with its status, objectives met and evidence, and a panel to work on one. */
export function RequirementsView({ organizationId, assessment, base }: { organizationId: string; assessment: AssessmentDetail; base: string }) {
  const { canAt } = useAuth();
  const toast = useToast();
  const list = useList<RequirementRow>(`${base}/requirements`);
  const [filter, setFilter] = useState<Filter>("all");
  const [family, setFamily] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const mayEdit = canAt("compliance.edit", { organizationId }) && assessment.state === "draft";
  const refresh = useApiMutation(() => api.post<{ updated: number; keptStated: number; inScope: number; notes: string[] }>(`${base}/refresh`), {
    invalidate: [base],
    onSuccess: (r) => toast.success(`${r.updated} objective(s) set from the latest scan.`),
  });
  const families = useMemo(() => Array.from(new Set(list.items.map((r) => r.family))).sort(), [list.items]);
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  const rows = list.items.filter((r) => (filter === "all" || r.status === filter) && (family === "" || r.family === family));
  return (
    <Card
      title="Requirements"
      actions={
        mayEdit && (
          <Button loading={refresh.isPending} onClick={() => refresh.mutate(undefined)}>
            Apply the latest scan
          </Button>
        )
      }
    >
      <InlineError error={refresh.error} />
      {refresh.data && refresh.data.notes.length > 0 && <Alert tone="warn">{refresh.data.notes.join(" ")}</Alert>}
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Segmented<Filter>
          label="Show"
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: "All" },
            { value: "not_met", label: "Not met" },
            { value: "not_assessed", label: "Not assessed" },
            { value: "met", label: "Met" },
          ]}
        />
        <select aria-label="Family" className="rounded-md border border-line bg-surface px-2 py-1.5 text-sm" value={family} onChange={(e) => setFamily(e.target.value)}>
          <option value="">All families</option>
          {families.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
      </div>
      {rows.length === 0 ? (
        <EmptyState title="Nothing matches" compact />
      ) : (
        <TableWrap>
          <table className="w-full text-left text-sm" aria-label="Requirements">
            <thead>
              <tr className="text-xs text-muted">
                <th className="px-3 py-2 font-medium">Requirement</th>
                <th className="px-2 py-2 font-medium">Status</th>
                <th className="px-2 py-2 font-medium">Points</th>
                <th className="px-2 py-2 font-medium">Objectives</th>
                <th className="px-2 py-2 font-medium">Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.map((r) => (
                <tr key={r.reqId}>
                  <td className="px-3 py-2 align-top">
                    <button type="button" className="text-left text-accent hover:underline" onClick={() => setOpen(r.reqId)}>
                      <span className="font-mono text-xs">{r.nistId}</span> {r.title}
                    </button>
                    <span className="block text-xs text-muted">{r.reqId}</span>
                  </td>
                  <td className="px-2 py-2 align-top">
                    <Badge tone={DETERMINATION_WORDS[r.status].tone}>{DETERMINATION_WORDS[r.status].label}</Badge>
                  </td>
                  <td className="px-2 py-2 align-top">{r.weight}</td>
                  <td className="px-2 py-2 align-top">
                    {r.objectivesMet} of {r.objectives}
                  </td>
                  <td className="px-2 py-2 align-top">{r.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {open && <RequirementPanel organizationId={organizationId} assessment={assessment} base={base} reqId={open} onClose={() => setOpen(null)} />}
    </Card>
  );
}
