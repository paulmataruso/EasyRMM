import { useEffect, useState } from "react";
import { api } from "../../../api/client";
import { useApi, useApiMutation, useList } from "../../../api/hooks";
import type { AssessmentDetail, Device, ScopeState } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { useToast } from "../../../components/Toast";
import { Alert, Button, Card, ErrorState, InlineError, Select, Spinner, TableWrap, TextField } from "../../../components/ui";
import { CATEGORIES } from "./cmmcText";

type Choice = { category: string; reason: string };

/**
 * The scope editor. Scope is recorded by a person, never inferred: each computer is put in a category, or left out. Computers
 * not named are not counted, and the count of them is shown so that nothing drops out unseen. Out-of-scope computers stay
 * on the report.
 */
export function ScopeEditor({ organizationId, assessment, base }: { organizationId: string; assessment: AssessmentDetail; base: string }) {
  const { canAt } = useAuth();
  const toast = useToast();
  const mayEdit = canAt("compliance.edit", { organizationId }) && assessment.state === "draft";
  const scope = useApi<ScopeState>(`${base}/scope`);
  const devices = useList<Device>("/devices", { organizationId, limit: 200 });
  const [choices, setChoices] = useState<Record<string, Choice>>({});
  const items = scope.data?.items;
  useEffect(() => {
    if (!items) return;
    const next: Record<string, Choice> = {};
    for (const i of items) if (i.deviceId) next[i.deviceId] = { category: i.category, reason: i.reason };
    setChoices(next);
  }, [items]);
  const save = useApiMutation(
    () =>
      api.put<ScopeState>(`${base}/scope`, {
        items: Object.entries(choices)
          .filter(([, c]) => c.category !== "")
          .map(([deviceId, c]) => ({ deviceId, category: c.category, reason: c.reason })),
      }),
    { invalidate: [base], onSuccess: () => toast.success("Scope saved.") },
  );
  if (scope.isPending || devices.isPending) return <Spinner />;
  if (scope.isError) return <ErrorState error={scope.error} onRetry={() => void scope.refetch()} />;
  const set = (id: string, patch: Partial<Choice>) => setChoices((c) => ({ ...c, [id]: { category: "", reason: "", ...c[id], ...patch } }));
  return (
    <Card
      title="Scope"
      actions={
        mayEdit && (
          <Button variant="primary" loading={save.isPending} onClick={() => save.mutate(undefined)}>
            Save the scope
          </Button>
        )
      }
    >
      <Alert tone="info">
        Choose what each computer is. A scan decides requirements only on the computers in scope. A computer left unchosen is not counted
        {scope.data && scope.data.unlisted > 0 ? ` (${scope.data.unlisted} of this organization's computers are not named now)` : ""}.
      </Alert>
      <InlineError error={save.error} />
      {devices.items.length === 0 ? (
        <p className="mt-3 text-sm text-muted">This organization has no computers yet.</p>
      ) : (
        <TableWrap className="mt-3">
          <table className="w-full text-left text-sm" aria-label="Scope">
            <thead>
              <tr className="text-xs text-muted">
                <th className="px-3 py-2 font-medium">Computer</th>
                <th className="px-2 py-2 font-medium">Category</th>
                <th className="px-2 py-2 font-medium">Why</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {devices.items.map((d) => (
                <tr key={d.id}>
                  <td className="px-3 py-2">
                    {d.name}
                    <span className="block text-xs text-muted">{d.siteName}</span>
                  </td>
                  <td className="px-2 py-2">
                    <Select aria-label={`Category of ${d.name}`} disabled={!mayEdit} value={choices[d.id]?.category ?? ""} onChange={(e) => set(d.id, { category: e.target.value })}>
                      <option value="">Not named</option>
                      {CATEGORIES.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.label}
                        </option>
                      ))}
                    </Select>
                  </td>
                  <td className="px-2 py-2">
                    <TextField label="" aria-label={`Reason for ${d.name}`} disabled={!mayEdit || !choices[d.id]?.category} value={choices[d.id]?.reason ?? ""} onChange={(e) => set(d.id, { reason: e.target.value })} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Card>
  );
}
