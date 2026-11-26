import { useId, useState } from "react";
import { useApi, useList } from "../../api/hooks";
import type { CompliancePack, FrameworkStatus } from "../../api/types";
import { Alert, Badge, EmptyState, ErrorState, Field, Select, Spinner, TableWrap } from "../../components/ui";
import { REQUIREMENT_STATUS } from "./complianceText";

/**
 * A framework's results (ADR-0078, section 7), for the organization or for one computer. A requirement says what a scan
 * could check: "checked: all in-scope computers meet", "checked: does not meet" or "not assessed". The frameworks offered
 * are those whose review is not pending, so a pack waiting on its licence is not shown. Titles are our own.
 */
export function FrameworkResults({ organizationId, deviceId }: { organizationId: string; deviceId?: string }) {
  const id = useId();
  const packs = useList<CompliancePack>(`/organizations/${organizationId}/compliance/packs`, undefined, { staleTime: 60_000 });
  const frameworks = packs.items.filter((p) => p.kind === "framework" && p.reviewState !== "needed" && p.framework);
  const [picked, setPicked] = useState("");
  const key = picked || frameworks[0]?.framework || "";
  const path = deviceId ? `/devices/${deviceId}/compliance/frameworks/${key}` : `/organizations/${organizationId}/compliance/frameworks/${key}`;
  const status = useApi<FrameworkStatus>(key ? path : null, undefined, { refetchInterval: 60_000 });
  const [only, setOnly] = useState(true);

  if (packs.isPending) return <Spinner />;
  if (packs.isError) return <ErrorState error={packs.error} onRetry={() => void packs.refetch()} compact />;
  if (frameworks.length === 0) return <EmptyState title="No framework is available" compact>The frameworks installed here are waiting for review.</EmptyState>;

  const s = status.data;
  const rows = s ? s.requirements.filter((r) => !only || r.status === "checked_not_meets" || r.status === "checked_meets") : [];
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Framework" htmlFor={id} className="min-w-56">
          <Select id={id} value={key} onChange={(e) => setPicked(e.target.value)}>
            {frameworks.map((f) => (
              <option key={f.framework} value={f.framework}>
                {f.title}
              </option>
            ))}
          </Select>
        </Field>
        <label className="flex items-center gap-2 pb-2 text-sm">
          <input type="checkbox" className="size-4 accent-accent" checked={only} onChange={(e) => setOnly(e.target.checked)} />
          Only requirements a scan checked
        </label>
      </div>
      {status.isPending ? (
        <Spinner />
      ) : status.isError ? (
        <ErrorState error={status.error} onRetry={() => void status.refetch()} compact />
      ) : (
        s && (
          <>
            <p className="text-sm text-muted">
              {s.coverage.checked} of {s.coverage.total} requirements can be checked by a scan, {s.coverage.partly} partly. {s.coverage.organisational} are for people to
              show, and are not assessed here.
              {s.scanId === null ? " No scan has finished yet." : ""}
            </p>
            <div className="flex flex-wrap gap-2 text-sm">
              {(Object.keys(REQUIREMENT_STATUS) as (keyof typeof REQUIREMENT_STATUS)[]).map((k) => (
                <Badge key={k} tone={REQUIREMENT_STATUS[k].tone}>
                  {REQUIREMENT_STATUS[k].label}: {s.counts[k] ?? 0}
                </Badge>
              ))}
            </div>
            {rows.length === 0 ? (
              <p className="text-sm text-muted">No requirement has been checked yet.</p>
            ) : (
              <TableWrap>
                <table className="w-full text-left text-sm" aria-label={`${s.title} requirements`}>
                  <thead>
                    <tr className="text-xs text-muted">
                      <th className="px-3 py-2 font-medium">Requirement</th>
                      <th className="px-2 py-2 font-medium">Result</th>
                      <th className="px-2 py-2 font-medium">What is failing</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {rows.map((r) => (
                      <tr key={r.reqId}>
                        <td className="px-3 py-2 align-top">
                          <span className="font-mono text-xs">{r.reqId}</span>
                          {s.titles[r.reqId] && <span className="block">{s.titles[r.reqId]}</span>}
                        </td>
                        <td className="px-2 py-2 align-top">
                          <Badge tone={REQUIREMENT_STATUS[r.status].tone}>{r.label}</Badge>
                          {r.reason && <span className="block text-xs text-muted">{r.reason}</span>}
                        </td>
                        <td className="px-2 py-2 align-top text-muted">
                          {r.failing && r.failing.length > 0 ? `${new Set(r.failing.map((f) => f.deviceId)).size} computer(s), ${new Set(r.failing.map((f) => f.controlId)).size} control(s)` : ""}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
            {s.notes?.map((n) => (
              <p key={n} className="text-xs text-muted">
                {n}
              </p>
            ))}
            <Alert tone="info">{s.disclaimer}</Alert>
          </>
        )
      )}
    </div>
  );
}
