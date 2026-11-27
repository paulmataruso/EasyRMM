import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../../../../../api/client";
import { useApi } from "../../../../../api/hooks";
import type { Device } from "../../../../../api/types";
import { Dialog } from "../../../../../components/Dialog";
import { Alert, Badge, Button, Card, EmptyState, InlineError, TableWrap, TextareaField, type Tone } from "../../../../../components/ui";
import { formatDateTime } from "../../../../../lib/format";
import { SkeletonTable } from "../../skeletons";
import { SENSITIVITY_TEXT } from "./gpoText";
import type { GpoRequest, GpoSettings } from "./types";

const TONE: Record<GpoRequest["status"], Tone> = { pending: "warn", approved: "ok", rejected: "danger", expired: "neutral" };

/**
 * Two-person approval (ADR-0083 section 7): a change at the domain root, the Domain Controllers OU or a site, to a Default
 * policy, or (if the organization asks) to anything, waits here for a second administrator, who reads exactly what will
 * be sent, approves or rejects, and confirms it is them. The change then runs under their name.
 */
export function ApprovalsPanel({ device, perms }: { device: Device; perms: { edit: boolean; manage: boolean } }) {
  const client = useQueryClient();
  const org = device.organizationId;
  const list = useApi<GpoRequest[]>(`/organizations/${org}/gpo/requests`, undefined, { refetchInterval: 15_000 });
  const settings = useApi<GpoSettings>(`/organizations/${org}/gpo/settings`);
  const [deciding, setDeciding] = useState<{ r: GpoRequest; approve: boolean } | null>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const requests = list.data ?? null;
  async function save(next: GpoSettings) {
    setSaveError(null);
    try {
      await api.put(`/organizations/${org}/gpo/settings`, next);
      await client.invalidateQueries({ queryKey: ["organizations", org, "gpo"] });
    } catch (e) {
      setSaveError(e);
    }
  }
  return (
    <div className="flex flex-col gap-4">
      <Card title="Requests" padded={false}>
        <InlineError error={list.error} />
        {!requests ? <SkeletonTable columns={4} rows={3} /> : requests.length === 0 ? (
          <EmptyState compact title="Nothing waiting">A request appears here when someone asks for a change that needs a second person.</EmptyState>
        ) : (
          <TableWrap className="rounded-none border-0">
            <table className="table-base">
              <thead>
                <tr><th scope="col">Change</th><th scope="col">Asked by</th><th scope="col">State</th><th scope="col"><span className="sr-only">Actions</span></th></tr>
              </thead>
              <tbody>
                {requests.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <div className="font-medium">{r.summary}</div>
                      <div className="text-xs text-muted">Needs two people because of {SENSITIVITY_TEXT[r.sensitivity]}. Reason: {r.reason}</div>
                    </td>
                    <td>{r.requestedLabel}<div className="text-xs text-muted">{formatDateTime(r.createdAt)}</div></td>
                    <td><Badge tone={TONE[r.status]}>{r.status}</Badge>{r.decidedLabel && <div className="text-xs text-muted">{r.decidedLabel}: {r.decidedReason}</div>}</td>
                    <td className="text-right whitespace-nowrap">
                      {r.status === "pending" && r.canDecide && <Button size="sm" variant="primary" onClick={() => setDeciding({ r, approve: true })}>Review</Button>}
                      {r.status === "pending" && !r.canDecide && <span className="text-xs text-muted">Waiting for another administrator</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>
      {settings.data && perms.manage && (
        <Card title="Approval rules">
          <div className="flex flex-col gap-2 text-sm">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={settings.data.approvalSensitive} onChange={(e) => void save({ ...settings.data, approvalSensitive: e.target.checked })} />
              Two people for the domain root, the Domain Controllers OU, sites and the Default policies (recommended)
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={settings.data.approvalAll} onChange={(e) => void save({ ...settings.data, approvalAll: e.target.checked })} />
              Two people for every Group Policy change
            </label>
            <p className="text-xs text-muted">Turning a rule off needs an Organization Administrator and is recorded in the audit log. An organization with one administrator cannot approve its own change.</p>
            <InlineError error={saveError} />
          </div>
        </Card>
      )}
      {deciding && <DecideDialog request={deciding.r} onClose={() => setDeciding(null)} />}
    </div>
  );
}

function DecideDialog({ request, onClose }: { request: GpoRequest; onClose: () => void }) {
  const client = useQueryClient();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<unknown>(null);
  const ok = reason.trim().length >= 10;
  async function decide(kind: "approve" | "reject") {
    setBusy(kind);
    setError(null);
    try {
      await api.post(`/gpo/requests/${request.id}/${kind}`, { reason: reason.trim() });
      await client.invalidateQueries({ predicate: (q) => q.queryKey.includes("gpo") || q.queryKey[0] === "winmod" });
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  }
  return (
    <Dialog open onClose={onClose} title="Review a change" description={request.summary} size="lg">
      <div className="flex flex-col gap-3">
        <Alert tone="warn">Approving runs this change now, under your name. A backup of the GPO is taken first. The change is refused if the GPO was changed since it was asked for.</Alert>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt className="text-muted">Change</dt><dd>{request.label}</dd>
          <dt className="text-muted">Asked by</dt><dd>{request.requestedLabel}</dd>
          <dt className="text-muted">Their reason</dt><dd>{request.reason}</dd>
          {Object.entries(request.params).filter(([k]) => k !== "reason").map(([k, v]) => (
            <div key={k} className="contents"><dt className="text-muted">{k}</dt><dd className="break-all"><code>{typeof v === "string" ? v : JSON.stringify(v)}</code></dd></div>
          ))}
        </dl>
        <TextareaField label="Your reason" value={reason} onChange={(e) => setReason(e.target.value)} rows={2} maxLength={500} hint="Required, 10 to 500 characters. It goes in the audit log." />
        <InlineError error={error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose} disabled={busy !== null}>Cancel</Button>
          <Button variant="danger" loading={busy === "reject"} disabled={!ok || busy !== null} onClick={() => void decide("reject")}>Reject</Button>
          <Button variant="primary" loading={busy === "approve"} disabled={!ok || busy !== null} onClick={() => void decide("approve")}>Approve and run</Button>
        </div>
      </div>
    </Dialog>
  );
}
