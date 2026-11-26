import { useState } from "react";
import type { Device } from "../../../../../api/types";
import { useAuth } from "../../../../../auth/AuthContext";
import { Alert, Badge, Button, Card, EmptyState, InlineError, KeyValueList, Segmented, SelectField, TableWrap, TextField } from "../../../../../components/ui";
import { formatDateTime } from "../../../../../lib/format";
import { ModuleTab } from "../../ModuleTab";
import { failureText, useWinmodChange, useWinmodRead } from "../../winmod";
import { ActionDialog, FormDialog, send } from "../kit";
import type { CaFindings, CaRequest, CaRequests, CaStatus, CaTemplate, CaTemplates } from "./types";

const M = "certificate_authority";
const REASONS: [string, string][] = [
  ["unspecified", "Unspecified"],
  ["key_compromise", "Key compromise"],
  ["ca_compromise", "CA compromise"],
  ["affiliation_changed", "Affiliation changed"],
  ["superseded", "Superseded"],
  ["cessation_of_operation", "Cessation of operation"],
  ["certificate_hold", "Certificate hold (can be undone)"],
];
const HOLD = 6;

type Dialog =
  | { kind: "approve"; req: CaRequest }
  | { kind: "deny"; req: CaRequest }
  | { kind: "revoke"; req: CaRequest }
  | { kind: "unrevoke"; req: CaRequest }
  | { kind: "publish"; t: CaTemplate }
  | { kind: "unpublish"; t: CaTemplate };

/** The Certificate Authority module (ADR-0076, section 3). It never shows or touches a key, and never edits a template. */
export function CaView({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const manage = canAt("ca.manage", { organizationId: device.organizationId, siteId: device.siteId });
  const [started, setStarted] = useState(false);
  const [panel, setPanel] = useState<"requests" | "templates" | "findings">("requests");
  const [kind, setKind] = useState<"issued" | "revoked" | "failed" | "denied">("issued");
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const status = useWinmodRead<CaStatus>(device.id, `${M}.status`, {}, started);
  const pending = useWinmodRead<CaRequests>(device.id, `${M}.requests_pending`, {}, started && panel === "requests");
  const issued = useWinmodRead<CaRequests>(device.id, `${M}.requests_list`, { disposition: kind }, started && panel === "requests");
  const published = useWinmodRead<CaTemplates>(device.id, `${M}.template_list`, {}, started && panel === "templates");
  const available = useWinmodRead<CaTemplates>(device.id, `${M}.template_available`, {}, started && panel === "templates");
  const findings = useWinmodRead<CaFindings>(device.id, `${M}.ca_findings`, {}, started && panel === "findings");
  const change = useWinmodChange(device.id, M);

  const reads = [status, ...(panel === "requests" ? [pending, issued] : panel === "templates" ? [published, available] : [findings])];
  const refresh = () => (started ? reads.forEach((r) => void r.refetch()) : setStarted(true));
  const failure = reads.map((r) => r.data?.failure).find(Boolean);
  const lost = reads.map((r) => r.data?.lost).find(Boolean);
  const st = status.data?.data ?? null;
  const open = (d: Dialog) => {
    change.reset();
    setDialog(d);
  };
  const close = () => setDialog(null);
  const common = { device, change, onClose: close };

  return (
    <ModuleTab
      name="Certificate authority"
      asOf={st ? (status.data?.finishedAt ?? null) : null}
      onRefresh={refresh}
      refreshing={reads.some((r) => r.isFetching)}
      unavailable={failure ? failureText(failure) : (lost ?? undefined)}
    >
      <InlineError error={reads.map((r) => r.error).find(Boolean)} />
      {st && (
        <Card
          title={st.caName}
          actions={
            manage && (
              <Button size="sm" onClick={() => send(change, device, { action: `${M}.crl_publish`, params: { kind: "base" }, confirmed: false }, () => void status.refetch())} loading={change.isPending}>
                Publish revocation list
              </Button>
            )
          }
        >
          <KeyValueList
            items={[
              ["Type", st.caType.replaceAll("_", " ")],
              ["Service", <Badge key="s" tone={st.serviceState === "running" ? "ok" : "danger"}>{st.serviceState}</Badge>],
              ["CA certificate ends", st.certificate ? `${formatDateTime(st.certificate.notAfter)} (${st.certificate.daysLeft} days)` : "—"],
              ["Revocation list lapses", st.crl?.baseNextUpdate ? formatDateTime(st.crl.baseNextUpdate) : "—"],
              ["Requests", st.counts ? `${st.counts.pending} pending, ${st.counts.issued} issued, ${st.counts.revoked} revoked, ${st.counts.failed} failed` : "—"],
            ]}
          />
          <p className="mt-2 text-xs text-muted">The CA&apos;s keys are never shown or touched by this console.</p>
        </Card>
      )}
      {st && (
        <Segmented
          label="View"
          value={panel}
          onChange={setPanel}
          options={[
            { value: "requests", label: "Requests and certificates" },
            { value: "templates", label: "Templates" },
            { value: "findings", label: "Findings" },
          ]}
        />
      )}
      {st && panel === "requests" && (
        <>
          <Card title="Waiting for approval" padded={false}>
            <RequestTable
              rows={pending.data?.data?.requests ?? null}
              empty="No request is waiting."
              actions={(r) =>
                manage && (
                  <>
                    <Button size="sm" variant="ghost" onClick={() => open({ kind: "approve", req: r })}>Approve</Button>
                    <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "deny", req: r })}>Deny</Button>
                  </>
                )
              }
            />
          </Card>
          <Card title="Certificates" padded={false} actions={<Segmented label="Kind" value={kind} onChange={setKind} options={[{ value: "issued", label: "Issued" }, { value: "revoked", label: "Revoked" }, { value: "failed", label: "Failed" }, { value: "denied", label: "Denied" }]} />}>
            <RequestTable
              rows={issued.data?.data?.requests ?? null}
              empty="None."
              actions={(r) =>
                manage &&
                (r.disposition === "issued" ? (
                  <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "revoke", req: r })}>Revoke</Button>
                ) : r.disposition === "revoked" && r.revokedReason === HOLD ? (
                  <Button size="sm" variant="ghost" onClick={() => open({ kind: "unrevoke", req: r })}>Reinstate</Button>
                ) : null)
              }
            />
            {issued.data?.data?.next != null && <p className="px-4 py-2 text-xs text-muted">Only the first 100 are shown.</p>}
          </Card>
        </>
      )}
      {st && panel === "templates" && (
        <>
          {st.enterprise ? (
            <>
              <Card title="Published on this CA" padded={false}>
                <TemplateTable rows={published.data?.data?.templates ?? null} empty="This CA publishes no template." action={(t) => manage && <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "unpublish", t })}>Unpublish</Button>} />
              </Card>
              <Card title="Available to publish" padded={false}>
                <TemplateTable rows={available.data?.data?.templates ?? null} empty="Nothing else to publish." action={(t) => manage && <Button size="sm" variant="ghost" onClick={() => open({ kind: "publish", t })}>Publish</Button>} />
              </Card>
              <p className="text-xs text-muted">Templates are listed, published and unpublished here, never created or edited.</p>
            </>
          ) : (
            <EmptyState title="A standalone CA has no templates">Only the request and certificate actions apply.</EmptyState>
          )}
        </>
      )}
      {st && panel === "findings" && (
        <Card title="Misconfiguration check (ESC1 to ESC8)">
          {findings.data?.data ? (
            <div className="flex flex-col gap-3">
              {findings.data.data.findings.length === 0 && <Alert tone="ok">No finding.</Alert>}
              {findings.data.data.findings.map((f) => (
                <Alert key={f.id} tone="warn" title={`${f.class}: ${f.subject}`}>{f.evidence}</Alert>
              ))}
              {findings.data.data.notes.map((n) => (
                <p key={n} className="text-xs text-muted">{n}</p>
              ))}
              <p className="text-xs text-muted">Read only: the console shows what it found and does not offer a fix.</p>
            </div>
          ) : (
            <p className="text-sm text-muted">Reading…</p>
          )}
        </Card>
      )}
      {dialog?.kind === "approve" && (
        <ActionDialog {...common} title="Approve request" label="Approve and issue" danger op={{ action: `${M}.request_approve`, params: { id: dialog.req.id }, confirmed: true }}>
          This issues a certificate for <strong>{dialog.req.commonName || dialog.req.requester}</strong> (template {dialog.req.template || "none"}, requested by {dialog.req.requester}). Every computer that trusts this CA will accept it. This needs a second factor.
        </ActionDialog>
      )}
      {dialog?.kind === "deny" && (
        <ActionDialog {...common} title="Deny request" label="Deny" op={{ action: `${M}.request_deny`, params: { id: dialog.req.id }, confirmed: true }}>
          Deny request {dialog.req.id} from {dialog.req.requester}?
        </ActionDialog>
      )}
      {dialog?.kind === "unrevoke" && (
        <ActionDialog {...common} title="Reinstate certificate" label="Reinstate" op={{ action: `${M}.certificate_unrevoke`, params: { serial: dialog.req.serial }, confirmed: true }}>
          Take the certificate on hold ({dialog.req.commonName}) back into use?
        </ActionDialog>
      )}
      {dialog?.kind === "revoke" && <RevokeDialog req={dialog.req} {...common} />}
      {dialog?.kind === "publish" && (
        <ActionDialog
          {...common}
          title="Publish template"
          label="Publish"
          danger={dialog.t.risky}
          op={{ action: `${M}.${dialog.t.risky ? "template_publish_risky" : "template_publish"}`, params: { name: dialog.t.name }, confirmed: true }}
        >
          Let this CA issue certificates from <strong>{dialog.t.displayName || dialog.t.name}</strong>?
          {dialog.t.risky && <> <strong>The requester names the subject of a certificate that can sign in</strong>, so anyone allowed to enroll can ask for a certificate as anyone. This needs a second factor.</>}
        </ActionDialog>
      )}
      {dialog?.kind === "unpublish" && (
        <ActionDialog {...common} title="Unpublish template" label="Unpublish" op={{ action: `${M}.template_unpublish`, params: { name: dialog.t.name }, confirmed: true }}>
          Stop issuing from <strong>{dialog.t.displayName || dialog.t.name}</strong>? Certificates already issued stay valid.
        </ActionDialog>
      )}
    </ModuleTab>
  );
}

function RevokeDialog({ req, ...p }: { req: CaRequest; device: Device; change: ReturnType<typeof useWinmodChange>; onClose: () => void }) {
  const [reason, setReason] = useState("unspecified");
  const [note, setNote] = useState("");
  return (
    <FormDialog
      {...p}
      title="Revoke certificate"
      description={req.commonName || req.requester}
      label="Revoke"
      valid
      build={() => ({ action: `${M}.certificate_revoke`, confirmed: true, params: { serial: req.serial, reason, ...(note.trim() ? { note: note.trim() } : {}) } })}
    >
      <SelectField label="Reason" value={reason} onChange={(e) => setReason(e.target.value)}>
        {REASONS.map(([v, l]) => (
          <option key={v} value={v}>{l}</option>
        ))}
      </SelectField>
      <TextField label="Note (kept in the audit log only)" value={note} onChange={(e) => setNote(e.target.value)} />
      <Alert tone="warn">A revocation cannot be undone, except for certificate hold. It reaches clients when the next revocation list is published and fetched: publish it afterwards. This needs a second factor.</Alert>
    </FormDialog>
  );
}

function RequestTable({ rows, empty, actions }: { rows: CaRequest[] | null; empty: string; actions: (r: CaRequest) => React.ReactNode }) {
  if (!rows) return <p className="p-4 text-sm text-muted">Reading…</p>;
  if (rows.length === 0) return <EmptyState compact title={empty} />;
  return (
    <TableWrap className="rounded-none border-0">
      <table className="table-base">
        <thead>
          <tr>
            <th scope="col">Request</th>
            <th scope="col">Subject</th>
            <th scope="col" className="hidden md:table-cell">Template</th>
            <th scope="col" className="hidden sm:table-cell">When</th>
            <th scope="col"><span className="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>{r.id}</td>
              <td>{r.commonName || r.requester}<div className="text-xs text-muted">{r.requester}</div></td>
              <td className="hidden md:table-cell">{r.template}</td>
              <td className="hidden sm:table-cell">{r.submitted ? formatDateTime(r.submitted) : "—"}</td>
              <td className="text-right whitespace-nowrap">{actions(r)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

function TemplateTable({ rows, empty, action }: { rows: CaTemplate[] | null; empty: string; action: (t: CaTemplate) => React.ReactNode }) {
  if (!rows) return <p className="p-4 text-sm text-muted">Reading…</p>;
  if (rows.length === 0) return <EmptyState compact title={empty} />;
  return (
    <TableWrap className="rounded-none border-0">
      <table className="table-base">
        <thead>
          <tr>
            <th scope="col">Template</th>
            <th scope="col">Risk</th>
            <th scope="col"><span className="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((t) => (
            <tr key={t.name}>
              <td className="font-medium">{t.displayName || t.name}</td>
              <td>
                {t.risky ? <Badge tone="danger">requester names the subject</Badge> : t.anyPurpose ? <Badge tone="warn">any purpose</Badge> : "—"}
                {t.lowPrivilegeEnroll && <Badge className="ml-2">anyone may enroll</Badge>}
              </td>
              <td className="text-right whitespace-nowrap">{action(t)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}
