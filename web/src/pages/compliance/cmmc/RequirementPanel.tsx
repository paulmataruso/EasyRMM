import { useState } from "react";
import { api, fieldError } from "../../../api/client";
import { useApi, useApiMutation, useList } from "../../../api/hooks";
import type { AssessmentDetail, EvidenceView, ObjectiveView, RequirementDetail } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { Dialog } from "../../../components/Dialog";
import { useToast } from "../../../components/Toast";
import { Badge, Button, ErrorState, InlineError, Mono, SelectField, Spinner, TextareaField, TextField } from "../../../components/ui";
import { formatRelative } from "../../../lib/format";
import { DETERMINATION_WORDS, RESPONSIBILITY, SOURCE_WORDS } from "./cmmcText";

/** One requirement in full: its text, objectives, statement, responsibility, evidence and attestations. */
export function RequirementPanel({ organizationId, assessment, base, reqId, onClose }: { organizationId: string; assessment: AssessmentDetail; base: string; reqId: string; onClose: () => void }) {
  const detail = useApi<RequirementDetail>(`${base}/requirements/${encodeURIComponent(reqId)}`);
  return (
    <Dialog open onClose={onClose} size="lg" title={detail.data ? `${detail.data.nistId} ${detail.data.title}` : "Requirement"} description={detail.data?.text}>
      {detail.isPending ? <Spinner /> : detail.isError ? <ErrorState error={detail.error} onRetry={() => void detail.refetch()} compact /> : <Body organizationId={organizationId} assessment={assessment} base={base} d={detail.data} />}
    </Dialog>
  );
}

function Body({ organizationId, assessment, base, d }: { organizationId: string; assessment: AssessmentDetail; base: string; d: RequirementDetail }) {
  const { canAt } = useAuth();
  const toast = useToast();
  const path = `${base}/requirements/${encodeURIComponent(d.reqId)}`;
  const mayEdit = canAt("compliance.edit", { organizationId }) && assessment.state === "draft";
  const mayAttest = canAt("compliance.attest", { organizationId }) && assessment.state === "draft";
  const [statement, setStatement] = useState(d.statement);
  const [responsibility, setResponsibility] = useState(d.responsibility);
  const [partial, setPartial] = useState(d.partial);
  const save = useApiMutation(() => api.put(path, { statement, responsibility, partial }), { invalidate: [base], onSuccess: () => toast.success("Saved.") });
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge tone={DETERMINATION_WORDS[d.status].tone}>{DETERMINATION_WORDS[d.status].label}</Badge>
        <span className="text-muted">Worth {d.weight} point(s) on the score.</span>
        {d.status !== "not_assessed" && <span className="text-muted">Decided by {d.origin === "scan" ? "a scan" : d.origin === "attested" ? "an attestation or evidence" : "a person's own call"}.</span>}
      </div>

      <section aria-label="Objectives" className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold">Objectives</h3>
        {d.objectiveList.map((o) => (
          <ObjectiveRow key={o.id} o={o} base={base} reqId={d.reqId} mayEdit={mayEdit} />
        ))}
      </section>

      <section aria-label="Statement" className="flex flex-col gap-3">
        <h3 className="text-sm font-semibold">How this is implemented</h3>
        <TextareaField label="Statement" rows={5} disabled={!mayEdit} value={statement} onChange={(e) => setStatement(e.target.value)} error={fieldError(save.error, "statement")} hint="In your own words. It goes into the system security plan." />
        <div className="flex flex-wrap items-end gap-3">
          <SelectField label="Who is responsible" disabled={!mayEdit} value={responsibility} onChange={(e) => setResponsibility(e.target.value as typeof responsibility)}>
            {Object.entries(RESPONSIBILITY).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </SelectField>
          {d.hasPartial && (
            <label className="flex items-center gap-2 pb-2 text-sm">
              <input type="checkbox" className="size-4 accent-accent" disabled={!mayEdit} checked={partial} onChange={(e) => setPartial(e.target.checked)} />
              Partly implemented (the methodology's partial-credit case)
            </label>
          )}
          {mayEdit && (
            <Button variant="primary" loading={save.isPending} onClick={() => save.mutate(undefined)}>
              Save
            </Button>
          )}
        </div>
        <InlineError error={save.error} fields={["statement"]} />
      </section>

      <Evidence organizationId={organizationId} base={base} d={d} mayEdit={mayEdit} assessmentId={assessment.id} />
      {mayAttest && <Attest base={base} d={d} />}
      {d.attestations.length > 0 && (
        <section aria-label="Attestations" className="flex flex-col gap-2">
          <h3 className="text-sm font-semibold">Attestations</h3>
          {d.attestations.map((a) => (
            <div key={a.id} className="rounded-md border border-line p-2 text-sm">
              <p>{a.statement}</p>
              <p className="text-xs text-muted">
                Signed {formatRelative(a.signedAt)}, {a.expired ? "expired" : "stands until"} {new Date(a.expiresAt).toLocaleDateString()}. An attestation is evidence, not a scan result.
              </p>
            </div>
          ))}
        </section>
      )}
    </div>
  );
}

function ObjectiveRow({ o, base, reqId, mayEdit }: { o: ObjectiveView; base: string; reqId: string; mayEdit: boolean }) {
  const toast = useToast();
  const [source, setSource] = useState<"upload" | "interview">("upload");
  const [note, setNote] = useState("");
  const set = useApiMutation((determination: string) => api.put(`${base}/requirements/${encodeURIComponent(reqId)}/objectives/${encodeURIComponent(o.id)}`, { determination, source, note }), {
    invalidate: [base],
    onSuccess: () => toast.success("Recorded."),
  });
  const w = DETERMINATION_WORDS[o.determination];
  return (
    <div className="rounded-md border border-line p-2 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{o.whole ? "The requirement as a whole" : `Objective ${o.id}`}</span>
        <Badge tone={w.tone}>{w.label}</Badge>
        {o.source && <span className="text-xs text-muted">{SOURCE_WORDS[o.source] ?? o.source}</span>}
        {o.expired && <Badge tone="warn">Expired</Badge>}
      </div>
      {!o.whole && o.text && <p className="text-muted">{o.text}</p>}
      {o.controls.length > 0 && (
        <p className="text-xs text-muted">
          Decided by scan on: <Mono>{o.controls.join(", ")}</Mono>
        </p>
      )}
      {o.note && <p className="text-xs text-muted">{o.note}</p>}
      {mayEdit && (
        <div className="mt-2 flex flex-wrap items-end gap-2">
          <SelectField label="By" value={source} onChange={(e) => setSource(e.target.value as typeof source)}>
            <option value="upload">Evidence attached</option>
            <option value="interview">Interview</option>
          </SelectField>
          <TextField label="Note" value={note} onChange={(e) => setNote(e.target.value)} className="min-w-48" />
          <Button loading={set.isPending} onClick={() => set.mutate("met")}>
            Mark met
          </Button>
          <Button loading={set.isPending} onClick={() => set.mutate("not_met")}>
            Mark not met
          </Button>
          <Button variant="ghost" loading={set.isPending} onClick={() => set.mutate("not_assessed")}>
            Clear
          </Button>
        </div>
      )}
      <InlineError error={set.error} />
    </div>
  );
}

function Evidence({ organizationId, base, d, mayEdit, assessmentId }: { organizationId: string; base: string; d: RequirementDetail; mayEdit: boolean; assessmentId: string }) {
  const toast = useToast();
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [picked, setPicked] = useState("");
  const library = useList<EvidenceView>(`/organizations/${organizationId}/compliance/evidence`);
  const ev = `/organizations/${organizationId}/compliance/evidence`;
  const upload = useApiMutation(
    () =>
      api.upload(
        `${ev}?title=${encodeURIComponent(title.trim() || file?.name || "Evidence")}&fileName=${encodeURIComponent(file?.name ?? "")}&mediaType=${encodeURIComponent(file?.type ?? "")}&assessmentId=${assessmentId}&reqId=${encodeURIComponent(d.reqId)}`,
        file as Blob,
      ),
    {
      invalidate: [base, ev],
      onSuccess: () => {
        toast.success("Evidence stored, encrypted.");
        setFile(null);
        setTitle("");
      },
    },
  );
  const attach = useApiMutation(() => api.post(`${ev}/${picked}/links`, { assessmentId, reqId: d.reqId }), { invalidate: [base, ev], onSuccess: () => toast.success("Attached.") });
  const linked = new Set(d.evidenceList.map((e) => e.id));
  return (
    <section aria-label="Evidence" className="flex flex-col gap-2">
      <h3 className="text-sm font-semibold">Evidence</h3>
      {d.evidenceList.length === 0 ? <p className="text-sm text-muted">No evidence is attached yet.</p> : null}
      <ul className="flex flex-col gap-1 text-sm">
        {d.evidenceList.map((e) => (
          <li key={e.id} className="flex flex-wrap items-center gap-2">
            <span>{e.title}</span>
            {e.supersededBy && <Badge tone="neutral">Replaced</Badge>}
            {e.expired && <Badge tone="warn">Expired</Badge>}
            <Mono className="text-xs text-muted">{e.sha256.slice(0, 12)}</Mono>
            {e.kind !== "link" ? (
              <a className="text-accent hover:underline" href={`/api/v1${ev}/${e.id}/download`} download>
                Download
              </a>
            ) : (
              <a className="text-accent hover:underline" href={e.url} target="_blank" rel="noreferrer noopener">
                Open link
              </a>
            )}
          </li>
        ))}
      </ul>
      {mayEdit && (
        <div className="flex flex-col gap-2 rounded-md border border-line p-2">
          <div className="flex flex-wrap items-end gap-2">
            <TextField label="Title" value={title} onChange={(e) => setTitle(e.target.value)} />
            <label className="text-sm">
              <span className="mb-1 block text-xs text-muted">File (up to 64 MiB)</span>
              <input type="file" aria-label="Evidence file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </label>
            <Button variant="primary" disabled={!file} loading={upload.isPending} onClick={() => upload.mutate(undefined)}>
              Upload
            </Button>
          </div>
          <InlineError error={upload.error} />
          <div className="flex flex-wrap items-end gap-2">
            <SelectField label="Or attach evidence already stored" value={picked} onChange={(e) => setPicked(e.target.value)}>
              <option value="">Choose</option>
              {library.items
                .filter((e) => !e.supersededBy && !linked.has(e.id))
                .map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.title}
                  </option>
                ))}
            </SelectField>
            <Button disabled={!picked} loading={attach.isPending} onClick={() => attach.mutate(undefined)}>
              Attach
            </Button>
          </div>
          <InlineError error={attach.error} />
        </div>
      )}
    </section>
  );
}

function Attest({ base, d }: { base: string; d: RequirementDetail }) {
  const toast = useToast();
  const [statement, setStatement] = useState("");
  const sign = useApiMutation(() => api.post(`${base}/requirements/${encodeURIComponent(d.reqId)}/attestations`, { statement }), {
    invalidate: [base],
    onSuccess: () => {
      toast.success("Attestation signed.");
      setStatement("");
    },
  });
  return (
    <section aria-label="Attest" className="flex flex-col gap-2 rounded-md border border-line p-2">
      <h3 className="text-sm font-semibold">Attest that this is implemented</h3>
      <p className="text-xs text-muted">
        You state, under your name, that this is implemented. It needs you to confirm again, it stands for one year, and it counts as evidence, never as a scan result. A scan
        that finds it does not meet outweighs it.
      </p>
      <TextareaField label="Your statement" rows={3} value={statement} onChange={(e) => setStatement(e.target.value)} error={fieldError(sign.error, "statement")} />
      <div>
        <Button variant="primary" disabled={statement.trim() === ""} loading={sign.isPending} onClick={() => sign.mutate(undefined)}>
          Sign the attestation
        </Button>
      </div>
      <InlineError error={sign.error} fields={["statement"]} />
    </section>
  );
}
