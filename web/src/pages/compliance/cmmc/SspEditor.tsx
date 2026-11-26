import { useState } from "react";
import { api } from "../../../api/client";
import { useApi, useApiMutation } from "../../../api/hooks";
import type { AssessmentDetail, SspDocument, SspSection } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { useToast } from "../../../components/Toast";
import { Alert, Badge, Button, Card, ErrorState, InlineError, Spinner, TextareaField } from "../../../components/ui";

/**
 * The system security plan editor, from EasyRMM's own template. Some sections are written from the assessment (scope,
 * requirements, plan of action, score); the rest are for a person to write, with prompts. Editing a generated section makes
 * it the person's own: it is no longer rewritten.
 */
export function SspEditor({ assessment, base }: { assessment: AssessmentDetail; base: string }) {
  const { canAt } = useAuth();
  const toast = useToast();
  const doc = useApi<SspDocument>(`${base}/ssp`);
  const mayEdit = canAt("compliance.edit", { organizationId: assessment.organizationId }) && assessment.state === "draft";
  const gen = useApiMutation(() => api.post<SspDocument>(`${base}/ssp/generate`), {
    invalidate: [`${base}/ssp`],
    onSuccess: () => toast.success("The plan was written from the assessment."),
  });
  if (doc.isPending) return <Spinner />;
  if (doc.isError) return <ErrorState error={doc.error} onRetry={() => void doc.refetch()} />;
  const d = doc.data;
  return (
    <Card
      title={d.title}
      actions={
        mayEdit && (
          <Button variant="primary" loading={gen.isPending} onClick={() => gen.mutate(undefined)}>
            {d.exists ? "Write the generated sections again" : "Start the plan"}
          </Button>
        )
      }
    >
      {!d.exists && <Alert tone="info">The plan has not been started. These are the sections it will have; start it to write them from the assessment.</Alert>}
      <InlineError error={gen.error} />
      <div className="mt-3 flex flex-col gap-4">
        {d.sections.map((s) => (
          <Section key={`${s.position}:${s.body.length}:${s.generated}`} s={s} base={base} editable={mayEdit && d.exists} />
        ))}
      </div>
    </Card>
  );
}

function Section({ s, base, editable }: { s: SspSection; base: string; editable: boolean }) {
  const toast = useToast();
  const [body, setBody] = useState(s.body);
  const save = useApiMutation(() => api.put(`${base}/ssp/sections/${s.position}`, { body }), { invalidate: [`${base}/ssp`], onSuccess: () => toast.success("Section saved.") });
  return (
    <section className="flex flex-col gap-1.5">
      <h3 className="flex items-center gap-2 text-sm font-semibold">
        {s.heading}
        {s.generated && <Badge tone="info">Written from the assessment</Badge>}
      </h3>
      {s.hint && !s.generated && <p className="whitespace-pre-line text-xs text-muted">{s.hint}</p>}
      <TextareaField label="" aria-label={s.heading} rows={s.generated ? 6 : 4} disabled={!editable} value={body} onChange={(e) => setBody(e.target.value)} />
      {editable && body !== s.body && (
        <div>
          <Button loading={save.isPending} onClick={() => save.mutate(undefined)}>
            Save this section
          </Button>
        </div>
      )}
      <InlineError error={save.error} />
    </section>
  );
}
