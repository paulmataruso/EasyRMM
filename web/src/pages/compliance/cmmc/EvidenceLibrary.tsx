import { useState } from "react";
import { api } from "../../../api/client";
import { useApiMutation, useList } from "../../../api/hooks";
import type { AssessmentDetail, EvidenceView } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { useToast } from "../../../components/Toast";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, InlineError, Mono, Spinner, TableWrap, TextField } from "../../../components/ui";
import { formatRelative } from "../../../lib/format";
import { bytes } from "./cmmcText";

/**
 * The organization's evidence. It is encrypted when stored, its SHA-256 is recorded and checked on every download, every
 * upload and download is in the audit log, and nothing is ever deleted: a newer version replaces an older one, and the
 * older one stays.
 */
export function EvidenceLibrary({ organizationId }: { organizationId: string; assessment: AssessmentDetail }) {
  const { canAt } = useAuth();
  const toast = useToast();
  const path = `/organizations/${organizationId}/compliance/evidence`;
  const list = useList<EvidenceView>(path, { all: 1 });
  const mayEdit = canAt("compliance.edit", { organizationId });
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [replace, setReplace] = useState<EvidenceView | null>(null);
  const upload = useApiMutation(
    () =>
      api.upload(
        `${path}${replace ? `/${replace.id}/supersede` : ""}?title=${encodeURIComponent(title.trim() || file?.name || "Evidence")}&fileName=${encodeURIComponent(file?.name ?? "")}&mediaType=${encodeURIComponent(file?.type ?? "")}`,
        file as Blob,
      ),
    {
      invalidate: [path],
      onSuccess: () => {
        toast.success(replace ? "Replaced. The older version is kept." : "Evidence stored, encrypted.");
        setFile(null);
        setTitle("");
        setReplace(null);
      },
    },
  );
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  return (
    <Card title="Evidence">
      <Alert tone="info">Evidence may hold controlled information. It is encrypted at rest, only people with access to this organization can read it, and every upload and download is recorded. It is never deleted.</Alert>
      {mayEdit && (
        <div className="mt-3 flex flex-wrap items-end gap-3">
          <TextField label={replace ? `New version of “${replace.title}”` : "Title"} value={title} onChange={(e) => setTitle(e.target.value)} />
          <label className="text-sm">
            <span className="mb-1 block text-xs text-muted">File (up to 64 MiB)</span>
            <input type="file" aria-label="File to store" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          </label>
          <Button variant="primary" disabled={!file} loading={upload.isPending} onClick={() => upload.mutate(undefined)}>
            {replace ? "Replace" : "Upload"}
          </Button>
          {replace && (
            <Button variant="ghost" onClick={() => setReplace(null)}>
              Cancel the replacement
            </Button>
          )}
        </div>
      )}
      <InlineError error={upload.error} />
      {list.items.length === 0 ? (
        <EmptyState title="No evidence yet" compact />
      ) : (
        <TableWrap className="mt-3">
          <table className="w-full text-left text-sm" aria-label="Evidence">
            <thead>
              <tr className="text-xs text-muted">
                <th className="px-3 py-2 font-medium">Title</th>
                <th className="px-2 py-2 font-medium">Stored</th>
                <th className="px-2 py-2 font-medium">Size</th>
                <th className="px-2 py-2 font-medium">SHA-256</th>
                <th className="px-2 py-2 font-medium" />
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {list.items.map((e) => (
                <tr key={e.id}>
                  <td className="px-3 py-2">
                    {e.title} {e.supersededBy && <Badge tone="neutral">Replaced</Badge>} {e.expired && <Badge tone="warn">Expired</Badge>}
                    <span className="block text-xs text-muted">{e.fileName}</span>
                  </td>
                  <td className="px-2 py-2">{formatRelative(e.collectedAt)}</td>
                  <td className="px-2 py-2">{bytes(e.size)}</td>
                  <td className="px-2 py-2">
                    <Mono className="text-xs">{e.sha256.slice(0, 16)}…</Mono>
                  </td>
                  <td className="px-2 py-2 text-right">
                    {e.kind !== "link" ? (
                      <a className="text-accent hover:underline" href={`/api/v1${path}/${e.id}/download`} download>
                        Download
                      </a>
                    ) : (
                      <a className="text-accent hover:underline" href={e.url} target="_blank" rel="noreferrer noopener">
                        Open link
                      </a>
                    )}
                    {mayEdit && !e.supersededBy && e.kind !== "link" && (
                      <button type="button" className="ml-3 text-accent hover:underline" onClick={() => setReplace(e)}>
                        Replace
                      </button>
                    )}
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
