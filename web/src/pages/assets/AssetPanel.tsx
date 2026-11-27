// The Asset tab of a device (ADR-0066, slice 2): the hardware record with each field's value by source. The agent's
// values and a person's sit side by side and never overwrite each other.

import { useEffect, useState, type FormEvent } from "react";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { api, ApiError, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { Asset, AssetField, AssetPatch } from "../../api/assetTypes";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, InlineError, SelectField, Spinner, TextField } from "../../components/ui";
import { formatDate } from "../../lib/format";
import { ageBadge, ASSET_KINDS, ASSET_STATUSES, kindLabel, osSupportBadge, statusLabel, warrantyBadge } from "./assetText";

const DATE_FIELDS = new Set(["purchase_date", "warranty_expiry", "os_eol_date"]);

function manualOf(f: AssetField): string {
  return f.sources.find((s) => s.source === "manual")?.value ?? "";
}

function agentOf(f: AssetField) {
  return f.sources.find((s) => s.source === "agent");
}

function shown(f: AssetField): string {
  if (!f.effective) return "—";
  return DATE_FIELDS.has(f.field) ? formatDate(f.effective) : f.effective;
}

/** Where the agent's value stands: what it reported, or why it has none. */
function AgentNote({ f }: { f: AssetField }) {
  const a = agentOf(f);
  if (!a) return null;
  if (a.state !== "reported" || !a.value) {
    return <span className="text-muted">Agent: not reported{a.reason ? ` (${a.reason})` : ""}</span>;
  }
  return <span className="text-muted">Agent: {a.value}</span>;
}

export function AssetPanel({ deviceId }: { deviceId: string }) {
  const toast = useToast();
  const asset = useApi<Asset>(`/devices/${deviceId}/asset`, undefined, { staleTime: 15_000 });
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const create = useApiMutation(() => api.post<Asset>(`/devices/${deviceId}/asset`), {
    invalidate: [`/devices/${deviceId}/asset`, "/audit"],
    onSuccess: () => toast.success("Asset record created."),
  });
  const remove = useApiMutation((a: Asset) => api.del(`/assets/${a.id}`), {
    invalidate: [`/devices/${deviceId}/asset`, "/audit"],
    onSuccess: () => {
      toast.success("Asset record deleted.");
      setDeleting(false);
    },
  });

  if (asset.isPending) return <Spinner />;
  if (asset.isError) {
    if (asset.error instanceof ApiError && asset.error.status === 404) {
      return (
        <Card>
          <EmptyState title="No asset record" action={<Button variant="primary" icon={<Plus className="size-4" aria-hidden />} loading={create.isPending} onClick={() => create.mutate()}>Create asset record</Button>}>
            This device has no asset record yet. One is made when the agent reports its hardware; you can also make it now.
            <InlineError error={create.error} />
          </EmptyState>
        </Card>
      );
    }
    return <ErrorState error={asset.error} onRetry={() => void asset.refetch()} />;
  }
  const a = asset.data;
  const warranty = warrantyBadge(a.warrantyState);
  const age = ageBadge(a.ageStatus);
  const os = osSupportBadge(a.osSupport);
  return (
    <Card
      title="Asset record"
      actions={
        a.canManage && (
          <div className="flex gap-2">
            <Button size="sm" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setEditing(true)}>
              Edit
            </Button>
            <Button size="sm" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={() => setDeleting(true)}>
              Delete
            </Button>
          </div>
        )
      }
    >
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Badge>{kindLabel(a.kind)}</Badge>
        <Badge tone={a.status === "in_use" ? "ok" : "neutral"}>{statusLabel(a.status)}</Badge>
        <Badge tone={warranty.tone}>{warranty.label}</Badge>
        {age && <Badge tone={age.tone}>{age.label}</Badge>}
        {os && <Badge tone={os.tone}>{os.label}</Badge>}
      </div>
      <dl className="grid grid-cols-1 gap-x-8 gap-y-3 md:grid-cols-2">
        {(a.fields ?? []).map((f) => (
          <div key={f.field}>
            <dt className="text-xs font-medium uppercase tracking-wide text-muted">{f.label}</dt>
            <dd className="break-words">
              {shown(f)}
              <div className="flex flex-wrap gap-x-3 text-xs">
                <AgentNote f={f} />
                {f.differs && <Badge tone="warn">Entered: {manualOf(f)} (differs)</Badge>}
              </div>
            </dd>
          </div>
        ))}
        <div>
          <dt className="text-xs font-medium uppercase tracking-wide text-muted">Site</dt>
          <dd>{a.siteName}</dd>
        </div>
      </dl>
      {a.notes && (
        <div className="mt-4">
          <h3 className="text-xs font-medium uppercase tracking-wide text-muted">Notes</h3>
          <p className="whitespace-pre-wrap">{a.notes}</p>
        </div>
      )}
      <AssetDialog asset={a} open={editing} onClose={() => setEditing(false)} invalidate={[`/devices/${deviceId}/asset`]} />
      <ConfirmDialog
        open={deleting}
        onClose={() => {
          setDeleting(false);
          remove.reset();
        }}
        onConfirm={() => remove.mutate(a)}
        title="Delete asset record"
        confirmLabel="Delete record"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        <p>Delete this asset record, with the values entered by hand? The device stays; the agent makes a new record when it next reports.</p>
      </ConfirmDialog>
    </Card>
  );
}

/** Edits an asset: kind, status, notes and the manual value of each field. */
export function AssetDialog({ asset, open, onClose, invalidate }: { asset: Asset; open: boolean; onClose: () => void; invalidate: string[] }) {
  const toast = useToast();
  const fields = asset.fields ?? [];
  const [kind, setKind] = useState(asset.kind);
  const [status, setStatus] = useState(asset.status);
  const [notes, setNotes] = useState(asset.notes);
  const [values, setValues] = useState<Record<string, string>>({});
  useEffect(() => {
    if (!open) return;
    setKind(asset.kind);
    setStatus(asset.status);
    setNotes(asset.notes);
    setValues(Object.fromEntries((asset.fields ?? []).map((f) => [f.field, manualOf(f)])));
  }, [open, asset]);
  const save = useApiMutation((p: AssetPatch) => api.patch<Asset>(`/assets/${asset.id}`, p), {
    invalidate: [...invalidate, `/assets/${asset.id}`, `/organizations/${asset.organizationId}/assets`, "/audit"],
    onSuccess: () => {
      toast.success("Asset record updated.");
      onClose();
    },
  });
  useEffect(() => {
    if (open) save.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function patch(confirm: boolean): AssetPatch {
    const p: AssetPatch = {};
    if (kind !== asset.kind) p.kind = kind;
    if (status !== asset.status) p.status = status;
    if (notes !== asset.notes) p.notes = notes;
    const changed: Record<string, string | null> = {};
    for (const f of fields) {
      const now = (values[f.field] ?? "").trim();
      if (now !== manualOf(f)) changed[f.field] = now === "" ? null : now;
    }
    if (Object.keys(changed).length > 0) p.fields = changed;
    if (confirm) p.confirmDuplicateSerial = true;
    return p;
  }
  const duplicate = save.error instanceof ApiError && save.error.code === "duplicate_serial";
  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate(patch(false));
  }

  return (
    <Dialog open={open} onClose={onClose} title="Edit asset record" description="Values you enter sit beside the agent's and never replace them." size="lg">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2">
          <SelectField label="Kind" value={kind} onChange={(e) => setKind(e.target.value)} error={fieldError(save.error, "kind")}>
            {ASSET_KINDS.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </SelectField>
          <SelectField label="Status" value={status} onChange={(e) => setStatus(e.target.value)} error={fieldError(save.error, "status")}>
            {ASSET_STATUSES.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </SelectField>
          {fields.map((f) =>
            f.field === "warranty_status" ? (
              <SelectField key={f.field} label={f.label} value={values[f.field] ?? ""} onChange={(e) => setValues((v) => ({ ...v, [f.field]: e.target.value }))} error={fieldError(save.error, f.field)}>
                <option value="">Not set</option>
                <option value="active">Active</option>
                <option value="expired">Expired</option>
                <option value="unknown">Unknown</option>
              </SelectField>
            ) : (
              <TextField
                key={f.field}
                label={f.label}
                type={DATE_FIELDS.has(f.field) ? "date" : "text"}
                value={values[f.field] ?? ""}
                maxLength={200}
                hint={agentOf(f) ? <AgentNote f={f} /> : undefined}
                onChange={(e) => setValues((v) => ({ ...v, [f.field]: e.target.value }))}
                error={fieldError(save.error, f.field)}
              />
            ),
          )}
        </div>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">Notes</span>
          <textarea className="min-h-20 rounded-md border border-line bg-surface p-2" value={notes} maxLength={4000} onChange={(e) => setNotes(e.target.value)} />
          {fieldError(save.error, "notes") && <span className="text-danger">{fieldError(save.error, "notes")}</span>}
        </label>
        {duplicate ? (
          <Alert tone="warn">
            An asset with this serial number already exists in this organization.
            <Button className="ml-2" size="sm" loading={save.isPending} onClick={() => save.mutate(patch(true))}>
              Save anyway
            </Button>
          </Alert>
        ) : (
          <InlineError error={save.error} fields={["kind", "status", "notes", ...fields.map((f) => f.field)]} />
        )}
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending}>
            Save changes
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
