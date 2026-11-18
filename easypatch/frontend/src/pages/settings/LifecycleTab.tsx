import { useEffect, useState, type FormEvent } from 'react';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import { api } from '../../api/client';
import { useApiMutation, useList } from '../../api/hooks';
import type { OsLifecycleDto, OsLifecycleRequest } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Badge, Button, EmptyState, ErrorState, InlineError, Spinner, TableWrap, TextField } from '../../components/ui';
import { formatDate } from '../../lib/format';

function status(entry: OsLifecycleDto): { label: string; tone: 'ok' | 'info' | 'danger' } {
  const today = new Date().toISOString().slice(0, 10);
  if (entry.endOfServicing >= today) return { label: 'Supported', tone: 'ok' };
  if (entry.esuEndDate && entry.esuEndDate >= today) return { label: 'ESU only', tone: 'info' };
  return { label: 'Out of support', tone: 'danger' };
}

export function LifecycleTab() {
  const { isSuperAdmin } = useAuth();
  const toast = useToast();
  const list = useList<OsLifecycleDto>('/lifecycle');
  const [editing, setEditing] = useState<OsLifecycleDto | 'new' | null>(null);
  const [deleting, setDeleting] = useState<OsLifecycleDto | null>(null);
  const remove = useApiMutation((id: string) => api.del(`/lifecycle/${id}`), {
    invalidate: ['/lifecycle'],
    onSuccess: () => {
      toast.success('Lifecycle entry deleted.');
      setDeleting(null);
    },
  });

  const rows = [...list.page.items].sort((a, b) => a.product.localeCompare(b.product) || b.buildNumber - a.buildNumber || a.editionGroup.localeCompare(b.editionGroup));

  return (
    <>
      <div className="mb-3 flex items-center justify-between gap-2">
        <p className="max-w-3xl text-sm text-muted">
          End-of-servicing dates used to flag unsupported operating systems. Entries are matched by product, edition group and build number. Microsoft can change
          these dates; keep them current.
        </p>
        {isSuperAdmin && (
          <Button variant="primary" icon={<Plus className="size-4" aria-hidden />} onClick={() => setEditing('new')}>
            Add entry
          </Button>
        )}
      </div>
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState title="No lifecycle entries" />
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>Product</th>
                <th>Version</th>
                <th className="text-right">Build</th>
                <th>Editions</th>
                <th>End of servicing</th>
                <th>ESU until</th>
                <th>Status</th>
                <th>Notes</th>
                {isSuperAdmin && <th className="text-right">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => {
                const st = status(e);
                return (
                  <tr key={e.id}>
                    <td className="whitespace-nowrap">{e.product}</td>
                    <td>{e.versionLabel}</td>
                    <td className="text-right tabular-nums">{e.buildNumber}</td>
                    <td>{e.editionGroup}</td>
                    <td className="whitespace-nowrap">{formatDate(e.endOfServicing)}</td>
                    <td className="whitespace-nowrap">{e.esuEndDate ? formatDate(e.esuEndDate) : '—'}</td>
                    <td>
                      <Badge tone={st.tone}>{st.label}</Badge>
                    </td>
                    <td className="text-xs text-muted">{e.notes ?? ''}</td>
                    {isSuperAdmin && (
                      <td>
                        <div className="flex justify-end gap-1">
                          <Button size="sm" variant="ghost" aria-label={`Edit ${e.product} ${e.versionLabel}`} onClick={() => setEditing(e)}>
                            <Pencil className="size-3.5" aria-hidden />
                          </Button>
                          <Button size="sm" variant="danger-ghost" aria-label={`Delete ${e.product} ${e.versionLabel}`} onClick={() => setDeleting(e)}>
                            <Trash2 className="size-3.5" aria-hidden />
                          </Button>
                        </div>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
      <LifecycleDialog entry={editing === 'new' ? null : editing} open={editing !== null} onClose={() => setEditing(null)} />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && remove.mutate(deleting.id)}
        loading={remove.isPending}
        error={remove.error}
        tone="danger"
        title={`Delete ${deleting?.product ?? ''} ${deleting?.versionLabel ?? ''}?`}
        confirmLabel="Delete entry"
      >
        Endpoints on this build show an unknown support status until a matching entry exists.
      </ConfirmDialog>
    </>
  );
}

const BLANK_ENTRY: OsLifecycleRequest = { product: 'Windows 11', editionGroup: 'HomePro', buildNumber: 26100, versionLabel: '24H2', endOfServicing: '', esuEndDate: null, notes: null };

function toRequest(e: OsLifecycleDto): OsLifecycleRequest {
  return { product: e.product, editionGroup: e.editionGroup, buildNumber: e.buildNumber, versionLabel: e.versionLabel, endOfServicing: e.endOfServicing, esuEndDate: e.esuEndDate, notes: e.notes };
}

function LifecycleDialog({ entry, open, onClose }: { entry: OsLifecycleDto | null; open: boolean; onClose: () => void }) {
  const toast = useToast();
  const [form, setForm] = useState<OsLifecycleRequest>(BLANK_ENTRY);
  useEffect(() => {
    if (open) setForm(entry ? toRequest(entry) : BLANK_ENTRY);
  }, [open, entry]);
  const save = useApiMutation((req: OsLifecycleRequest) => (entry ? api.put(`/lifecycle/${entry.id}`, req) : api.post('/lifecycle', req)), {
    invalidate: ['/lifecycle', '/endpoints'],
    onSuccess: () => {
      toast.success('Lifecycle entry saved.');
      onClose();
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ ...form, notes: form.notes?.trim() || null, esuEndDate: form.esuEndDate || null });
  }

  return (
    <Dialog open={open} onClose={onClose} title={entry ? 'Edit lifecycle entry' : 'Add lifecycle entry'}>
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
          <TextField label="Product" value={form.product} onChange={(e) => setForm({ ...form, product: e.target.value })} required hint="e.g. Windows 11, Windows Server" />
          <TextField label="Edition group" value={form.editionGroup} onChange={(e) => setForm({ ...form, editionGroup: e.target.value })} required hint="As used by existing entries" />
          <TextField label="Version label" value={form.versionLabel} onChange={(e) => setForm({ ...form, versionLabel: e.target.value })} required hint="e.g. 24H2" />
          <TextField label="Build number" type="number" min={1} value={form.buildNumber} onChange={(e) => setForm({ ...form, buildNumber: Number(e.target.value) })} required />
          <TextField label="End of servicing" type="date" value={form.endOfServicing} onChange={(e) => setForm({ ...form, endOfServicing: e.target.value })} required />
          <TextField label="ESU end date" type="date" value={form.esuEndDate ?? ''} onChange={(e) => setForm({ ...form, esuEndDate: e.target.value || null })} hint="Optional" />
        </div>
        <TextField label="Notes" value={form.notes ?? ''} onChange={(e) => setForm({ ...form, notes: e.target.value })} maxLength={500} />
        <InlineError error={save.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!form.product || !form.editionGroup || !form.versionLabel || !form.endOfServicing}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
