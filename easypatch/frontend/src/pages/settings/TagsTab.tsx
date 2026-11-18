import { useEffect, useState, type FormEvent } from 'react';
import { Pencil, Plus, Shield, Tag as TagIcon, Trash2 } from 'lucide-react';
import { Link } from 'react-router';
import { api } from '../../api/client';
import { useApiMutation, useList, usePolicy } from '../../api/hooks';
import { TAG_COLORS, type PolicyRequest, type TagDto, type TagRequest } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
import { PolicyEditor, resolveInherited } from '../../components/PolicyEditor';
import { TagChip } from '../../components/Tags';
import { useToast } from '../../components/Toast';
import { Alert, Badge, Button, cx, EmptyState, ErrorState, InlineError, Spinner, TableWrap, TextField } from '../../components/ui';

export function TagsTab() {
  const { isSuperAdmin } = useAuth();
  const toast = useToast();
  const list = useList<TagDto>('/tags');
  const [editing, setEditing] = useState<TagDto | 'new' | null>(null);
  const [deleting, setDeleting] = useState<TagDto | null>(null);
  const [policyFor, setPolicyFor] = useState<TagDto | null>(null);
  const remove = useApiMutation((t: TagDto) => api.del(`/tags/${t.id}`), {
    invalidate: ['/tags', '/endpoints'],
    onSuccess: (_, t) => {
      setDeleting(null);
      toast.success(`Tag ${t.name} deleted.`);
    },
  });

  return (
    <>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <p className="max-w-3xl text-sm text-muted">
          Tags group endpoints across organizations, for example update rings (“Pilot”, “Broad”) or roles (“SQL servers”). A tag can carry a policy that applies
          after the site policy and before the endpoint’s own policy; when an endpoint has several tags with policies, the higher priority wins. Put a tag on an
          endpoint, or on an organization or site (on the organization’s page) to give it to every endpoint there.
        </p>
        {isSuperAdmin && (
          <Button variant="primary" icon={<Plus className="size-4" aria-hidden />} onClick={() => setEditing('new')}>
            New tag
          </Button>
        )}
      </div>
      {!isSuperAdmin && <Alert tone="info" className="mb-3">Only super administrators can create tags and tag policies.</Alert>}
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.page.items.length === 0 ? (
        <EmptyState title="No tags" icon={<TagIcon className="size-8" aria-hidden />}>
          Create a tag such as “Pilot” and give it a short rollout delay to test updates on a few endpoints first.
        </EmptyState>
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>Tag</th>
                <th>Priority</th>
                <th>Endpoints</th>
                <th>Policy</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {list.page.items.map((t) => (
                <tr key={t.id}>
                  <td>
                    <TagChip tag={t} />
                    {t.description && <div className="mt-0.5 text-xs text-muted">{t.description}</div>}
                  </td>
                  <td className="tabular-nums">{t.priority}</td>
                  <td>
                    <Link className="text-accent hover:underline" to={`/endpoints?tagId=${t.id}`}>
                      {t.endpointCount}
                    </Link>
                    {(t.siteCount > 0 || t.organizationCount > 0) && (
                      <div className="text-xs text-muted">
                        {[
                          t.organizationCount > 0 && `${t.organizationCount} organization${t.organizationCount === 1 ? '' : 's'}`,
                          t.siteCount > 0 && `${t.siteCount} site${t.siteCount === 1 ? '' : 's'}`,
                        ]
                          .filter(Boolean)
                          .join(' · ')}
                      </div>
                    )}
                  </td>
                  <td>{t.hasPolicy ? <Badge tone="accent">Policy</Badge> : <span className="text-sm text-subtle">None</span>}</td>
                  <td>
                    {isSuperAdmin && (
                      <div className="flex justify-end gap-1">
                        <Button size="sm" variant="ghost" icon={<Shield className="size-3.5" aria-hidden />} onClick={() => setPolicyFor(t)}>
                          Policy
                        </Button>
                        <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setEditing(t)}>
                          Edit
                        </Button>
                        <Button size="sm" variant="danger-ghost" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={() => setDeleting(t)}>
                          Delete
                        </Button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <TagDialog tag={editing} onClose={() => setEditing(null)} />
      <TagPolicyDialog tag={policyFor} onClose={() => setPolicyFor(null)} />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && remove.mutate(deleting)}
        title={`Delete tag ${deleting?.name ?? ''}?`}
        confirmLabel="Delete tag"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        The tag is removed from {deleting?.endpointCount ?? 0} endpoint(s)
        {(deleting?.siteCount ?? 0) + (deleting?.organizationCount ?? 0) > 0 ? ' (including those that have it through a site or organization)' : ''}
        {deleting?.hasPolicy ? ' and its policy is deleted; those endpoints go back to their site, organization and global policy' : ''}.
      </ConfirmDialog>
    </>
  );
}

function TagDialog({ tag, onClose }: { tag: TagDto | 'new' | null; onClose: () => void }) {
  const toast = useToast();
  const isNew = tag === 'new';
  const [form, setForm] = useState<TagRequest>({ name: '', color: 'blue', description: null, priority: 0 });
  useEffect(() => {
    if (tag === 'new') setForm({ name: '', color: 'blue', description: null, priority: 0 });
    else if (tag) setForm({ name: tag.name, color: tag.color, description: tag.description, priority: tag.priority });
  }, [tag]);
  const save = useApiMutation((req: TagRequest) => (isNew ? api.post<TagDto>('/tags', req) : api.put<TagDto>(`/tags/${(tag as TagDto).id}`, req)), {
    invalidate: ['/tags', '/endpoints'],
    onSuccess: (t) => {
      toast.success(isNew ? `Tag ${t.name} created.` : `Tag ${t.name} saved.`);
      onClose();
    },
  });
  const nameError = form.name.trim().length > 40 ? 'At most 40 characters.' : null;

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!form.name.trim() || nameError) return;
    save.mutate({ ...form, name: form.name.trim(), description: form.description?.trim() || null });
  }

  return (
    <Dialog open={tag !== null} onClose={onClose} title={isNew ? 'New tag' : 'Edit tag'} size="sm">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <TextField label="Name" required maxLength={40} value={form.name} error={nameError ?? undefined} onChange={(e) => setForm({ ...form, name: e.target.value })} autoFocus />
        <fieldset>
          <legend className="mb-1 text-sm font-medium">Color</legend>
          <div className="flex flex-wrap gap-1.5">
            {TAG_COLORS.map((c) => (
              <button
                key={c}
                type="button"
                aria-pressed={form.color === c}
                onClick={() => setForm({ ...form, color: c })}
                className={cx('rounded-md p-0.5 ring-offset-1 ring-offset-surface', form.color === c && 'ring-2 ring-accent')}
              >
                <TagChip tag={{ id: c, name: c, color: c }} />
              </button>
            ))}
          </div>
        </fieldset>
        <TextField label="Description" maxLength={500} value={form.description ?? ''} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        <TextField
          label="Priority"
          type="number"
          min={0}
          max={1000}
          step={1}
          hint="When an endpoint has several tags with policies, the tag with the higher priority wins (ties: alphabetical order)."
          value={String(form.priority)}
          onChange={(e) => setForm({ ...form, priority: e.target.value === '' ? 0 : Number(e.target.value) })}
        />
        <InlineError error={save.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!form.name.trim() || !!nameError}>
            {isNew ? 'Create tag' : 'Save'}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function TagPolicyDialog({ tag, onClose }: { tag: TagDto | null; onClose: () => void }) {
  const toast = useToast();
  const path = tag ? `/tags/${tag.id}/policy` : null;
  const policy = usePolicy(path);
  const global = usePolicy(tag ? '/policies/global' : null);
  const save = useApiMutation((req: PolicyRequest) => api.put(path as string, req), {
    invalidate: ['/tags', '/endpoints'],
    onSuccess: () => toast.success(`Policy of tag ${tag?.name ?? ''} saved. Endpoints pick up the change at their next check-in.`),
  });
  const reset = useApiMutation(() => api.del(path as string), {
    invalidate: ['/tags', '/endpoints'],
    onSuccess: () => {
      toast.success(`Policy of tag ${tag?.name ?? ''} removed.`);
      onClose();
    },
  });

  return (
    <Dialog open={tag !== null} onClose={onClose} title={<>Policy of tag {tag && <TagChip tag={tag} className="ml-1 align-middle" />}</>} size="xl">
      {policy.isPending || global.isPending ? (
        <Spinner />
      ) : policy.isError ? (
        <ErrorState error={policy.error} onRetry={() => void policy.refetch()} />
      ) : (
        <PolicyEditor
          scope="Tag"
          policy={policy.data?.id ? policy.data : null}
          inherited={resolveInherited([global.data])}
          readOnly={false}
          saving={save.isPending}
          deleting={reset.isPending}
          error={save.error ?? reset.error}
          onSave={(req) => save.mutate(req)}
          onReset={() => reset.mutate()}
        />
      )}
    </Dialog>
  );
}
