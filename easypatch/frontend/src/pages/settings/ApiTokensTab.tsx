import { useEffect, useState, type FormEvent } from 'react';
import { Ban, KeyRound, Plus } from 'lucide-react';
import { api } from '../../api/client';
import { useApiMutation, useList, useOrganizations } from '../../api/hooks';
import { API_TOKEN_ROLES, type ApiTokenDto, type ApiTokenRole, type CreateApiTokenRequest, type CreateApiTokenResponse } from '../../api/types';
import { CodeBlock, OneTimeNotice } from '../../components/Copy';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
import { useToast } from '../../components/Toast';
import { Badge, Button, EmptyState, ErrorState, InlineError, Mono, SelectField, Spinner, TableWrap, TextField } from '../../components/ui';
import { formatDateTime, formatRelative } from '../../lib/format';
import { OrgAccessPicker } from './UsersTab';

const ROLE_LABEL: Record<ApiTokenRole, string> = { ReadOnly: 'Read only', Admin: 'Operator' };

const ROLE_HELP: Record<ApiTokenRole, string> = {
  ReadOnly: 'Read endpoints, updates, jobs, alerts and reports. Cannot change anything.',
  Admin: 'Everything an Admin user can do in its organizations, including installing updates and restarting endpoints.',
};

const LIFETIMES = [30, 90, 180, 365];
const EXPIRING_SOON_DAYS = 14;

function roleLabel(role: string): string {
  return ROLE_LABEL[role as ApiTokenRole] ?? role;
}

function expiringSoon(token: ApiTokenDto): boolean {
  return token.status === 'Active' && new Date(token.expiresAt).getTime() - Date.now() < EXPIRING_SOON_DAYS * 86_400_000;
}

export function ApiTokensTab() {
  const toast = useToast();
  const list = useList<ApiTokenDto>('/api-tokens');
  const orgs = useOrganizations(true);
  const orgName = (id: string) => orgs.page.items.find((o) => o.id === id)?.name ?? 'Deleted organization';
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<CreateApiTokenResponse | null>(null);
  const [revoking, setRevoking] = useState<ApiTokenDto | null>(null);
  const revoke = useApiMutation((t: ApiTokenDto) => api.post<ApiTokenDto>(`/api-tokens/${t.id}/revoke`), {
    invalidate: ['/api-tokens'],
    onSuccess: (t) => {
      setRevoking(null);
      toast.success(`API token ${t.name} revoked. Requests with it are refused from now on.`);
    },
  });

  return (
    <>
      <div className="mb-3 flex items-start justify-between gap-2">
        <p className="text-sm text-muted">
          Tokens for scripts and integrations, sent as <Mono>Authorization: Bearer &lt;token&gt;</Mono>. A token acts with its role in its organizations. It cannot
          manage users, API tokens, server settings or anything else only super administrators can change. Requests are audited as <Mono>token:&lt;name&gt;</Mono>.
        </p>
        <Button variant="primary" icon={<Plus className="size-4" aria-hidden />} onClick={() => setCreating(true)}>
          New token
        </Button>
      </div>
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.page.items.length === 0 ? (
        <EmptyState title="No API tokens" icon={<KeyRound className="size-8" aria-hidden />} />
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>Token</th>
                <th>Role</th>
                <th>Organizations</th>
                <th>Expires</th>
                <th>Last used</th>
                <th>Created</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {list.page.items.map((t) => (
                <tr key={t.id} className={t.status === 'Active' ? undefined : 'opacity-60'}>
                  <td>
                    <div className="flex items-center gap-2 font-medium">
                      {t.name}
                      {t.status === 'Revoked' && <Badge tone="danger" title={`By ${t.revokedBy ?? 'unknown'} on ${formatDateTime(t.revokedAt)}`}>revoked</Badge>}
                      {t.status === 'Expired' && <Badge tone="warn">expired</Badge>}
                      {expiringSoon(t) && <Badge tone="warn">expires soon</Badge>}
                    </div>
                    <Mono className="text-xs text-muted">{t.prefix}…</Mono>
                  </td>
                  <td>{roleLabel(t.role)}</td>
                  <td className="max-w-64 text-sm">
                    {t.allOrganizations ? (
                      <span className="text-muted">All organizations</span>
                    ) : t.organizationIds.length === 0 ? (
                      <span className="text-muted">None (organizations deleted)</span>
                    ) : (
                      <span title={t.organizationIds.map(orgName).join(', ')}>{t.organizationIds.map(orgName).join(', ')}</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap" title={formatDateTime(t.expiresAt)}>
                    {formatRelative(t.expiresAt)}
                  </td>
                  <td className="whitespace-nowrap text-muted" title={t.lastUsedAt ? `${formatDateTime(t.lastUsedAt)} from ${t.lastUsedIp ?? 'unknown address'}` : undefined}>
                    {t.lastUsedAt ? formatRelative(t.lastUsedAt) : 'Never'}
                  </td>
                  <td className="whitespace-nowrap text-muted" title={formatDateTime(t.createdAt)}>
                    {formatRelative(t.createdAt)}
                    {t.createdBy && <div className="text-xs">by {t.createdBy}</div>}
                  </td>
                  <td>
                    <div className="flex justify-end">
                      {t.status !== 'Revoked' && (
                        <Button size="sm" variant="ghost" icon={<Ban className="size-3.5" aria-hidden />} onClick={() => setRevoking(t)}>
                          Revoke
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <CreateApiTokenDialog
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={(r) => {
          setCreating(false);
          setCreated(r);
        }}
      />
      <ConfirmDialog
        open={revoking !== null}
        onClose={() => setRevoking(null)}
        onConfirm={() => revoking && revoke.mutate(revoking)}
        loading={revoke.isPending}
        error={revoke.error}
        tone="danger"
        title={`Revoke the API token ${revoking?.name ?? ''}?`}
        confirmLabel="Revoke"
      >
        Scripts and integrations using it stop working immediately. This cannot be undone; create a new token to restore access.
      </ConfirmDialog>
      <Dialog open={created !== null} onClose={() => setCreated(null)} title={`API token ${created?.token.name ?? ''}`} footer={<Button variant="primary" onClick={() => setCreated(null)}>Done</Button>}>
        {created && (
          <div className="flex flex-col gap-3 text-sm">
            <OneTimeNotice>
              EasyPatch stores only a hash of this token. Keep it in a secrets manager, not in scripts or source control. If it is lost or exposed, revoke it and create a new
              one. It expires {formatRelative(created.token.expiresAt)} ({formatDateTime(created.token.expiresAt)}).
            </OneTimeNotice>
            <CodeBlock code={created.secret} />
            <p className="text-muted">Example:</p>
            <CodeBlock code={`curl -H "Authorization: Bearer $EASYPATCH_TOKEN" ${window.location.origin}/api/v1/endpoints`} />
          </div>
        )}
      </Dialog>
    </>
  );
}

function CreateApiTokenDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (r: CreateApiTokenResponse) => void }) {
  const empty: CreateApiTokenRequest = { name: '', role: 'ReadOnly', organizationIds: [], expiresInDays: 90 };
  const [form, setForm] = useState<CreateApiTokenRequest>(empty);
  const create = useApiMutation((req: CreateApiTokenRequest) => api.post<CreateApiTokenResponse>('/api-tokens', req), {
    invalidate: ['/api-tokens'],
    onSuccess: onCreated,
  });
  const reset = create.reset;
  useEffect(() => {
    if (open) {
      setForm({ name: '', role: 'ReadOnly', organizationIds: [], expiresInDays: 90 });
      reset();
    }
  }, [open, reset]);

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!form.name.trim()) return;
    create.mutate({ ...form, name: form.name.trim() });
  }

  return (
    <Dialog open={open} onClose={onClose} title="New API token">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <TextField
          label="Name"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          required
          maxLength={50}
          autoComplete="off"
          autoFocus
          placeholder="e.g. PSA compliance sync"
          hint="Shown in the audit log as token:<name>."
        />
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
          <SelectField label="Role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as ApiTokenRole })} hint={ROLE_HELP[form.role]}>
            {API_TOKEN_ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABEL[r]}
              </option>
            ))}
          </SelectField>
          <SelectField label="Expires after" value={String(form.expiresInDays)} onChange={(e) => setForm({ ...form, expiresInDays: Number(e.target.value) })}>
            {LIFETIMES.map((d) => (
              <option key={d} value={d}>
                {d} days
              </option>
            ))}
          </SelectField>
        </div>
        <OrgAccessPicker subject="token" value={form.organizationIds} onChange={(ids) => setForm({ ...form, organizationIds: ids })} />
        <InlineError error={create.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending} disabled={!form.name.trim()}>
            Create token
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
