import { useEffect, useState, type FormEvent } from 'react';
import { KeyRound, Plus } from 'lucide-react';
import { api } from '../../api/client';
import { useApiMutation, useList } from '../../api/hooks';
import type { CreatedTokenDto, CreateTokensRequest, EnrollmentTokenDto } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { CodeBlock, CopyButton, DownloadButton, OneTimeNotice } from '../../components/Copy';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
import { OrganizationSelect, SiteSelect } from '../../components/Filters';
import { StateBadge } from '../../components/StatusBadges';
import { useToast } from '../../components/Toast';
import { Alert, Button, Checkbox, EmptyState, ErrorState, InlineError, Pagination, Spinner, TableWrap, TextField, Toolbar } from '../../components/ui';
import { formatDateTime, formatRelative } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';
import { MacOSExperimentalNotice } from './DeploymentCodesTab';

export function TokensTab() {
  const { canOperate } = useAuth();
  const toast = useToast();
  const url = useUrlState();
  const organizationId = url.get('organizationId');
  const includeInactive = url.get('inactive') === 'true';
  const list = useList<EnrollmentTokenDto>('/enrollment-tokens', {
    organizationId: organizationId || undefined,
    includeInactive: includeInactive || undefined,
    page: url.page,
    pageSize: 50,
  }, { keepPrevious: true });
  const [creating, setCreating] = useState(url.get('create') === '1' && canOperate);
  const [created, setCreated] = useState<CreatedTokenDto[] | null>(null);
  const [revoking, setRevoking] = useState<EnrollmentTokenDto | null>(null);

  const revoke = useApiMutation((id: string) => api.post(`/enrollment-tokens/${id}/revoke`), {
    invalidate: ['/enrollment-tokens'],
    onSuccess: () => {
      toast.success('Token revoked. It can no longer enroll endpoints.');
      setRevoking(null);
    },
  });

  const items = includeInactive ? list.page.items : list.page.items.filter((t) => t.state === 'Active');

  return (
    <>
      <Alert tone="info" className="mb-4">
        Enrollment tokens are secrets for <code>msiexec</code> or Group Policy installs on Windows, and for <code>easypatch-agent enroll</code> on Linux (and on
        macOS, where the agent is experimental). Endpoints
        enrolled with a token are active immediately. Tokens are stored hashed, expire, and are limited to a number of uses. For RMM scripts without a secret, use
        a deployment code instead.
      </Alert>
      <Toolbar>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v })} />
        <Checkbox label="Show expired, used and revoked" checked={includeInactive} onChange={(e) => url.set({ inactive: e.target.checked })} className="pb-2" />
        <span className="flex-1" />
        {canOperate && (
          <Button variant="primary" className="mb-0.5" icon={<Plus className="size-4" aria-hidden />} onClick={() => setCreating(true)}>
            Create tokens
          </Button>
        )}
      </Toolbar>
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState title="No active enrollment tokens" icon={<KeyRound className="size-8" aria-hidden />} />
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <th>Token</th>
                  <th>Organization / site</th>
                  <th>Description</th>
                  <th className="text-right">Uses</th>
                  <th>Expires</th>
                  <th>Last used</th>
                  <th>State</th>
                  {canOperate && <th className="text-right">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {items.map((t) => (
                  <tr key={t.id}>
                    <td className="font-mono text-xs whitespace-nowrap">{t.tokenPrefix}…</td>
                    <td className="whitespace-nowrap">
                      {t.organizationName}
                      {t.siteName && <span className="text-muted"> · {t.siteName}</span>}
                    </td>
                    <td className="text-muted">{t.description ?? '—'}</td>
                    <td className="text-right tabular-nums">
                      {t.useCount} / {t.maxUses}
                    </td>
                    <td className="whitespace-nowrap" title={formatDateTime(t.expiresAt)}>
                      {formatRelative(t.expiresAt)}
                    </td>
                    <td className="whitespace-nowrap text-muted">{formatRelative(t.lastUsedAt)}</td>
                    <td>
                      <StateBadge state={t.state} />
                    </td>
                    {canOperate && (
                      <td className="text-right">
                        {t.state === 'Active' && (
                          <Button size="sm" variant="danger-ghost" onClick={() => setRevoking(t)}>
                            Revoke
                          </Button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={(p) => url.set({ page: p })} />
        </>
      )}

      <CreateTokensDialog
        open={creating}
        defaultOrganizationId={organizationId}
        onClose={() => {
          setCreating(false);
          url.set({ create: null }, { resetPage: false });
        }}
        onCreated={(tokens) => {
          setCreating(false);
          url.set({ create: null }, { resetPage: false });
          setCreated(tokens);
        }}
      />
      <CreatedTokensDialog tokens={created} onClose={() => setCreated(null)} />
      <ConfirmDialog
        open={revoking !== null}
        onClose={() => setRevoking(null)}
        onConfirm={() => revoking && revoke.mutate(revoking.id)}
        loading={revoke.isPending}
        error={revoke.error}
        tone="danger"
        title="Revoke this enrollment token?"
        confirmLabel="Revoke token"
      >
        Endpoints already enrolled with it are not affected. Installers that still use it will fail to enroll.
      </ConfirmDialog>
    </>
  );
}

function CreateTokensDialog({ open, defaultOrganizationId, onClose, onCreated }: {
  open: boolean;
  defaultOrganizationId: string;
  onClose: () => void;
  onCreated: (tokens: CreatedTokenDto[]) => void;
}) {
  const [org, setOrg] = useState(defaultOrganizationId);
  const [site, setSite] = useState('');
  const [description, setDescription] = useState('');
  const [hours, setHours] = useState(24);
  const [maxUses, setMaxUses] = useState(1);
  const [count, setCount] = useState(1);
  useEffect(() => {
    if (open) {
      setOrg(defaultOrganizationId);
      setSite('');
      setDescription('');
      setHours(24);
      setMaxUses(1);
      setCount(1);
    }
  }, [open, defaultOrganizationId]);

  const create = useApiMutation((req: CreateTokensRequest) => api.post<CreatedTokenDto[]>('/enrollment-tokens', req), {
    invalidate: ['/enrollment-tokens'],
    onSuccess: (tokens) => onCreated(Array.isArray(tokens) ? tokens : []),
  });

  const invalid = !org || hours < 1 || hours > 720 || maxUses < 1 || maxUses > 1000 || count < 1 || count > 500;

  function submit(e: FormEvent) {
    e.preventDefault();
    if (invalid) return;
    create.mutate({ organizationId: org, siteId: site || null, description: description.trim() || null, expiresInHours: hours, maxUses, count });
  }

  return (
    <Dialog open={open} onClose={onClose} title="Create enrollment tokens">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
          <OrganizationSelect value={org} onChange={(v) => { setOrg(v); setSite(''); }} required />
          <SiteSelect organizationId={org} value={site} onChange={setSite} allLabel="No site" />
        </div>
        <TextField label="Description" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={200} placeholder="e.g. Accounting laptops rollout" />
        <div className="grid grid-cols-3 gap-3.5">
          <TextField label="Expires in (hours)" type="number" min={1} max={720} value={hours} onChange={(e) => setHours(Number(e.target.value))} hint="1–720" />
          <TextField label="Uses per token" type="number" min={1} max={1000} value={maxUses} onChange={(e) => setMaxUses(Number(e.target.value))} hint="1–1000" />
          <TextField label="Number of tokens" type="number" min={1} max={500} value={count} onChange={(e) => setCount(Number(e.target.value))} hint="1–500" />
        </div>
        <p className="text-xs text-muted">Prefer short expiry and single use. A multi-use token is a shared secret until it expires.</p>
        <InlineError error={create.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending} disabled={invalid}>
            Create
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function CreatedTokensDialog({ tokens, onClose }: { tokens: CreatedTokenDto[] | null; onClose: () => void }) {
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    if (tokens) setSaved(false);
  }, [tokens]);
  const mac = (tokens ?? []).some((t) => t.macEnrollCommand);
  const text = (tokens ?? [])
    .map((t) => [t.plaintextToken, t.msiExecCommand, t.linuxEnrollCommand ?? '', ...(mac ? [t.macEnrollCommand ?? ''] : [])].join('\t'))
    .join('\n');
  return (
    <Dialog
      open={tokens !== null}
      onClose={onClose}
      dismissible={false}
      size="lg"
      title={`${tokens?.length ?? 0} enrollment token${tokens?.length === 1 ? '' : 's'} created`}
      footer={
        <>
          <Checkbox label="I have copied the tokens" checked={saved} onChange={(e) => setSaved(e.target.checked)} className="mr-auto" />
          <Button variant="primary" disabled={!saved} onClick={onClose}>
            Done
          </Button>
        </>
      }
    >
      {tokens && (
        <div className="flex flex-col gap-4">
          <OneTimeNotice>
            Tokens are shown only now. Treat them like passwords: anyone holding a token can enroll a device into this organization until it expires or its uses run
            out.
          </OneTimeNotice>
          {mac && <MacOSExperimentalNotice />}
          {tokens.length > 1 && (
            <div className="flex gap-2">
              <CopyButton text={tokens.map((t) => t.plaintextToken).join('\n')} label="Copy all tokens" />
              <DownloadButton fileName="easypatch-enrollment-tokens.tsv" text={`token\tmsiexec\tlinux${mac ? '\tmacos' : ''}\n${text}\n`} label="Download (TSV)" mime="text/tab-separated-values" />
            </div>
          )}
          {tokens.map((t, i) => (
            <div key={t.token.id} className="flex flex-col gap-2 rounded-md border border-line p-3">
              <p className="text-xs font-medium text-muted">
                Token {tokens.length > 1 ? `${i + 1} ` : ''}· expires {formatDateTime(t.token.expiresAt)} · {t.token.maxUses} use{t.token.maxUses === 1 ? '' : 's'}
              </p>
              <CodeBlock code={t.plaintextToken} />
              <p className="text-xs text-muted">Windows: silent install command (run as administrator; download the MSI from the Agent packages tab):</p>
              <CodeBlock code={t.msiExecCommand} />
              {t.linuxEnrollCommand && (
                <>
                  <p className="text-xs text-muted">
                    Linux: install the .deb or .rpm package from the Agent packages tab, then enroll (the token is piped in, so it does not appear in the process
                    list):
                  </p>
                  <CodeBlock code={t.linuxEnrollCommand} />
                </>
              )}
              {t.macEnrollCommand && (
                <>
                  <p className="text-xs text-muted">
                    macOS (experimental): install the .pkg package from the Agent packages tab (<code>sudo installer -pkg &lt;file&gt; -target /</code>), then
                    enroll (the token is piped in, so it does not appear in the process list):
                  </p>
                  <CodeBlock code={t.macEnrollCommand} />
                </>
              )}
            </div>
          ))}
        </div>
      )}
    </Dialog>
  );
}
