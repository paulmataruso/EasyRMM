import { useEffect, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { Archive, ArchiveRestore, KeyRound, MapPin, Pencil, Plus, Power, ScrollText, Settings2, Tag as TagIcon, Terminal, Trash2 } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation, usePolicy } from '../../api/hooks';
import type { BulkResultDto, OrganizationDto, PolicyRequest, SiteDto, SiteRequest } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
import { PolicyEditor, resolveInherited } from '../../components/PolicyEditor';
import { RestartDialog, type RestartTarget } from '../../components/RestartDialogs';
import { GroupTagsDialog, TagList } from '../../components/Tags';
import { useToast } from '../../components/Toast';
import {
  Badge,
  Button,
  buttonClasses,
  Card,
  EmptyState,
  ErrorState,
  InlineError,
  KeyValueList,
  PageHeader,
  ProgressBar,
  Spinner,
  StatTile,
  TableWrap,
  Tabs,
  TextField,
} from '../../components/ui';
import { formatDateTime, formatNumber, formatPercent, formatRelative } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';
import { BulkResultDialog, EndpointList } from '../endpoints/EndpointsPage';
import { OrganizationFormDialog, TimeZoneField } from './OrganizationsPage';

export function OrganizationDetailPage() {
  const { id = '' } = useParams();
  const url = useUrlState();
  const tab = url.get('tab', 'overview');
  const org = useApi<OrganizationDto>(`/organizations/${id}`, undefined, { refetchInterval: 60_000 });
  const { canOperate, isUnrestricted } = useAuth();
  const [tagsOpen, setTagsOpen] = useState(false);
  const [restart, setRestart] = useState<RestartTarget | null>(null);
  const [result, setResult] = useState<{ title: string; data: BulkResultDto } | null>(null);

  if (org.isPending) return <Spinner />;
  if (org.isError) return <ErrorState error={org.error} onRetry={() => void org.refetch()} />;
  const o = org.data;

  return (
    <>
      <PageHeader
        breadcrumb={<Link to="/organizations" className="hover:text-fg">Organizations</Link>}
        actions={
          canOperate && (
            <Button
              icon={<Power className="size-4" aria-hidden />}
              disabled={o.summary.rebootRequiredCount === 0}
              title={o.summary.rebootRequiredCount === 0 ? 'No endpoint in this organization reports a pending restart.' : undefined}
              onClick={() => setRestart({ kind: 'pending', organizationId: o.id, siteId: null, scopeName: o.name })}
            >
              Restart all that need it{o.summary.rebootRequiredCount > 0 ? ` (${formatNumber(o.summary.rebootRequiredCount)})` : ''}…
            </Button>
          )
        }
        title={
          <span className="flex items-center gap-2">
            {o.name}
            {!o.isActive && <Badge>Archived</Badge>}
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>{o.description ?? `${o.summary.endpointCount} endpoints · ${o.sites.length} sites · ${o.timeZone}`}</span>
            {(o.tags?.length ?? 0) > 0 && <TagList tags={o.tags} max={8} />}
            {canOperate && isUnrestricted && (
              <Button size="sm" variant="ghost" icon={<TagIcon className="size-3.5" aria-hidden />} onClick={() => setTagsOpen(true)}>
                {(o.tags?.length ?? 0) > 0 ? 'Edit tags' : 'Add tags'}
              </Button>
            )}
          </span>
        }
      />
      <GroupTagsDialog
        target={tagsOpen ? { kind: 'organization', id: o.id, name: o.name, current: o.tags ?? [] } : null}
        onClose={() => setTagsOpen(false)}
      />
      <Tabs
        active={tab}
        onChange={(t) => url.set({ tab: t === 'overview' ? null : t })}
        tabs={[
          { id: 'overview', label: 'Overview' },
          { id: 'sites', label: 'Sites', count: o.sites.length },
          { id: 'endpoints', label: 'Endpoints', count: o.summary.endpointCount },
          { id: 'policy', label: 'Policy' },
          { id: 'deploy', label: 'Deploy agents' },
        ]}
      />
      {tab === 'overview' && <OverviewTab org={o} />}
      {tab === 'sites' && (
        <SitesTab org={o} onRestart={(site) => setRestart({ kind: 'pending', organizationId: o.id, siteId: site.id, scopeName: site.name })} />
      )}
      {tab === 'endpoints' && <EndpointList organizationId={o.id} />}
      {tab === 'policy' && <OrganizationPolicyTab org={o} />}
      {tab === 'deploy' && <DeployTab org={o} />}
      <RestartDialog target={restart} onClose={() => setRestart(null)} onBulkResult={(title, data) => setResult({ title, data })} />
      <BulkResultDialog result={result} onClose={() => setResult(null)} />
    </>
  );
}

function OverviewTab({ org }: { org: OrganizationDto }) {
  const { canOperate } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const [editing, setEditing] = useState(false);
  const [confirm, setConfirm] = useState<'archive' | 'delete' | null>(null);
  const s = org.summary;

  const archive = useApiMutation(() => api.post(`/organizations/${org.id}/${org.isActive ? 'archive' : 'restore'}`), {
    invalidate: ['/organizations', '/dashboard'],
    onSuccess: () => {
      toast.success(org.isActive ? 'Organization archived.' : 'Organization restored.');
      setConfirm(null);
    },
  });
  const remove = useApiMutation(() => api.del(`/organizations/${org.id}`), {
    invalidate: ['/organizations', '/dashboard'],
    onSuccess: () => {
      toast.success('Organization deleted.');
      navigate('/organizations', { replace: true });
    },
  });

  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        <StatTile label="Compliance" value={s.endpointCount ? formatPercent(s.compliancePercent, 1) : '—'} tone={s.compliancePercent >= 90 ? 'ok' : s.compliancePercent >= 70 ? 'warn' : 'danger'} hint={`${s.compliantCount} of ${s.endpointCount} compliant`} />
        <StatTile label="Endpoints" value={formatNumber(s.endpointCount)} hint={`${s.onlineCount} online · ${s.offlineCount} offline`} />
        <StatTile label="Missing updates" value={formatNumber(s.missingRequiredUpdates)} tone={s.missingRequiredUpdates ? 'warn' : undefined} hint={`${s.nonCompliantCount} non-compliant endpoints`} />
        <StatTile label="Failed" value={formatNumber(s.failedCount)} tone={s.failedCount ? 'danger' : undefined} hint="endpoints with failed updates" />
        <StatTile label="Restart required" value={formatNumber(s.rebootRequiredCount)} tone={s.rebootRequiredCount ? 'info' : undefined} />
        <StatTile label="Last activity" value={<span className="text-base">{formatRelative(s.lastActivityAt)}</span>} />
      </div>
      {s.endpointCount > 0 && (
        <Card>
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium">Compliance</span>
            <ProgressBar value={s.compliancePercent} tone={s.compliancePercent >= 90 ? 'ok' : s.compliancePercent >= 70 ? 'warn' : 'danger'} />
            <span className="text-sm tabular-nums">{formatPercent(s.compliancePercent, 1)}</span>
          </div>
        </Card>
      )}
      <Card
        title="Details"
        actions={
          canOperate && (
            <>
              <Button size="sm" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setEditing(true)}>
                Edit
              </Button>
              <Button size="sm" icon={org.isActive ? <Archive className="size-3.5" aria-hidden /> : <ArchiveRestore className="size-3.5" aria-hidden />} onClick={() => setConfirm('archive')}>
                {org.isActive ? 'Archive' : 'Restore'}
              </Button>
              <Button size="sm" variant="danger-ghost" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={() => setConfirm('delete')} disabled={s.endpointCount > 0} title={s.endpointCount > 0 ? 'Only organizations without endpoints can be deleted.' : undefined}>
                Delete
              </Button>
            </>
          )
        }
      >
        <KeyValueList
          items={[
            ['Name', org.name],
            ['Description', org.description],
            ['Contact', org.contactName || org.contactEmail ? <>{org.contactName}{org.contactEmail && <> · <a className="text-accent hover:underline" href={`mailto:${org.contactEmail}`}>{org.contactEmail}</a></>}</> : null],
            ['Time zone', org.timeZone],
            ['Notes', org.notes ? <span className="whitespace-pre-wrap">{org.notes}</span> : null],
            ['Created', formatDateTime(org.createdAt)],
            ['Updated', formatDateTime(org.updatedAt)],
            ...(org.archivedAt ? [['Archived', formatDateTime(org.archivedAt)] as [string, string]] : []),
          ]}
        />
      </Card>
      <OrganizationFormDialog open={editing} organization={org} onClose={() => setEditing(false)} onSaved={() => setEditing(false)} />
      <ConfirmDialog
        open={confirm === 'archive'}
        onClose={() => setConfirm(null)}
        onConfirm={() => archive.mutate(undefined)}
        loading={archive.isPending}
        error={archive.error}
        title={org.isActive ? `Archive ${org.name}?` : `Restore ${org.name}?`}
        confirmLabel={org.isActive ? 'Archive' : 'Restore'}
      >
        {org.isActive
          ? 'Archived organizations are hidden from lists and excluded from scheduled installations. Existing agents keep reporting. You can restore it later.'
          : 'The organization becomes active again.'}
      </ConfirmDialog>
      <ConfirmDialog
        open={confirm === 'delete'}
        onClose={() => setConfirm(null)}
        onConfirm={() => remove.mutate(undefined)}
        loading={remove.isPending}
        error={remove.error}
        tone="danger"
        title={`Delete ${org.name}?`}
        confirmLabel="Delete organization"
        confirmText={org.name}
      >
        This permanently deletes the organization, its sites, policies, tokens and deployment codes.
      </ConfirmDialog>
    </div>
  );
}

function SitesTab({ org, onRestart }: { org: OrganizationDto; onRestart: (site: SiteDto) => void }) {
  const { canOperate, isUnrestricted } = useAuth();
  const toast = useToast();
  const [editing, setEditing] = useState<SiteDto | 'new' | null>(null);
  const [tagging, setTagging] = useState<SiteDto | null>(null);
  const [policySite, setPolicySite] = useState<SiteDto | null>(null);
  const [confirm, setConfirm] = useState<{ site: SiteDto; action: 'archive' | 'restore' | 'delete' } | null>(null);

  const act = useApiMutation(
    (c: { site: SiteDto; action: 'archive' | 'restore' | 'delete' }) => (c.action === 'delete' ? api.del(`/sites/${c.site.id}`) : api.post(`/sites/${c.site.id}/${c.action}`)),
    {
      invalidate: ['/organizations', '/sites'],
      onSuccess: (_, c) => {
        toast.success(`Site ${c.action === 'delete' ? 'deleted' : c.action === 'archive' ? 'archived' : 'restored'}.`);
        setConfirm(null);
      },
    },
  );

  return (
    <>
      <div className="mb-3 flex justify-between gap-2">
        <p className="text-sm text-muted">Sites group endpoints by location. A site can override the organization policy and time zone.</p>
        {canOperate && (
          <Button variant="primary" icon={<Plus className="size-4" aria-hidden />} onClick={() => setEditing('new')}>
            New site
          </Button>
        )}
      </div>
      {org.sites.length === 0 ? (
        <EmptyState title="No sites" icon={<MapPin className="size-8" aria-hidden />}>
          Sites are optional. Endpoints without a site use the organization policy.
        </EmptyState>
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>Name</th>
                <th>Tags</th>
                <th>Address</th>
                <th>Time zone</th>
                <th className="text-right">Endpoints</th>
                <th className="text-right">Restart pending</th>
                <th>Created</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {org.sites.map((site) => (
                <tr key={site.id}>
                  <td>
                    <span className="font-medium">{site.name}</span>
                    {!site.isActive && <Badge className="ml-2">Archived</Badge>}
                    {site.description && <p className="text-xs text-muted">{site.description}</p>}
                  </td>
                  <td>
                    <span className="inline-flex flex-wrap items-center gap-1">
                      <TagList tags={site.tags} max={4} />
                      {canOperate && isUnrestricted && (
                        <Button size="sm" variant="ghost" icon={<TagIcon className="size-3.5" aria-hidden />} onClick={() => setTagging(site)}
                          aria-label={`Tags of ${site.name}`} title="Edit tags">
                          {(site.tags?.length ?? 0) > 0 ? undefined : 'Add'}
                        </Button>
                      )}
                      {(site.tags?.length ?? 0) === 0 && !(canOperate && isUnrestricted) && <span className="text-subtle">—</span>}
                    </span>
                  </td>
                  <td className="text-muted">{site.address ?? '—'}</td>
                  <td>{site.timeZone}</td>
                  <td className="text-right tabular-nums">
                    <Link to={`/endpoints?organizationId=${org.id}&siteId=${site.id}`} className="hover:text-accent">
                      {site.endpointCount}
                    </Link>
                  </td>
                  <td className="text-right tabular-nums">
                    {site.rebootPendingCount > 0 ? (
                      <Link to={`/endpoints?organizationId=${org.id}&siteId=${site.id}&rebootPending=true`} className="text-info hover:text-accent">
                        {site.rebootPendingCount}
                      </Link>
                    ) : (
                      <span className="text-subtle">0</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap text-muted">{formatDateTime(site.createdAt)}</td>
                  <td>
                    <div className="flex justify-end gap-1">
                      {canOperate && site.rebootPendingCount > 0 && (
                        <Button size="sm" variant="ghost" icon={<Power className="size-3.5" aria-hidden />} onClick={() => onRestart(site)}
                          title={`Restart the endpoints of ${site.name} that report a pending restart`}>
                          Restart {site.rebootPendingCount}…
                        </Button>
                      )}
                      <Button size="sm" variant="ghost" icon={<Settings2 className="size-3.5" aria-hidden />} onClick={() => setPolicySite(site)}>
                        Policy
                      </Button>
                      {canOperate && (
                        <>
                          <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setEditing(site)}>
                            Edit
                          </Button>
                          <Button size="sm" variant="ghost" onClick={() => setConfirm({ site, action: site.isActive ? 'archive' : 'restore' })}>
                            {site.isActive ? 'Archive' : 'Restore'}
                          </Button>
                          <Button
                            size="sm"
                            variant="danger-ghost"
                            disabled={site.endpointCount > 0}
                            title={site.endpointCount > 0 ? 'Move or remove its endpoints first.' : undefined}
                            onClick={() => setConfirm({ site, action: 'delete' })}
                            aria-label={`Delete ${site.name}`}
                          >
                            <Trash2 className="size-3.5" aria-hidden />
                          </Button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <SiteFormDialog org={org} site={editing === 'new' ? undefined : (editing ?? undefined)} open={editing !== null} onClose={() => setEditing(null)} />
      <GroupTagsDialog
        target={tagging ? { kind: 'site', id: tagging.id, name: tagging.name, current: tagging.tags ?? [], organization: { name: org.name, tags: org.tags ?? [] } } : null}
        onClose={() => setTagging(null)}
      />
      <SitePolicyDialog org={org} site={policySite} onClose={() => setPolicySite(null)} />
      <ConfirmDialog
        open={confirm !== null}
        onClose={() => setConfirm(null)}
        onConfirm={() => confirm && act.mutate(confirm)}
        loading={act.isPending}
        error={act.error}
        tone={confirm?.action === 'delete' ? 'danger' : 'primary'}
        title={confirm ? `${confirm.action === 'delete' ? 'Delete' : confirm.action === 'archive' ? 'Archive' : 'Restore'} site ${confirm.site.name}?` : ''}
        confirmLabel={confirm?.action === 'delete' ? 'Delete site' : confirm?.action === 'archive' ? 'Archive' : 'Restore'}
      >
        {confirm?.action === 'delete' && 'The site and its policy are deleted permanently.'}
        {confirm?.action === 'archive' && 'Archived sites cannot receive new enrollments. Existing endpoints keep reporting.'}
      </ConfirmDialog>
    </>
  );
}

function SiteFormDialog({ org, site, open, onClose }: { org: OrganizationDto; site?: SiteDto; open: boolean; onClose: () => void }) {
  const toast = useToast();
  const [form, setForm] = useState<SiteRequest>({ name: '', description: null, address: null, timeZone: org.timeZone });
  useEffect(() => {
    if (open) setForm(site ? { name: site.name, description: site.description, address: site.address, timeZone: site.timeZone } : { name: '', description: null, address: null, timeZone: org.timeZone });
  }, [open, site, org.timeZone]);
  const save = useApiMutation((req: SiteRequest) => (site ? api.put<SiteDto>(`/sites/${site.id}`, req) : api.post<SiteDto>(`/organizations/${org.id}/sites`, req)), {
    invalidate: ['/organizations', '/sites'],
    onSuccess: () => {
      toast.success(site ? 'Site updated.' : 'Site created.');
      onClose();
    },
  });
  const empty = (v: string) => (v.trim() === '' ? null : v);

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ ...form, name: form.name.trim() });
  }

  return (
    <Dialog open={open} onClose={onClose} title={site ? `Edit site ${site.name}` : `New site in ${org.name}`}>
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <TextField label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required maxLength={200} autoFocus />
        <TextField label="Description" value={form.description ?? ''} onChange={(e) => setForm({ ...form, description: empty(e.target.value) })} maxLength={500} />
        <TextField label="Address" value={form.address ?? ''} onChange={(e) => setForm({ ...form, address: empty(e.target.value) })} maxLength={500} />
        <TimeZoneField value={form.timeZone ?? org.timeZone} onChange={(v) => setForm({ ...form, timeZone: v })} hint="Maintenance windows for endpoints in this site use this time zone." />
        <InlineError error={save.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!form.name.trim()}>
            {site ? 'Save changes' : 'Create site'}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function usePolicyMutations(path: string, onDone?: () => void) {
  const toast = useToast();
  const save = useApiMutation((req: PolicyRequest) => api.put(path, req), {
    invalidate: [path, '/endpoints'],
    onSuccess: () => {
      toast.success('Policy saved. Endpoints pick up the change at their next check-in.');
      onDone?.();
    },
  });
  const reset = useApiMutation(() => api.del(path), {
    invalidate: [path, '/endpoints'],
    onSuccess: () => {
      toast.success('Policy removed. All values are now inherited.');
      onDone?.();
    },
  });
  return { save, reset };
}

function OrganizationPolicyTab({ org }: { org: OrganizationDto }) {
  const { canOperate } = useAuth();
  const global = usePolicy('/policies/global');
  const policy = usePolicy(`/organizations/${org.id}/policy`);
  const { save, reset } = usePolicyMutations(`/organizations/${org.id}/policy`);
  const [confirmReset, setConfirmReset] = useState(false);

  if (policy.isPending || global.isPending) return <Spinner />;
  if (policy.isError) return <ErrorState error={policy.error} onRetry={() => void policy.refetch()} />;

  return (
    <>
      <PolicyEditor
        scope="Organization"
        policy={policy.data}
        inherited={resolveInherited([global.data])}
        readOnly={!canOperate}
        saving={save.isPending}
        deleting={reset.isPending}
        error={save.error ?? reset.error}
        onSave={(req) => save.mutate(req)}
        onReset={() => setConfirmReset(true)}
        timeZone={org.timeZone}
      />
      <ConfirmDialog
        open={confirmReset}
        onClose={() => setConfirmReset(false)}
        onConfirm={() => reset.mutate(undefined, { onSuccess: () => setConfirmReset(false) })}
        loading={reset.isPending}
        title="Remove the organization policy?"
        confirmLabel="Inherit everything"
      >
        Every value will be inherited from the global policy. Site policies are kept.
      </ConfirmDialog>
    </>
  );
}

function SitePolicyDialog({ org, site, onClose }: { org: OrganizationDto; site: SiteDto | null; onClose: () => void }) {
  const { canOperate } = useAuth();
  const global = usePolicy(site ? '/policies/global' : null);
  const orgPolicy = usePolicy(site ? `/organizations/${org.id}/policy` : null);
  const policy = usePolicy(site ? `/sites/${site.id}/policy` : null);
  const { save, reset } = usePolicyMutations(site ? `/sites/${site.id}/policy` : '/sites/none/policy', onClose);

  return (
    <Dialog open={site !== null} onClose={onClose} title={site ? `Site policy: ${site.name}` : ''} size="xl" description="Overrides the organization policy for endpoints in this site.">
      {site &&
        (policy.isPending || global.isPending || orgPolicy.isPending ? (
          <Spinner />
        ) : policy.isError ? (
          <ErrorState error={policy.error} />
        ) : (
          <PolicyEditor
            scope="Site"
            policy={policy.data}
            inherited={resolveInherited([global.data, orgPolicy.data])}
            readOnly={!canOperate}
            saving={save.isPending}
            deleting={reset.isPending}
            error={save.error ?? reset.error}
            onSave={(req) => save.mutate(req)}
            onReset={() => reset.mutate(undefined)}
            timeZone={site.timeZone}
          />
        ))}
    </Dialog>
  );
}

function DeployTab({ org }: { org: OrganizationDto }) {
  const { canOperate } = useAuth();
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card title={<span className="flex items-center gap-2"><KeyRound className="size-4" aria-hidden /> Enrollment tokens</span>}>
        <p className="text-sm text-muted">
          Secret, limited-use tokens for a manual or GPO-based <code>msiexec</code> installation on Windows, or <code>easypatch-agent enroll</code> on Linux and
          macOS (experimental).
          Endpoints enrolled with a token become active immediately.
        </p>
        <div className="mt-3 flex gap-2">
          <Link to={`/deploy?tab=tokens&organizationId=${org.id}${canOperate ? '&create=1' : ''}`} className={buttonClasses(canOperate ? 'primary' : 'secondary')}>
            {canOperate ? 'Create token' : 'View tokens'}
          </Link>
        </div>
      </Card>
      <Card title={<span className="flex items-center gap-2"><Terminal className="size-4" aria-hidden /> Deployment codes (RMM)</span>}>
        <p className="text-sm text-muted">
          Tokenless PowerShell (Windows) or shell (Linux, experimental macOS) installer for RMM tools. The script contains no secret; each new endpoint waits
          in{' '}
          <strong>Pending Approvals</strong> until an administrator approves it.
        </p>
        <div className="mt-3 flex gap-2">
          <Link to={`/deploy?tab=codes&organizationId=${org.id}${canOperate ? '&create=1' : ''}`} className={buttonClasses(canOperate ? 'primary' : 'secondary')}>
            {canOperate ? 'Create deployment code' : 'View deployment codes'}
          </Link>
          <Link to="/approvals" className={buttonClasses('secondary')}>
            <ScrollText className="size-4" aria-hidden />
            Pending Approvals
          </Link>
        </div>
      </Card>
    </div>
  );
}
