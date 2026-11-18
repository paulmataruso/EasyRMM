import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { ArrowUpCircle, Download, MessageSquare, Monitor, Power, RefreshCw, Tag as TagIcon } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation, useList } from '../../api/hooks';
import { COMPLIANCE_STATUSES, type BulkResultDto, type EndpointSummaryDto, type TagDto } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { AgentUpdateDialog } from '../../components/AgentUpdateDialog';
import { Dialog } from '../../components/Dialog';
import { EnumSelect, OrganizationSelect, SearchInput, SiteSelect } from '../../components/Filters';
import { MessageDialog, RestartDialog } from '../../components/RestartDialogs';
import { ComplianceBadge, EndpointStatusBadge, OnlineBadge, OsSupportBadge, PlatformBadge } from '../../components/StatusBadges';
import { BulkTagsDialog, TagList } from '../../components/Tags';
import { useToast } from '../../components/Toast';
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  EmptyState,
  ErrorState,
  Field,
  InlineError,
  PageHeader,
  Pagination,
  Select,
  SortHeader,
  Spinner,
  TableWrap,
  Toolbar,
} from '../../components/ui';
import { humanize, formatRelative, osDetails } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';

export function EndpointsPage() {
  return (
    <>
      <PageHeader title="Endpoints" subtitle="Windows, Linux and (experimental) macOS devices running the EasyPatch agent." />
      <EndpointList />
    </>
  );
}

/** Filterable endpoint table with bulk actions. With `organizationId`, the organization filter is fixed. */
export function EndpointList({ organizationId: fixedOrg }: { organizationId?: string }) {
  const { canOperate, isUnrestricted } = useAuth();
  const navigate = useNavigate();
  const tags = useApi<TagDto[]>('/tags', undefined, { staleTime: 30_000 });
  const toast = useToast();
  const url = useUrlState();
  const organizationId = fixedOrg ?? url.get('organizationId');
  const filters = {
    organizationId: organizationId || undefined,
    siteId: url.get('siteId') || undefined,
    search: url.get('search') || undefined,
    compliance: url.get('compliance') || undefined,
    online: url.get('online') || undefined,
    os: url.get('os') || undefined,
    rebootPending: url.get('rebootPending') || undefined,
    outdatedAgent: url.get('outdatedAgent') || undefined,
    tagId: url.get('tagId') || undefined,
    knownExploited: url.get('knownExploited') || undefined,
  };
  const list = useList<EndpointSummaryDto>(
    '/endpoints',
    { ...filters, page: url.page, pageSize: 50, sort: url.sort.sort ?? undefined, dir: url.sort.sort ? url.sort.dir : undefined },
    { keepPrevious: true, refetchInterval: 30_000 },
  );

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirmInstall, setConfirmInstall] = useState(false);
  const [result, setResult] = useState<{ title: string; data: BulkResultDto } | null>(null);
  const [bulkDialog, setBulkDialog] = useState<'restart' | 'message' | 'agent-update' | 'tags' | null>(null);
  const items = list.page.items;
  const selectable = useMemo(() => items.filter((e) => e.status === 'Active'), [items]);
  const allSelected = selectable.length > 0 && selectable.every((e) => selected.has(e.id));

  const bulkScan = useApiMutation((ids: string[]) => api.post<BulkResultDto>('/endpoints/bulk/scan', { endpointIds: ids, force: false }), {
    invalidate: ['/jobs', '/endpoints', '/dashboard'],
    onSuccess: (data) => {
      setResult({ title: 'Scan requested', data });
      setSelected(new Set());
    },
  });
  const bulkInstall = useApiMutation(
    (vars: { ids: string[]; force: boolean }) => api.post<BulkResultDto>('/endpoints/bulk/install-updates', { endpointIds: vars.ids, force: vars.force }),
    {
      invalidate: ['/jobs', '/endpoints', '/dashboard'],
      onSuccess: (data) => {
        setConfirmInstall(false);
        setResult({ title: 'Installation requested', data });
        setSelected(new Set());
      },
    },
  );

  const toggle = (id: string) =>
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const anyFilter = Object.entries(filters).some(([k, v]) => v && !(fixedOrg && k === 'organizationId'));

  return (
    <>
      <Toolbar>
        <SearchInput value={url.get('search')} onChange={(v) => url.set({ search: v })} placeholder="Hostname, IP, serial…" />
        {!fixedOrg && <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null })} />}
        <SiteSelect organizationId={organizationId} value={url.get('siteId')} onChange={(v) => url.set({ siteId: v })} />
        <EnumSelect label="Compliance" value={url.get('compliance')} onChange={(v) => url.set({ compliance: v })} options={COMPLIANCE_STATUSES} format={humanize} />
        <Field label="Connectivity" htmlFor="online-filter" className="min-w-32">
          <Select id="online-filter" value={url.get('online')} onChange={(e) => url.set({ online: e.target.value })}>
            <option value="">Any</option>
            <option value="true">Online</option>
            <option value="false">Offline</option>
          </Select>
        </Field>
        <Field label="OS" htmlFor="os-filter" className="min-w-36">
          <Select id="os-filter" value={url.get('os')} onChange={(e) => url.set({ os: e.target.value })}>
            <option value="">Any</option>
            <optgroup label="Windows">
              <option value="Windows 11">Windows 11</option>
              <option value="Windows 10">Windows 10</option>
              <option value="Windows Server">Windows Server</option>
            </optgroup>
            <optgroup label="Linux">
              <option value="Ubuntu">Ubuntu</option>
              <option value="Debian">Debian</option>
              <option value="Red Hat Enterprise Linux">Red Hat Enterprise Linux</option>
              <option value="Rocky Linux">Rocky Linux</option>
              <option value="AlmaLinux">AlmaLinux</option>
              <option value="Oracle Linux">Oracle Linux</option>
            </optgroup>
            <optgroup label="macOS (experimental)">
              <option value="macOS">All macOS</option>
              <option value="macOS Tahoe">macOS Tahoe</option>
              <option value="macOS Sequoia">macOS Sequoia</option>
              <option value="macOS Sonoma">macOS Sonoma</option>
            </optgroup>
          </Select>
        </Field>
        {(tags.data ?? []).length > 0 && (
          <Field label="Tag" htmlFor="tag-filter" className="min-w-32">
            <Select id="tag-filter" value={url.get('tagId')} onChange={(e) => url.set({ tagId: e.target.value || null })}>
              <option value="">Any</option>
              {(tags.data ?? []).map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </Select>
          </Field>
        )}
        <div className="flex flex-col gap-1.5 pb-1">
          <Checkbox label="Restart pending" checked={url.get('rebootPending') === 'true'} onChange={(e) => url.set({ rebootPending: e.target.checked ? 'true' : null })} />
          <Checkbox label="Outdated agent" checked={url.get('outdatedAgent') === 'true'} onChange={(e) => url.set({ outdatedAgent: e.target.checked ? 'true' : null })} />
          <Checkbox
            label="Known-exploited vulnerability"
            checked={url.get('knownExploited') === 'true'}
            onChange={(e) => url.set({ knownExploited: e.target.checked ? 'true' : null })}
          />
        </div>
        {anyFilter && (
          <Button
            variant="ghost"
            size="sm"
            className="mb-1"
            onClick={() =>
              url.set({ search: null, organizationId: null, siteId: null, compliance: null, online: null, os: null, rebootPending: null, outdatedAgent: null, tagId: null, knownExploited: null })
            }
          >
            Clear filters
          </Button>
        )}
      </Toolbar>

      {canOperate && selected.size > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-accent/40 bg-accent-soft px-3 py-2 text-sm">
          <span className="font-medium">{selected.size} selected</span>
          <Button size="sm" icon={<RefreshCw className="size-3.5" aria-hidden />} loading={bulkScan.isPending} onClick={() => bulkScan.mutate([...selected])}>
            Scan now
          </Button>
          <Button size="sm" variant="primary" icon={<Download className="size-3.5" aria-hidden />} onClick={() => setConfirmInstall(true)}>
            Install all missing updates
          </Button>
          <Button size="sm" icon={<Power className="size-3.5" aria-hidden />} onClick={() => setBulkDialog('restart')}>
            Restart…
          </Button>
          <Button size="sm" icon={<MessageSquare className="size-3.5" aria-hidden />} onClick={() => setBulkDialog('message')}>
            Send message…
          </Button>
          <Button size="sm" icon={<ArrowUpCircle className="size-3.5" aria-hidden />} onClick={() => setBulkDialog('agent-update')}>
            Update agent…
          </Button>
          {isUnrestricted && (
            <Button size="sm" icon={<TagIcon className="size-3.5" aria-hidden />} onClick={() => setBulkDialog('tags')}>
              Tags…
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
            Clear selection
          </Button>
          {bulkScan.error && <span className="text-danger">{bulkScan.error.message}</span>}
        </div>
      )}

      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState title={anyFilter ? 'No endpoints match these filters' : 'No endpoints yet'} icon={<Monitor className="size-8" aria-hidden />}>
          {!anyFilter && (
            <>
              Deploy the agent from <Link to="/deploy" className="text-accent hover:underline">Deploy</Link> using an enrollment token or a deployment code.
            </>
          )}
        </EmptyState>
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  {canOperate && (
                    <th className="w-8">
                      <input
                        type="checkbox"
                        aria-label="Select all endpoints on this page"
                        className="size-4"
                        checked={allSelected}
                        onChange={() => setSelected(allSelected ? new Set() : new Set(selectable.map((e) => e.id)))}
                      />
                    </th>
                  )}
                  <SortHeader field="hostname" label="Hostname" state={url.sort} onSort={url.toggleSort} />
                  {!fixedOrg && <SortHeader field="organization" label="Organization" state={url.sort} onSort={url.toggleSort} />}
                  <SortHeader field="site" label="Site" state={url.sort} onSort={url.toggleSort} />
                  <SortHeader field="os" label="Operating system" state={url.sort} onSort={url.toggleSort} />
                  <SortHeader field="compliance" label="Compliance" state={url.sort} onSort={url.toggleSort} />
                  <SortHeader field="missing" label="Missing" state={url.sort} onSort={url.toggleSort} className="text-right" />
                  <th className="text-right">Failed</th>
                  <SortHeader field="lastCheckIn" label="Last check-in" state={url.sort} onSort={url.toggleSort} />
                  <SortHeader field="agentVersion" label="Agent" state={url.sort} onSort={url.toggleSort} />
                </tr>
              </thead>
              <tbody>
                {items.map((e) => (
                  <tr key={e.id} className="cursor-pointer" onClick={() => navigate(`/endpoints/${e.id}`)}>
                    {canOperate && (
                      <td onClick={(ev) => ev.stopPropagation()}>
                        <input
                          type="checkbox"
                          className="size-4"
                          aria-label={`Select ${e.hostname}`}
                          disabled={e.status !== 'Active'}
                          checked={selected.has(e.id)}
                          onChange={() => toggle(e.id)}
                        />
                      </td>
                    )}
                    <td className="whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <Link to={`/endpoints/${e.id}`} className="font-medium hover:text-accent" onClick={(ev) => ev.stopPropagation()}>
                          {e.hostname}
                        </Link>
                        <EndpointStatusBadge status={e.status} />
                        {e.rebootPending && (
                          <span title="Restart pending" className="text-info">
                            <Power className="size-3.5" aria-label="Restart pending" />
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <OnlineBadge online={e.isOnline} lastSeen={e.lastCheckInAt} />
                        {e.currentActivity && <span className="max-w-48 truncate text-xs text-accent">{e.currentActivity}</span>}
                      </div>
                      {e.tags?.length > 0 && (
                        <div className="mt-1">
                          <TagList tags={e.tags} />
                        </div>
                      )}
                    </td>
                    {!fixedOrg && <td className="whitespace-nowrap">{e.organizationName}</td>}
                    <td className="whitespace-nowrap text-muted">{e.siteName ?? '—'}</td>
                    <td>
                      <div className="flex items-center gap-1.5 whitespace-nowrap">
                        {e.operatingSystem ?? 'Unknown'}
                        <PlatformBadge platform={e.platform} />
                      </div>
                      <div className="flex items-center gap-1.5 text-xs text-muted">
                        {osDetails(e).map((d) => (
                          <span key={d}>{d}</span>
                        ))}
                        {e.osSupportStatus !== 'Supported' && e.osSupportStatus !== 'Unknown' && <OsSupportBadge status={e.osSupportStatus} />}
                      </div>
                    </td>
                    <td>
                      <ComplianceBadge status={e.complianceStatus} />
                    </td>
                    <td className="text-right tabular-nums">
                      {e.missingRequiredCount > 0 ? <span className="font-medium text-warn">{e.missingRequiredCount}</span> : '0'}
                      {e.missingTotalCount > e.missingRequiredCount && <span className="text-xs text-subtle" title="Including updates not required by policy"> / {e.missingTotalCount}</span>}
                      {e.knownExploitedMissingCount > 0 && (
                        <div className="text-xs font-medium text-danger" title="Missing updates that fix a vulnerability in the CISA Known Exploited Vulnerabilities catalog">
                          {e.knownExploitedMissingCount} known exploited
                        </div>
                      )}
                      {e.missingDeferredCount > 0 && (
                        <div className="text-xs text-subtle" title="Allowed updates still inside their rollout delay (not counted as missing yet)">
                          {e.missingDeferredCount} deferred
                        </div>
                      )}
                    </td>
                    <td className="text-right tabular-nums">{e.failedCount > 0 ? <span className="font-medium text-danger">{e.failedCount}</span> : '0'}</td>
                    <td className="whitespace-nowrap text-muted" title={e.lastCheckInAt ? new Date(e.lastCheckInAt).toLocaleString() : undefined}>
                      {formatRelative(e.lastCheckInAt)}
                    </td>
                    <td className="whitespace-nowrap">
                      <span className="font-mono text-xs">{e.agentVersion ?? '—'}</span>
                      {e.agentOutdated && <Badge tone="warn" className="ml-1.5">outdated</Badge>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={(p) => url.set({ page: p })} />
        </>
      )}

      <BulkInstallDialog
        open={confirmInstall}
        count={selected.size}
        loading={bulkInstall.isPending}
        error={bulkInstall.error}
        onClose={() => setConfirmInstall(false)}
        onConfirm={(force) => bulkInstall.mutate({ ids: [...selected], force })}
      />
      <RestartDialog
        target={bulkDialog === 'restart' ? { kind: 'bulk', ids: [...selected] } : null}
        onClose={() => setBulkDialog(null)}
        onBulkResult={(title, data) => setResult({ title, data })}
      />
      <BulkTagsDialog open={bulkDialog === 'tags'} onClose={() => setBulkDialog(null)} endpointIds={[...selected]} />
      <AgentUpdateDialog
        target={bulkDialog === 'agent-update' ? { kind: 'bulk', ids: [...selected] } : null}
        onClose={() => setBulkDialog(null)}
        onBulkResult={(title, data) => setResult({ title, data })}
      />
      <MessageDialog
        target={bulkDialog === 'message' ? { kind: 'bulk', ids: [...selected] } : null}
        onClose={() => setBulkDialog(null)}
        onBulkResult={(title, data) => setResult({ title, data })}
      />
      <BulkResultDialog
        result={result}
        onClose={() => {
          if (result) toast.success(`${result.title}: ${result.data.succeeded} succeeded, ${result.data.failed} failed.`);
          setResult(null);
        }}
      />
    </>
  );
}

function BulkInstallDialog({ open, count, loading, error, onClose, onConfirm }: {
  open: boolean;
  count: number;
  loading: boolean;
  error: unknown;
  onClose: () => void;
  onConfirm: (force: boolean) => void;
}) {
  const [force, setForce] = useState(false);
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Install all missing updates on ${count} endpoint${count === 1 ? '' : 's'}?`}
      footer={
        <>
          <Button onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button variant="primary" loading={loading} onClick={() => onConfirm(force)} icon={<Download className="size-4" aria-hidden />}>
            Queue installations
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        <p>
          Each endpoint receives an <strong>Install all missing updates</strong> job. The agent performs a fresh update scan (Windows Update on Windows, apt or dnf
          on Linux, softwareupdate on macOS) and installs every update its policy allows (allowed categories, optional updates and exclusions). On Apple silicon
          Macs, macOS updates that need a restart cannot be installed by the agent and fail.
        </p>
        <Alert tone="warn" title="Installing does not restart endpoints">
          Updates that need a restart are reported as <em>Pending restart</em>. Restart those endpoints with <strong>Restart…</strong> or a restart schedule in
          policy.
        </Alert>
        <p className="text-muted">
          Offline endpoints keep their job queued until they check in or the job expires. Global and per-site concurrency limits apply. To review the exact list for
          a single endpoint first, use “Install all missing updates” on its detail page.
        </p>
        <Checkbox
          label="Queue even if an installation job is already active"
          hint="By default, endpoints with an active installation job are skipped."
          checked={force}
          onChange={(e) => setForce(e.target.checked)}
        />
        <InlineError error={error} />
      </div>
    </Dialog>
  );
}

/** How a bulk item that did not queue a job is shown: skipped on purpose, already active, or failed. */
export function bulkOutcome(errorCode: string | null): { label: string; tone: 'neutral' | 'danger' } {
  if (errorCode === 'duplicate_job') return { label: 'Already active', tone: 'neutral' };
  if (errorCode === 'no_restart_pending' || errorCode === 'out_of_scope') return { label: 'Skipped', tone: 'neutral' };
  return { label: 'Failed', tone: 'danger' };
}

export function BulkResultDialog({ result, onClose }: { result: { title: string; data: BulkResultDto } | null; onClose: () => void }) {
  return (
    <Dialog
      open={result !== null}
      onClose={onClose}
      title={result?.title ?? ''}
      description={result ? `${result.data.succeeded} succeeded, ${result.data.failed} failed` : undefined}
      size="lg"
      footer={<Button variant="primary" onClick={onClose}>Done</Button>}
    >
      {result && (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>Outcome</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {result.data.results.map((r) => (
                <tr key={r.endpointId}>
                  <td className="whitespace-nowrap">
                    <Link to={`/endpoints/${r.endpointId}`} className="font-medium hover:text-accent">
                      {r.hostname ?? r.endpointId}
                    </Link>
                  </td>
                  <td>{r.success ? <Badge tone="ok">Queued</Badge> : <Badge tone={bulkOutcome(r.errorCode).tone}>{bulkOutcome(r.errorCode).label}</Badge>}</td>
                  <td className="text-sm">
                    {r.jobId && (
                      <Link to={`/jobs/${r.jobId}`} className="text-accent hover:underline">
                        View job
                      </Link>
                    )}
                    {!r.success && <span className="text-muted">{r.message ?? r.errorCode}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Dialog>
  );
}

