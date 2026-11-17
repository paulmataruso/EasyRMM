import { useEffect, useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import { Download, ExternalLink, PauseCircle, Undo2 } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation, useList } from '../../api/hooks';
import { ENDPOINT_UPDATE_STATES, type BulkResultDto, type FleetUpdateDetailDto, type FleetUpdateEndpointDto, type VulnerabilityDto } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { Dialog } from '../../components/Dialog';
import { EnumSelect, OrganizationSelect, SiteSelect } from '../../components/Filters';
import { Advisories } from '../../components/PackageInfo';
import { FleetRemoveUpdateDialog } from '../../components/RemoveUpdateDialog';
import { HoldUpdateDialog, UpdateHoldBanner } from '../../components/UpdateHolds';
import { CategoryBadge, KnownExploitedBadge, OnlineBadge, SeverityBadge, UpdateStateBadge } from '../../components/StatusBadges';
import { Alert, Badge, Button, Card, EmptyState, ErrorState, InlineError, KeyValueList, PageHeader, Pagination, Spinner, StatTile, TableWrap, Toolbar } from '../../components/ui';
import { formatBytes, formatDate, formatRelative, humanize } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';
import { BulkResultDialog } from '../endpoints/EndpointsPage';

export function UpdateDetailPage() {
  const { guid = '' } = useParams();
  const url = useUrlState();
  const { canOperate } = useAuth();
  const [installOpen, setInstallOpen] = useState(false);
  const [removeOpen, setRemoveOpen] = useState(false);
  const [holdOpen, setHoldOpen] = useState(false);
  const [resultTitle, setResultTitle] = useState('Installation requested');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [result, setResult] = useState<BulkResultDto | null>(null);
  const organizationId = url.get('organizationId');
  const siteId = url.get('siteId');
  const state = url.get('state');
  const detail = useApi<FleetUpdateDetailDto>(`/updates/${guid}`, { organizationId: organizationId || undefined, siteId: siteId || undefined });
  const endpoints = useList<FleetUpdateEndpointDto>(
    `/updates/${guid}/endpoints`,
    { state: state || undefined, organizationId: organizationId || undefined, siteId: siteId || undefined, page: url.page, pageSize: 100 },
    { keepPrevious: true, refetchInterval: 30_000 },
  );

  if (detail.isPending) return <Spinner />;
  if (detail.isError) return <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />;
  const d = detail.data;
  const s = d.summary;
  const pkg = s.package;
  const installable = (e: FleetUpdateEndpointDto) => (e.state === 'Missing' || e.state === 'Failed') && !e.isExcluded;
  const rows = endpoints.page.items;
  const selectable = rows.filter(installable);
  const allSelected = selectable.length > 0 && selectable.every((e) => selected.has(e.endpointId));

  return (
    <>
      <PageHeader
        breadcrumb={<Link to="/updates" className="hover:text-fg">Update Management</Link>}
        title={s.title}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            {pkg ? (
              <span className="font-mono">
                {pkg.name}
                {pkg.architecture && ` (${pkg.architecture})`}
              </span>
            ) : (
              d.kbNumbers.length > 0 && <span className="font-mono">{d.kbNumbers.join(', ')}</span>
            )}
            <CategoryBadge category={s.category} />
            <SeverityBadge severity={s.msrcSeverity} />
            {s.knownExploited && <KnownExploitedBadge />}
            {s.onHold && <Badge tone="warn">On hold</Badge>}
            {d.rebootLikely && <Badge tone="info">Restart likely</Badge>}
          </span>
        }
        actions={
          canOperate && (
            <>
              <Button icon={<PauseCircle className="size-4" aria-hidden />} onClick={() => setHoldOpen(true)}>
                Hold
              </Button>
              {!pkg && s.category !== 'Application' && s.installedCount + s.pendingRebootCount > 0 && (
                <Button icon={<Undo2 className="size-4" aria-hidden />} onClick={() => setRemoveOpen(true)}>
                  Remove from endpoints
                </Button>
              )}
              {s.missingCount + s.failedCount > 0 && (
                <Button variant="primary" icon={<Download className="size-4" aria-hidden />} onClick={() => setInstallOpen(true)}>
                  {selected.size > 0 ? `Install on ${selected.size} selected` : 'Install on affected endpoints'}
                </Button>
              )}
            </>
          )
        }
      />
      <UpdateHoldBanner holds={d.holds ?? []} />
      <div className={`mb-5 grid grid-cols-2 gap-3 ${s.reofferedCount ? 'md:grid-cols-6' : 'md:grid-cols-5'}`}>
        <StatTile label="Missing" value={s.missingCount} tone={s.missingCount ? 'warn' : undefined} />
        <StatTile label="Failed" value={s.failedCount} tone={s.failedCount ? 'danger' : undefined} />
        <StatTile label="Pending restart" value={s.pendingRebootCount} tone={s.pendingRebootCount ? 'info' : undefined} />
        <StatTile label="Installed" value={s.installedCount} tone="ok" />
        <StatTile label="Excluded" value={s.excludedCount} />
        {s.reofferedCount > 0 && <StatTile label="Offered again" value={s.reofferedCount} tone="warn" />}
      </div>
      <Card title="Details" className="mb-5">
        <KeyValueList
          items={[
            ['Description', d.description],
            ...(pkg
              ? ([
                  ['Package', <span className="font-mono">{pkg.name}</span>],
                  ['Version', pkg.version ? <span className="font-mono">{pkg.version}</span> : null],
                  ['Architecture', pkg.architecture],
                  ['Repository', pkg.repository],
                  ['Advisories', pkg.advisories.length ? <Advisories advisories={pkg.advisories} max={pkg.advisories.length} /> : 'None reported'],
                ] as [ReactNode, ReactNode][])
              : []),
            ['Released', formatDate(s.releaseDate)],
            ['Download size', formatBytes(s.sizeBytes)],
            ...(pkg ? [] : ([['Microsoft classification', d.msClassification]] as [ReactNode, ReactNode][])),
            ['Products', d.products.join(', ') || null],
            ['Supersedes', d.supersededUpdateGuids.length ? `${d.supersededUpdateGuids.length} older update(s)` : null],
            [
              'More information',
              d.supportUrl ? (
                <a href={d.supportUrl} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-accent hover:underline">
                  {d.supportUrl} <ExternalLink className="size-3" aria-hidden />
                </a>
              ) : null,
            ],
            ['Update ID', <span className="font-mono text-xs">{s.updateGuid}</span>],
          ]}
        />
      </Card>

      {d.vulnerabilities && d.vulnerabilities.length > 0 && <VulnerabilitiesCard vulnerabilities={d.vulnerabilities} windows={!pkg} />}

      <h2 className="mb-2 text-base font-semibold">Endpoints</h2>
      <Toolbar>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null })} />
        <SiteSelect organizationId={organizationId} value={siteId} onChange={(v) => url.set({ siteId: v })} />
        <EnumSelect label="State" value={state} onChange={(v) => url.set({ state: v })} options={ENDPOINT_UPDATE_STATES} format={humanize} />
      </Toolbar>
      {endpoints.isPending ? (
        <Spinner />
      ) : endpoints.isError ? (
        <ErrorState error={endpoints.error} onRetry={() => void endpoints.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState title="No endpoints in this view" />
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
                        className="size-4"
                        aria-label="Select all affected endpoints on this page"
                        checked={allSelected}
                        disabled={selectable.length === 0}
                        onChange={() => setSelected(allSelected ? new Set() : new Set(selectable.map((e) => e.endpointId)))}
                      />
                    </th>
                  )}
                  <th>Endpoint</th>
                  <th>Organization / site</th>
                  <th>State</th>
                  <th>Details</th>
                  <th>Changed</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.endpointId}>
                    {canOperate && (
                      <td>
                        <input
                          type="checkbox"
                          className="size-4"
                          aria-label={`Select ${e.hostname}`}
                          disabled={!installable(e)}
                          checked={selected.has(e.endpointId)}
                          onChange={() =>
                            setSelected((cur) => {
                              const next = new Set(cur);
                              if (next.has(e.endpointId)) next.delete(e.endpointId);
                              else next.add(e.endpointId);
                              return next;
                            })
                          }
                        />
                      </td>
                    )}
                    <td className="whitespace-nowrap">
                      <Link to={`/endpoints/${e.endpointId}?tab=updates`} className="font-medium hover:text-accent">
                        {e.hostname}
                      </Link>
                      <div>
                        <OnlineBadge online={e.isOnline} />
                      </div>
                    </td>
                    <td className="whitespace-nowrap">
                      {e.organizationName}
                      {e.siteName && <span className="text-muted"> · {e.siteName}</span>}
                    </td>
                    <td>
                      {e.isExcluded ? <Badge>Excluded</Badge> : <UpdateStateBadge state={e.state} />}
                      {!e.isRequired && !e.isExcluded && <div className="mt-0.5 text-xs text-muted">not required by policy</div>}
                    </td>
                    <td className="text-sm">
                      {e.errorCode || e.errorMessage ? (
                        <span className="text-danger">
                          {e.errorCode && <span className="font-mono">{e.errorCode} </span>}
                          {e.errorMessage}
                          {e.failedAttempts > 1 && ` (${e.failedAttempts} attempts)`}
                        </span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td className="whitespace-nowrap text-muted">{formatRelative(e.stateChangedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <Pagination page={endpoints.page.page} pageSize={endpoints.page.pageSize} totalCount={endpoints.page.totalCount} onPage={(p) => url.set({ page: p })} />
        </>
      )}

      <FleetInstallDialog
        open={installOpen}
        onClose={() => setInstallOpen(false)}
        guid={guid}
        title={s.title}
        selectedIds={[...selected]}
        defaultOrganizationId={organizationId}
        defaultSiteId={siteId}
        onHold={s.onHold}
        onDone={(r) => {
          setInstallOpen(false);
          setSelected(new Set());
          setResultTitle('Installation requested');
          setResult(r);
        }}
      />
      <FleetRemoveUpdateDialog
        open={removeOpen}
        onClose={() => setRemoveOpen(false)}
        guid={guid}
        title={s.title}
        defaultOrganizationId={organizationId}
        defaultSiteId={siteId}
        onDone={(r) => {
          setRemoveOpen(false);
          setResultTitle('Removal requested');
          setResult(r);
        }}
      />
      <HoldUpdateDialog open={holdOpen} onClose={() => setHoldOpen(false)} guid={guid} title={s.title} defaultOrganizationId={organizationId} />
      <BulkResultDialog result={result ? { title: resultTitle, data: result } : null} onClose={() => setResult(null)} />
    </>
  );
}

function FleetInstallDialog({ open, onClose, guid, title, selectedIds, defaultOrganizationId, defaultSiteId, onDone, onHold }: {
  open: boolean;
  onClose: () => void;
  guid: string;
  title: string;
  selectedIds: string[];
  defaultOrganizationId: string;
  defaultSiteId: string;
  onDone: (result: BulkResultDto) => void;
  onHold: boolean;
}) {
  const [org, setOrg] = useState(defaultOrganizationId);
  const [site, setSite] = useState(defaultSiteId);
  useEffect(() => {
    if (open) {
      setOrg(defaultOrganizationId);
      setSite(defaultSiteId);
    }
  }, [open, defaultOrganizationId, defaultSiteId]);
  const useSelection = selectedIds.length > 0;
  const install = useApiMutation(
    () =>
      api.post<BulkResultDto>(`/updates/${guid}/install`, {
        organizationId: useSelection ? null : org || null,
        siteId: useSelection ? null : site || null,
        endpointIds: useSelection ? selectedIds : null,
      }),
    { invalidate: ['/updates', '/jobs', '/endpoints', '/dashboard'], onSuccess: onDone },
  );

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Install this update"
      description={title}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={install.isPending} onClick={() => install.mutate(undefined)} icon={<Download className="size-4" aria-hidden />}>
            Queue installations
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        {useSelection ? (
          <p>
            Creates an installation job for this update on the <strong>{selectedIds.length} selected endpoint{selectedIds.length === 1 ? '' : 's'}</strong>.
          </p>
        ) : (
          <>
            <p>Creates an installation job for this update on every endpoint where it is missing or failed, within the scope below.</p>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <OrganizationSelect value={org} onChange={(v) => { setOrg(v); setSite(''); }} />
              <SiteSelect organizationId={org} value={site} onChange={setSite} />
            </div>
            {!org && <Alert tone="warn">No organization selected: every affected endpoint you can access is included.</Alert>}
          </>
        )}
        {onHold && (
          <Alert tone="warn" title="This update is on hold">
            Installing it here overrides the hold on these endpoints. Scheduled installations keep skipping it until the hold is released.
          </Alert>
        )}
        <Alert tone="info" title="No automatic restarts">
          Installing does not restart endpoints (use Restart… or a restart schedule). Endpoints where this update is excluded are skipped. Because you are choosing this update explicitly, it installs even if its category is not in the policy’s automatic-install categories.
        </Alert>
        <InlineError error={install.error} />
      </div>
    </Dialog>
  );
}

/** CVEs the update fixes on the endpoints in scope: known-exploited first, then by CVSS score. */
function VulnerabilitiesCard({ vulnerabilities, windows }: { vulnerabilities: VulnerabilityDto[]; windows: boolean }) {
  const exploited = vulnerabilities.filter((v) => v.kev).length;
  return (
    <Card
      title={`Vulnerabilities fixed (${vulnerabilities.length})`}
      className="mb-5"
      actions={exploited > 0 ? <span className="text-sm text-danger">{exploited} known exploited</span> : undefined}
    >
      <TableWrap className="max-h-96 overflow-y-auto">
        <table className="table-base">
          <thead>
            <tr>
              <th>CVE</th>
              <th>Title</th>
              <th>Severity</th>
              <th className="text-right">CVSS</th>
              <th>Exploitation</th>
            </tr>
          </thead>
          <tbody>
            {vulnerabilities.map((v) => (
              <tr key={v.cveId}>
                <td className="whitespace-nowrap">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${v.cveId}`}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="inline-flex items-center gap-1 font-mono text-accent hover:underline"
                  >
                    {v.cveId} <ExternalLink className="size-3" aria-hidden />
                  </a>
                  {windows && (
                    <a
                      href={`https://msrc.microsoft.com/update-guide/vulnerability/${v.cveId}`}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="ml-2 text-xs text-muted hover:text-accent hover:underline"
                    >
                      MSRC
                    </a>
                  )}
                </td>
                <td className="min-w-64">{v.title ?? v.kevName ?? <span className="text-subtle">—</span>}</td>
                <td>
                  <SeverityBadge severity={v.severity} />
                </td>
                <td className="text-right tabular-nums">{v.cvssBase !== null ? v.cvssBase.toFixed(1) : '—'}</td>
                <td>
                  <div className="flex flex-col items-start gap-1">
                    {v.kev ? (
                      <>
                        <KnownExploitedBadge dueDate={v.kevDueDate} />
                        <span className="text-xs text-muted">
                          CISA KEV since {v.kevDateAdded ?? '—'}
                          {v.kevDueDate && `, due ${v.kevDueDate}`}
                        </span>
                        {v.kevRansomware && <Badge tone="danger">Used by ransomware</Badge>}
                      </>
                    ) : v.msrcExploited ? (
                      <Badge tone="warn" title="Microsoft reports exploitation; not (yet) in the CISA KEV catalog">
                        Exploited (Microsoft)
                      </Badge>
                    ) : (
                      <span className="text-subtle">—</span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Card>
  );
}
