import { Link, useNavigate } from 'react-router';
import { PackageCheck } from 'lucide-react';
import { useList } from '../../api/hooks';
import { ENDPOINT_UPDATE_STATES, UPDATE_CATEGORIES, type FleetUpdateDto } from '../../api/types';
import { EnumSelect, OrganizationSelect, SearchInput, SiteSelect } from '../../components/Filters';
import { PackageFacts } from '../../components/PackageInfo';
import { CategoryBadge, CveCount, KnownExploitedBadge, SeverityBadge } from '../../components/StatusBadges';
import { Badge, EmptyState, ErrorState, PageHeader, Pagination, SortHeader, Spinner, TableWrap, Toolbar } from '../../components/ui';
import { formatBytes, formatDate, formatNumber, humanize } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';

export function UpdatesPage() {
  const url = useUrlState();
  const navigate = useNavigate();
  const organizationId = url.get('organizationId');
  const scope = { organizationId: organizationId || undefined, siteId: url.get('siteId') || undefined };
  const list = useList<FleetUpdateDto>(
    '/updates',
    {
      ...scope,
      category: url.get('category') || undefined,
      state: url.get('state') || undefined,
      knownExploited: url.get('knownExploited') || undefined,
      search: url.get('search') || undefined,
      page: url.page,
      pageSize: 50,
      sort: url.sort.sort ?? undefined,
      dir: url.sort.sort ? url.sort.dir : undefined,
    },
    { keepPrevious: true, refetchInterval: 60_000 },
  );
  const scopeQuery = new URLSearchParams(Object.entries(scope).filter((e): e is [string, string] => !!e[1])).toString();

  return (
    <>
      <PageHeader
        title="Update Management"
        subtitle="Every update reported by your endpoints, aggregated across the fleet. Updates fixing known-exploited vulnerabilities are listed first."
      />
      <Toolbar>
        <SearchInput value={url.get('search')} onChange={(v) => url.set({ search: v })} placeholder="Title, KB or package" />
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null })} />
        <SiteSelect organizationId={organizationId} value={url.get('siteId')} onChange={(v) => url.set({ siteId: v })} />
        <EnumSelect label="Category" value={url.get('category')} onChange={(v) => url.set({ category: v })} options={UPDATE_CATEGORIES} format={humanize} />
        <EnumSelect label="State" value={url.get('state')} onChange={(v) => url.set({ state: v })} options={ENDPOINT_UPDATE_STATES} format={humanize} />
        <EnumSelect
          label="Exploitation"
          value={url.get('knownExploited')}
          onChange={(v) => url.set({ knownExploited: v })}
          options={['true', 'false'] as const}
          format={(v) => (v === 'true' ? 'Known exploited' : 'Not known exploited')}
        />
      </Toolbar>
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.page.items.length === 0 ? (
        <EmptyState title="No updates found" icon={<PackageCheck className="size-8" aria-hidden />}>
          Updates appear after endpoints complete an update scan (Windows Update, apt/dnf on Linux, or softwareupdate on macOS).
        </EmptyState>
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <SortHeader field="title" label="Update" state={url.sort} onSort={url.toggleSort} />
                  <th>Category</th>
                  <th>Severity</th>
                  <SortHeader field="releaseDate" label="Released" state={url.sort} onSort={url.toggleSort} />
                  <th className="text-right">Size</th>
                  <SortHeader field="missing" label="Missing" state={url.sort} onSort={url.toggleSort} className="text-right" />
                  <SortHeader field="failed" label="Failed" state={url.sort} onSort={url.toggleSort} className="text-right" />
                  <th className="text-right">Pending restart</th>
                  <SortHeader field="installed" label="Installed" state={url.sort} onSort={url.toggleSort} className="text-right" />
                  <th className="text-right">Excluded</th>
                </tr>
              </thead>
              <tbody>
                {list.page.items.map((u) => {
                  const to = `/updates/${u.updateGuid}${scopeQuery ? `?${scopeQuery}` : ''}`;
                  return (
                    <tr key={u.updateGuid} className="cursor-pointer" onClick={() => navigate(to)}>
                      <td className="min-w-72">
                        <Link to={to} className="font-medium hover:text-accent" onClick={(e) => e.stopPropagation()}>
                          {u.title}
                        </Link>
                        {u.package ? (
                          <PackageFacts pkg={u.package} />
                        ) : (
                          u.kbNumber && <div className="font-mono text-xs text-muted">{u.kbNumber}</div>
                        )}
                        {u.cveCount > 0 && (
                          <div className="text-xs text-muted">
                            <CveCount count={u.cveCount} />
                          </div>
                        )}
                      </td>
                      <td>
                        <CategoryBadge category={u.category} />
                      </td>
                      <td>
                        <div className="flex flex-col items-start gap-1">
                          <SeverityBadge severity={u.msrcSeverity} />
                          {u.knownExploited && <KnownExploitedBadge />}
                          {u.onHold && (
                            <Badge tone="warn" title="Not installed automatically until the hold is released on the update's page">
                              On hold
                            </Badge>
                          )}
                        </div>
                      </td>
                      <td className="whitespace-nowrap text-muted">{formatDate(u.releaseDate)}</td>
                      <td className="text-right whitespace-nowrap tabular-nums">{formatBytes(u.sizeBytes)}</td>
                      <td className="text-right tabular-nums">{u.missingCount ? <span className="font-medium text-warn">{formatNumber(u.missingCount)}</span> : '0'}</td>
                      <td className="text-right tabular-nums">{u.failedCount ? <span className="font-medium text-danger">{formatNumber(u.failedCount)}</span> : '0'}</td>
                      <td className="text-right tabular-nums">{u.pendingRebootCount ? <span className="text-info">{formatNumber(u.pendingRebootCount)}</span> : '0'}</td>
                      <td className="text-right tabular-nums">{formatNumber(u.installedCount)}</td>
                      <td className="text-right tabular-nums text-muted">{formatNumber(u.excludedCount)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
          <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={(p) => url.set({ page: p })} />
        </>
      )}
    </>
  );
}
