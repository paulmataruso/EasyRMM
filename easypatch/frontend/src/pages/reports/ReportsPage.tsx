import { Link } from 'react-router';
import { FileDown } from 'lucide-react';
import { apiUrl, type QueryParams } from '../../api/client';
import { useApi, useList } from '../../api/hooks';
import {
  COMPLIANCE_STATUSES,
  JOB_ITEM_STATUSES,
  UPDATE_CATEGORIES,
  type ComplianceReportDto,
  type ComplianceTrendPoint,
  type InstallationReportRow,
} from '../../api/types';
import { EnumSelect, OrganizationSelect, SiteSelect } from '../../components/Filters';
import { CategoryBadge, ComplianceBadge, complianceTone, JobItemStatusBadge, OnlineBadge, OsSupportBadge } from '../../components/StatusBadges';
import { ComplianceTrendChart } from '../../components/TrendChart';
import {
  Badge,
  buttonClasses,
  Card,
  EmptyState,
  ErrorState,
  Field,
  Input,
  PageHeader,
  Pagination,
  Select,
  Spinner,
  StatTile,
  TableWrap,
  Tabs,
  Toolbar,
} from '../../components/ui';
import { dayBoundary, describeSkipReason, formatDate, formatDateTime, formatPercent, formatRelative, humanize, isLinux } from '../../lib/format';
import { aggregateTrend, daysAgo, isoDate } from '../../lib/trend';
import { useUrlState } from '../../lib/urlState';
import { MonthlyReportsTab } from './MonthlyReportsTab';

function CsvLink({ path, params }: { path: string; params: QueryParams }) {
  return (
    <a href={apiUrl(path, params)} className={buttonClasses('secondary')} download>
      <FileDown className="size-4" aria-hidden />
      Export CSV
    </a>
  );
}

export function ReportsPage() {
  const url = useUrlState();
  const tab = url.get('tab', 'compliance');
  return (
    <>
      <PageHeader title="Reports" subtitle="Compliance and installation reporting, and monthly PDF reports per customer. CSV exports respect the current filters." />
      <Tabs
        active={tab}
        onChange={(t) => url.set({ tab: t === 'compliance' ? null : t, status: null, result: null, from: null, to: null, page: null })}
        tabs={[
          { id: 'compliance', label: 'Compliance' },
          { id: 'installations', label: 'Installations' },
          { id: 'trend', label: 'Trend' },
          { id: 'monthly', label: 'Monthly reports' },
        ]}
      />
      {tab === 'compliance' && <ComplianceReport />}
      {tab === 'installations' && <InstallationsReport />}
      {tab === 'trend' && <TrendReport />}
      {tab === 'monthly' && <MonthlyReportsTab />}
    </>
  );
}

function ComplianceReport() {
  const url = useUrlState();
  const organizationId = url.get('organizationId');
  const status = url.get('status');
  const params: QueryParams = {
    organizationId: organizationId || undefined,
    siteId: url.get('siteId') || undefined,
    os: url.get('os') || undefined,
  };
  // The status filter is applied locally so the per-status tiles keep their counts; the CSV export filters server-side.
  const report = useApi<ComplianceReportDto>('/reports/compliance', params, { keepPrevious: true });
  const rows = (report.data?.rows ?? []).filter((r) => !status || r.complianceStatus === status);

  return (
    <>
      <Toolbar>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null })} />
        <SiteSelect organizationId={organizationId} value={url.get('siteId')} onChange={(v) => url.set({ siteId: v })} />
        <Field label="OS" htmlFor="rep-os" className="min-w-36">
          <Select id="rep-os" value={url.get('os')} onChange={(e) => url.set({ os: e.target.value })}>
            <option value="">Any</option>
            <option value="Windows 11">Windows 11</option>
            <option value="Windows 10">Windows 10</option>
            <option value="Windows Server">Windows Server</option>
          </Select>
        </Field>
        <EnumSelect label="Status" value={status} onChange={(v) => url.set({ status: v })} options={COMPLIANCE_STATUSES} format={humanize} />
        <span className="flex-1" />
        <div className="pb-0.5">
          <CsvLink path="/reports/compliance.csv" params={{ ...params, compliance: status || undefined }} />
        </div>
      </Toolbar>
      {report.isPending ? (
        <Spinner />
      ) : report.isError ? (
        <ErrorState error={report.error} onRetry={() => void report.refetch()} />
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
            <StatTile label="Compliance" value={formatPercent(report.data.compliancePercent, 1)} tone={report.data.compliancePercent >= 90 ? 'ok' : report.data.compliancePercent >= 70 ? 'warn' : 'danger'} hint={`${report.data.compliant} of ${report.data.total}`} />
            {COMPLIANCE_STATUSES.map((s) => (
              <button key={s} type="button" className="text-left" onClick={() => url.set({ status: status === s ? null : s })} aria-pressed={status === s}>
                <StatTile label={humanize(s)} value={report.data.byStatus[s] ?? 0} tone={(report.data.byStatus[s] ?? 0) > 0 ? complianceTone[s] : undefined} />
              </button>
            ))}
          </div>
          {rows.length === 0 ? (
            <EmptyState title="No endpoints in this report" />
          ) : (
            <TableWrap>
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Endpoint</th>
                    <th>Organization / site</th>
                    <th>Operating system</th>
                    <th>Status</th>
                    <th className="text-right">Missing</th>
                    <th className="text-right">Failed</th>
                    <th>Restart</th>
                    <th>Last scan</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.endpointId}>
                      <td className="whitespace-nowrap">
                        <Link to={`/endpoints/${r.endpointId}`} className="font-medium hover:text-accent">
                          {r.hostname}
                        </Link>
                        <div>
                          <OnlineBadge online={r.isOnline} lastSeen={r.lastCheckInAt} />
                        </div>
                      </td>
                      <td className="whitespace-nowrap">
                        {r.organizationName}
                        {r.siteName && <span className="text-muted"> · {r.siteName}</span>}
                      </td>
                      <td>
                        <div className="whitespace-nowrap">{r.operatingSystem ?? '—'}</div>
                        <div className="flex items-center gap-1.5 text-xs text-muted">
                          {r.osBuild && <span>{isLinux(r.platform) ? 'kernel' : 'build'} {r.osBuild}</span>}
                          {r.osSupportStatus !== 'Supported' && r.osSupportStatus !== 'Unknown' && <OsSupportBadge status={r.osSupportStatus} />}
                        </div>
                      </td>
                      <td>
                        <ComplianceBadge status={r.complianceStatus} />
                      </td>
                      <td className="text-right tabular-nums">
                        {r.missingRequiredCount}
                        {r.missingTotalCount > r.missingRequiredCount && <span className="text-xs text-subtle"> / {r.missingTotalCount}</span>}
                      </td>
                      <td className="text-right tabular-nums">{r.failedCount ? <span className="text-danger">{r.failedCount}</span> : 0}</td>
                      <td>{r.rebootPending ? <Badge tone="info">Pending</Badge> : <span className="text-subtle">—</span>}</td>
                      <td className="whitespace-nowrap text-muted" title={formatDateTime(r.lastScanAt)}>
                        {formatRelative(r.lastScanAt)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </>
      )}
    </>
  );
}

function InstallationsReport() {
  const url = useUrlState();
  const organizationId = url.get('organizationId');
  const from = url.get('from', daysAgo(30));
  const to = url.get('to', isoDate(new Date()));
  const params: QueryParams = {
    from: dayBoundary(from, false),
    to: dayBoundary(to, true),
    organizationId: organizationId || undefined,
    siteId: url.get('siteId') || undefined,
    category: url.get('category') || undefined,
    result: url.get('result') || undefined,
  };
  const list = useList<InstallationReportRow>('/reports/installations', { ...params, page: url.page, pageSize: 100 }, { keepPrevious: true });

  return (
    <>
      <Toolbar>
        <Field label="From" htmlFor="inst-from">
          <Input id="inst-from" type="date" value={from} onChange={(e) => url.set({ from: e.target.value })} />
        </Field>
        <Field label="To" htmlFor="inst-to">
          <Input id="inst-to" type="date" value={to} onChange={(e) => url.set({ to: e.target.value })} />
        </Field>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null })} />
        <SiteSelect organizationId={organizationId} value={url.get('siteId')} onChange={(v) => url.set({ siteId: v })} />
        <EnumSelect label="Category" value={url.get('category')} onChange={(v) => url.set({ category: v })} options={UPDATE_CATEGORIES} format={humanize} />
        <EnumSelect label="Result" value={url.get('result')} onChange={(v) => url.set({ result: v })} options={JOB_ITEM_STATUSES} format={humanize} />
        <span className="flex-1" />
        <div className="pb-0.5">
          <CsvLink path="/reports/installations.csv" params={params} />
        </div>
      </Toolbar>
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.page.items.length === 0 ? (
        <EmptyState title="No installation results in this period" />
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <th>Finished</th>
                  <th>Endpoint</th>
                  <th>Update</th>
                  <th>Category</th>
                  <th>Result</th>
                  <th>Details</th>
                  <th>Requested by</th>
                </tr>
              </thead>
              <tbody>
                {list.page.items.map((r) => (
                  <tr key={`${r.jobId}-${r.updateGuid}`}>
                    <td className="whitespace-nowrap text-muted">{formatDateTime(r.completedAt)}</td>
                    <td className="whitespace-nowrap">
                      <Link to={`/endpoints/${r.endpointId}`} className="font-medium hover:text-accent">
                        {r.hostname}
                      </Link>
                      <div className="text-xs text-muted">
                        {r.organizationName}
                        {r.siteName && ` · ${r.siteName}`}
                      </div>
                    </td>
                    <td className="min-w-64">
                      {r.title}
                      {r.kbNumber && <span className="ml-2 font-mono text-xs text-muted">{r.kbNumber}</span>}
                    </td>
                    <td>
                      <CategoryBadge category={r.category} />
                    </td>
                    <td>
                      <Link to={`/jobs/${r.jobId}`} title="View job">
                        <JobItemStatusBadge status={r.status} />
                      </Link>
                      {r.rebootRequired && <div className="mt-0.5 text-xs text-info">restart required</div>}
                    </td>
                    <td className="text-sm">
                      {r.status === 'Skipped' ? (
                        <span className="text-muted">{describeSkipReason(r.skipReason)}</span>
                      ) : r.errorCode || r.errorMessage ? (
                        <span className="text-danger">
                          {r.errorCode && <span className="font-mono">{r.errorCode} </span>}
                          {r.errorMessage}
                        </span>
                      ) : (
                        <span className="text-subtle">—</span>
                      )}
                    </td>
                    <td className="whitespace-nowrap text-muted">{r.requestedBy}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={(p) => url.set({ page: p })} />
        </>
      )}
    </>
  );
}

function TrendReport() {
  const url = useUrlState();
  const organizationId = url.get('organizationId');
  const from = url.get('from', daysAgo(90));
  const to = url.get('to', isoDate(new Date()));
  const trend = useApi<ComplianceTrendPoint[]>('/reports/compliance/trend', { organizationId: organizationId || undefined, from, to }, { keepPrevious: true });
  const points = aggregateTrend(trend.data ?? []);

  return (
    <>
      <Toolbar>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v })} />
        <Field label="From" htmlFor="trend-from">
          <Input id="trend-from" type="date" value={from} onChange={(e) => url.set({ from: e.target.value })} />
        </Field>
        <Field label="To" htmlFor="trend-to">
          <Input id="trend-to" type="date" value={to} onChange={(e) => url.set({ to: e.target.value })} />
        </Field>
      </Toolbar>
      {trend.isPending ? (
        <Spinner />
      ) : trend.isError ? (
        <ErrorState error={trend.error} onRetry={() => void trend.refetch()} />
      ) : (
        <div className="flex flex-col gap-5">
          <Card title="Compliance over time">
            <ComplianceTrendChart points={points} height={220} />
          </Card>
          {points.length > 0 && (
            <TableWrap>
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Date</th>
                    <th className="text-right">Endpoints</th>
                    <th className="text-right">Compliant</th>
                    <th className="text-right">Compliance</th>
                    <th className="text-right">Missing</th>
                    <th className="text-right">Failed</th>
                    <th className="text-right">Restart</th>
                    <th className="text-right">Stale / never</th>
                    <th className="text-right">Offline</th>
                    <th className="text-right">Missing updates</th>
                  </tr>
                </thead>
                <tbody>
                  {[...points].reverse().map((p) => (
                    <tr key={p.date}>
                      <td className="whitespace-nowrap">{formatDate(p.date)}</td>
                      <td className="text-right tabular-nums">{p.totalEndpoints}</td>
                      <td className="text-right tabular-nums">{p.compliant}</td>
                      <td className="text-right tabular-nums">{formatPercent(p.compliancePercent, 1)}</td>
                      <td className="text-right tabular-nums">{p.missingUpdates}</td>
                      <td className="text-right tabular-nums">{p.failedUpdates}</td>
                      <td className="text-right tabular-nums">{p.rebootRequired}</td>
                      <td className="text-right tabular-nums">
                        {p.scanStale} / {p.neverScanned}
                      </td>
                      <td className="text-right tabular-nums">{p.offline}</td>
                      <td className="text-right tabular-nums">{p.missingRequiredUpdates}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </div>
      )}
    </>
  );
}
