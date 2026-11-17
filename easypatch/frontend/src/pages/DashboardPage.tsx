import { Link } from 'react-router';
import { AlertTriangle, CheckCircle2, Clock, Monitor, Power, ShieldAlert, ShieldX, UserCheck, Wifi, WifiOff } from 'lucide-react';
import { useApi, useList } from '../api/hooks';
import type { AlertDto, AlertSummaryDto, ComplianceTrendPoint, DashboardSummaryDto, EndpointEventDto } from '../api/types';
import { AlertSeverityBadge } from './alerts/AlertsPage';
import { Card, EmptyState, ErrorState, PageHeader, ProgressBar, Spinner, StatTile, TableWrap } from '../components/ui';
import { EventSeverityDot } from '../components/StatusBadges';
import { ComplianceTrendChart } from '../components/TrendChart';
import { formatNumber, formatPercent, formatRelative } from '../lib/format';
import { aggregateTrend, daysAgo, isoDate } from '../lib/trend';

export function DashboardPage() {
  const summary = useApi<DashboardSummaryDto>('/dashboard/summary', undefined, { refetchInterval: 30_000 });
  const activity = useList<EndpointEventDto>('/dashboard/activity', { limit: 25 }, { refetchInterval: 30_000 });
  const alerts = useList<AlertDto>('/alerts', { status: 'open', pageSize: 5 }, { refetchInterval: 30_000 });
  const alertSummary = useApi<AlertSummaryDto>('/alerts/summary', undefined, { refetchInterval: 30_000 });
  const trend = useApi<ComplianceTrendPoint[]>('/reports/compliance/trend', { from: daysAgo(30), to: isoDate(new Date()) }, { staleTime: 5 * 60_000 });

  return (
    <>
      <PageHeader title="Dashboard" subtitle="Patch compliance across every organization you can access." />
      {summary.isPending ? (
        <Spinner />
      ) : summary.isError ? (
        <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />
      ) : (
        <SummaryTiles s={summary.data} />
      )}

      <div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-3">
        <Card title="Compliance, last 30 days" className="xl:col-span-2">
          {trend.isPending ? (
            <Spinner />
          ) : trend.isError ? (
            <ErrorState error={trend.error} compact onRetry={() => void trend.refetch()} />
          ) : (
            <ComplianceTrendChart points={aggregateTrend(trend.data)} />
          )}
        </Card>
        <Card title="Least compliant organizations" padded={false}>
          {summary.data && summary.data.leastCompliantOrganizations.length === 0 ? (
            <EmptyState title="No organizations yet" />
          ) : (
            <ul className="divide-y divide-line">
              {summary.data?.leastCompliantOrganizations.map((o) => (
                <li key={o.id} className="px-4 py-2.5">
                  <div className="flex items-center justify-between gap-2 text-sm">
                    <Link to={`/organizations/${o.id}`} className="truncate font-medium hover:text-accent">
                      {o.name}
                    </Link>
                    <span className="tabular-nums text-muted">{formatPercent(o.compliancePercent)}</span>
                  </div>
                  <div className="mt-1.5">
                    <ProgressBar value={o.compliancePercent} tone={o.compliancePercent >= 90 ? 'ok' : o.compliancePercent >= 70 ? 'warn' : 'danger'} label={`${o.name} compliance`} />
                  </div>
                  <p className="mt-1 text-xs text-muted">
                    {o.endpointCount} endpoints · {o.missingRequiredUpdates} missing updates · {o.failedCount} failed · {o.offlineCount} offline
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card
        title={alertSummary.data ? `Open alerts (${alertSummary.data.open})` : 'Open alerts'}
        className="mt-5"
        padded={false}
        actions={<Link to="/alerts" className="text-xs text-accent hover:underline">View alerts</Link>}
      >
        {alerts.isPending ? (
          <Spinner />
        ) : alerts.isError ? (
          <ErrorState error={alerts.error} compact />
        ) : alerts.page.items.length === 0 ? (
          <p className="px-4 py-3 text-sm text-muted">No open alerts.</p>
        ) : (
          <ul className="divide-y divide-line">
            {alerts.page.items.map((a) => (
              <li key={a.id} className="flex items-center gap-3 px-4 py-2 text-sm">
                <AlertSeverityBadge severity={a.severity} />
                {a.endpointId ? (
                  <Link to={`/endpoints/${a.endpointId}`} className="min-w-0 flex-1 truncate font-medium hover:text-accent">
                    {a.title}
                  </Link>
                ) : (
                  <Link to="/alerts" className="min-w-0 flex-1 truncate font-medium hover:text-accent">
                    {a.title}
                  </Link>
                )}
                <span className="hidden truncate text-muted md:inline">{a.organizationName}</span>
                <span className="whitespace-nowrap text-muted" title={new Date(a.openedAt).toLocaleString()}>
                  {formatRelative(a.openedAt)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Recent activity" className="mt-5" padded={false} actions={<Link to="/jobs" className="text-xs text-accent hover:underline">View jobs</Link>}>
        {activity.isPending ? (
          <Spinner />
        ) : activity.isError ? (
          <ErrorState error={activity.error} compact />
        ) : activity.page.items.length === 0 ? (
          <EmptyState title="No activity yet">Agent check-ins, scans and installations appear here.</EmptyState>
        ) : (
          <TableWrap className="rounded-none border-0">
            <table className="table-base">
              <tbody>
                {activity.page.items.map((e) => (
                  <tr key={e.id}>
                    <td className="w-6 pr-0">
                      <EventSeverityDot severity={e.severity} />
                    </td>
                    <td className="whitespace-nowrap">
                      <Link to={`/endpoints/${e.endpointId}`} className="font-medium hover:text-accent">
                        {e.hostname ?? 'Endpoint'}
                      </Link>
                    </td>
                    <td className="w-full min-w-64">
                      <span className="text-muted">{e.type}: </span>
                      {e.message}
                      {e.jobId && (
                        <Link to={`/jobs/${e.jobId}`} className="ml-2 text-xs text-accent hover:underline">
                          job
                        </Link>
                      )}
                    </td>
                    <td className="text-right whitespace-nowrap text-muted" title={new Date(e.createdAt).toLocaleString()}>
                      {formatRelative(e.createdAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>
    </>
  );
}

function SummaryTiles({ s }: { s: DashboardSummaryDto }) {
  const link = (to: string, text: string) => (
    <Link to={to} className="text-xs text-accent hover:underline">
      {text}
    </Link>
  );
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      <StatTile
        label="Compliance"
        value={formatPercent(s.compliancePercent, 1)}
        tone={s.compliancePercent >= 90 ? 'ok' : s.compliancePercent >= 70 ? 'warn' : 'danger'}
        icon={<CheckCircle2 className="size-4" aria-hidden />}
        hint={`${formatNumber(s.compliant)} of ${formatNumber(s.endpoints)} endpoints`}
      />
      <StatTile label="Endpoints" value={formatNumber(s.endpoints)} icon={<Monitor className="size-4" aria-hidden />} hint={`${s.organizations} organizations`} to={link('/endpoints', 'View all')} />
      <StatTile
        label="Online / offline"
        value={`${formatNumber(s.online)} / ${formatNumber(s.offline)}`}
        tone={s.offline > 0 ? 'warn' : 'ok'}
        icon={s.offline > 0 ? <WifiOff className="size-4" aria-hidden /> : <Wifi className="size-4" aria-hidden />}
        to={link('/endpoints?online=false', 'View offline')}
      />
      <StatTile
        label="Missing updates"
        value={formatNumber(s.missingUpdates)}
        tone={s.missingUpdates > 0 ? 'warn' : undefined}
        icon={<ShieldAlert className="size-4" aria-hidden />}
        hint={`${formatNumber(s.missingRequiredUpdates)} required updates outstanding`}
        to={link('/endpoints?compliance=MissingUpdates', 'View endpoints')}
      />
      <StatTile
        label="Known-exploited exposure"
        value={formatNumber(s.knownExploitedEndpoints)}
        tone={s.knownExploitedEndpoints > 0 ? 'danger' : 'ok'}
        icon={<ShieldX className="size-4" aria-hidden />}
        hint="Endpoints missing a fix for a CISA known-exploited vulnerability"
        to={link('/endpoints?knownExploited=true', 'View endpoints')}
      />
      <StatTile
        label="Failed updates"
        value={formatNumber(s.failedUpdates)}
        tone={s.failedUpdates > 0 ? 'danger' : undefined}
        icon={<AlertTriangle className="size-4" aria-hidden />}
        to={link('/endpoints?compliance=FailedUpdates', 'View endpoints')}
      />
      <StatTile
        label="Restart required"
        value={formatNumber(s.rebootRequired)}
        tone={s.rebootRequired > 0 ? 'info' : undefined}
        icon={<Power className="size-4" aria-hidden />}
        to={link('/endpoints?rebootPending=true', 'View endpoints')}
      />
      <StatTile
        label="Scan stale / never"
        value={`${formatNumber(s.scanStale)} / ${formatNumber(s.neverScanned)}`}
        tone={s.scanStale + s.neverScanned > 0 ? 'warn' : undefined}
        icon={<Clock className="size-4" aria-hidden />}
        to={link('/endpoints?compliance=ScanStale', 'View stale')}
      />
      <StatTile label="Jobs running / queued" value={`${formatNumber(s.runningJobs)} / ${formatNumber(s.queuedJobs)}`} to={link('/jobs?status=Running', 'View jobs')} />
      <StatTile
        label="Failed jobs (24 h)"
        value={formatNumber(s.failedJobs24h)}
        tone={s.failedJobs24h > 0 ? 'danger' : undefined}
        to={link('/jobs?status=Failed', 'View failed')}
      />
      <StatTile
        label="Pending approvals"
        value={formatNumber(s.pendingApprovals)}
        tone={s.pendingApprovals > 0 ? 'warn' : undefined}
        icon={<UserCheck className="size-4" aria-hidden />}
        to={link('/approvals', 'Review')}
      />
      <StatTile
        label="Unsupported OS / outdated agents"
        value={`${formatNumber(s.unsupportedOs)} / ${formatNumber(s.outdatedAgents)}`}
        tone={s.unsupportedOs > 0 ? 'danger' : s.outdatedAgents > 0 ? 'warn' : undefined}
        to={link('/endpoints?outdatedAgent=true', 'Outdated agents')}
      />
    </div>
  );
}
