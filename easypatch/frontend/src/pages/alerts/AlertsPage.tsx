import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { BellOff, Check } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation, useList } from '../../api/hooks';
import {
  ALERT_RULE_TYPE_LABELS,
  ALERT_RULE_TYPES,
  ALERT_SEVERITIES,
  ALERT_STATUS_FILTERS,
  type AcknowledgeAlertsResult,
  type AlertDto,
  type AlertSeverity,
  type AlertSummaryDto,
} from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { EnumSelect, OrganizationSelect, SearchInput } from '../../components/Filters';
import { useToast } from '../../components/Toast';
import { Badge, Button, EmptyState, ErrorState, PageHeader, Pagination, Spinner, TableWrap, Toolbar, type Tone } from '../../components/ui';
import { formatDateTime, formatRelative, humanize } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';

export const severityTone: Record<AlertSeverity, Tone> = { Critical: 'danger', Warning: 'warn', Info: 'info' };

export function AlertSeverityBadge({ severity }: { severity: AlertSeverity }) {
  return <Badge tone={severityTone[severity]}>{severity}</Badge>;
}

const STATUS_LABELS: Record<string, string> = {
  unresolved: 'Unresolved',
  open: 'Open (not acknowledged)',
  acknowledged: 'Acknowledged',
  resolved: 'Resolved',
  all: 'All',
};

export function AlertsPage() {
  const url = useUrlState();
  const { canOperate, isSuperAdmin } = useAuth();
  const toast = useToast();
  const status = url.get('status', 'unresolved');
  const params = {
    status,
    severity: url.get('severity') || undefined,
    organizationId: url.get('organizationId') || undefined,
    endpointId: url.get('endpointId') || undefined,
    ruleType: url.get('ruleType') || undefined,
    search: url.get('search') || undefined,
    page: url.page,
    pageSize: 50,
  };
  const list = useList<AlertDto>('/alerts', params, { keepPrevious: true, refetchInterval: 30_000 });
  const summary = useApi<AlertSummaryDto>('/alerts/summary', undefined, { refetchInterval: 30_000 });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const selectable = useMemo(() => list.page.items.filter((a) => a.status === 'Open'), [list.page.items]);
  const allSelected = selectable.length > 0 && selectable.every((a) => selected.has(a.id));
  const filterKey = JSON.stringify(params);
  useEffect(() => setSelected(new Set()), [filterKey]);

  const acknowledge = useApiMutation((ids: string[]) => api.post<AcknowledgeAlertsResult>('/alerts/acknowledge', { alertIds: ids }), {
    invalidate: ['/alerts'],
    onSuccess: (r) => {
      setSelected(new Set());
      toast.success(r.acknowledged === 1 ? 'Alert acknowledged.' : `${r.acknowledged} alerts acknowledged.`);
    },
  });

  const filtered = ['severity', 'organizationId', 'endpointId', 'ruleType', 'search'].some((k) => url.get(k)) || status !== 'unresolved';

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <>
      <PageHeader
        title="Alerts"
        subtitle={
          summary.data
            ? `${summary.data.open} open, ${summary.data.acknowledged} acknowledged · ${summary.data.critical} critical, ${summary.data.warning} warning, ${summary.data.info} info`
            : 'Conditions that need attention, raised by alert rules.'
        }
        actions={
          isSuperAdmin ? (
            <Link to="/settings?tab=alert-rules" className="text-sm text-accent hover:underline">
              Alert rules and notifications
            </Link>
          ) : undefined
        }
      />
      <Toolbar>
        <EnumSelect
          label="Status"
          value={status === 'unresolved' ? '' : status}
          allLabel="Unresolved"
          onChange={(v) => url.set({ status: v || null })}
          options={ALERT_STATUS_FILTERS.filter((s) => s !== 'unresolved')}
          format={(s) => STATUS_LABELS[s] ?? humanize(s)}
        />
        <EnumSelect label="Severity" value={url.get('severity')} onChange={(v) => url.set({ severity: v })} options={ALERT_SEVERITIES} />
        <OrganizationSelect value={url.get('organizationId')} onChange={(v) => url.set({ organizationId: v })} />
        <EnumSelect
          label="Rule type"
          value={url.get('ruleType')}
          onChange={(v) => url.set({ ruleType: v })}
          options={ALERT_RULE_TYPES}
          format={(t) => ALERT_RULE_TYPE_LABELS[t]}
          className="min-w-52"
        />
        <SearchInput value={url.get('search')} onChange={(v) => url.set({ search: v })} placeholder="Search titles…" />
        {filtered && (
          <Button
            variant="ghost"
            size="sm"
            className="mb-1"
            onClick={() => url.set({ status: null, severity: null, organizationId: null, endpointId: null, ruleType: null, search: null })}
          >
            Clear filters
          </Button>
        )}
      </Toolbar>
      {url.get('endpointId') && <p className="mb-2 text-xs text-muted">Filtered to one endpoint.</p>}
      {canOperate && selected.size > 0 && (
        <div className="mb-2 flex items-center gap-3 rounded-md border border-line bg-surface px-3 py-2 text-sm">
          <span>{selected.size} selected</span>
          <Button size="sm" variant="primary" icon={<Check className="size-3.5" aria-hidden />} loading={acknowledge.isPending} onClick={() => acknowledge.mutate([...selected])}>
            Acknowledge
          </Button>
          <span className="text-xs text-muted">Acknowledged alerts stay visible until the condition clears and no longer send reminders.</span>
        </div>
      )}
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.page.items.length === 0 ? (
        <EmptyState title={filtered ? 'No alerts match these filters' : 'No unresolved alerts'} icon={<BellOff className="size-8" aria-hidden />}>
          {filtered ? undefined : 'Alerts open when a rule matches (for example an endpoint offline for a day) and resolve by themselves when the condition clears.'}
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
                        aria-label="Select all open alerts on this page"
                        className="size-4"
                        checked={allSelected}
                        disabled={selectable.length === 0}
                        onChange={() => setSelected(allSelected ? new Set() : new Set(selectable.map((a) => a.id)))}
                      />
                    </th>
                  )}
                  <th>Severity</th>
                  <th>Alert</th>
                  <th>Organization</th>
                  <th>Opened</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {list.page.items.map((a) => (
                  <tr key={a.id}>
                    {canOperate && (
                      <td>
                        <input
                          type="checkbox"
                          className="size-4"
                          aria-label={`Select alert ${a.title}`}
                          disabled={a.status !== 'Open'}
                          checked={selected.has(a.id)}
                          onChange={() => toggle(a.id)}
                        />
                      </td>
                    )}
                    <td>
                      <AlertSeverityBadge severity={a.severity} />
                    </td>
                    <td className="max-w-xl">
                      <AlertTitle alert={a} />
                      <div className="mt-0.5 text-xs text-muted">
                        {a.ruleName ?? ALERT_RULE_TYPE_LABELS[a.ruleType]}
                        {a.details ? ` · ${a.details}` : ''}
                      </div>
                    </td>
                    <td>
                      <Link to={`/organizations/${a.organizationId}`} className="hover:text-accent">
                        {a.organizationName}
                      </Link>
                    </td>
                    <td className="whitespace-nowrap" title={formatDateTime(a.openedAt)}>
                      {formatRelative(a.openedAt)}
                    </td>
                    <td className="whitespace-nowrap">
                      <AlertStatusCell alert={a} />
                    </td>
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

function AlertTitle({ alert }: { alert: AlertDto }) {
  const to = alert.endpointId
    ? `/endpoints/${alert.endpointId}`
    : alert.ruleType === 'EnrollmentPending'
      ? '/approvals'
      : alert.ruleType === 'UpdateHeld'
        ? '/updates'
        : null;
  return to ? (
    <Link to={to} className="font-medium hover:text-accent">
      {alert.title}
    </Link>
  ) : (
    <span className="font-medium">{alert.title}</span>
  );
}

function AlertStatusCell({ alert }: { alert: AlertDto }) {
  if (alert.status === 'Resolved') {
    return (
      <span title={formatDateTime(alert.resolvedAt)}>
        <Badge tone="ok">Resolved</Badge> <span className="text-xs text-muted">{formatRelative(alert.resolvedAt)}</span>
      </span>
    );
  }
  if (alert.status === 'Acknowledged') {
    return (
      <span title={`Acknowledged ${formatDateTime(alert.acknowledgedAt)}${alert.acknowledgedBy ? ` by ${alert.acknowledgedBy}` : ''}`}>
        <Badge tone="neutral">Acknowledged</Badge>
        {alert.acknowledgedBy && <span className="ml-1 text-xs text-muted">{alert.acknowledgedBy}</span>}
      </span>
    );
  }
  return <Badge tone={severityTone[alert.severity]}>Open</Badge>;
}
