import { ListChecks } from 'lucide-react';
import { useList } from '../../api/hooks';
import { JOB_STATUSES, JOB_TRIGGERS, JOB_TYPES, type JobSummaryDto } from '../../api/types';
import { EnumSelect, OrganizationSelect } from '../../components/Filters';
import { JobTable } from '../../components/JobTable';
import { Button, EmptyState, ErrorState, Field, Input, PageHeader, Pagination, Spinner, Toolbar } from '../../components/ui';
import { dayBoundary, humanize } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';

/** Converts a yyyy-MM-dd date input into an ISO instant at local midnight (start) or end of day. */
export function JobsPage() {
  const url = useUrlState();
  const from = url.get('from');
  const to = url.get('to');
  const endpointId = url.get('endpointId');
  const list = useList<JobSummaryDto>(
    '/jobs',
    {
      endpointId: endpointId || undefined,
      organizationId: url.get('organizationId') || undefined,
      status: url.get('status') || undefined,
      type: url.get('type') || undefined,
      trigger: url.get('trigger') || undefined,
      from: dayBoundary(from, false),
      to: dayBoundary(to, true),
      page: url.page,
      pageSize: 50,
    },
    { keepPrevious: true, refetchInterval: 10_000 },
  );

  const filtered = ['organizationId', 'status', 'type', 'trigger', 'from', 'to', 'endpointId'].some((k) => url.get(k));

  return (
    <>
      <PageHeader title="Jobs" subtitle="Scans, installations and inventory refreshes sent to agents." />
      <Toolbar>
        <OrganizationSelect value={url.get('organizationId')} onChange={(v) => url.set({ organizationId: v })} />
        <EnumSelect label="Status" value={url.get('status')} onChange={(v) => url.set({ status: v })} options={JOB_STATUSES} format={humanize} />
        <EnumSelect label="Type" value={url.get('type')} onChange={(v) => url.set({ type: v })} options={JOB_TYPES} format={humanize} />
        <EnumSelect label="Trigger" value={url.get('trigger')} onChange={(v) => url.set({ trigger: v })} options={JOB_TRIGGERS} format={humanize} />
        <Field label="From" htmlFor="jobs-from">
          <Input id="jobs-from" type="date" value={from} onChange={(e) => url.set({ from: e.target.value })} />
        </Field>
        <Field label="To" htmlFor="jobs-to">
          <Input id="jobs-to" type="date" value={to} onChange={(e) => url.set({ to: e.target.value })} />
        </Field>
        {filtered && (
          <Button variant="ghost" size="sm" className="mb-1" onClick={() => url.set({ organizationId: null, status: null, type: null, trigger: null, from: null, to: null, endpointId: null })}>
            Clear filters
          </Button>
        )}
      </Toolbar>
      {endpointId && <p className="mb-2 text-xs text-muted">Filtered to one endpoint.</p>}
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.page.items.length === 0 ? (
        <EmptyState title={filtered ? 'No jobs match these filters' : 'No jobs yet'} icon={<ListChecks className="size-8" aria-hidden />} />
      ) : (
        <>
          <JobTable jobs={list.page.items} />
          <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={(p) => url.set({ page: p })} />
        </>
      )}
    </>
  );
}
