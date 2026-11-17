import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { Check, Circle, Power, RotateCcw, XCircle } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation } from '../../api/hooks';
import { ACTIVE_JOB_STATUSES, type JobDetailDto, type JobItemStatus, type JobStatus } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { ConfirmDialog } from '../../components/Dialog';
import { jobIdOf } from '../../components/InstallDialog';
import { CategoryBadge, JobItemStatusBadge, JobStatusBadge } from '../../components/StatusBadges';
import { useToast } from '../../components/Toast';
import { Alert, Button, Card, cx, EmptyState, ErrorState, KeyValueList, PageHeader, ProgressBar, Spinner, StatTile, TableWrap } from '../../components/ui';
import { describeSkipReason, formatDateTime, formatRelative, humanize, jobItemPercent } from '../../lib/format';
import { EventList } from '../endpoints/EndpointTabs';

const TERMINAL: JobStatus[] = ['Completed', 'Failed', 'Cancelled', 'Expired'];

export function JobDetailPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { canOperate } = useAuth();
  const [confirmCancel, setConfirmCancel] = useState(false);
  const job = useApi<JobDetailDto>(`/jobs/${id}`, undefined, {
    refetchInterval: (data) => (!data || ACTIVE_JOB_STATUSES.includes(data.summary.status) || data.summary.status === 'WaitingForReboot' ? 5_000 : false),
  });

  const cancel = useApiMutation(() => api.del(`/jobs/${id}`), {
    invalidate: [`/jobs`, '/endpoints'],
    onSuccess: () => {
      toast.success('Cancellation requested.');
      setConfirmCancel(false);
    },
  });
  const retry = useApiMutation(() => api.post<unknown>(`/jobs/${id}/retry`), {
    invalidate: ['/jobs', '/endpoints'],
    onSuccess: (result) => {
      const newId = jobIdOf(result);
      toast.success('Retry queued.');
      if (newId) navigate(`/jobs/${newId}`);
    },
  });

  if (job.isPending) return <Spinner />;
  if (job.isError) return <ErrorState error={job.error} onRetry={() => void job.refetch()} />;
  const d = job.data;
  const j = d.summary;
  const active = ACTIVE_JOB_STATUSES.includes(j.status);
  const canCancel = canOperate && (active || j.status === 'WaitingForReboot') && !j.cancelRequested;
  // Downloads ahead of a window are not retried: the installation in the window downloads what is missing.
  const canRetry =
    canOperate &&
    j.type !== 'DownloadUpdates' &&
    (j.status === 'Failed' || j.status === 'Expired' || j.status === 'Cancelled' || (j.status === 'Completed' && j.failedCount > 0));
  const counts = countItems(d.items.map((i) => i.status));
  const removal = j.type === 'UninstallUpdate';

  return (
    <>
      <PageHeader
        breadcrumb={<Link to="/jobs" className="hover:text-fg">Jobs</Link>}
        title={
          <span className="flex flex-wrap items-center gap-2">
            {humanize(j.type)}
            <JobStatusBadge status={j.status} timedOut={j.timedOut} />
          </span>
        }
        subtitle={
          <>
            <Link to={`/endpoints/${j.endpointId}`} className="font-medium text-fg hover:text-accent">
              {j.hostname}
            </Link>{' '}
            · {j.organizationName} · {humanize(j.trigger)} by {j.requestedBy} · {formatDateTime(j.createdAt)}
          </>
        }
        actions={
          <>
            {canCancel && (
              <Button variant="danger-ghost" icon={<XCircle className="size-4" aria-hidden />} onClick={() => setConfirmCancel(true)}>
                Cancel job
              </Button>
            )}
            {canRetry && (
              <Button icon={<RotateCcw className="size-4" aria-hidden />} loading={retry.isPending} onClick={() => retry.mutate(undefined)}>
                Retry
              </Button>
            )}
          </>
        }
      />

      <div className="mb-4 flex flex-col gap-3">
        {retry.error && <Alert tone="danger">{retry.error.message}</Alert>}
        {j.cancelRequested && active && (
          <Alert tone="warn" title="Cancellation requested">
            {removal
              ? 'The removal is cancelled if it has not started. A removal that has started cannot be interrupted safely and finishes first.'
              : 'The agent stops before the next update. An update that is already installing cannot be interrupted safely and finishes first.'}
          </Alert>
        )}
        {j.status === 'WaitingForReboot' && (
          <Alert tone="info" title="Waiting for a restart">
            <Power className="mr-1 inline size-3.5" aria-hidden />
            Installed updates take effect after the endpoint restarts. EasyPatch does not restart endpoints; restart it through your own process and the agent
            verifies the result with a new scan.
          </Alert>
        )}
        {j.status === 'Completed' && j.rebootRequired && (
          <Alert tone="info" title="Restart required">
            {removal ? 'Windows needs a restart to finish removing the update.' : 'Some updates need a restart to finish.'} EasyPatch will not restart this endpoint.
          </Alert>
        )}
        {j.timedOut && (
          <Alert tone="warn" title="Timed out">
            The agent stopped reporting progress. If it reports a result later, that result replaces this outcome.
          </Alert>
        )}
        {(j.errorMessage || j.errorCode) && (
          <Alert tone="danger" title="Error">
            {j.errorCode && <span className="font-mono text-xs">{j.errorCode} </span>}
            {j.errorMessage}
          </Alert>
        )}
      </div>

      {(active || j.progressPercent !== null) && (
        <Card className="mb-5">
          <div className="flex items-center gap-3">
            <ProgressBar value={j.status === 'Completed' ? 100 : j.progressPercent} label="Job progress" tone={j.status === 'Failed' ? 'danger' : j.status === 'Completed' ? 'ok' : 'accent'} />
            <span className="w-10 text-right text-sm tabular-nums">{j.status === 'Completed' ? 100 : (j.progressPercent ?? 0)}%</span>
          </div>
          {(j.phase || j.progressMessage) && (
            <p className="mt-2 text-sm text-muted">
              {j.phase && <span className="font-medium text-fg">{humanize(j.phase)}: </span>}
              {j.progressMessage}
            </p>
          )}
        </Card>
      )}

      <div className="mb-5 grid grid-cols-1 gap-5 xl:grid-cols-3">
        <Card title="Timeline" className="xl:col-span-1">
          <Timeline d={d} />
        </Card>
        <Card title="Details" className="xl:col-span-2">
          <KeyValueList
            items={[
              ['Install mode', d.installMode ? humanize(d.installMode) : null],
              ['Expires', `${formatDateTime(j.expiresAt)}${active ? ` (${formatRelative(j.expiresAt)})` : ''}`],
              ['Not before', d.notBefore ? formatDateTime(d.notBefore) : null],
              ['Delivery attempts', d.deliveryCount],
              ['Last progress', d.lastProgressAt ? `${formatDateTime(d.lastProgressAt)} (${formatRelative(d.lastProgressAt)})` : null],
              ['Retry of', d.retryOfJobId ? <Link to={`/jobs/${d.retryOfJobId}`} className="text-accent hover:underline">previous job</Link> : null],
              ['Cancel requested', d.cancelRequestedAt ? formatDateTime(d.cancelRequestedAt) : null],
              ['Job ID', <span className="font-mono text-xs">{j.id}</span>],
            ]}
          />
        </Card>
      </div>

      {d.items.length > 0 && (
        <>
          <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-5">
            <StatTile label="Updates" value={d.items.length} />
            <StatTile label={removal ? 'Removed' : 'Succeeded'} value={counts.Succeeded} tone={counts.Succeeded ? 'ok' : undefined} />
            <StatTile label="Failed" value={counts.Failed} tone={counts.Failed ? 'danger' : undefined} />
            <StatTile label="In progress" value={counts.Pending + counts.Downloading + counts.Downloaded + counts.Installing} tone="accent" />
            <StatTile label="Skipped / cancelled" value={counts.Skipped + counts.Cancelled} />
          </div>
          <Card title="Updates in this job" padded={false} className="mb-5">
            <TableWrap className="rounded-none border-0">
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Update</th>
                    <th>Category</th>
                    <th>Status</th>
                    <th>Result</th>
                    <th>Finished</th>
                  </tr>
                </thead>
                <tbody>
                  {d.items.map((i) => (
                    <tr key={i.updateGuid}>
                      <td className="min-w-72">
                        <div className="font-medium">{i.title}</div>
                        {i.kbNumber && <div className="font-mono text-xs text-muted">{i.kbNumber}</div>}
                      </td>
                      <td>
                        <CategoryBadge category={i.category} />
                      </td>
                      <td>
                        <JobItemStatusBadge status={i.status} percent={jobItemPercent(i)} removal={removal} />
                        {jobItemPercent(i) !== null && (
                          <div className="mt-1.5 w-28">
                            <ProgressBar value={jobItemPercent(i)} label={`${humanize(i.status)} ${i.kbNumber ?? i.title}`} />
                          </div>
                        )}
                        {i.rebootRequired && <div className="mt-0.5 text-xs text-info">restart required</div>}
                      </td>
                      <td className="text-sm">
                        {i.status === 'Skipped' ? (
                          <span className="text-muted">{describeSkipReason(i.skipReason)}</span>
                        ) : i.errorCode || i.errorMessage ? (
                          <span className="text-danger">
                            {i.errorCode && <span className="font-mono">{i.errorCode} </span>}
                            {i.errorMessage}
                          </span>
                        ) : i.status === 'Succeeded' ? (
                          <span className="text-muted">Installed{i.rebootRequired ? ' — pending restart' : ''}; verified by the next scan</span>
                        ) : (
                          <span className="text-subtle">—</span>
                        )}
                      </td>
                      <td className="whitespace-nowrap text-muted">{i.completedAt ? formatRelative(i.completedAt) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </Card>
        </>
      )}

      <h2 className="mb-2 text-base font-semibold">Events</h2>
      {d.events.length === 0 ? <EmptyState title="No events for this job yet" /> : <EventList events={d.events} />}

      <ConfirmDialog
        open={confirmCancel}
        onClose={() => setConfirmCancel(false)}
        onConfirm={() => cancel.mutate(undefined)}
        loading={cancel.isPending}
        error={cancel.error}
        tone="danger"
        title="Cancel this job?"
        confirmLabel="Cancel job"
      >
        {j.status === 'Queued'
          ? 'The job has not been delivered yet and is cancelled immediately.'
          : 'The agent is asked to stop at its next check-in. Updates already installing finish first; completed installations are not rolled back.'}
      </ConfirmDialog>
    </>
  );
}

function countItems(statuses: JobItemStatus[]): Record<JobItemStatus, number> {
  const counts: Record<JobItemStatus, number> = { Pending: 0, Downloading: 0, Downloaded: 0, Installing: 0, Succeeded: 0, Failed: 0, Skipped: 0, Cancelled: 0 };
  for (const s of statuses) counts[s]++;
  return counts;
}

function Timeline({ d }: { d: JobDetailDto }) {
  const j = d.summary;
  const terminal = TERMINAL.includes(j.status);
  const steps: { label: string; at: string | null; done: boolean; failed?: boolean }[] = [
    { label: 'Created', at: j.createdAt, done: true },
    { label: 'Delivered to agent', at: d.deliveredAt, done: !!d.deliveredAt },
    { label: 'Acknowledged', at: d.acknowledgedAt, done: !!d.acknowledgedAt },
    { label: 'Started', at: j.startedAt, done: !!j.startedAt },
    {
      label: terminal ? humanize(j.status) : j.status === 'WaitingForReboot' ? 'Waiting for restart' : 'Finished',
      at: j.completedAt,
      done: terminal,
      failed: j.status === 'Failed' || j.status === 'Expired' || j.status === 'Cancelled',
    },
  ];
  return (
    <ol className="flex flex-col gap-3">
      {steps.map((s, i) => (
        <li key={s.label} className="flex items-start gap-3">
          <span
            className={cx(
              'mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full',
              s.failed ? 'bg-danger-soft text-danger' : s.done ? 'bg-ok-soft text-ok' : 'bg-neutral-soft text-subtle',
            )}
          >
            {s.failed ? <XCircle className="size-3.5" aria-hidden /> : s.done ? <Check className="size-3.5" aria-hidden /> : <Circle className="size-2.5" aria-hidden />}
          </span>
          <div className="min-w-0">
            <p className={cx('text-sm', s.done ? 'text-fg' : 'text-muted')}>
              {s.label}
              <span className="sr-only">{s.done ? ' (done)' : ' (pending)'}</span>
            </p>
            {s.at && <p className="text-xs text-muted">{formatDateTime(s.at)}</p>}
            {!s.at && i === 1 && !s.done && j.status === 'Queued' && <p className="text-xs text-muted">Waiting for the agent's next check-in</p>}
          </div>
        </li>
      ))}
    </ol>
  );
}
