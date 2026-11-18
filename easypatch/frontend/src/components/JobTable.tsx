import { Link, useNavigate } from 'react-router';
import type { JobSummaryDto } from '../api/types';
import { formatDateTime, formatRelative, humanize } from '../lib/format';
import { JobStatusBadge } from './StatusBadges';
import { ProgressBar, TableWrap } from './ui';

export function JobTable({ jobs, showEndpoint = true }: { jobs: JobSummaryDto[]; showEndpoint?: boolean }) {
  const navigate = useNavigate();
  return (
    <TableWrap>
      <table className="table-base">
        <thead>
          <tr>
            <th>Job</th>
            {showEndpoint && <th>Endpoint</th>}
            <th>Status</th>
            <th>Progress / result</th>
            <th>Requested</th>
            <th>Finished</th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((j) => (
            <tr key={j.id} className="cursor-pointer" onClick={() => navigate(`/jobs/${j.id}`)}>
              <td className="whitespace-nowrap">
                <Link to={`/jobs/${j.id}`} className="font-medium hover:text-accent" onClick={(e) => e.stopPropagation()}>
                  {humanize(j.type)}
                </Link>
                <div className="text-xs text-muted">
                  {humanize(j.trigger)} · {j.requestedBy}
                </div>
              </td>
              {showEndpoint && (
                <td className="whitespace-nowrap">
                  <Link to={`/endpoints/${j.endpointId}`} className="hover:text-accent" onClick={(e) => e.stopPropagation()}>
                    {j.hostname}
                  </Link>
                  <div className="text-xs text-muted">{j.organizationName}</div>
                </td>
              )}
              <td>
                <JobStatusBadge status={j.status} timedOut={j.timedOut} />
                {j.cancelRequested && j.status !== 'Cancelled' && <div className="mt-0.5 text-xs text-warn">Cancellation requested</div>}
                {j.rebootRequired && <div className="mt-0.5 text-xs text-info">Restart required</div>}
              </td>
              <td className="min-w-48">
                {j.status === 'Running' ? (
                  <div className="flex flex-col gap-1">
                    <ProgressBar value={j.progressPercent} label="Job progress" />
                    <span className="truncate text-xs text-muted">{j.progressMessage ?? j.phase ?? ''}</span>
                  </div>
                ) : j.itemCount > 0 ? (
                  <span className="text-sm">
                    {j.succeededCount} of {j.itemCount} succeeded
                    {j.failedCount > 0 && <span className="text-danger">, {j.failedCount} failed</span>}
                  </span>
                ) : j.errorMessage ? (
                  <span className="line-clamp-2 text-sm text-danger">{j.errorMessage}</span>
                ) : (
                  <span className="text-sm text-muted">{j.progressMessage ?? '—'}</span>
                )}
              </td>
              <td className="whitespace-nowrap text-muted" title={formatDateTime(j.createdAt)}>
                {formatRelative(j.createdAt)}
              </td>
              <td className="whitespace-nowrap text-muted" title={j.completedAt ? formatDateTime(j.completedAt) : undefined}>
                {j.completedAt ? formatRelative(j.completedAt) : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}
