import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { Download, Power, RefreshCw } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useApi, useApiMutation } from '../api/hooks';
import type { InstallMode, InstallPreview, JobDetailDto, JobSummaryDto } from '../api/types';
import { describeSkipReason, formatBytes, formatRelative, humanize } from '../lib/format';
import { CategoryBadge, UpdateStateBadge } from './StatusBadges';
import { Dialog } from './Dialog';
import { useToast } from './Toast';
import { Alert, Button, ErrorState, InlineError, Spinner, StatTile, TableWrap } from './ui';

/** Job-creation endpoints return a job DTO; accept either the summary or the detail shape. */
export function jobIdOf(result: unknown): string | null {
  if (!result || typeof result !== 'object') return null;
  const r = result as Partial<JobSummaryDto> & Partial<JobDetailDto>;
  return r.id ?? r.summary?.id ?? null;
}

export function InstallUpdatesDialog({
  endpointId,
  hostname,
  mode,
  updateGuids,
  open,
  onClose,
  onQueued,
}: {
  endpointId: string;
  hostname: string;
  mode: InstallMode;
  updateGuids?: string[];
  open: boolean;
  onClose: () => void;
  onQueued?: (jobId: string | null) => void;
}) {
  const toast = useToast();
  const navigate = useNavigate();
  const [duplicateJobId, setDuplicateJobId] = useState<string | null>(null);
  const guids = mode === 'Selected' ? (updateGuids ?? []) : [];
  const preview = useApi<InstallPreview>(
    open ? `/endpoints/${endpointId}/install-preview` : null,
    { mode: mode === 'AllEligible' ? 'all' : 'selected', updateGuids: guids.length ? guids.join(',') : undefined },
    { staleTime: 0 },
  );

  const install = useApiMutation(
    (force: boolean) => api.post<unknown>(`/endpoints/${endpointId}/install-updates`, { mode, updateGuids: mode === 'Selected' ? guids : null, force }),
    {
      invalidate: [`/endpoints/${endpointId}`, '/jobs', '/dashboard'],
      onSuccess: (result) => {
        const jobId = jobIdOf(result);
        toast.success(
          <span>
            Installation queued for {hostname}.{' '}
            {jobId && (
              <Link to={`/jobs/${jobId}`} className="text-accent hover:underline">
                View job
              </Link>
            )}
          </span>,
        );
        onQueued?.(jobId);
        onClose();
      },
    },
  );

  const resetInstall = install.reset;
  useEffect(() => {
    if (open) {
      setDuplicateJobId(null);
      resetInstall();
    }
  }, [open, resetInstall]);

  useEffect(() => {
    const err = install.error;
    if (err instanceof ApiError && err.code === 'duplicate_job') {
      setDuplicateJobId(err.extension<string>('existingJobId') ?? null);
    }
  }, [install.error]);

  const p = preview.data;
  const isDuplicate = install.error instanceof ApiError && install.error.code === 'duplicate_job';
  const canQueue = !!p && (mode === 'AllEligible' || p.items.length > 0);
  const noScan = p && !p.lastScanAt;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      size="lg"
      title={mode === 'AllEligible' ? `Install all missing updates on ${hostname}?` : `Install ${guids.length} selected update${guids.length === 1 ? '' : 's'} on ${hostname}?`}
      description="Review what the agent will install. Nothing happens until you confirm."
      footer={
        <>
          <Button onClick={onClose} disabled={install.isPending}>
            Cancel
          </Button>
          {isDuplicate ? (
            <Button variant="primary" loading={install.isPending} onClick={() => install.mutate(true)} icon={<Download className="size-4" aria-hidden />}>
              Queue another job anyway
            </Button>
          ) : (
            <Button variant="primary" loading={install.isPending} disabled={!canQueue} onClick={() => install.mutate(false)} icon={<Download className="size-4" aria-hidden />}>
              {mode === 'AllEligible' && p && p.items.length === 0 ? 'Queue installation (agent rescans first)' : 'Confirm installation'}
            </Button>
          )}
        </>
      }
    >
      {preview.isPending ? (
        <Spinner label="Calculating what would be installed…" />
      ) : preview.isError ? (
        <ErrorState error={preview.error} onRetry={() => void preview.refetch()} compact />
      ) : (
        p && (
          <div className="flex flex-col gap-4">
            <div className="grid grid-cols-3 gap-3">
              <StatTile label="Updates to install" value={p.items.length} tone={p.items.length ? 'accent' : 'neutral'} />
              <StatTile label="Total download" value={<span className="text-xl">{formatBytes(p.totalSizeBytes)}</span>} />
              <StatTile label="Likely need a restart" value={p.rebootLikelyCount} tone={p.rebootLikelyCount ? 'info' : 'neutral'} />
            </div>

            {p.warnings.length > 0 && (
              <Alert tone="warn" title={p.warnings.length === 1 ? 'Warning' : `${p.warnings.length} warnings`}>
                <ul className="list-disc space-y-0.5 pl-4">
                  {p.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              </Alert>
            )}

            <Alert tone="info" title="Installing does not restart this endpoint">
              <span className="inline-flex items-start gap-1">
                <Power className="mt-0.5 size-3.5 shrink-0" aria-hidden />
                Updates that need a restart are reported as “Pending restart”. Restart the endpoint afterwards with Restart… (or a restart schedule in policy).
              </span>
            </Alert>

            <p className="flex items-start gap-1.5 text-xs text-muted">
              <RefreshCw className="mt-0.5 size-3.5 shrink-0" aria-hidden />
              {noScan
                ? 'This endpoint has not reported a scan yet. The agent scans first and installs what policy allows.'
                : `Based on the scan from ${formatRelative(p.lastScanAt)}. The agent runs a fresh scan before installing, so the final list can differ slightly.`}
              {p.filter && ` Allowed categories: ${p.filter.categories.map(humanize).join(', ')}${p.filter.includeOptional ? ' (including optional updates)' : ''}.`}
            </p>

            {p.items.length > 0 && (
              <TableWrap>
                <table className="table-base">
                  <thead>
                    <tr>
                      <th>Update</th>
                      <th>Category</th>
                      <th>State</th>
                      <th className="text-right">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {p.items.map((i) => (
                      <tr key={i.updateGuid}>
                        <td>
                          <div className="font-medium">{i.title}</div>
                          <div className="flex gap-2 text-xs text-muted">
                            {i.kbNumber && <span className="font-mono">{i.kbNumber}</span>}
                            {i.rebootBehavior !== null && i.rebootBehavior > 0 && <span className="text-info">restart likely</span>}
                          </div>
                        </td>
                        <td>
                          <CategoryBadge category={i.category} />
                        </td>
                        <td>
                          <UpdateStateBadge state={i.state} />
                        </td>
                        <td className="text-right whitespace-nowrap tabular-nums">{formatBytes(i.sizeBytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}

            {p.skipped.length > 0 && (
              <details className="rounded-md border border-line">
                <summary className="cursor-pointer px-3 py-2 text-sm font-medium">
                  {p.skipped.length} update{p.skipped.length === 1 ? '' : 's'} will be skipped
                </summary>
                <ul className="divide-y divide-line border-t border-line">
                  {p.skipped.map((s) => (
                    <li key={s.updateGuid} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm">
                      <span className="min-w-0">
                        {s.title} {s.kbNumber && <span className="font-mono text-xs text-muted">{s.kbNumber}</span>}
                      </span>
                      <span className="text-xs text-muted">{describeSkipReason(s.reason)}</span>
                    </li>
                  ))}
                </ul>
              </details>
            )}

            {mode === 'Selected' && p.items.length === 0 && (
              <Alert tone="warn">None of the selected updates can be installed. See the skipped list for reasons.</Alert>
            )}

            {isDuplicate ? (
              <Alert tone="warn" title="An installation job is already active for this endpoint">
                {duplicateJobId ? (
                  <button type="button" className="text-accent hover:underline" onClick={() => { onClose(); navigate(`/jobs/${duplicateJobId}`); }}>
                    View the existing job
                  </button>
                ) : (
                  'Check the Jobs tab.'
                )}{' '}
                or queue another job anyway.
              </Alert>
            ) : (
              <InlineError error={install.error} />
            )}
          </div>
        )
      )}
    </Dialog>
  );
}
