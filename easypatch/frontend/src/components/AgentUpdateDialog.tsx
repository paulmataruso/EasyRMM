import { Link } from 'react-router';
import { ArrowUpCircle } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useApiMutation } from '../api/hooks';
import type { AgentUpdateRequest, BulkAgentUpdateRequest, BulkResultDto } from '../api/types';
import { describeAgentPackage, isLinux, isMacOS } from '../lib/format';
import { Dialog } from './Dialog';
import { jobIdOf } from './InstallDialog';
import type { EndpointTarget } from './RestartDialogs';
import { useToast } from './Toast';
import { Alert, Button, InlineError } from './ui';

/** Updates the EasyPatch agent on one endpoint or a bulk selection to the newest signed package on the server. */
export function AgentUpdateDialog({ target, onClose, onBulkResult }: {
  target: EndpointTarget | null;
  onClose: () => void;
  onBulkResult?: (title: string, data: BulkResultDto) => void;
}) {
  const toast = useToast();
  const endpoint = target?.kind === 'endpoint' ? target.endpoint : null;
  const info = endpoint?.agentUpdate ?? null;
  const linux = endpoint !== null && isLinux(endpoint.summary.platform);
  const mac = endpoint !== null && isMacOS(endpoint.summary.platform);

  const update = useApiMutation(
    () =>
      target?.kind === 'endpoint'
        ? api.post<unknown>(`/endpoints/${target.endpoint.summary.id}/agent-update`, { version: null } satisfies AgentUpdateRequest)
        : api.post<BulkResultDto>('/endpoints/bulk/agent-update', {
            endpointIds: target?.kind === 'bulk' ? target.ids : [],
            version: null,
          } satisfies BulkAgentUpdateRequest),
    {
      invalidate: ['/endpoints', '/jobs'],
      onSuccess: (result) => {
        if (target?.kind === 'bulk') {
          onBulkResult?.('Agent update', result as BulkResultDto);
        } else {
          const jobId = jobIdOf(result);
          toast.success(
            <span>
              Agent update queued.{' '}
              {jobId && (
                <Link to={`/jobs/${jobId}`} className="text-accent hover:underline">
                  View job
                </Link>
              )}
            </span>,
          );
        }
        onClose();
      },
    },
  );

  const blocked = endpoint !== null && (info === null || info.code !== null);
  const duplicate = update.error instanceof ApiError && update.error.code === 'duplicate_job';
  const title = !target ? '' : target.kind === 'endpoint' ? target.endpoint.summary.hostname : `${target.ids.length} endpoint${target.ids.length === 1 ? '' : 's'}`;

  return (
    <Dialog
      open={target !== null}
      onClose={onClose}
      title={`Update the agent on ${title}`}
      footer={
        <>
          <Button onClick={onClose} disabled={update.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            icon={<ArrowUpCircle className="size-4" aria-hidden />}
            loading={update.isPending}
            disabled={blocked}
            onClick={() => update.mutate(undefined)}
          >
            {endpoint && info?.availableVersion ? `Update to ${info.availableVersion}` : 'Update agent'}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        {endpoint && info?.code && (
          <Alert tone={info.code === 'agent_up_to_date' ? 'info' : 'warn'} title={info.code === 'agent_up_to_date' ? 'Already up to date' : 'Cannot update'}>
            {info.message}
          </Alert>
        )}
        {endpoint && info?.availableVersion && (
          <p>
            EasyPatch Agent <span className="font-mono">{endpoint.summary.agentVersion ?? '—'}</span> will be updated to{' '}
            <span className="font-mono">{info.availableVersion}</span> ({[info.architecture, info.packageFormat && describeAgentPackage(info.packageFormat)].filter(Boolean).join(', ')}).
          </p>
        )}
        {endpoint && !endpoint.summary.isOnline && info?.availableVersion && (
          <Alert tone="warn">The endpoint is offline. The update waits until it checks in, for up to 24 hours.</Alert>
        )}
        {target?.kind === 'bulk' && (
          <p>
            Each endpoint gets its own job and installs the newest signed agent package for its architecture and package format (MSI, DEB, RPM, or the
            experimental macOS PKG). Endpoints that are up to date, older than 1.2.0
            (those need one manual install), or that do not trust the package's release key are skipped and listed in the results.
          </p>
        )}
        <p className="text-muted">
          {linux ? (
            <>
              The agent checks the package's release signature against the key built into it, downloads the package from this server, checks its hash and
              installs it with apt or dnf. The agent service restarts; the computer is not restarted and nobody is asked anything.
            </>
          ) : mac ? (
            <>
              The agent checks the package's release signature against the key built into it, downloads the package from this server, checks its hash and
              installs it with the macOS installer. The agent restarts; the Mac is not restarted and nobody is asked anything.
            </>
          ) : (
            <>
              The agent checks the package's release signature against the key built into it, downloads the package from this server, checks its hash and lets
              {target?.kind === 'bulk' ? ' Windows Installer (apt/dnf on Linux, the installer on macOS)' : ' Windows Installer'} replace it. The agent service restarts and the tray icon
              disappears for a moment; the computer is not restarted and nobody is asked anything.
            </>
          )}{' '}
          The job completes when the new version checks in, and fails if the old version comes back.
        </p>
        {duplicate ? <Alert tone="warn">An agent update is already queued or running for this endpoint.</Alert> : <InlineError error={update.error} />}
      </div>
    </Dialog>
  );
}
