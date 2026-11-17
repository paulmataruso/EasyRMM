import { useEffect, useId, useState } from 'react';
import { Link } from 'react-router';
import type { UseQueryResult } from '@tanstack/react-query';
import { MessageSquare, Power } from 'lucide-react';
import { ApiError, api } from '../api/client';
import { useApi, useApiMutation } from '../api/hooks';
import {
  AGENT_CAPABILITIES,
  type BulkResultDto,
  type EndpointDetailDto,
  type NotifyRequest,
  type RestartMode,
  type RestartPendingDto,
  type RestartPendingRequest,
  type RestartRequest,
  type UserMessagePreset,
  type UserMessagePresetDto,
} from '../api/types';
import { formatDuration, formatRelative, isLinux, isMacOS } from '../lib/format';
import { Dialog } from './Dialog';
import { jobIdOf } from './InstallDialog';
import { EXPIRY_OPTIONS, RestartModeFields } from './PolicySections';
import { useToast } from './Toast';
import { Alert, Badge, Button, Checkbox, cx, InlineError, Input, Select, Spinner } from './ui';

/** One endpoint (with its live state) or a bulk selection. */
export type EndpointTarget = { kind: 'endpoint'; endpoint: EndpointDetailDto } | { kind: 'bulk'; ids: string[] };

/** An endpoint target, or every endpoint of an organization or site that reports a pending restart. */
export type RestartTarget = EndpointTarget | { kind: 'pending'; organizationId: string; siteId: string | null; scopeName: string };

/** "2026-11-14T03:00" (local) for a datetime-local input. */
function toLocalInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function parseLocalInput(value: string): Date | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function targetTitle(target: RestartTarget | null): string {
  if (!target) return '';
  if (target.kind === 'pending') return `all that need it in ${target.scopeName}`;
  return target.kind === 'endpoint' ? target.endpoint.summary.hostname : `${target.ids.length} endpoint${target.ids.length === 1 ? '' : 's'}`;
}

function useJobToast() {
  const toast = useToast();
  return (label: string, result: unknown) => {
    const jobId = jobIdOf(result);
    toast.success(
      <span>
        {label}{' '}
        {jobId && (
          <Link to={`/jobs/${jobId}`} className="text-accent hover:underline">
            View job
          </Link>
        )}
      </span>,
    );
  };
}

function duplicateMessage(error: unknown): string | null {
  return error instanceof ApiError && error.code === 'duplicate_job' ? 'A restart or the same message is already queued or running for this endpoint.' : null;
}

export function RestartDialog({ target, onClose, onBulkResult }: {
  target: RestartTarget | null;
  onClose: () => void;
  onBulkResult?: (title: string, data: BulkResultDto) => void;
}) {
  const jobToast = useJobToast();
  const whenId = useId();
  const atId = useId();
  const expiryId = useId();
  const [when, setWhen] = useState<'now' | 'later'>('now');
  const [at, setAt] = useState('');
  const [mode, setMode] = useState<RestartMode>('PromptWithDeadline');
  const [countdownMinutes, setCountdownMinutes] = useState(5);
  const [deadlineMinutes, setDeadlineMinutes] = useState(240);
  const [onlyIfPending, setOnlyIfPending] = useState(false);
  const [expiry, setExpiry] = useState(120);

  useEffect(() => {
    if (!target) return;
    setWhen('now');
    const tonight = new Date();
    tonight.setDate(tonight.getDate() + (tonight.getHours() >= 22 ? 1 : 0));
    tonight.setHours(22, 0, 0, 0);
    setAt(toLocalInput(tonight));
    setMode('PromptWithDeadline');
    setOnlyIfPending(false);
    setExpiry(120);
  }, [target]);

  const pending = target?.kind === 'pending' ? target : null;
  const preview = useApi<RestartPendingDto>(
    pending ? `/organizations/${pending.organizationId}/restart-pending` : null,
    pending?.siteId ? { siteId: pending.siteId } : undefined,
  );
  const pendingIds = preview.data?.endpoints.filter((e) => e.canRestart).map((e) => e.id) ?? [];

  const restart = useApiMutation(
    (req: RestartRequest) => {
      if (target?.kind === 'endpoint') return api.post<unknown>(`/endpoints/${target.endpoint.summary.id}/restart`, req);
      if (target?.kind === 'pending') {
        const body: RestartPendingRequest = { siteId: target.siteId, endpointIds: pendingIds, restart: req };
        return api.post<BulkResultDto>(`/organizations/${target.organizationId}/restart-pending`, body);
      }
      return api.post<BulkResultDto>('/endpoints/bulk/restart', { endpointIds: target?.kind === 'bulk' ? target.ids : [], restart: req });
    },
    {
      invalidate: ['/endpoints', '/jobs', '/organizations'],
      onSuccess: (result) => {
        if (target?.kind === 'bulk') onBulkResult?.('Restart', result as BulkResultDto);
        else if (target?.kind === 'pending') onBulkResult?.(`Restart all that need it in ${target.scopeName}`, result as BulkResultDto);
        else jobToast(when === 'now' ? 'Restart requested.' : 'Restart scheduled.', result);
        onClose();
      },
    },
  );

  const scheduled = when === 'later' ? parseLocalInput(at) : null;
  const timeProblem =
    when === 'later' && (!scheduled || scheduled.getTime() < Date.now() - 60_000)
      ? 'Choose a time in the future.'
      : scheduled && scheduled.getTime() > Date.now() + 31 * 86_400_000
        ? 'A restart can be scheduled up to 31 days ahead.'
        : null;
  const endpoint = target?.kind === 'endpoint' ? target.endpoint : null;
  const unsupported =
    (endpoint !== null && !endpoint.agentCapabilities.includes(AGENT_CAPABILITIES.restart)) ||
    (pending !== null && (preview.isFetching || pendingIds.length === 0));
  const plural = pendingIds.length === 1 ? '' : 's';

  function submit() {
    restart.mutate({
      mode,
      // "All that need it" is always conditional: an endpoint that no longer needs a restart when the job arrives is left alone.
      condition: pending || onlyIfPending ? 'OnlyIfPending' : 'Always',
      countdownMinutes: mode === 'Countdown' ? countdownMinutes : null,
      deadlineMinutes: mode === 'PromptWithDeadline' ? deadlineMinutes : null,
      scheduledAt: scheduled ? scheduled.toISOString() : null,
      expiresAfterMinutes: expiry,
      force: false,
    });
  }

  return (
    <Dialog
      open={target !== null}
      onClose={onClose}
      title={`Restart ${targetTitle(target)}`}
      footer={
        <>
          <Button onClick={onClose} disabled={restart.isPending}>
            Cancel
          </Button>
          <Button
            variant={mode === 'Immediate' && when === 'now' ? 'danger' : 'primary'}
            loading={restart.isPending}
            disabled={unsupported || !!timeProblem}
            onClick={submit}
            icon={<Power className="size-4" aria-hidden />}
          >
            {pending
              ? when === 'now'
                ? `Restart ${pendingIds.length} endpoint${plural}`
                : `Schedule ${pendingIds.length} restart${plural}`
              : when === 'now'
                ? 'Restart'
                : 'Schedule restart'}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4 text-sm">
        {endpoint && <EndpointRestartContext endpoint={endpoint} />}
        {pending && <PendingRestartList scopeName={pending.scopeName} showSite={pending.siteId === null} preview={preview} />}
        {target?.kind === 'bulk' && (
          <p className="text-muted">
            Each endpoint gets its own restart job. Endpoints whose agent is older than 1.1.0 are skipped and listed in the results. macOS endpoints
            (experimental agent) restart without warning signed-in users on screen.
          </p>
        )}

        <div className="flex flex-wrap gap-4">
          <div className="flex flex-col gap-1">
            <label htmlFor={whenId} className="text-xs font-medium text-muted">
              When
            </label>
            <Select id={whenId} className="w-48" value={when} onChange={(e) => setWhen(e.target.value as 'now' | 'later')}>
              <option value="now">Now</option>
              <option value="later">At a specific time</option>
            </Select>
          </div>
          {when === 'later' && (
            <div className="flex flex-col gap-1">
              <label htmlFor={atId} className="text-xs font-medium text-muted">
                Time (your browser's time zone)
              </label>
              <Input id={atId} type="datetime-local" className="w-56" value={at} onChange={(e) => setAt(e.target.value)} aria-invalid={timeProblem ? true : undefined} />
            </div>
          )}
          <div className="flex flex-col gap-1">
            <label htmlFor={expiryId} className="text-xs font-medium text-muted">
              If the computer is off, give up after
            </label>
            <Select id={expiryId} className="w-40" value={expiry} onChange={(e) => setExpiry(Number(e.target.value))}>
              {EXPIRY_OPTIONS.map((m) => (
                <option key={m} value={m}>
                  {formatDuration(m)}
                </option>
              ))}
            </Select>
          </div>
        </div>
        {timeProblem && <p className="text-xs text-danger">{timeProblem}</p>}

        <RestartModeFields
          mode={mode}
          countdownMinutes={countdownMinutes}
          deadlineMinutes={deadlineMinutes}
          onChange={(c) => {
            if (c.mode) setMode(c.mode);
            if (c.countdownMinutes) setCountdownMinutes(c.countdownMinutes);
            if (c.deadlineMinutes) setDeadlineMinutes(c.deadlineMinutes);
          }}
        />
        <Checkbox
          label="Only if the operating system reports a pending restart"
          hint={
            pending
              ? 'Always on here: the agent checks when the job arrives and completes without restarting if nothing is pending any more.'
              : 'The agent checks when the job arrives and completes without restarting if nothing is pending.'
          }
          checked={pending !== null || onlyIfPending}
          disabled={pending !== null}
          onChange={(e) => setOnlyIfPending(e.target.checked)}
        />
        <p className="text-xs text-muted">If nobody is signed in when the restart is due, the computer restarts at once in every mode.</p>
        {duplicateMessage(restart.error) ? <Alert tone="warn">{duplicateMessage(restart.error)}</Alert> : <InlineError error={restart.error} />}
      </div>
    </Dialog>
  );
}

/** The endpoints "Restart all that need it" would restart, as the server lists them now. */
function PendingRestartList({ scopeName, showSite, preview }: { scopeName: string; showSite: boolean; preview: UseQueryResult<RestartPendingDto> }) {
  if (preview.isPending) return <Spinner label="Finding endpoints that need a restart…" className="py-4" />;
  if (preview.isError) return <InlineError error={preview.error} />;
  const { total, endpoints } = preview.data;
  if (total === 0) return <Alert tone="ok">No endpoint in {scopeName} reports a pending restart.</Alert>;

  const restartable = endpoints.filter((e) => e.canRestart);
  const servers = restartable.filter((e) => e.isServer).length;
  const offline = restartable.filter((e) => !e.isOnline).length;
  const macs = restartable.filter((e) => isMacOS(e.platform)).length;
  const tooOld = endpoints.length - restartable.length;
  return (
    <div className="flex flex-col gap-3">
      <p>
        {total} endpoint{total === 1 ? '' : 's'} in {scopeName} report{total === 1 ? 's' : ''} a pending restart. Each one that can be restarted gets
        its own restart job; endpoints that report a pending restart later are not included.
      </p>
      {servers > 0 && (
        <Alert tone="warn" title={`Includes ${servers} server${servers === 1 ? '' : 's'}`}>
          Windows Server and domain controllers stop their services while they restart. Consider scheduling the restart for a maintenance window.
        </Alert>
      )}
      {macs > 0 && (
        <Alert tone="warn">
          {macs} macOS endpoint{macs === 1 ? '' : 's'} (experimental agent) restart{macs === 1 ? 's' : ''} without warning signed-in users on screen.
        </Alert>
      )}
      <div className="max-h-56 overflow-y-auto rounded-md border border-line">
        <ul className="divide-y divide-line">
          {endpoints.map((e) => (
            <li key={e.id} className={cx('flex flex-wrap items-center gap-x-2 gap-y-1 px-3 py-1.5', !e.canRestart && 'text-muted')}>
              <span className="font-medium">{e.hostname}</span>
              {showSite && e.siteName && <span className="text-xs text-muted">{e.siteName}</span>}
              {e.isServer && <Badge tone="warn">Server</Badge>}
              {isMacOS(e.platform) && <Badge>macOS (experimental)</Badge>}
              {!e.isOnline && <Badge>Offline</Badge>}
              {!e.canRestart && <Badge tone="danger">Agent too old, skipped</Badge>}
              <span className="ml-auto text-xs text-muted">{e.rebootPendingSince ? `pending ${formatRelative(e.rebootPendingSince)}` : ''}</span>
            </li>
          ))}
        </ul>
      </div>
      <p className="text-xs text-muted">
        {offline > 0 && `${offline} offline endpoint${offline === 1 ? '' : 's'} restart${offline === 1 ? 's' : ''} when they check in, within the time limit below. `}
        {tooOld > 0 && `${tooOld} endpoint${tooOld === 1 ? '' : 's'} with an agent older than 1.1.0 cannot restart and ${tooOld === 1 ? 'is' : 'are'} skipped. `}
        {total > endpoints.length && `Only the first ${endpoints.length} of ${total} are restarted by this action.`}
      </p>
    </div>
  );
}

function EndpointRestartContext({ endpoint }: { endpoint: EndpointDetailDto }) {
  const s = endpoint.summary;
  if (!endpoint.agentCapabilities.includes(AGENT_CAPABILITIES.restart)) {
    return (
      <Alert tone="danger" title="This agent cannot restart the computer">
        Agent {s.agentVersion ?? 'version unknown'} does not support restarts. Install EasyPatch agent 1.1.0 or later on this endpoint.
      </Alert>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      {!s.isOnline && <Alert tone="warn">The endpoint is offline. The restart waits until it checks in, up to the time limit below.</Alert>}
      {isMacOS(s.platform) && (
        <Alert tone="warn" title="Signed-in users are not warned on screen">
          The experimental macOS agent restarts the Mac with <code>shutdown -r</code>. It shows no countdown, deadline or question, so unsaved work in open
          sessions can be lost.
        </Alert>
      )}
      <SessionSummary endpoint={endpoint} />
      {endpoint.activeJob && endpoint.activeJob.type !== 'NotifyUser' && (
        <p className="text-xs text-muted">Another job is active; the restart starts after it finishes.</p>
      )}
    </div>
  );
}

export function SessionSummary({ endpoint }: { endpoint: EndpointDetailDto }) {
  const users = endpoint.signedInUsers;
  const trays = endpoint.trayConnectedSessions ?? 0;
  if (users === null) return <p className="text-xs text-muted">Signed-in users: unknown until the agent reports.</p>;
  if (users === 0) return <p className="text-xs text-muted">Nobody is signed in.</p>;
  if (isMacOS(endpoint.summary.platform)) {
    return (
      <p className="text-xs text-warn">
        {users} signed-in user{users === 1 ? '' : 's'}. The macOS agent has no EasyPatch tray and does not warn signed-in users on screen before a restart.
      </p>
    );
  }
  if (isLinux(endpoint.summary.platform) && !endpoint.agentCapabilities.includes(AGENT_CAPABILITIES.tray)) {
    return (
      <p className="text-xs text-muted">
        {users} signed-in user{users === 1 ? '' : 's'}. Linux agents have no EasyPatch tray: countdowns and deadlines warn users through the system's
        shutdown messages, and “Ask users, no deadline” cannot be answered.
      </p>
    );
  }
  return (
    <p className={cx('text-xs', trays < users ? 'text-warn' : 'text-muted')}>
      {users} signed-in user{users === 1 ? '' : 's'}; the EasyPatch tray is running in {trays} of {users} session{users === 1 ? '' : 's'}.
      {trays === 0 &&
        ' Without the tray, countdowns and deadlines rely on the Windows restart warning, and “Ask users, no deadline” waits until the tray starts.'}
    </p>
  );
}

export function MessageDialog({ target, onClose, onBulkResult }: {
  target: EndpointTarget | null;
  onClose: () => void;
  onBulkResult?: (title: string, data: BulkResultDto) => void;
}) {
  const jobToast = useJobToast();
  const presets = useApi<UserMessagePresetDto[]>(target ? '/user-messages' : null, undefined, { staleTime: 3_600_000 });
  const [preset, setPreset] = useState<UserMessagePreset>('SaveYourWork');
  const [at, setAt] = useState('');
  const atId = useId();

  useEffect(() => {
    if (!target) return;
    setPreset('SaveYourWork');
    const soon = new Date(Date.now() + 3_600_000);
    soon.setMinutes(0, 0, 0);
    setAt(toLocalInput(soon));
  }, [target]);

  const send = useApiMutation(
    (req: NotifyRequest) =>
      target?.kind === 'endpoint'
        ? api.post<unknown>(`/endpoints/${target.endpoint.summary.id}/notify`, req)
        : api.post<BulkResultDto>('/endpoints/bulk/notify', { endpointIds: target?.kind === 'bulk' ? target.ids : [], message: req }),
    {
      invalidate: ['/endpoints', '/jobs'],
      onSuccess: (result) => {
        if (target?.kind === 'bulk') onBulkResult?.('Message to users', result as BulkResultDto);
        else jobToast('Message queued.', result);
        onClose();
      },
    },
  );

  const selected = presets.data?.find((p) => p.preset === preset);
  const restartAt = selected?.needsRestartTime ? parseLocalInput(at) : null;
  const timeProblem = selected?.needsRestartTime && (!restartAt || restartAt.getTime() < Date.now()) ? 'Choose the restart time to show.' : null;
  const endpoint = target?.kind === 'endpoint' ? target.endpoint : null;
  const unsupported = endpoint !== null && !endpoint.agentCapabilities.includes(AGENT_CAPABILITIES.notifyUser);

  return (
    <Dialog
      open={target !== null}
      onClose={onClose}
      title={`Send a message to ${targetTitle(target)}`}
      description="Users see a notification from the EasyPatch icon. Only these preset messages can be sent."
      footer={
        <>
          <Button onClick={onClose} disabled={send.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={send.isPending}
            disabled={unsupported || !selected || !!timeProblem}
            onClick={() => send.mutate({ preset, restartAt: restartAt ? restartAt.toISOString() : null })}
            icon={<MessageSquare className="size-4" aria-hidden />}
          >
            Send message
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4 text-sm">
        {unsupported && (
          <Alert tone="danger" title="This agent cannot show messages">
            {endpoint && isLinux(endpoint.summary.platform)
              ? 'Linux agents have no EasyPatch tray, so they cannot show messages to users.'
              : endpoint && isMacOS(endpoint.summary.platform)
                ? 'The macOS agent has no EasyPatch tray, so it cannot show messages to users.'
                : 'Install EasyPatch agent 1.1.0 or later on this endpoint.'}
          </Alert>
        )}
        {target?.kind === 'bulk' && (
          <p className="text-muted">
            Endpoints whose agent cannot show messages (Linux and macOS agents, and agents older than 1.1.0) are skipped and listed in the results.
          </p>
        )}
        {endpoint && !unsupported && <SessionSummary endpoint={endpoint} />}
        {presets.isPending ? (
          <Spinner />
        ) : presets.isError ? (
          <InlineError error={presets.error} />
        ) : (
          <fieldset className="flex flex-col gap-2">
            <legend className="sr-only">Message</legend>
            {presets.data.map((p) => (
              <label
                key={p.preset}
                className={cx(
                  'flex cursor-pointer gap-3 rounded-md border px-3 py-2',
                  p.preset === preset ? 'border-accent bg-accent-soft' : 'border-line hover:bg-hover',
                )}
              >
                <input type="radio" name="preset" className="mt-1" checked={p.preset === preset} onChange={() => setPreset(p.preset)} />
                <span>
                  <span className="block font-medium">{p.title}</span>
                  <span className="block text-xs text-muted">
                    {p.needsRestartTime ? p.body.replace('{time}', restartAt ? restartAt.toLocaleString([], { weekday: 'long', hour: 'numeric', minute: '2-digit' }) : '…') : p.body}
                  </span>
                </span>
              </label>
            ))}
          </fieldset>
        )}
        {selected?.needsRestartTime && (
          <div className="flex flex-col gap-1">
            <label htmlFor={atId} className="text-xs font-medium text-muted">
              Restart time to show (your browser's time zone; users see it in theirs)
            </label>
            <Input id={atId} type="datetime-local" className="w-56" value={at} onChange={(e) => setAt(e.target.value)} />
            {timeProblem && <p className="text-xs text-danger">{timeProblem}</p>}
            <p className="text-xs text-muted">This only tells users; schedule the restart itself with Restart….</p>
          </div>
        )}
        {duplicateMessage(send.error) ? <Alert tone="warn">This message is already queued for the endpoint.</Alert> : <InlineError error={send.error} />}
      </div>
    </Dialog>
  );
}
