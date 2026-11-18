import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { ArrowUpCircle, Ban, Download, MessageSquare, MoreHorizontal, PackageX, Pencil, Power, RefreshCw, ScanSearch, Tag as TagIcon, Trash2, WifiOff } from 'lucide-react';
import { ApiError, api } from '../../api/client';
import { useApi, useApiMutation, useSites } from '../../api/hooks';
import { AGENT_CAPABILITIES, ESU_OVERRIDES, type EndpointDetailDto, type EsuOverride, type UpdateEndpointRequest } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { AgentUpdateDialog } from '../../components/AgentUpdateDialog';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
import { InstallUpdatesDialog, jobIdOf } from '../../components/InstallDialog';
import { MessageDialog, RestartDialog } from '../../components/RestartDialogs';
import { ComplianceBadge, EndpointStatusBadge, JobStatusBadge, OnlineBadge, OsSupportBadge, PlatformBadge } from '../../components/StatusBadges';
import { EndpointTagsDialog, TagList } from '../../components/Tags';
import { useToast } from '../../components/Toast';
import {
  Alert,
  Button,
  Card,
  ErrorState,
  Field,
  InlineError,
  PageHeader,
  ProgressBar,
  Select,
  Spinner,
  StatTile,
  Tabs,
  Textarea,
} from '../../components/ui';
import { describeAgentPackage, formatDateTime, formatRelative, humanize, isLinux, isMacOS, isWindows, MACOS_EXPERIMENTAL, osDetails } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';
import { ActivityTab, EffectivePolicyTab, HistoryTab, InstalledTab, JobsTab, OverviewTab, UpdatesTab } from './EndpointTabs';

export function EndpointDetailPage() {
  const { id = '' } = useParams();
  const url = useUrlState();
  const tab = url.get('tab', 'overview');
  const { canOperate, isUnrestricted } = useAuth();
  const [tagsOpen, setTagsOpen] = useState(false);
  const [install, setInstall] = useState<{ mode: 'AllEligible' | 'Selected'; guids?: string[] } | null>(null);
  const [restartOpen, setRestartOpen] = useState(false);
  const endpoint = useApi<EndpointDetailDto>(`/endpoints/${id}`, undefined, {
    // Poll quickly while a job is active so progress is live.
    refetchInterval: (data) => (data?.activeJob ? 5_000 : 30_000),
  });
  const active = endpoint.data?.activeJob;

  if (endpoint.isPending) return <Spinner />;
  if (endpoint.isError) return <ErrorState error={endpoint.error} onRetry={() => void endpoint.refetch()} />;
  const e = endpoint.data;
  const s = e.summary;
  const managed = s.status === 'Active';
  const windows = isWindows(s.platform);
  const details = osDetails(s);

  return (
    <>
      <PageHeader
        breadcrumb={
          <>
            <Link to="/endpoints" className="hover:text-fg">Endpoints</Link>
            {' / '}
            <Link to={`/organizations/${s.organizationId}`} className="hover:text-fg">{s.organizationName}</Link>
            {s.siteName && <> · {s.siteName}</>}
          </>
        }
        title={
          <span className="flex flex-wrap items-center gap-2">
            {s.hostname}
            <EndpointStatusBadge status={s.status} />
            <ComplianceBadge status={s.complianceStatus} />
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <OnlineBadge online={s.isOnline} lastSeen={s.lastCheckInAt} />
            <PlatformBadge platform={s.platform} />
            <span>
              {s.operatingSystem ?? 'Unknown OS'}
              {details.length > 0 ? ` (${details.join(', ')})` : ''}
            </span>
            <OsSupportBadge status={s.osSupportStatus} />
            <span>Last check-in {formatRelative(s.lastCheckInAt)}</span>
            {s.currentActivity && <span className="text-accent">{s.currentActivity}</span>}
            {(s.tags?.length ?? 0) > 0 && <TagList tags={s.tags} max={8} />}
            {canOperate && isUnrestricted && (
              <Button size="sm" variant="ghost" icon={<TagIcon className="size-3.5" aria-hidden />} onClick={() => setTagsOpen(true)}>
                {(s.tags?.length ?? 0) > 0 ? 'Edit tags' : 'Add tags'}
              </Button>
            )}
          </span>
        }
        actions={canOperate && managed && <EndpointActions endpoint={e} onInstallAll={() => setInstall({ mode: 'AllEligible' })} onRestart={() => setRestartOpen(true)} />}
      />

      <div className="mb-4 flex flex-col gap-3">
        {isMacOS(s.platform) && (
          <Alert tone="warn" title="Experimental macOS agent">
            {MACOS_EXPERIMENTAL} On Apple silicon it cannot install macOS updates that need a restart (Apple requires a volume owner's password or
            an MDM), and signed-in users are not warned on screen before a restart.
          </Alert>
        )}
        {!managed && (
          <Alert tone="danger" title={`This endpoint is ${s.status.toLowerCase()}`}>
            Its credentials are revoked. The agent can no longer report or receive jobs. Reinstall the agent and enroll again to manage it.
          </Alert>
        )}
        {(e.summary.rebootPending || e.pendingRebootUpdateCount > 0) && (
          <Alert tone="info" title={`Restart pending${e.rebootPendingSince ? ` since ${formatDateTime(e.rebootPendingSince)}` : ''}`}>
            <RestartDetails endpoint={e} windows={windows} />
            <p className="mt-2">
              <Power className="mr-1 inline size-3.5" aria-hidden />
              EasyPatch restarts an endpoint only when you ask it to, or on a restart schedule set in policy. The agent reports the new state after the restart.
            </p>
            {canOperate && managed && (
              <Button size="sm" className="mt-2" icon={<Power className="size-3.5" aria-hidden />} onClick={() => setRestartOpen(true)}>
                Restart…
              </Button>
            )}
          </Alert>
        )}
        {managed && !s.isOnline && (
          <Alert tone="warn" title="Endpoint offline">
            <WifiOff className="mr-1 inline size-3.5" aria-hidden />
            No check-in since {formatDateTime(s.lastCheckInAt)}. New jobs stay queued until it reconnects or they expire.
          </Alert>
        )}
        {active && <ActiveJobCard job={active} />}
      </div>

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        <StatTile
          label="Missing (required)"
          value={s.missingRequiredCount}
          tone={s.missingRequiredCount ? 'warn' : 'ok'}
          hint={`${s.missingTotalCount} missing in total${s.missingDeferredCount > 0 ? `, ${s.missingDeferredCount} in rollout delay` : ''}`}
        />
        <StatTile label="Failed" value={s.failedCount} tone={s.failedCount ? 'danger' : undefined} />
        <StatTile label="Installed" value={e.installedCount} />
        <StatTile label="Pending restart" value={e.pendingRebootUpdateCount} tone={e.pendingRebootUpdateCount ? 'info' : undefined} />
        <StatTile label="Last scan" value={<span className="text-base">{formatRelative(s.lastScanAt)}</span>} hint={e.lastScanError ? <span className="text-danger">Last attempt failed</span> : undefined} />
        <StatTile
          label="Agent"
          value={<span className="font-mono text-base">{s.agentVersion ?? '—'}</span>}
          tone={s.agentOutdated ? 'warn' : undefined}
          hint={agentHint(e)}
        />
      </div>

      <Tabs
        active={tab}
        onChange={(t) => url.set({ tab: t === 'overview' ? null : t, state: null, category: null })}
        tabs={[
          { id: 'overview', label: 'Overview' },
          { id: 'updates', label: 'Updates', count: s.missingTotalCount + s.failedCount },
          { id: 'installed', label: 'Installed' },
          { id: 'history', label: 'Update history' },
          { id: 'jobs', label: 'Jobs' },
          { id: 'activity', label: 'Activity' },
          { id: 'policy', label: e.hasOwnPolicy ? 'Policy (endpoint override)' : 'Policy' },
        ]}
      />
      {tab === 'overview' && <OverviewTab endpoint={e} />}
      {tab === 'updates' && <UpdatesTab endpoint={e} onInstallSelected={(guids) => setInstall({ mode: 'Selected', guids })} onInstallAll={() => setInstall({ mode: 'AllEligible' })} />}
      {tab === 'installed' && <InstalledTab endpoint={e} />}
      {tab === 'history' && <HistoryTab endpointId={e.summary.id} platform={s.platform} />}
      {tab === 'jobs' && <JobsTab endpointId={e.summary.id} />}
      {tab === 'activity' && <ActivityTab endpointId={e.summary.id} />}
      {tab === 'policy' && <EffectivePolicyTab endpoint={e} />}

      <InstallUpdatesDialog
        endpointId={s.id}
        hostname={s.hostname}
        mode={install?.mode ?? 'AllEligible'}
        updateGuids={install?.guids}
        open={install !== null}
        onClose={() => setInstall(null)}
      />
      <RestartDialog target={restartOpen ? { kind: 'endpoint', endpoint: e } : null} onClose={() => setRestartOpen(false)} />
      <EndpointTagsDialog open={tagsOpen} onClose={() => setTagsOpen(false)} endpointId={s.id} hostname={s.hostname} current={s.tags ?? []}
        siteName={s.siteName} organizationName={s.organizationName} />
    </>
  );
}

/** "Updates automatically", "1.3.0 available", or why the agent cannot update itself. */
function agentHint(e: EndpointDetailDto): ReactNode {
  const u = e.agentUpdate;
  const pkg = u?.packageFormat ? describeAgentPackage(u.packageFormat) : isWindows(e.summary.platform) ? 'MSI' : 'package';
  if (!u?.supported) return e.summary.agentOutdated ? `Newer version available (install the ${pkg} once)` : undefined;
  if (u.availableVersion) return u.automaticUpdates ? `Updating to ${u.availableVersion} automatically` : `${u.availableVersion} available`;
  if (u.code === 'agent_up_to_date') return u.automaticUpdates ? 'Up to date, updates automatically' : 'Up to date';
  return <span className="text-warn" title={u.message ?? undefined}>Update not possible</span>;
}

function ActiveJobCard({ job }: { job: NonNullable<EndpointDetailDto['activeJob']> }) {
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-3">
        <JobStatusBadge status={job.status} />
        <Link to={`/jobs/${job.id}`} className="font-medium hover:text-accent">
          {humanize(job.type)}
        </Link>
        <span className="text-sm text-muted">
          requested by {job.requestedBy} {formatRelative(job.createdAt)}
        </span>
        <span className="flex-1" />
        {job.itemCount > 0 && (
          <span className="text-sm text-muted">
            {job.succeededCount} of {job.itemCount} installed{job.failedCount ? `, ${job.failedCount} failed` : ''}
          </span>
        )}
      </div>
      {(job.status === 'Running' || job.progressPercent !== null) && (
        <div className="mt-3 flex items-center gap-3">
          <ProgressBar value={job.progressPercent} label="Job progress" />
          <span className="w-10 text-right text-xs tabular-nums">{job.progressPercent ?? 0}%</span>
        </div>
      )}
      {(job.phase || job.progressMessage) && (
        <p className="mt-2 text-sm text-muted">
          {job.phase && <span className="font-medium text-fg">{humanize(job.phase)}: </span>}
          {job.progressMessage}
        </p>
      )}
      {job.status === 'Queued' && <p className="mt-2 text-sm text-muted">Waiting for the agent to pick up the job at its next check-in.</p>}
    </Card>
  );
}

function EndpointActions({ endpoint, onInstallAll, onRestart }: { endpoint: EndpointDetailDto; onInstallAll: () => void; onRestart: () => void }) {
  const s = endpoint.summary;
  const toast = useToast();
  const navigate = useNavigate();
  const [menu, setMenu] = useState(false);
  const [dialog, setDialog] = useState<'edit' | 'revoke' | 'delete' | 'message' | 'agent-update' | 'uninstall' | null>(null);
  const canNotify = endpoint.agentCapabilities.includes(AGENT_CAPABILITIES.notifyUser);
  const notifyHint = canNotify
    ? undefined
    : isLinux(s.platform)
      ? 'Linux agents have no EasyPatch tray, so they cannot show messages to users.'
      : isMacOS(s.platform)
        ? 'The macOS agent has no EasyPatch tray, so it cannot show messages to users.'
        : 'This agent cannot show messages. Install EasyPatch agent 1.1.0 or later.';
  const canUninstall = endpoint.agentCapabilities.includes(AGENT_CAPABILITIES.uninstall);
  const uninstallHint = canUninstall
    ? undefined
    : 'This agent cannot uninstall itself. Update it to 1.6.0 or later, or uninstall it on the computer.';

  const queueJob = useApiMutation((kind: 'scan' | 'inventory-refresh') => api.post<unknown>(`/endpoints/${s.id}/${kind}`), {
    invalidate: [`/endpoints/${s.id}`, '/jobs'],
    onSuccess: (result, kind) => {
      const jobId = jobIdOf(result);
      toast.success(
        <span>
          {kind === 'scan' ? 'Update scan' : 'Inventory refresh'} queued.{' '}
          {jobId && <Link to={`/jobs/${jobId}`} className="text-accent hover:underline">View job</Link>}
        </span>,
      );
    },
  });

  useEffect(() => {
    const err = queueJob.error;
    if (!err) return;
    if (err instanceof ApiError && err.code === 'duplicate_job') {
      const existing = err.extension<string>('existingJobId');
      toast.info(
        <span>
          That job is already queued or running.{' '}
          {existing && <Link to={`/jobs/${existing}`} className="text-accent hover:underline">View job</Link>}
        </span>,
      );
    } else {
      toast.error(err.message);
    }
  }, [queueJob.error, toast]);

  const revoke = useApiMutation(() => api.post(`/endpoints/${s.id}/revoke`, { reason: 'Revoked by administrator' }), {
    invalidate: [`/endpoints`, '/dashboard'],
    onSuccess: () => {
      toast.success('Endpoint credentials revoked.');
      setDialog(null);
    },
  });
  const uninstall = useApiMutation(() => api.post<unknown>(`/endpoints/${s.id}/uninstall-agent`), {
    invalidate: [`/endpoints/${s.id}`, '/jobs'],
    onSuccess: (result) => {
      const jobId = jobIdOf(result);
      toast.success(
        <span>
          Agent uninstall queued.{' '}
          {jobId && <Link to={`/jobs/${jobId}`} className="text-accent hover:underline">View job</Link>}
        </span>,
      );
      setDialog(null);
    },
  });
  const remove = useApiMutation(() => api.del(`/endpoints/${s.id}`), {
    invalidate: ['/endpoints', '/dashboard', '/organizations'],
    onSuccess: () => {
      toast.success(`${s.hostname} deleted.`);
      navigate('/endpoints', { replace: true });
    },
  });

  return (
    <>
      <Button variant="primary" icon={<Download className="size-4" aria-hidden />} onClick={onInstallAll}>
        Install All Missing Updates
      </Button>
      <Button icon={<ScanSearch className="size-4" aria-hidden />} loading={queueJob.isPending && queueJob.variables === 'scan'} onClick={() => queueJob.mutate('scan')}>
        Scan now
      </Button>
      <Button icon={<Power className="size-4" aria-hidden />} onClick={onRestart}>
        Restart…
      </Button>
      <div className="relative">
        <Button aria-haspopup="menu" aria-expanded={menu} onClick={() => setMenu((m) => !m)} icon={<MoreHorizontal className="size-4" aria-hidden />}>
          More
        </Button>
        {menu && (
          <>
            <div className="fixed inset-0 z-10" onClick={() => setMenu(false)} aria-hidden />
            <div role="menu" className="absolute right-0 z-20 mt-1 w-56 rounded-md border border-line bg-surface py-1 shadow-lg"
              onKeyDown={(e) => e.key === 'Escape' && setMenu(false)}>
              <MenuItem icon={<MessageSquare className="size-4" aria-hidden />} disabled={!canNotify} hint={notifyHint} onClick={() => { setMenu(false); setDialog('message'); }}>
                Send message to users…
              </MenuItem>
              <MenuItem icon={<RefreshCw className="size-4" aria-hidden />} onClick={() => { setMenu(false); queueJob.mutate('inventory-refresh'); }}>
                Refresh inventory
              </MenuItem>
              <MenuItem icon={<ArrowUpCircle className="size-4" aria-hidden />} onClick={() => { setMenu(false); setDialog('agent-update'); }}>
                Update agent…
              </MenuItem>
              <MenuItem icon={<Pencil className="size-4" aria-hidden />} onClick={() => { setMenu(false); setDialog('edit'); }}>
                {isMacOS(s.platform) ? 'Edit site and notes' : 'Edit site, notes, ESU'}
              </MenuItem>
              <MenuItem icon={<PackageX className="size-4" aria-hidden />} danger disabled={!canUninstall} hint={uninstallHint}
                onClick={() => { setMenu(false); setDialog('uninstall'); }}>
                Uninstall agent…
              </MenuItem>
              <MenuItem icon={<Ban className="size-4" aria-hidden />} danger onClick={() => { setMenu(false); setDialog('revoke'); }}>
                Revoke credentials
              </MenuItem>
              <MenuItem icon={<Trash2 className="size-4" aria-hidden />} danger onClick={() => { setMenu(false); setDialog('delete'); }}>
                Delete endpoint
              </MenuItem>
            </div>
          </>
        )}
      </div>
      <EditEndpointDialog endpoint={endpoint} open={dialog === 'edit'} onClose={() => setDialog(null)} />
      <MessageDialog target={dialog === 'message' ? { kind: 'endpoint', endpoint } : null} onClose={() => setDialog(null)} />
      <AgentUpdateDialog target={dialog === 'agent-update' ? { kind: 'endpoint', endpoint } : null} onClose={() => setDialog(null)} />
      <ConfirmDialog
        open={dialog === 'uninstall'}
        onClose={() => setDialog(null)}
        onConfirm={() => uninstall.mutate(undefined)}
        loading={uninstall.isPending}
        error={uninstall.error}
        tone="danger"
        title={`Uninstall the agent from ${s.hostname}?`}
        confirmLabel="Uninstall agent"
        confirmText={s.hostname}
      >
        <p>
          The agent removes itself the next time it checks in, after any job it is running.{' '}
          {isLinux(s.platform)
            ? 'It removes the easypatch-agent package, which unenrolls it.'
            : isMacOS(s.platform)
              ? 'It unenrolls and removes the agent and its launchd daemon from the Mac.'
              : 'It runs its uninstaller, which restores the Windows Update settings EasyPatch changed, unenrolls it and removes the program.'}{' '}
          The endpoint then shows as decommissioned with its history kept; delete it afterwards if you no longer need the record.
        </p>
        <p className="mt-2">
          Queued jobs for this endpoint are cancelled. If the endpoint stays offline, the uninstall waits until the job expires. To manage the computer again,
          install and enroll the agent again.
        </p>
      </ConfirmDialog>
      <ConfirmDialog
        open={dialog === 'revoke'}
        onClose={() => setDialog(null)}
        onConfirm={() => revoke.mutate(undefined)}
        loading={revoke.isPending}
        error={revoke.error}
        tone="danger"
        title={`Revoke ${s.hostname}?`}
        confirmLabel="Revoke credentials"
      >
        The agent's credentials stop working immediately. The endpoint keeps its history but can no longer report or receive jobs. To manage it again, reinstall
        and re-enroll the agent.
      </ConfirmDialog>
      <ConfirmDialog
        open={dialog === 'delete'}
        onClose={() => setDialog(null)}
        onConfirm={() => remove.mutate(undefined)}
        loading={remove.isPending}
        error={remove.error}
        tone="danger"
        title={`Delete ${s.hostname}?`}
        confirmLabel="Delete endpoint"
        confirmText={s.hostname}
      >
        The endpoint record, its update state, jobs and history are deleted and its credentials are revoked. The agent remains installed on the device until you
        uninstall it.
      </ConfirmDialog>
    </>
  );
}

function MenuItem({ children, icon, onClick, danger, disabled, hint }: {
  children: string;
  icon: ReactNode;
  onClick: () => void;
  danger?: boolean;
  disabled?: boolean;
  /** Tooltip, e.g. why the item is disabled. */
  hint?: string;
}) {
  return (
    <button
      type="button"
      role="menuitem"
      onClick={onClick}
      disabled={disabled}
      title={hint}
      className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm hover:bg-hover disabled:cursor-not-allowed disabled:opacity-55 disabled:hover:bg-transparent ${danger ? 'text-danger' : 'text-fg'}`}
    >
      {icon}
      {children}
    </button>
  );
}

function EditEndpointDialog({ endpoint, open, onClose }: { endpoint: EndpointDetailDto; open: boolean; onClose: () => void }) {
  const s = endpoint.summary;
  const toast = useToast();
  const sites = useSites(open ? s.organizationId : null);
  const [form, setForm] = useState<UpdateEndpointRequest>({ siteId: s.siteId, notes: endpoint.notes, esuOverride: endpoint.esuOverride });
  useEffect(() => {
    if (open) setForm({ siteId: s.siteId, notes: endpoint.notes, esuOverride: endpoint.esuOverride });
  }, [open, s.siteId, endpoint.notes, endpoint.esuOverride]);

  const save = useApiMutation((req: UpdateEndpointRequest) => api.put(`/endpoints/${s.id}`, req), {
    invalidate: [`/endpoints`],
    onSuccess: () => {
      toast.success('Endpoint updated.');
      onClose();
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate({ ...form, notes: form.notes?.trim() ? form.notes : null });
  }

  return (
    <Dialog open={open} onClose={onClose} title={`Edit ${s.hostname}`}>
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <Field label="Site" htmlFor="ep-site" hint="Moving an endpoint changes which site policy and maintenance window apply.">
          <Select id="ep-site" value={form.siteId ?? ''} onChange={(e) => setForm({ ...form, siteId: e.target.value || null })}>
            <option value="">No site</option>
            {sites.page.items.map((site) => (
              <option key={site.id} value={site.id} disabled={!site.isActive && site.id !== s.siteId}>
                {site.name}
                {!site.isActive ? ' (archived)' : ''}
              </option>
            ))}
          </Select>
        </Field>
        {/* macOS has no extended support programme to record (Apple publishes no lifecycle dates). */}
        {!isMacOS(s.platform) && (
          <Field
            label={isLinux(s.platform) ? 'Extended security maintenance (Ubuntu Pro ESM)' : 'Extended Security Updates (ESU)'}
            htmlFor="ep-esu"
            hint={
              isLinux(s.platform)
                ? `Detected automatically on Ubuntu: ${endpoint.esuLicenseDetected ? 'Ubuntu Pro ESM services enabled' : 'no Ubuntu Pro ESM services found'}. Override only if detection is wrong.`
                : `Detected automatically: ${endpoint.esuLicenseDetected ? 'ESU license found' : 'no ESU license found'}. Override only if detection is wrong.`
            }
          >
            <Select id="ep-esu" value={form.esuOverride ?? 'Auto'} onChange={(e) => setForm({ ...form, esuOverride: e.target.value as EsuOverride })}>
              {ESU_OVERRIDES.map((o) => (
                <option key={o} value={o}>
                  {o === 'Auto' ? 'Automatic detection' : o === 'Enrolled' ? (isLinux(s.platform) ? 'Enrolled in extended support' : 'Enrolled in ESU') : 'Not enrolled'}
                </option>
              ))}
            </Select>
          </Field>
        )}
        <Field label="Notes" htmlFor="ep-notes">
          <Textarea id="ep-notes" value={form.notes ?? ''} maxLength={4000} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
        </Field>
        <InlineError error={save.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending}>
            Save changes
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

const RESTART_SOURCES: Record<string, string> = {
  Installed: 'installed, takes effect after the restart',
  WindowsUpdate: 'Windows Update lists it as waiting for the restart',
  Servicing: 'a pending Windows servicing package',
};

/** What the pending restart is for: the updates waiting for it and anything else Windows has queued. */
function RestartDetails({ endpoint: e, windows }: { endpoint: EndpointDetailDto; windows: boolean }) {
  const r = e.restart;
  const updates = r?.updates ?? [];
  const packages = r?.servicingPackages ?? [];
  const files = r?.fileOperations ?? [];
  const fileCount = r?.fileOperationCount ?? files.length;
  const reasons = e.rebootReasons.length > 0 && (
    <p className="text-xs">
      Reported by {windows ? 'Windows' : 'the operating system'}: {e.rebootReasons.join(', ')}.
    </p>
  );

  return (
    <div className="flex flex-col gap-2">
      {updates.length > 0 ? (
        <div>
          <p className="font-medium">
            {updates.length === 1 ? 'This update is' : `These ${updates.length} updates are`} waiting for the restart:
          </p>
          <ul className="mt-1 flex list-disc flex-col gap-0.5 pl-5">
            {updates.map((u) => {
              const kbs = u.kbNumbers.filter((kb) => !u.title.toUpperCase().includes(kb.toUpperCase()));
              return (
                <li key={`${u.updateGuid ?? ''}-${u.title}`}>
                  {u.updateGuid ? (
                    <Link to={`/updates/${u.updateGuid}`} className="text-accent hover:underline">
                      {u.title}
                    </Link>
                  ) : (
                    u.title
                  )}
                  {kbs.length > 0 && <span> ({kbs.join(', ')})</span>}
                  <span className="text-xs text-muted">
                    {' '}
                    · {RESTART_SOURCES[u.source] ?? u.source}
                    {u.installedAt && `, ${formatDateTime(u.installedAt)}`}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      ) : (
        <p>
          {r?.detailsSupported || !windows
            ? 'No update is waiting for this restart.'
            : 'No installed update is known to be waiting for this restart.'}
        </p>
      )}
      {packages.length > 0 && (
        <div>
          <p className="font-medium">Windows servicing packages waiting for the restart:</p>
          <ul className="mt-1 flex list-disc flex-col gap-0.5 pl-5 font-mono text-xs break-all">
            {packages.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </div>
      )}
      {files.length > 0 && (
        <details open={updates.length === 0}>
          <summary className="cursor-pointer font-medium">
            {fileCount === 1 ? 'One file' : `${fileCount} files`} that Windows will change during the restart
          </summary>
          <p className="mt-1 text-xs">
            Usually left by an installer that had to replace a file that was in use, or that cleans up after itself. The folder shows which program it
            was.
          </p>
          <ul className="mt-1 flex flex-col gap-0.5 font-mono text-xs break-all">
            {files.map((f) => (
              <li key={`${f.action}-${f.path}`}>
                <span className="text-muted">{f.action === 'Delete' ? 'Delete ' : 'Replace '}</span>
                {f.path}
              </li>
            ))}
          </ul>
          {fileCount > files.length && <p className="mt-1 text-xs text-muted">and {fileCount - files.length} more.</p>}
        </details>
      )}
      {reasons}
      {windows && r && !r.detailsSupported && e.summary.rebootPending && (
        <p className="text-xs text-muted">Agent 1.5.3 and later also report which updates and files Windows has queued for the restart.</p>
      )}
    </div>
  );
}
