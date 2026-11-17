import { useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { Ban, CheckCircle2, Download, ExternalLink, EyeOff, History, Pencil, ShieldCheck, Undo2 } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation, useList, usePolicy } from '../../api/hooks';
import {
  AGENT_CAPABILITIES,
  ENDPOINT_UPDATE_STATES,
  UPDATE_CATEGORIES,
  WINDOWS_UPDATE_POLICY_GROUPS,
  type EffectivePolicyDto,
  type PolicyRequest,
  type WindowsUpdatePolicyState,
  type EndpointDetailDto,
  type EndpointEventDto,
  type EndpointUpdateDto,
  type EndpointUpdateState,
  type JobSummaryDto,
  type PolicyScope,
  type TagPolicyLayerDto,
  type UpdateHistoryDto,
} from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { Dialog } from '../../components/Dialog';
import { EnumSelect } from '../../components/Filters';
import { JobTable } from '../../components/JobTable';
import { PackageFacts } from '../../components/PackageInfo';
import { PolicyEditor, resolveInherited } from '../../components/PolicyEditor';
import { RemoveUpdateDialog, type RemovableUpdate } from '../../components/RemoveUpdateDialog';
import { describeRestartSchedule, describeWindowsUpdateGroup, WU_GROUPS } from '../../components/PolicySections';
import { SessionSummary } from '../../components/RestartDialogs';
import { TagChip } from '../../components/Tags';
import { CategoryBadge, CveCount, EventSeverityDot, JobItemStatusBadge, KnownExploitedBadge, SeverityBadge, UpdateStateBadge } from '../../components/StatusBadges';
import { useToast } from '../../components/Toast';
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  EmptyState,
  ErrorState,
  InlineError,
  KeyValueList,
  Mono,
  Pagination,
  Spinner,
  TableWrap,
  TextField,
  Toolbar,
} from '../../components/ui';
import {
  describeKeyProtection,
  formatBytes,
  formatDate,
  formatDateTime,
  formatDays,
  formatDuration,
  formatPackageFormat,
  formatRelative,
  formatVersionChange,
  humanize,
  isLinux,
  isMacOS,
  isWindows,
  jobItemPercent,
} from '../../lib/format';
import { describeApplicationUpdates } from '../../lib/applications';
import { useUrlState } from '../../lib/urlState';

// ---------------------------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------------------------

export function OverviewTab({ endpoint: e }: { endpoint: EndpointDetailDto }) {
  const s = e.summary;
  const linux = isLinux(s.platform);
  const mac = isMacOS(s.platform);
  const macVersion = e.macOS?.osVersion ?? s.osVersion;
  const macBuild = e.macOS?.osBuild ?? s.osBuild;
  const keyProtection = e.linux?.keyProtection ?? e.macOS?.keyProtection ?? null;
  const yesNo = (v: boolean | null) => (v === null ? '—' : v ? 'Yes' : 'No');
  const diskLow = e.systemDriveFreeBytes !== null && e.systemDriveFreeBytes < 10 * 1024 ** 3;
  const lastScanItems: [ReactNode, ReactNode][] = [
    ['Last scan', s.lastScanAt ? `${formatDateTime(s.lastScanAt)} (${formatRelative(s.lastScanAt)})` : 'Never'],
    ['Last scan attempt', formatDateTime(e.lastScanAttemptAt)],
  ];
  const supportStatus: [ReactNode, ReactNode] = [
    'Support status',
    <span className="flex flex-wrap items-center gap-2">
      {humanize(s.osSupportStatus)}
      {e.osEndOfServicing && <span className="text-muted">end of servicing {formatDate(e.osEndOfServicing)}</span>}
    </span>,
  ];
  const esuOverride = e.esuOverride !== 'Auto' ? ` (override: ${humanize(e.esuOverride)})` : '';
  const lastBoot: [ReactNode, ReactNode] = ['Last boot', e.lastBootAt ? `${formatDateTime(e.lastBootAt)} (${formatRelative(e.lastBootAt)})` : null];

  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
      <Card title="Operating system">
        <KeyValueList
          items={
            mac
              ? [
                  ['Operating system', s.operatingSystem],
                  ['Version / build', [macVersion, macBuild && `build ${macBuild}`].filter(Boolean).join(' · ') || null],
                  ['Darwin kernel', e.macOS?.kernelVersion],
                  ['Architecture', s.architecture],
                  [
                    'Support status',
                    <span className="flex flex-wrap items-center gap-2">
                      {humanize(s.osSupportStatus)}
                      <span className="text-muted">Apple publishes no end-of-support dates for macOS</span>
                    </span>,
                  ],
                  lastBoot,
                  ['Time zone', e.timeZoneId],
                ]
              : linux
              ? [
                  ['Operating system', s.operatingSystem],
                  ['Distribution', [e.linux?.osId, e.linux?.osVersion ?? s.osVersion].filter(Boolean).join(' ') || null],
                  ['Kernel', e.linux?.kernelVersion ?? s.osBuild],
                  ['Product type', e.osProductType],
                  ['Architecture', s.architecture],
                  supportStatus,
                  ...(e.linux?.osId === 'ubuntu' || e.esuLicenseDetected || e.esuOverride !== 'Auto'
                    ? [['Ubuntu Pro (ESM)', `${e.esuLicenseDetected ? 'ESM services enabled' : 'Not detected'}${esuOverride}`] as [ReactNode, ReactNode]]
                    : []),
                  lastBoot,
                  ['Time zone', e.timeZoneId],
                ]
              : [
                  ['Operating system', s.operatingSystem],
                  ['Edition', e.osEdition],
                  ['Version / build', [s.osVersion, s.osBuild && `build ${s.osBuild}`].filter(Boolean).join(' · ') || null],
                  ['Product type', e.osProductType],
                  ['Architecture', s.architecture],
                  ['Installed', formatDate(e.osInstallDate)],
                  supportStatus,
                  ['ESU', `${e.esuLicenseDetected ? 'License detected' : 'No license detected'}${esuOverride}`],
                  lastBoot,
                  ['Time zone', e.timeZoneId],
                ]
          }
        />
        {s.osSupportStatus === 'Unsupported' && (
          <Alert tone="danger" className="mt-4" title="Operating system out of support">
            {linux
              ? 'This release no longer receives security updates from its vendor. Upgrade it to a supported release.'
              : 'This version no longer receives security updates from Microsoft. Upgrade it or enroll it in Extended Security Updates.'}
          </Alert>
        )}
      </Card>

      {linux ? (
        <PackageManagerCard endpoint={e} lastScanItems={lastScanItems} />
      ) : mac ? (
        <SoftwareUpdateCard endpoint={e} lastScanItems={lastScanItems} />
      ) : (
        <WindowsUpdateCard endpoint={e} lastScanItems={lastScanItems} />
      )}
      {e.applications && (e.applications.enabled || e.applications.lastCheckAt || e.applications.wingetSetupError) && (
        <ApplicationUpdatesCard status={e.applications} />
      )}

      <Card title="Hardware">
        <KeyValueList
          items={[
            ['Manufacturer / model', [e.manufacturer, e.model].filter(Boolean).join(' ') || null],
            ['Serial number', e.serialNumber],
            ['Virtual machine', yesNo(e.isVirtualMachine)],
            ['Processor', e.processorName],
            ['Memory', formatBytes(e.totalMemoryBytes)],
            [
              linux ? 'Root file system' : mac ? 'Startup volume' : 'System drive',
              e.systemDriveTotalBytes !== null ? (
                <span className={diskLow ? 'text-warn' : undefined}>
                  {formatBytes(e.systemDriveFreeBytes)} free of {formatBytes(e.systemDriveTotalBytes)}
                  {diskLow && (linux || mac ? ' — low' : ' — low; cumulative updates may need 10 GB or more')}
                </span>
              ) : null,
            ],
            ['Domain', e.dnsDomain ? `${e.dnsDomain}${e.domainJoined ? ' (joined)' : ''}` : e.domainJoined === false ? 'Workgroup' : null],
            ['Last seen IP', s.lastSeenIp],
            ['Inventory updated', formatDateTime(e.lastInventoryAt)],
          ]}
        />
      </Card>

      <Card title="Agent and enrollment">
        <KeyValueList
          items={[
            ['Agent version', <span className="flex items-center gap-2"><Mono>{s.agentVersion ?? '—'}</Mono>{s.agentOutdated && <Badge tone="warn">update available</Badge>}</span>],
            ...(e.agentUpdate?.packageFormat
              ? [['Agent package', `${formatPackageFormat(e.agentUpdate.packageFormat)}${e.agentUpdate.architecture ? ` (${e.agentUpdate.architecture})` : ''}`] as [ReactNode, ReactNode]]
              : []),
            ['Agent installed', formatDateTime(e.agentInstalledAt)],
            ['Enrolled', formatDateTime(e.enrolledAt)],
            ['Last check-in', s.lastCheckInAt ? `${formatDateTime(s.lastCheckInAt)} (${formatRelative(s.lastCheckInAt)})` : 'Never'],
            ['Signed-in users', <SessionSummary endpoint={e} />],
            ...(linux || mac ? [['Key protection', describeKeyProtection(keyProtection)] as [ReactNode, ReactNode]] : []),
            ['Compliance evaluated', formatDateTime(e.complianceEvaluatedAt)],
            ['Notes', e.notes ? <span className="whitespace-pre-wrap">{e.notes}</span> : null],
          ]}
        />
        {linux && e.linux?.keyProtection === 'file-permissions' && (
          <p className="mt-3 text-xs text-muted">
            The agent's private key relies on root-only file permissions: systemd-creds (systemd 250 or later) was not available or did not work.
          </p>
        )}
        {mac && keyProtection === 'file-permissions' && (
          <p className="mt-3 text-xs text-muted">The agent's private key relies on root-only file permissions; the macOS agent does not use the keychain.</p>
        )}
        <h3 className="mt-5 mb-2 text-xs font-semibold tracking-wide text-muted uppercase">Credentials</h3>
        {e.credentials.length === 0 ? (
          <p className="text-sm text-muted">No credentials.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {e.credentials.map((c) => (
              <li key={c.credentialId} className="rounded-md border border-line px-3 py-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Mono>{c.keyFingerprint}</Mono>
                  {c.revokedAt ? <Badge tone="danger">Revoked</Badge> : new Date(c.expiresAt) < new Date() ? <Badge>Expired</Badge> : <Badge tone="ok">Active</Badge>}
                </div>
                <p className="mt-1 text-xs text-muted">
                  {c.credentialId} · created {formatDate(c.createdAt)} · expires {formatDate(c.expiresAt)} · last used {formatRelative(c.lastUsedAt)}
                  {c.revokedReason && ` · ${c.revokedReason}`}
                </p>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function WindowsUpdateCard({ endpoint: e, lastScanItems }: { endpoint: EndpointDetailDto; lastScanItems: [ReactNode, ReactNode][] }) {
  const yesNo = (v: boolean | null) => (v === null ? '—' : v ? 'Yes' : 'No');
  const wsus = e.updateSourceType?.toLowerCase().includes('wsus');
  const auOff = e.windowsUpdateServiceStartMode?.toLowerCase() === 'disabled';
  return (
    <Card title="Windows Update configuration">
      <KeyValueList
        items={[
          ['Update source', e.updateSourceType ? `${e.updateSourceType}${e.updateSourceServer ? ` (${e.updateSourceServer})` : ''}` : null],
          ['Microsoft Update registered', yesNo(e.microsoftUpdateRegistered)],
          ['Automatic Updates', e.automaticUpdatesMode],
          ['WUfB policies', e.wufbPoliciesConfigured ? 'Configured' : 'Not configured'],
          ['Quality update deferral', e.deferQualityUpdatesDays !== null ? `${e.deferQualityUpdatesDays} days` : null],
          ['Feature update deferral', e.deferFeatureUpdatesDays !== null ? `${e.deferFeatureUpdatesDays} days` : null],
          ['Target release version', e.targetReleaseVersion],
          ['Managed by MDM', yesNo(e.managedByMdm)],
          ['Windows Update service', [e.windowsUpdateServiceState, e.windowsUpdateServiceStartMode && `start: ${e.windowsUpdateServiceStartMode}`].filter(Boolean).join(' · ') || null],
          ...lastScanItems,
        ]}
      />
      <div className="mt-4 flex flex-col gap-2">
        {wsus && (
          <Alert tone="warn" title="Managed by WSUS">
            This endpoint gets updates from {e.updateSourceServer ?? 'a WSUS server'}. Only updates approved there are visible and installable. EasyPatch reports this
            configuration and does not change it.
          </Alert>
        )}
        {e.wufbPoliciesConfigured && (
          <Alert tone="warn" title="Windows Update for Business policies detected">
            Deferral or release-targeting policies apply (from EasyPatch policy or another source). Installing through EasyPatch can install updates before the
            deferral period ends.
          </Alert>
        )}
        {auOff && <Alert tone="danger" title="Windows Update service disabled">Scans and installations fail until the service start mode is restored.</Alert>}
        {e.lastScanError && <Alert tone="danger" title="Last scan failed">{e.lastScanError}</Alert>}
      </div>
    </Card>
  );
}

function ApplicationUpdatesCard({ status: a }: { status: NonNullable<EndpointDetailDto['applications']> }) {
  return (
    <Card title="Application updates (winget)">
      <KeyValueList
        items={[
          ['Policy', a.enabled ? `On for ${a.approvedApps} approved application${a.approvedApps === 1 ? '' : 's'}` : 'Off'],
          ['winget', a.wingetVersion ? <Mono>{a.wingetVersion}</Mono> : null],
          ['Last check', a.lastCheckAt ? `${formatDateTime(a.lastCheckAt)} (${formatRelative(a.lastCheckAt)})` : 'Never'],
        ]}
      />
      <div className="mt-4 flex flex-col gap-2">
        {a.enabled && !a.supported && (
          <Alert tone="warn" title="Agent too old">
            Application updates need agent 1.4.0 or newer. Update the agent to check approved applications.
          </Alert>
        )}
        {a.enabled && a.lastError && (
          <Alert tone="danger" title="Last application check failed">
            {a.lastError}
          </Alert>
        )}
        {a.wingetSetupError && (
          <Alert tone="warn" title="The agent could not install winget">
            {a.wingetSetupError}
            {a.serverCopyError && <span className="mt-1 block">The server could not download its own copy: {a.serverCopyError}</span>}
            <span className="mt-1 block text-muted">It tries again later on its own.</span>
          </Alert>
        )}
      </div>
    </Card>
  );
}

function PackageManagerCard({ endpoint: e, lastScanItems }: { endpoint: EndpointDetailDto; lastScanItems: [ReactNode, ReactNode][] }) {
  return (
    <Card title="Package management">
      <KeyValueList
        items={[
          ['Package manager', e.linux?.packageManager ? <Mono>{e.linux.packageManager}</Mono> : null],
          ['Update source', e.updateSourceType ? humanize(e.updateSourceType) : null],
          ['Automatic updates', e.automaticUpdatesMode],
          ...lastScanItems,
        ]}
      />
      {e.lastScanError && (
        <Alert tone="danger" className="mt-4" title="Last scan failed">
          {e.lastScanError}
        </Alert>
      )}
    </Card>
  );
}

/** macOS: Apple's software update service, which the (experimental) agent drives through softwareupdate. */
function SoftwareUpdateCard({ endpoint: e, lastScanItems }: { endpoint: EndpointDetailDto; lastScanItems: [ReactNode, ReactNode][] }) {
  const yesNo = (v: boolean | null) => (v === null ? '—' : v ? 'Yes' : 'No');
  const architecture = e.agentUpdate?.architecture ?? e.summary.architecture ?? '';
  const appleSilicon = /arm/i.test(architecture);
  return (
    <Card title="Software update">
      <KeyValueList
        items={[
          ['Update source', e.updateSourceType ? humanize(e.updateSourceType) : null],
          ['Managed by MDM', yesNo(e.managedByMdm)],
          ['Package manager', e.macOS?.packageManager ? <Mono>{e.macOS.packageManager}</Mono> : null],
          ['Automatic updates', e.automaticUpdatesMode],
          ...lastScanItems,
        ]}
      />
      <div className="mt-4 flex flex-col gap-2">
        {appleSilicon && (
          <Alert tone="warn" title="macOS updates that need a restart cannot be installed on Apple silicon">
            Apple requires a volume owner's password or an MDM to install them, so the agent fails them (macos_owner_required). Install them on the Mac or through
            your MDM. Updates that need no restart install normally.
          </Alert>
        )}
        {e.managedByMdm && (
          <Alert tone="info" title="Managed by MDM">
            An MDM manages this Mac's software updates. Its settings may defer or force updates regardless of what EasyPatch installs.
          </Alert>
        )}
        {e.lastScanError && <Alert tone="danger" title="Last scan failed">{e.lastScanError}</Alert>}
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------------------------
// Updates
// ---------------------------------------------------------------------------------------------

const OUTSTANDING: EndpointUpdateState[] = ['Missing', 'Failed', 'PendingVerification', 'PendingReboot', 'Reoffered', 'Excluded'];
const STATE_ORDER: Record<EndpointUpdateState, number> = {
  Failed: 0,
  Missing: 1,
  PendingVerification: 2,
  PendingReboot: 3,
  Reoffered: 4,
  Excluded: 5,
  Installed: 6,
  Superseded: 7,
  NotApplicable: 8,
};

export function UpdatesTab({ endpoint, onInstallSelected, onInstallAll }: {
  endpoint: EndpointDetailDto;
  onInstallSelected: (guids: string[]) => void;
  onInstallAll: () => void;
}) {
  const id = endpoint.summary.id;
  const { canOperate } = useAuth();
  const toast = useToast();
  const url = useUrlState();
  const state = url.get('state');
  const category = url.get('category');
  const requiredOnly = url.get('requiredOnly') === 'true';
  const list = useList<EndpointUpdateDto>(
    `/endpoints/${id}/updates`,
    { state: state || undefined, category: category || undefined, requiredOnly: requiredOnly || undefined },
    { refetchInterval: endpoint.activeJob ? 5_000 : 30_000, keepPrevious: true },
  );
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [excluding, setExcluding] = useState<EndpointUpdateDto | null>(null);
  const [removing, setRemoving] = useState<RemovableUpdate | null>(null);
  const managed = endpoint.summary.status === 'Active';
  const canRemove = managed && endpoint.agentCapabilities.includes(AGENT_CAPABILITIES.uninstallUpdates);

  const rows = useMemo(() => {
    const items = state ? list.page.items : list.page.items.filter((u) => OUTSTANDING.includes(u.state));
    return [...items].sort((a, b) => STATE_ORDER[a.state] - STATE_ORDER[b.state] || Number(b.isRequired) - Number(a.isRequired) || a.title.localeCompare(b.title));
  }, [list.page.items, state]);
  const installable = (u: EndpointUpdateDto) =>
    (u.state === 'Missing' || u.state === 'Failed' || u.state === 'Reoffered') && !u.isExcluded && !u.activeJob;
  const selectable = rows.filter(installable);
  const allSelected = selectable.length > 0 && selectable.every((u) => selected.has(u.updateGuid));

  const include = useApiMutation((guid: string) => api.del(`/endpoints/${id}/exclusions/${guid}`), {
    invalidate: [`/endpoints/${id}`],
    onSuccess: () => toast.success('Update included again. Compliance is recalculated.'),
  });

  return (
    <>
      <Toolbar>
        <EnumSelect label="State" value={state} onChange={(v) => url.set({ state: v })} options={ENDPOINT_UPDATE_STATES} format={humanize} allLabel="Outstanding" />
        <EnumSelect label="Category" value={category} onChange={(v) => url.set({ category: v })} options={UPDATE_CATEGORIES} format={humanize} />
        <Checkbox label="Required by policy only" checked={requiredOnly} onChange={(e) => url.set({ requiredOnly: e.target.checked })} className="pb-2" />
        <span className="flex-1" />
        {canOperate && managed && (
          <div className="flex gap-2 pb-0.5">
            <Button disabled={selected.size === 0} onClick={() => onInstallSelected([...selected])} icon={<Download className="size-4" aria-hidden />}>
              Install selected{selected.size ? ` (${selected.size})` : ''}
            </Button>
            <Button variant="primary" onClick={onInstallAll} icon={<Download className="size-4" aria-hidden />}>
              Install all missing
            </Button>
          </div>
        )}
      </Toolbar>
      <InlineError error={include.error} />
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState title={state || category ? 'No updates match these filters' : 'No outstanding updates'} icon={<ShieldCheck className="size-8 text-ok" aria-hidden />}>
          {!state && !category && (endpoint.summary.lastScanAt ? `The last scan (${formatRelative(endpoint.summary.lastScanAt)}) found nothing missing.` : 'This endpoint has not reported a scan yet.')}
        </EmptyState>
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                {canOperate && managed && (
                  <th className="w-8">
                    <input
                      type="checkbox"
                      className="size-4"
                      aria-label="Select all installable updates"
                      checked={allSelected}
                      disabled={selectable.length === 0}
                      onChange={() => setSelected(allSelected ? new Set() : new Set(selectable.map((u) => u.updateGuid)))}
                    />
                  </th>
                )}
                <th>Update</th>
                <th>Category</th>
                <th>Severity</th>
                <th>State</th>
                <th className="text-right">Size</th>
                <th>Detected</th>
                {canOperate && <th className="text-right">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((u) => (
                <tr key={u.updateGuid}>
                  {canOperate && managed && (
                    <td>
                      <input
                        type="checkbox"
                        className="size-4"
                        aria-label={`Select ${u.title}`}
                        disabled={!installable(u)}
                        checked={selected.has(u.updateGuid)}
                        onChange={() =>
                          setSelected((s) => {
                            const next = new Set(s);
                            if (next.has(u.updateGuid)) next.delete(u.updateGuid);
                            else next.add(u.updateGuid);
                            return next;
                          })
                        }
                      />
                    </td>
                  )}
                  <td className="min-w-72">
                    <div className="font-medium" title={u.description ?? undefined}>
                      {u.title}
                    </div>
                    <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-muted">
                      {u.package ? (
                        <PackageFacts pkg={u.package} className="contents" />
                      ) : (
                        u.kbNumbers.length > 0 && <span className="font-mono">{u.kbNumbers.join(', ')}</span>
                      )}
                      {u.deferredUntil ? (
                        <span className="text-info" title="Inside the rollout delay set in policy: not required and not installed by scheduled installs until then. Installing manually overrides the delay.">
                          deferred until {formatDate(u.deferredUntil)}
                        </span>
                      ) : (
                        !u.isRequired && <span title="Not installed by policy (category, optional or excluded)">not required by policy</span>
                      )}
                      {u.rebootLikely && <span className="text-info">restart likely</span>}
                      <CveCount cves={u.cveIds} />
                      {u.supportUrl && (
                        <a href={u.supportUrl} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-0.5 text-accent hover:underline">
                          details <ExternalLink className="size-3" aria-hidden />
                        </a>
                      )}
                    </div>
                    {u.state === 'Failed' && (u.errorMessage || u.errorCode) && (
                      <p className="mt-1 text-xs text-danger">
                        {u.errorCode && <span className="font-mono">{u.errorCode} </span>}
                        {u.errorMessage}
                        {u.failedAttempts > 1 && ` (${u.failedAttempts} attempts)`}
                      </p>
                    )}
                    {u.state === 'Reoffered' && u.errorMessage && <p className="mt-1 text-xs text-warn">{u.errorMessage}</p>}
                  </td>
                  <td>
                    <CategoryBadge category={u.category} />
                  </td>
                  <td>
                    <div className="flex flex-col items-start gap-1">
                      <SeverityBadge severity={u.msrcSeverity} />
                      {u.knownExploited && <KnownExploitedBadge dueDate={u.kevDueDate} />}
                    </div>
                  </td>
                  <td>
                    <div className="flex flex-col items-start gap-1">
                      {u.isExcluded ? <Badge icon={<EyeOff className="size-3" aria-hidden />}>Excluded</Badge> : <UpdateStateBadge state={u.state} />}
                      {u.holdReason && (
                        <Link to={`/updates/${u.updateGuid}`} className="hover:opacity-80" title={`On hold: ${u.holdReason} Not installed automatically; installing it here still works.`}>
                          <Badge tone="warn">On hold</Badge>
                        </Link>
                      )}
                      {u.activeJob && (
                        <Link to={`/jobs/${u.activeJob.jobId}`} className="hover:opacity-80" title="Part of an active job">
                          <JobItemStatusBadge
                            status={u.activeJob.itemStatus}
                            percent={jobItemPercent({ status: u.activeJob.itemStatus, ...u.activeJob })}
                            removal={u.activeJob.jobType === 'UninstallUpdate'}
                          />
                        </Link>
                      )}
                    </div>
                  </td>
                  <td className="text-right whitespace-nowrap tabular-nums">{formatBytes(u.sizeBytes)}</td>
                  <td className="whitespace-nowrap text-muted" title={formatDateTime(u.firstDetectedAt)}>
                    {formatRelative(u.firstDetectedAt)}
                  </td>
                  {canOperate && (
                    <td className="text-right">
                      {u.isExcluded ? (
                        <Button size="sm" variant="ghost" icon={<CheckCircle2 className="size-3.5" aria-hidden />} loading={include.isPending && include.variables === u.updateGuid} onClick={() => include.mutate(u.updateGuid)}>
                          Include
                        </Button>
                      ) : u.state === 'Missing' || u.state === 'Failed' ? (
                        <Button size="sm" variant="ghost" icon={<Ban className="size-3.5" aria-hidden />} onClick={() => setExcluding(u)}>
                          Exclude
                        </Button>
                      ) : (
                        u.state === 'PendingReboot' &&
                        canRemove &&
                        !u.package &&
                        !u.activeJob && (
                          <Button size="sm" variant="ghost" icon={<Undo2 className="size-3.5" aria-hidden />} onClick={() => setRemoving(u)}>
                            Remove
                          </Button>
                        )
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <ExcludeDialog endpointId={id} update={excluding} onClose={() => setExcluding(null)} />
      <RemoveUpdateDialog endpointId={id} hostname={endpoint.summary.hostname} update={removing} onClose={() => setRemoving(null)} />
    </>
  );
}

function ExcludeDialog({ endpointId, update, onClose }: { endpointId: string; update: EndpointUpdateDto | null; onClose: () => void }) {
  const toast = useToast();
  const [reason, setReason] = useState('');
  const exclude = useApiMutation((vars: { guid: string; reason: string | null }) => api.post(`/endpoints/${endpointId}/exclusions`, { updateGuid: vars.guid, reason: vars.reason }), {
    invalidate: [`/endpoints/${endpointId}`],
    onSuccess: () => {
      toast.success('Update excluded on this endpoint.');
      setReason('');
      onClose();
    },
  });
  return (
    <Dialog
      open={update !== null}
      onClose={onClose}
      title="Exclude this update on this endpoint?"
      size="sm"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={exclude.isPending} onClick={() => update && exclude.mutate({ guid: update.updateGuid, reason: reason.trim() || null })}>
            Exclude update
          </Button>
        </>
      }
    >
      {update && (
        <div className="flex flex-col gap-3 text-sm">
          <p>
            <strong>{update.title}</strong> will not be installed on this endpoint and no longer counts against its compliance.{' '}
            {update.package
              ? 'The exclusion applies to this package version only; a newer version is reported as a new update.'
              : 'To exclude a KB everywhere, add it to a policy instead.'}
          </p>
          <TextField label="Reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} placeholder="e.g. breaks line-of-business app" />
          <InlineError error={exclude.error} />
        </div>
      )}
    </Dialog>
  );
}

// ---------------------------------------------------------------------------------------------
// Installed, history, jobs, activity, effective policy
// ---------------------------------------------------------------------------------------------

export function InstalledTab({ endpoint }: { endpoint: EndpointDetailDto }) {
  const endpointId = endpoint.summary.id;
  const linux = isLinux(endpoint.summary.platform);
  const mac = isMacOS(endpoint.summary.platform);
  const { canOperate } = useAuth();
  const [search, setSearch] = useState('');
  const [removing, setRemoving] = useState<RemovableUpdate | null>(null);
  const list = useList<EndpointUpdateDto>(`/endpoints/${endpointId}/installed-updates`, undefined, { refetchInterval: 30_000 });
  const managed = endpoint.summary.status === 'Active';
  const canRemove = canOperate && managed && endpoint.agentCapabilities.includes(AGENT_CAPABILITIES.uninstallUpdates);
  const removeHint = canOperate && managed && isWindows(endpoint.summary.platform) && !canRemove ? ' Removing an update needs EasyPatch agent 1.8.0 or later.' : '';
  const items = list.page.items.filter(
    (u) => !search || `${u.title} ${u.kbNumbers.join(' ')} ${u.package?.name ?? ''}`.toLowerCase().includes(search.toLowerCase()),
  );
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  return (
    <>
      <Toolbar>
        <TextField label="Filter" type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder={linux ? 'Title or package' : mac ? 'Title' : 'Title or KB'} className="w-72" />
        <p className="pb-2 text-xs text-muted">
          {linux
            ? 'Package updates the agent reported as available and later found installed appear here. The full list of installed packages is not reported.'
            : mac
              ? 'macOS updates the agent reported as available and later found installed appear here. The Mac’s full update history is not reported.'
              : `Only updates confirmed installed by a Windows Update scan appear here.${removeHint}`}
        </p>
      </Toolbar>
      {items.length === 0 ? (
        <EmptyState title="No installed updates reported" />
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>Update</th>
                {!mac && <th>{linux ? 'Package' : 'KB'}</th>}
                <th>Category</th>
                <th>Installed</th>
                {canRemove && <th className="text-right">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {items.map((u) => (
                <tr key={u.updateGuid}>
                  <td className="min-w-72">
                    {u.title}
                    {u.activeJob && (
                      <Link to={`/jobs/${u.activeJob.jobId}`} className="mt-1 block w-fit hover:opacity-80" title="Part of an active job">
                        <JobItemStatusBadge status={u.activeJob.itemStatus} removal={u.activeJob.jobType === 'UninstallUpdate'} />
                      </Link>
                    )}
                  </td>
                  {!mac && (
                    <td className="text-xs">
                      {u.package ? (
                        <span className="flex flex-col gap-0.5">
                          <span className="font-mono">{u.package.name}</span>
                          <span className="font-mono text-muted">
                            {formatVersionChange(u.package.installedVersion, u.package.version)}
                            {u.package.architecture && ` · ${u.package.architecture}`}
                          </span>
                        </span>
                      ) : (
                        <span className="font-mono whitespace-nowrap">{u.kbNumbers.join(', ') || '—'}</span>
                      )}
                    </td>
                  )}
                  <td>
                    <CategoryBadge category={u.category} />
                  </td>
                  <td className="whitespace-nowrap text-muted">{formatDateTime(u.installedAt ?? u.stateChangedAt)}</td>
                  {canRemove && (
                    <td className="text-right">
                      {!u.package && !u.activeJob && (
                        <Button size="sm" variant="ghost" icon={<Undo2 className="size-3.5" aria-hidden />} onClick={() => setRemoving(u)}>
                          Remove
                        </Button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <RemoveUpdateDialog endpointId={endpointId} hostname={endpoint.summary.hostname} update={removing} onClose={() => setRemoving(null)} />
    </>
  );
}

export function HistoryTab({ endpointId, platform }: { endpointId: string; platform?: string | null }) {
  const [page, setPage] = useState(1);
  const windows = isWindows(platform);
  const list = useList<UpdateHistoryDto>(windows ? `/endpoints/${endpointId}/update-history` : null, { page, pageSize: 100 }, { keepPrevious: true });
  if (!windows) {
    return (
      <EmptyState title="No update history" icon={<History className="size-8" aria-hidden />}>
        {isMacOS(platform)
          ? 'The macOS agent does not report the Mac’s software update history.'
          : 'Linux agents do not report package-manager history.'}{' '}
        Installations made through EasyPatch are listed on the Jobs tab.
      </EmptyState>
    );
  }
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  if (list.page.items.length === 0) return <EmptyState title="No Windows Update history reported yet" />;
  return (
    <>
      <p className="mb-3 text-xs text-muted">History as recorded by Windows Update on the device, including installations made outside EasyPatch.</p>
      <TableWrap>
        <table className="table-base">
          <thead>
            <tr>
              <th>Date</th>
              <th>Update</th>
              <th>Operation</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {list.page.items.map((h) => (
              <tr key={h.id}>
                <td className="whitespace-nowrap text-muted">{formatDateTime(h.date)}</td>
                <td className="min-w-72">
                  {h.title}
                  {h.kbNumber && <span className="ml-2 font-mono text-xs text-muted">{h.kbNumber}</span>}
                </td>
                <td>{humanize(h.operation)}</td>
                <td>
                  <Badge tone={/succeed/i.test(h.result) ? 'ok' : /fail|abort/i.test(h.result) ? 'danger' : 'neutral'}>{humanize(h.result)}</Badge>
                  {h.hResult && (
                    <div className="mt-0.5 text-xs text-muted">
                      <span className="font-mono">{h.hResult}</span>
                      {h.errorDescription && ` ${h.errorDescription}`}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={setPage} />
    </>
  );
}

export function JobsTab({ endpointId }: { endpointId: string }) {
  const [page, setPage] = useState(1);
  const list = useList<JobSummaryDto>(`/endpoints/${endpointId}/jobs`, { page, pageSize: 50 }, { keepPrevious: true, refetchInterval: 10_000 });
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  if (list.page.items.length === 0) return <EmptyState title="No jobs yet">Scans, installations and inventory refreshes for this endpoint appear here.</EmptyState>;
  return (
    <>
      <JobTable jobs={list.page.items} showEndpoint={false} />
      <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={setPage} />
    </>
  );
}

export function ActivityTab({ endpointId }: { endpointId: string }) {
  const [page, setPage] = useState(1);
  const list = useList<EndpointEventDto>(`/endpoints/${endpointId}/events`, { page, pageSize: 100 }, { keepPrevious: true, refetchInterval: 15_000 });
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  if (list.page.items.length === 0) return <EmptyState title="No activity recorded yet" />;
  return (
    <>
      <EventList events={list.page.items} />
      <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={setPage} />
    </>
  );
}

export function EventList({ events, showHostname = false }: { events: EndpointEventDto[]; showHostname?: boolean }) {
  return (
    <ol className="relative flex flex-col rounded-lg border border-line bg-surface">
      {events.map((ev) => (
        <li key={ev.id} className="flex gap-3 border-b border-line px-4 py-2.5 last:border-b-0">
          <span className="pt-1.5">
            <EventSeverityDot severity={ev.severity} />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm">
              <span className="font-medium">{humanize(ev.type)}</span>
              {showHostname && ev.hostname && (
                <>
                  {' · '}
                  <Link to={`/endpoints/${ev.endpointId}`} className="hover:text-accent">
                    {ev.hostname}
                  </Link>
                </>
              )}
              <span className="text-muted"> — {ev.message}</span>
            </p>
            {ev.jobId && (
              <Link to={`/jobs/${ev.jobId}`} className="text-xs text-accent hover:underline">
                View job
              </Link>
            )}
          </div>
          <time className="text-xs whitespace-nowrap text-muted" dateTime={ev.createdAt} title={formatDateTime(ev.createdAt)}>
            {formatRelative(ev.createdAt)}
          </time>
        </li>
      ))}
    </ol>
  );
}

function sourceOf<T>(sources: Record<string, T> | null | undefined, field: string): T | undefined {
  if (!sources) return undefined;
  const pascal = field.charAt(0).toUpperCase() + field.slice(1);
  const camel = field.charAt(0).toLowerCase() + field.slice(1);
  return sources[pascal] ?? sources[camel];
}

function ScopeBadge({ scope, tagName }: { scope: PolicyScope | undefined; tagName?: string }) {
  if (!scope) return null;
  if (scope === 'Tag') {
    return (
      <Badge tone="ok" title="Set by a tag policy">
        Tag{tagName ? `: ${tagName}` : ''}
      </Badge>
    );
  }
  return <Badge tone={scope === 'Endpoint' ? 'warn' : scope === 'Site' ? 'accent' : scope === 'Organization' ? 'info' : 'neutral'}>{scope}</Badge>;
}

function delayText(days: number): string {
  return days > 0 ? `${days} day${days === 1 ? '' : 's'} after release` : 'None';
}

const WU_STATE_TONE: Record<WindowsUpdatePolicyState, 'ok' | 'warn' | 'danger' | 'neutral'> = {
  Applied: 'ok',
  Conflict: 'warn',
  Error: 'danger',
  NotManaged: 'neutral',
};

export function EffectivePolicyTab({ endpoint }: { endpoint: EndpointDetailDto }) {
  const endpointId = endpoint.summary.id;
  const { canOperate } = useAuth();
  const [editing, setEditing] = useState(false);
  const policy = useApi<EffectivePolicyDto>(`/endpoints/${endpointId}/effective-policy`);
  if (policy.isPending) return <Spinner />;
  if (policy.isError) return <ErrorState error={policy.error} onRetry={() => void policy.refetch()} />;
  const p = policy.data;
  const row = (label: string, field: string, value: ReactNode): [ReactNode, ReactNode] => [
    label,
    <span className="flex flex-wrap items-center gap-2">
      {value}
      <ScopeBadge scope={sourceOf(p.sources, field)} tagName={sourceOf(p.sourceTags, field)} />
    </span>,
  ];
  const report = endpoint.windowsUpdatePolicy;
  // Linux and macOS agents have no tray, winget or Windows Update settings.
  const windows = isWindows(endpoint.summary.platform);
  const supportsWu = endpoint.agentCapabilities.includes(AGENT_CAPABILITIES.windowsUpdatePolicy);
  const anyManaged = WINDOWS_UPDATE_POLICY_GROUPS.some((g) => p.windowsUpdate?.[WU_GROUPS[g].key]);
  return (
    <div className="flex flex-col gap-5">
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <p className="flex-1 text-sm">
            {endpoint.hasOwnPolicy
              ? 'This endpoint has its own policy layer, which overrides its tag, site, organization and global policy for the values it sets.'
              : 'This endpoint uses its tag, site, organization and global policy. You can override individual values for this endpoint only.'}
          </p>
          {canOperate && endpoint.summary.status === 'Active' && (
            <Button icon={<Pencil className="size-4" aria-hidden />} onClick={() => setEditing(true)}>
              {endpoint.hasOwnPolicy ? 'Edit endpoint overrides' : 'Override for this endpoint'}
            </Button>
          )}
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <Card title="Installation">
          <KeyValueList
            items={[
              row('Allowed categories', 'allowedCategories', p.allowedCategories.map(humanize).join(', ')),
              row('Include optional updates', 'includeOptional', p.includeOptional ? 'Yes' : 'No'),
              row('Accept license agreements', 'acceptEulas', p.acceptEulas ? 'Yes' : 'No'),
              row(
                'Excluded KBs',
                'excludedKbs',
                <>
                  {p.excludedKbs.length ? <span className="font-mono text-xs">{p.excludedKbs.join(', ')}</span> : 'None'}
                  {!windows && <span className="text-xs text-muted">(Windows updates only)</span>}
                </>,
              ),
              ...(windows
                ? [row('Application updates (winget)', 'applicationUpdates', describeApplicationUpdates(p.applicationUpdates))]
                : []),
              row('Rollout delay: security updates', 'securityInstallDelayDays', delayText(p.securityInstallDelayDays ?? 0)),
              row('Rollout delay: other updates', 'installDelayDays', delayText(p.installDelayDays ?? 0)),
              row(
                'Known-exploited vulnerabilities',
                'knownExploitedSkipsDelay',
                p.knownExploitedSkipsDelay === false ? 'Wait for the rollout delay' : 'Skip the rollout delay',
              ),
              row('Automatic installation', 'autoInstallEnabled', p.autoInstallEnabled ? 'On (inside maintenance window; installing never restarts)' : 'Off'),
              row(
                'Maintenance window',
                'maintenanceWindow',
                p.maintenanceDays && p.maintenanceDays.length > 0
                  ? `${formatDays(p.maintenanceDays)} at ${p.maintenanceStart?.slice(0, 5) ?? '—'} for ${formatDuration(p.maintenanceDurationMinutes)} (${p.timeZone})`
                  : 'None',
              ),
              ...(windows
                ? [
                    row(
                      'Download before the window',
                      'preDownloadHours',
                      (p.preDownloadHours ?? 0) > 0 ? `Up to ${p.preDownloadHours} hours before it opens (with automatic installation)` : 'Off',
                    ),
                  ]
                : []),
            ]}
          />
        </Card>
        <Card title="Restarts and users">
          <KeyValueList
            items={[
              row('Restart schedule', 'restartSchedule', p.restartSchedule ? `${describeRestartSchedule(p.restartSchedule)} (${p.timeZone})` : 'None'),
              ...(windows
                ? [
                    row('EasyPatch icon', 'trayIconEnabled', p.trayIconEnabled ? 'Shown' : 'Hidden (shown only with a message or restart request)'),
                    row('Installation notifications', 'installNotificationsEnabled', p.installNotificationsEnabled ? 'On' : 'Off'),
                  ]
                : []),
              row('Agent updates', 'agentAutoUpdateEnabled', p.agentAutoUpdateEnabled ? 'Automatic' : 'Manual'),
              ['Signed-in users', <SessionSummary endpoint={endpoint} />],
              [
                'Agent features',
                endpoint.agentCapabilities.length > 0 ? (
                  endpoint.agentCapabilities.map(humanize).join(', ')
                ) : (
                  <span className="text-warn">
                    {windows ? 'None: restarts, messages and Windows Update settings need agent 1.1.0 or later' : 'None reported'}
                  </span>
                ),
              ],
            ]}
          />
        </Card>
        {windows && (
          <Card title="Windows Update settings" className="xl:col-span-2">
            {!supportsWu && anyManaged && (
              <Alert tone="warn" className="mb-4">
                This agent does not apply Windows Update settings. Install EasyPatch agent 1.1.0 or later.
              </Alert>
            )}
            {report?.mdmUpdatePoliciesPresent && (
              <Alert tone="info" className="mb-4">
                MDM (for example Intune) update policies are present on this endpoint. Windows may apply those instead of the values below.
              </Alert>
            )}
            <TableWrap>
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Group</th>
                    <th>Effective setting</th>
                    <th>On the endpoint</th>
                  </tr>
                </thead>
                <tbody>
                  {WINDOWS_UPDATE_POLICY_GROUPS.map((group) => {
                    const status = report?.groups.find((g) => g.group === group);
                    const value = p.windowsUpdate?.[WU_GROUPS[group].key] ?? null;
                    return (
                      <tr key={group}>
                        <td className="font-medium whitespace-nowrap">{WU_GROUPS[group].label}</td>
                        <td>
                          <span className="flex flex-wrap items-center gap-2">
                            {describeWindowsUpdateGroup(group, value)}
                            <ScopeBadge scope={sourceOf(p.sources, `WindowsUpdate.${group}`)} />
                          </span>
                        </td>
                        <td>
                          {status ? (
                            <div className="flex flex-col gap-1">
                              <span className="flex flex-wrap items-center gap-2">
                                <Badge tone={WU_STATE_TONE[status.state]}>{humanize(status.state)}</Badge>
                                {status.appliedAt && <span className="text-xs text-muted">since {formatDateTime(status.appliedAt)}</span>}
                              </span>
                              {status.message && <span className="text-xs text-muted">{status.message}</span>}
                              {status.conflictingValues.length > 0 && (
                                <span className="font-mono text-xs text-warn">{status.conflictingValues.join('; ')}</span>
                              )}
                            </div>
                          ) : (
                            <span className="text-xs text-muted">{supportsWu ? 'Not reported yet' : '—'}</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </TableWrap>
            {p.windowsUpdateValues && p.windowsUpdateValues.length > 0 && (
              <details className="mt-4">
                <summary className="cursor-pointer text-sm font-medium">Registry values EasyPatch sets</summary>
                <ul className="mt-2 flex flex-col gap-1 font-mono text-xs">
                  {p.windowsUpdateValues.map((v) => (
                    <li key={`${v.path}\\${v.name}`}>
                      {v.path}\<strong>{v.name}</strong> = {v.value}
                    </li>
                  ))}
                </ul>
              </details>
            )}
            {endpoint.windowsUpdatePolicyReportedAt && (
              <p className="mt-3 text-xs text-muted">Last reported by the agent {formatRelative(endpoint.windowsUpdatePolicyReportedAt)}.</p>
            )}
          </Card>
        )}
        <Card title="Agent schedule and compliance" className="xl:col-span-2">
          <KeyValueList
            items={[
              row('Check-in interval', 'checkInIntervalSeconds', `${p.checkInIntervalSeconds} s`),
              row('Scan interval', 'scanIntervalMinutes', formatDuration(p.scanIntervalMinutes)),
              row('Inventory interval', 'inventoryIntervalMinutes', formatDuration(p.inventoryIntervalMinutes)),
              row('Jitter', 'jitterPercent', `${p.jitterPercent}%`),
              row('Scan stale after', 'scanStaleAfterHours', `${p.scanStaleAfterHours} h`),
              row('Max concurrent installs per site', 'maxConcurrentInstallsPerSite', p.maxConcurrentInstallsPerSite),
            ]}
          />
          <p className="mt-4 text-xs text-muted">The badge shows which policy layer supplied each value (Global, Organization, Site or Endpoint).</p>
        </Card>
      </div>
      <EndpointPolicyDialog endpoint={endpoint} open={editing} onClose={() => setEditing(false)} />
    </div>
  );
}

function EndpointPolicyDialog({ endpoint, open, onClose }: { endpoint: EndpointDetailDto; open: boolean; onClose: () => void }) {
  const s = endpoint.summary;
  const toast = useToast();
  const path = `/endpoints/${s.id}/policy`;
  const global = usePolicy(open ? '/policies/global' : null);
  const org = usePolicy(open ? `/organizations/${s.organizationId}/policy` : null);
  const site = usePolicy(open && s.siteId ? `/sites/${s.siteId}/policy` : null);
  const policy = usePolicy(open ? path : null);
  const tagLayers = useApi<TagPolicyLayerDto[]>(open ? `/endpoints/${s.id}/tag-policies` : null);
  const save = useApiMutation((req: PolicyRequest) => api.put(path, req), {
    invalidate: [path, `/endpoints/${s.id}`],
    onSuccess: () => {
      toast.success('Endpoint policy saved. The agent picks up the change at its next check-in.');
      onClose();
    },
  });
  const reset = useApiMutation(() => api.del(path), {
    invalidate: [path, `/endpoints/${s.id}`],
    onSuccess: () => {
      toast.success('Endpoint overrides removed. Every value is inherited again.');
      onClose();
    },
  });
  const loading = policy.isPending || global.isPending || org.isPending || (!!s.siteId && site.isPending) || tagLayers.isPending;
  const tagPolicies = tagLayers.data ?? [];

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Policy for ${s.hostname}`}
      size="xl"
      description={
        <>
          Overrides the tag, site, organization and global policy for this endpoint only.
          {tagPolicies.length > 0 && (
            <span className="ml-1 inline-flex flex-wrap items-center gap-1">
              Tag policies: {tagPolicies.map((l) => <TagChip key={l.tag.id} tag={l.tag} />)}
            </span>
          )}
        </>
      }
    >
      {open &&
        (loading ? (
          <Spinner />
        ) : policy.isError ? (
          <ErrorState error={policy.error} />
        ) : (
          <PolicyEditor
            scope="Endpoint"
            platform={s.platform}
            policy={policy.data ?? null}
            inherited={resolveInherited([global.data, org.data, site.data, ...tagPolicies.map((l) => l.policy)])}
            readOnly={false}
            saving={save.isPending}
            deleting={reset.isPending}
            error={save.error ?? reset.error}
            onSave={(req) => save.mutate(req)}
            onReset={() => reset.mutate(undefined)}
          />
        ))}
    </Dialog>
  );
}
