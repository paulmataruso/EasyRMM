import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Save } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation, usePolicy } from '../../api/hooks';
import type { PolicyRequest, ServerInfoDto, ServerSettings, VulnerabilityFeedDto } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { PolicyEditor } from '../../components/PolicyEditor';
import { useToast } from '../../components/Toast';
import { Alert, Badge, Button, Card, ErrorState, InlineError, Input, KeyValueList, Mono, PageHeader, Spinner, TableWrap, Tabs, TextField } from '../../components/ui';
import { formatDateTime, formatNumber, formatRelative } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';
import { AlertRulesTab } from './AlertRulesTab';
import { ApiTokensTab } from './ApiTokensTab';
import { AuditTab } from './AuditTab';
import { LifecycleTab } from './LifecycleTab';
import { NotificationsTab } from './NotificationsTab';
import { SsoTab } from './SsoTab';
import { TagsTab } from './TagsTab';
import { UsersTab } from './UsersTab';

export function SettingsPage() {
  const url = useUrlState();
  const { isSuperAdmin, canOperate } = useAuth();
  const tab = url.get('tab', 'policy');
  return (
    <>
      <PageHeader title="Settings" subtitle="Global policy, tags, alerts and notifications, server behavior, users, OS lifecycle data and the audit log." />
      <Tabs
        active={tab}
        onChange={(t) => url.set({ tab: t === 'policy' ? null : t, action: null, userId: null, from: null, to: null, organizationId: null })}
        tabs={[
          { id: 'policy', label: 'Global policy' },
          { id: 'tags', label: 'Tags' },
          { id: 'alert-rules', label: 'Alert rules', hidden: !isSuperAdmin },
          { id: 'notifications', label: 'Notifications', hidden: !isSuperAdmin },
          { id: 'server', label: 'Server settings' },
          { id: 'users', label: 'Users', hidden: !isSuperAdmin },
          { id: 'api-tokens', label: 'API tokens', hidden: !isSuperAdmin },
          { id: 'sso', label: 'Single sign-on', hidden: !isSuperAdmin },
          { id: 'lifecycle', label: 'OS lifecycle' },
          { id: 'audit', label: 'Audit log', hidden: !canOperate },
        ]}
      />
      {tab === 'policy' && <GlobalPolicyTab />}
      {tab === 'tags' && <TagsTab />}
      {tab === 'alert-rules' && isSuperAdmin && <AlertRulesTab />}
      {tab === 'notifications' && isSuperAdmin && <NotificationsTab />}
      {tab === 'server' && <ServerSettingsTab />}
      {tab === 'users' && isSuperAdmin && <UsersTab />}
      {tab === 'api-tokens' && isSuperAdmin && <ApiTokensTab />}
      {tab === 'sso' && isSuperAdmin && <SsoTab />}
      {tab === 'lifecycle' && <LifecycleTab />}
      {tab === 'audit' && canOperate && <AuditTab />}
    </>
  );
}

function GlobalPolicyTab() {
  const { isSuperAdmin } = useAuth();
  const toast = useToast();
  const policy = usePolicy('/policies/global');
  const save = useApiMutation((req: PolicyRequest) => api.put('/policies/global', req), {
    invalidate: ['/policies', '/endpoints', '/organizations', '/sites'],
    onSuccess: () => toast.success('Global policy saved. Endpoints pick up the change at their next check-in.'),
  });
  if (policy.isPending) return <Spinner />;
  if (policy.isError) return <ErrorState error={policy.error} onRetry={() => void policy.refetch()} />;
  return (
    <>
      {!isSuperAdmin && <Alert tone="info" className="mb-4">Only super administrators can change the global policy.</Alert>}
      <PolicyEditor scope="Global" policy={policy.data} readOnly={!isSuperAdmin} saving={save.isPending} error={save.error} onSave={(req) => save.mutate(req)} />
    </>
  );
}

interface SettingSpec {
  key: keyof ServerSettings;
  label: string;
  unit?: string;
  hint: string;
  min?: number;
  max?: number;
}

const GROUPS: { title: string; fields: SettingSpec[] }[] = [
  {
    title: 'Jobs',
    fields: [
      { key: 'globalMaxConcurrentInstalls', label: 'Max concurrent installations (all endpoints)', unit: 'endpoints', hint: 'Installation jobs beyond this limit wait in the queue.', min: 1 },
      { key: 'jobDefaultExpiryHours', label: 'Job expiry', unit: 'hours', hint: 'Queued jobs not picked up within this time expire.', min: 1 },
      { key: 'runningJobTimeoutHours', label: 'Running job timeout', unit: 'hours', hint: 'Jobs without progress for this long are marked failed (a late result still wins).', min: 1 },
      { key: 'waitingForRebootExpiryDays', label: 'Waiting-for-restart expiry', unit: 'days', hint: 'Jobs waiting for a restart that never happens expire after this.', min: 1 },
      { key: 'deliveryLeaseMinutes', label: 'Delivery lease', unit: 'minutes', hint: 'A delivered job not acknowledged in this time is delivered again.', min: 1 },
      { key: 'maxDeliveryAttempts', label: 'Max delivery attempts', unit: 'attempts', hint: 'After this many unacknowledged deliveries the job fails.', min: 1 },
    ],
  },
  {
    title: 'Agents',
    fields: [
      { key: 'offlineThresholdMinutes', label: 'Offline after', unit: 'minutes', hint: 'Endpoints without a check-in for this long are shown offline.', min: 1 },
      { key: 'credentialLifetimeDays', label: 'Agent credential lifetime', unit: 'days', hint: 'Agents rotate their key before it expires.', min: 1 },
      { key: 'credentialRotateBeforeDays', label: 'Rotate credentials before expiry', unit: 'days', hint: 'Agents are asked to rotate when this close to expiry.', min: 1 },
      { key: 'enrollmentRequestExpiryDays', label: 'Pending approval expiry', unit: 'days', hint: 'Unapproved deployment-code requests expire after this.', min: 1 },
    ],
  },
  {
    title: 'Administrator sessions',
    fields: [
      { key: 'sessionIdleMinutes', label: 'Idle timeout', unit: 'minutes', hint: 'Sessions end after this much inactivity.', min: 1 },
      { key: 'sessionAbsoluteHours', label: 'Maximum session length', unit: 'hours', hint: 'Sessions end after this long regardless of activity.', min: 1 },
    ],
  },
  {
    title: 'Data retention',
    fields: [
      { key: 'retentionEventsDays', label: 'Endpoint activity events', unit: 'days', hint: '', min: 1 },
      { key: 'retentionAuditDays', label: 'Audit log and compliance snapshots', unit: 'days', hint: '', min: 1 },
      { key: 'retentionJobsDays', label: 'Finished jobs', unit: 'days', hint: '', min: 1 },
      { key: 'retentionScansDays', label: 'Scan records', unit: 'days', hint: '', min: 1 },
      { key: 'retentionHistoryDays', label: 'Windows Update history', unit: 'days', hint: '', min: 1 },
      { key: 'retentionReportsMonths', label: 'Monthly reports (PDF)', unit: 'months', hint: '', min: 1, max: 120 },
    ],
  },
];

function ServerSettingsTab() {
  const { isSuperAdmin } = useAuth();
  const toast = useToast();
  const settings = useApi<ServerSettings>('/settings');
  const info = useApi<ServerInfoDto>('/server-info', undefined, { staleTime: 60_000 });
  const [form, setForm] = useState<ServerSettings | null>(null);
  useEffect(() => {
    if (settings.data) setForm(settings.data);
  }, [settings.data]);
  const dirty = useMemo(() => !!form && !!settings.data && JSON.stringify(form) !== JSON.stringify(settings.data), [form, settings.data]);
  const save = useApiMutation((s: ServerSettings) => api.put<ServerSettings>('/settings', s), {
    invalidate: ['/settings'],
    onSuccess: () => toast.success('Server settings saved.'),
  });

  if (settings.isPending || !form) return settings.isError ? <ErrorState error={settings.error} onRetry={() => void settings.refetch()} /> : <Spinner />;
  const readOnly = !isSuperAdmin;

  function submit(e: FormEvent) {
    e.preventDefault();
    if (form) save.mutate(form);
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      {readOnly && <Alert tone="info">Only super administrators can change server settings.</Alert>}
      {info.data && (
        <Card title="Server">
          <KeyValueList
            items={[
              ['Version', <Mono key="v">{info.data.version}</Mono>],
              ['Public URL', <Mono key="u">{info.data.publicUrl}</Mono>],
              ['Server time', formatDateTime(info.data.serverTime)],
            ]}
          />
        </Card>
      )}
      <Card title="Security">
        <label className="flex items-start gap-2.5">
          <input
            type="checkbox"
            className="mt-0.5 size-4"
            checked={form.requireMfa}
            disabled={readOnly}
            onChange={(e) => setForm({ ...form, requireMfa: e.target.checked })}
          />
          <span>
            <span className="text-sm font-medium">Require two-factor authentication for every administrator</span>
            <span className="block text-xs text-muted">Users without MFA must enroll at their next sign-in. Strongly recommended.</span>
          </span>
        </label>
        {!form.requireMfa && (
          <Alert tone="warn" className="mt-3">
            Without mandatory MFA, a stolen password is enough to install updates on every managed endpoint.
          </Alert>
        )}
      </Card>
      <Card title="Vulnerability data">
        <label className="flex items-start gap-2.5">
          <input
            type="checkbox"
            className="mt-0.5 size-4"
            checked={form.vulnerabilityFeedsEnabled}
            disabled={readOnly}
            onChange={(e) => setForm({ ...form, vulnerabilityFeedsEnabled: e.target.checked })}
          />
          <span>
            <span className="text-sm font-medium">Download public vulnerability data</span>
            <span className="block text-xs text-muted">
              The worker downloads the CISA Known Exploited Vulnerabilities catalog (every 6 hours), Microsoft security update data (daily) and, while Debian
              endpoints are managed, the Debian Security Tracker (daily). EasyPatch uses them to show which CVEs each update fixes and to flag known-exploited
              ones. Nothing about your endpoints is sent. When turned off, the data already downloaded is kept but no longer refreshed.
            </span>
          </span>
        </label>
        <FeedStatus />
      </Card>
      <Card title="Rollout guard">
        <label className="flex items-start gap-2.5">
          <input
            type="checkbox"
            className="mt-0.5 size-4"
            checked={form.rolloutGuardEnabled}
            disabled={readOnly}
            onChange={(e) => setForm({ ...form, rolloutGuardEnabled: e.target.checked })}
          />
          <span>
            <span className="text-sm font-medium">Hold Windows updates that fail on too many endpoints</span>
            <span className="block text-xs text-muted">
              Every 5 minutes the worker looks at each endpoint's latest installation result per update. When an update failed on at least the number and
              percentage of endpoints below, it is put on hold for every organization: maintenance windows and Install all missing skip it, including jobs already
              queued, and the Update on hold alert opens. Selecting it on an endpoint still installs it. A super administrator releases the hold on the update's
              page; failures from before the release are not counted again. With a shorter rollout delay for a pilot group, failures there stop the update before
              the other endpoints are due.
            </span>
          </span>
        </label>
        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
          {(
            [
              { key: 'rolloutGuardMinFailedEndpoints', label: 'Failed on at least', unit: 'endpoints', min: 1, max: 1000 },
              { key: 'rolloutGuardFailurePercent', label: 'And at least', unit: '% of endpoints that tried to install it', min: 1, max: 100 },
              { key: 'rolloutGuardWindowDays', label: 'Counting installations of the last', unit: 'days', min: 1, max: 90 },
            ] as const
          ).map((f) => (
            <TextField
              key={f.key}
              label={f.label}
              hint={f.unit}
              type="number"
              min={f.min}
              max={f.max}
              required
              disabled={readOnly || !form.rolloutGuardEnabled}
              value={form[f.key]}
              onChange={(e) => setForm({ ...form, [f.key]: Number(e.target.value) })}
            />
          ))}
        </div>
      </Card>
      <Card title="Monthly reports">
        <TextField
          label="Prepared by"
          maxLength={100}
          disabled={readOnly}
          placeholder="Your company name"
          hint="Shown on the title page of monthly compliance reports, e.g. your MSP's name. Leave empty to leave it out."
          value={form.reportBrandName ?? ''}
          onChange={(e) => setForm({ ...form, reportBrandName: e.target.value.trim() ? e.target.value : null })}
        />
      </Card>
      {GROUPS.map((g) => (
        <Card key={g.title} title={g.title}>
          <div className="grid grid-cols-1 gap-x-6 gap-y-4 md:grid-cols-2">
            {g.fields.map((f) => (
              <div key={f.key} className="flex flex-col gap-1">
                <label htmlFor={`setting-${f.key}`} className="text-sm font-medium">
                  {f.label}
                </label>
                <div className="flex items-center gap-2">
                  <Input
                    id={`setting-${f.key}`}
                    type="number"
                    min={f.min}
                    max={f.max}
                    step={1}
                    className="max-w-36"
                    disabled={readOnly}
                    value={String(form[f.key])}
                    onChange={(e) => setForm({ ...form, [f.key]: e.target.value === '' ? 0 : Number(e.target.value) })}
                    required
                  />
                  {f.unit && <span className="text-xs text-muted">{f.unit}</span>}
                </div>
                {f.hint && <p className="text-xs text-muted">{f.hint}</p>}
              </div>
            ))}
          </div>
        </Card>
      ))}
      <InlineError error={save.error} />
      {!readOnly && (
        <div className="sticky bottom-0 flex justify-end gap-2 border-t border-line bg-canvas/95 py-3">
          <Button onClick={() => setForm(settings.data ?? null)} disabled={!dirty}>
            Discard changes
          </Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!dirty} icon={<Save className="size-4" aria-hidden />}>
            Save settings
          </Button>
        </div>
      )}
    </form>
  );
}

const FEED_LABELS: Record<string, string> = {
  kev: 'CISA Known Exploited Vulnerabilities',
  msrc: 'Microsoft Security Response Center',
  debian: 'Debian Security Tracker',
};

function FeedStatus() {
  const feeds = useApi<VulnerabilityFeedDto[]>('/vulnerability-feeds', undefined, { refetchInterval: 60_000 });
  if (feeds.isPending) return null;
  if (feeds.isError) return <ErrorState error={feeds.error} onRetry={() => void feeds.refetch()} />;
  if (feeds.data.length === 0) {
    return <p className="mt-3 text-sm text-muted">No feed has been downloaded yet. The worker checks every hour (the first check runs shortly after it starts).</p>;
  }
  return (
    <TableWrap className="mt-3">
      <table className="table-base">
        <thead>
          <tr>
            <th>Feed</th>
            <th>Last update</th>
            <th>Version</th>
            <th className="text-right">Entries</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {feeds.data.map((f) => (
            <tr key={f.name}>
              <td>{FEED_LABELS[f.name] ?? f.name}</td>
              <td className="whitespace-nowrap" title={f.lastSuccessAt ? formatDateTime(f.lastSuccessAt) : undefined}>
                {f.lastSuccessAt ? formatRelative(f.lastSuccessAt) : 'Never'}
              </td>
              <td className="text-muted">{f.version ?? '—'}</td>
              <td className="text-right tabular-nums">{formatNumber(f.itemCount)}</td>
              <td>
                {f.lastError ? (
                  <span className="flex flex-col items-start gap-1">
                    <Badge tone="danger">Failed</Badge>
                    <span className="text-xs text-danger">{f.lastError}</span>
                    {f.lastAttemptAt && <span className="text-xs text-muted">Last attempt {formatRelative(f.lastAttemptAt)}; retried after an hour.</span>}
                  </span>
                ) : f.lastSuccessAt ? (
                  <Badge tone="ok">OK</Badge>
                ) : (
                  <Badge>Pending</Badge>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}
