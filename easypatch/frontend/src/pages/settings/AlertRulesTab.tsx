import { useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { BellRing, Pencil, Plus, Trash2 } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation, useList, useOrganizations } from '../../api/hooks';
import {
  ALERT_RULE_TYPE_LABELS,
  ALERT_RULE_TYPES,
  ALERT_SEVERITIES,
  type AlertRuleDto,
  type AlertRuleRequest,
  type AlertRuleType,
  type AlertRuleTypeDto,
  type AlertSeverity,
  type NotificationChannelDto,
  type TagDto,
} from '../../api/types';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
import { OrganizationSelect } from '../../components/Filters';
import { TagChip } from '../../components/Tags';
import { useToast } from '../../components/Toast';
import { Alert, Badge, Button, Checkbox, EmptyState, ErrorState, InlineError, SelectField, Spinner, TableWrap, TextField } from '../../components/ui';
import { AlertSeverityBadge } from '../alerts/AlertsPage';

const RULE_HELP: Record<AlertRuleType, string> = {
  EndpointOffline: 'An endpoint has not checked in for longer than the threshold.',
  InstallFailed: 'An endpoint has updates whose last installation attempt failed.',
  SecurityUpdateMissing: 'A required security update is still missing this many days after it became required (after the rollout delay).',
  ScanStale: 'An endpoint has had no successful update scan for too long (see the scan-stale setting of its policy).',
  RestartPending: 'An endpoint has been waiting for a restart for longer than the threshold. EasyPatch never restarts endpoints by itself.',
  EnrollmentPending: 'Computers enrolled with a deployment code are waiting for approval (one alert per organization).',
  OsUnsupported: 'The operating system no longer receives security updates, or support ends within the threshold.',
  KnownExploitedMissing:
    'An endpoint is missing an allowed update that fixes a vulnerability in the CISA Known Exploited Vulnerabilities catalog (attackers are using it).',
  UpdateHeld:
    'An update that endpoints still need is on hold (by the rollout guard or an administrator), so it is not installed automatically (one alert per organization).',
};

function thresholdText(rule: AlertRuleDto): string {
  if (rule.threshold === null || !rule.thresholdUnit) return '—';
  if (rule.type === 'OsUnsupported') return rule.threshold === 0 ? 'When unsupported' : `${rule.threshold} ${rule.thresholdUnit} before end of support`;
  return `${rule.threshold} ${rule.thresholdUnit}`;
}

/** Super administrators only. */
export function AlertRulesTab() {
  const toast = useToast();
  const rules = useList<AlertRuleDto>('/alert-rules');
  const channels = useList<NotificationChannelDto>('/notifications/channels', undefined, { staleTime: 30_000 });
  const tags = useList<TagDto>('/tags', undefined, { staleTime: 30_000 });
  const orgs = useOrganizations(true);
  const [editing, setEditing] = useState<AlertRuleDto | 'new' | null>(null);
  const [deleting, setDeleting] = useState<AlertRuleDto | null>(null);
  const toggle = useApiMutation((r: AlertRuleDto) => api.put<AlertRuleDto>(`/alert-rules/${r.id}`, { ...toRequest(r), enabled: !r.enabled }), {
    invalidate: ['/alert-rules', '/alerts'],
    onSuccess: (r) => toast.success(r.enabled ? `Rule ${r.name} enabled.` : `Rule ${r.name} disabled; its alerts were closed.`),
  });
  const remove = useApiMutation((r: AlertRuleDto) => api.del(`/alert-rules/${r.id}`), {
    invalidate: ['/alert-rules', '/alerts'],
    onSuccess: (_, r) => {
      setDeleting(null);
      toast.success(`Rule ${r.name} deleted.`);
    },
  });
  const channelName = (id: string) => channels.page.items.find((c) => c.id === id)?.name ?? 'Deleted channel';
  const orgName = (id: string) => orgs.page.items.find((o) => o.id === id)?.name ?? 'Organization';
  const noChannels = channels.data !== undefined && channels.page.items.length === 0;

  return (
    <>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <p className="max-w-3xl text-sm text-muted">
          Rules are evaluated every two minutes. An alert opens when a rule matches, stays open while the condition lasts, and resolves after two evaluations
          without a match. Offline endpoints only raise the offline alert. Alerts appear on the <Link to="/alerts" className="text-accent hover:underline">Alerts</Link>{' '}
          page; rules with channels also send notifications.
        </p>
        <Button variant="primary" icon={<Plus className="size-4" aria-hidden />} onClick={() => setEditing('new')}>
          New rule
        </Button>
      </div>
      {noChannels && (
        <Alert tone="info" className="mb-3">
          No notification channels yet: alerts are only shown in the console. Add email or webhook channels on the{' '}
          <Link to="/settings?tab=notifications" className="text-accent hover:underline">
            Notifications
          </Link>{' '}
          tab and select them in the rules.
        </Alert>
      )}
      {rules.isPending ? (
        <Spinner />
      ) : rules.isError ? (
        <ErrorState error={rules.error} onRetry={() => void rules.refetch()} />
      ) : rules.page.items.length === 0 ? (
        <EmptyState title="No alert rules" icon={<BellRing className="size-8" aria-hidden />} />
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Severity</th>
                <th>Threshold</th>
                <th>Applies to</th>
                <th>Notifies</th>
                <th>Open alerts</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.page.items.map((r) => {
                const tag = r.tagId ? tags.page.items.find((t) => t.id === r.tagId) : null;
                return (
                  <tr key={r.id} className={r.enabled ? undefined : 'opacity-60'}>
                    <td>
                      <div className="font-medium">{r.name}</div>
                      <div className="text-xs text-muted">{ALERT_RULE_TYPE_LABELS[r.type]}</div>
                    </td>
                    <td>
                      <AlertSeverityBadge severity={r.severity} />
                    </td>
                    <td className="text-sm">{thresholdText(r)}</td>
                    <td className="text-sm">
                      {r.organizationId ? orgName(r.organizationId) : 'All organizations'}
                      {tag && <TagChip tag={tag} className="ml-1.5" />}
                    </td>
                    <td className="max-w-56 text-sm">
                      {r.channelIds.length === 0 ? (
                        <span className="text-subtle">Console only</span>
                      ) : (
                        <span>{r.channelIds.map(channelName).join(', ')}</span>
                      )}
                      {r.channelIds.length > 0 && (r.notifyOnResolve || r.renotifyHours > 0) && (
                        <div className="text-xs text-muted">
                          {[r.notifyOnResolve && 'also when resolved', r.renotifyHours > 0 && `reminder every ${r.renotifyHours} h`].filter(Boolean).join(', ')}
                        </div>
                      )}
                    </td>
                    <td className="tabular-nums">
                      {r.unresolvedAlerts > 0 ? (
                        <Link to={`/alerts?ruleType=${r.type}`} className="text-accent hover:underline">
                          {r.unresolvedAlerts}
                        </Link>
                      ) : (
                        <span className="text-subtle">0</span>
                      )}
                    </td>
                    <td>
                      <div className="flex justify-end gap-1">
                        <Button size="sm" variant="ghost" loading={toggle.isPending && toggle.variables?.id === r.id} onClick={() => toggle.mutate(r)}>
                          {r.enabled ? 'Disable' : 'Enable'}
                        </Button>
                        <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setEditing(r)}>
                          Edit
                        </Button>
                        <Button size="sm" variant="danger-ghost" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={() => setDeleting(r)}>
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
      <InlineError error={toggle.error} />
      <RuleDialog rule={editing} channels={channels.page.items} tags={tags.page.items} onClose={() => setEditing(null)} />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && remove.mutate(deleting)}
        title={`Delete rule ${deleting?.name ?? ''}?`}
        confirmLabel="Delete rule"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        Its {deleting?.unresolvedAlerts ?? 0} unresolved alert(s) are closed without a notification. To pause a rule instead, disable it.
      </ConfirmDialog>
    </>
  );
}

function toRequest(r: AlertRuleDto): AlertRuleRequest {
  return {
    name: r.name,
    type: r.type,
    enabled: r.enabled,
    severity: r.severity,
    threshold: r.threshold,
    organizationId: r.organizationId,
    tagId: r.tagId,
    channelIds: r.channelIds,
    notifyOnResolve: r.notifyOnResolve,
    renotifyHours: r.renotifyHours,
  };
}

const EMPTY: AlertRuleRequest = {
  name: '',
  type: 'EndpointOffline',
  enabled: true,
  severity: 'Warning',
  threshold: 24,
  organizationId: null,
  tagId: null,
  channelIds: [],
  notifyOnResolve: false,
  renotifyHours: 0,
};

function RuleDialog({ rule, channels, tags, onClose }: {
  rule: AlertRuleDto | 'new' | null;
  channels: NotificationChannelDto[];
  tags: TagDto[];
  onClose: () => void;
}) {
  const toast = useToast();
  const isNew = rule === 'new';
  const types = useApi<AlertRuleTypeDto[]>(rule ? '/alert-rules/types' : null, undefined, { staleTime: Infinity });
  const [form, setForm] = useState<AlertRuleRequest>(EMPTY);
  useEffect(() => {
    if (rule === 'new') setForm({ ...EMPTY, name: ALERT_RULE_TYPE_LABELS.EndpointOffline });
    else if (rule) setForm(toRequest(rule));
  }, [rule]);
  const spec = types.data?.find((t) => t.type === form.type);
  const save = useApiMutation(
    (req: AlertRuleRequest) => (isNew ? api.post<AlertRuleDto>('/alert-rules', req) : api.put<AlertRuleDto>(`/alert-rules/${(rule as AlertRuleDto).id}`, req)),
    {
      invalidate: ['/alert-rules', '/alerts'],
      onSuccess: (r) => {
        toast.success(isNew ? `Rule ${r.name} created.` : `Rule ${r.name} saved.`);
        onClose();
      },
    },
  );
  const scopeChanged =
    !isNew && rule && (rule.organizationId !== form.organizationId || rule.tagId !== form.tagId || rule.threshold !== form.threshold || rule.type !== form.type);
  const thresholdError =
    spec?.thresholdUnit && form.threshold !== null && spec.thresholdMin !== null && spec.thresholdMax !== null && (form.threshold < spec.thresholdMin || form.threshold > spec.thresholdMax)
      ? `Between ${spec.thresholdMin} and ${spec.thresholdMax} ${spec.thresholdUnit}.`
      : null;

  function changeType(type: AlertRuleType) {
    const s = types.data?.find((t) => t.type === type);
    setForm((f) => ({
      ...f,
      type,
      threshold: s?.thresholdDefault ?? null,
      tagId: s?.supportsTag === false ? null : f.tagId,
      name: !f.name.trim() || f.name === ALERT_RULE_TYPE_LABELS[f.type] ? ALERT_RULE_TYPE_LABELS[type] : f.name,
    }));
  }

  function toggleChannel(id: string) {
    setForm((f) => {
      const current = f.channelIds ?? [];
      return { ...f, channelIds: current.includes(id) ? current.filter((c) => c !== id) : [...current, id] };
    });
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!form.name.trim() || thresholdError) return;
    save.mutate({ ...form, name: form.name.trim() });
  }

  return (
    <Dialog open={rule !== null} onClose={onClose} title={isNew ? 'New alert rule' : 'Edit alert rule'} size="lg">
      {types.isPending ? (
        <Spinner />
      ) : types.isError ? (
        <ErrorState error={types.error} onRetry={() => void types.refetch()} />
      ) : (
        <form onSubmit={submit} className="flex flex-col gap-3">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <SelectField label="Condition" value={form.type} onChange={(e) => changeType(e.target.value as AlertRuleType)} disabled={!isNew}>
              {ALERT_RULE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {ALERT_RULE_TYPE_LABELS[t]}
                </option>
              ))}
            </SelectField>
            <TextField label="Name" required maxLength={100} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <p className="text-xs text-muted">{RULE_HELP[form.type]}</p>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <SelectField label="Severity" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value as AlertSeverity })}>
              {ALERT_SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </SelectField>
            {spec?.thresholdUnit ? (
              <TextField
                label={`Threshold (${spec.thresholdUnit})`}
                type="number"
                min={spec.thresholdMin ?? undefined}
                max={spec.thresholdMax ?? undefined}
                step={1}
                required
                error={thresholdError ?? undefined}
                hint={form.type === 'OsUnsupported' ? '0 alerts only once support has ended.' : undefined}
                value={form.threshold === null ? '' : String(form.threshold)}
                onChange={(e) => setForm({ ...form, threshold: e.target.value === '' ? null : Number(e.target.value) })}
              />
            ) : (
              <div />
            )}
          </div>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <OrganizationSelect value={form.organizationId ?? ''} onChange={(v) => setForm({ ...form, organizationId: v || null })} />
            <SelectField
              label="Tag"
              value={form.tagId ?? ''}
              disabled={spec?.supportsTag === false}
              hint={spec?.supportsTag === false ? 'This rule raises one alert per organization, not per endpoint.' : 'Only endpoints with this tag.'}
              onChange={(e) => setForm({ ...form, tagId: e.target.value || null })}
            >
              <option value="">Any tag</option>
              {tags.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </SelectField>
          </div>
          <fieldset className="rounded-md border border-line p-3">
            <legend className="px-1 text-sm font-medium">Notify</legend>
            {channels.length === 0 ? (
              <p className="text-sm text-muted">No channels yet. Without channels the rule only shows alerts in the console.</p>
            ) : (
              <div className="flex flex-col gap-1.5">
                {channels.map((c) => (
                  <Checkbox
                    key={c.id}
                    label={
                      <>
                        {c.name} {!c.enabled && <Badge>Disabled</Badge>}
                      </>
                    }
                    hint={c.type === 'Email' ? c.emailRecipients.join(', ') : `${c.webhookFormat ?? 'Generic'} webhook · ${c.webhookHost ?? ''}`}
                    checked={(form.channelIds ?? []).includes(c.id)}
                    onChange={() => toggleChannel(c.id)}
                  />
                ))}
              </div>
            )}
            <div className="mt-3 grid grid-cols-1 gap-3 border-t border-line pt-3 md:grid-cols-2">
              <Checkbox label="Also notify when alerts resolve" checked={form.notifyOnResolve} onChange={(e) => setForm({ ...form, notifyOnResolve: e.target.checked })} />
              <TextField
                label="Reminder (hours)"
                type="number"
                min={0}
                max={720}
                step={1}
                hint="Notify again while an alert stays open and unacknowledged. 0 = no reminders."
                value={String(form.renotifyHours)}
                onChange={(e) => setForm({ ...form, renotifyHours: e.target.value === '' ? 0 : Number(e.target.value) })}
              />
            </div>
          </fieldset>
          <Checkbox label="Enabled" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
          {scopeChanged && <Alert tone="info">Changing the condition or scope closes the rule’s current alerts; matching endpoints raise new ones at the next evaluation.</Alert>}
          <InlineError error={save.error} />
          <div className="flex justify-end gap-2 pt-1">
            <Button onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="primary" loading={save.isPending} disabled={!form.name.trim() || !!thresholdError}>
              {isNew ? 'Create rule' : 'Save'}
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
