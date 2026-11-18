import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { KeyRound, Mail, Pencil, Plus, Save, Send, Trash2, Webhook } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation, useList } from '../../api/hooks';
import {
  SMTP_SECURITY,
  WEBHOOK_FORMATS,
  type DeliveryStatus,
  type NotificationChannelDto,
  type NotificationChannelRequest,
  type NotificationChannelSavedDto,
  type NotificationChannelType,
  type NotificationDeliveryDto,
  type NotificationSettingsDto,
  type NotificationSettingsRequest,
  type SmtpSecurity,
  type WebhookFormat,
} from '../../api/types';
import { CodeBlock, OneTimeNotice } from '../../components/Copy';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
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
  SelectField,
  Spinner,
  TableWrap,
  Textarea,
  TextField,
  type Tone,
} from '../../components/ui';
import { formatDateTime, formatRelative, humanize } from '../../lib/format';

const SECURITY_LABELS: Record<SmtpSecurity, string> = {
  StartTls: 'STARTTLS (port 587)',
  SslOnConnect: 'TLS on connect (port 465)',
  None: 'None (unencrypted, internal relays only)',
};

const FORMAT_LABELS: Record<WebhookFormat, string> = {
  Generic: 'Generic JSON (signed)',
  Slack: 'Slack incoming webhook',
  Teams: 'Microsoft Teams workflow',
};

export const deliveryTone: Record<DeliveryStatus, Tone> = { Pending: 'info', Sent: 'ok', Failed: 'danger' };

/** Super administrators only: SMTP server, notification channels and the delivery log. */
export function NotificationsTab() {
  return (
    <div className="flex flex-col gap-4">
      <p className="max-w-3xl text-sm text-muted">
        Alert rules send notifications to channels: email recipients, or a webhook for Slack, Microsoft Teams or your PSA/ticketing system. Notifications are sent
        by the worker, grouped per channel, and retried for up to 24 hours. Secrets (SMTP password, webhook URLs, signing keys) are stored encrypted and never
        shown again.
      </p>
      <SmtpCard />
      <ChannelsCard />
      <DeliveriesCard />
    </div>
  );
}

function SmtpCard() {
  const toast = useToast();
  const settings = useApi<NotificationSettingsDto>('/notifications/settings');
  const [form, setForm] = useState<NotificationSettingsRequest | null>(null);
  const [changePassword, setChangePassword] = useState(false);
  useEffect(() => {
    if (!settings.data) return;
    const s = settings.data;
    setForm({
      smtpHost: s.smtpHost,
      smtpPort: s.smtpPort,
      smtpSecurity: s.smtpSecurity,
      smtpUsername: s.smtpUsername,
      smtpPassword: null,
      fromAddress: s.fromAddress,
      fromName: s.fromName,
      allowPrivateNetworkWebhooks: s.allowPrivateNetworkWebhooks,
      smtpSkipCertificateValidation: s.smtpSkipCertificateValidation ?? false,
    });
    setChangePassword(false);
  }, [settings.data]);
  const save = useApiMutation((req: NotificationSettingsRequest) => api.put<NotificationSettingsDto>('/notifications/settings', req), {
    invalidate: ['/notifications/settings'],
    onSuccess: () => toast.success('Notification settings saved.'),
  });

  if (settings.isPending || !form) return settings.isError ? <ErrorState error={settings.error} onRetry={() => void settings.refetch()} /> : <Spinner />;
  const configured = settings.data?.smtpPasswordConfigured ?? false;

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!form) return;
    const trim = (v: string | null) => (v?.trim() ? v.trim() : null);
    save.mutate({
      ...form,
      smtpHost: trim(form.smtpHost),
      smtpUsername: trim(form.smtpUsername),
      fromAddress: trim(form.fromAddress),
      fromName: trim(form.fromName),
      // null keeps the stored password; only send one when the administrator chose to change it.
      smtpPassword: changePassword ? (form.smtpPassword ?? '') : null,
    });
  }

  return (
    <Card title="Email server (SMTP)">
      <form onSubmit={submit} className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-x-6 gap-y-3 md:grid-cols-2">
          <TextField label="SMTP server" placeholder="smtp.example.com" maxLength={255} value={form.smtpHost ?? ''} onChange={(e) => setForm({ ...form, smtpHost: e.target.value })} />
          <div className="grid grid-cols-[8rem_1fr] gap-3">
            <TextField
              label="Port"
              type="number"
              min={1}
              max={65535}
              required
              value={String(form.smtpPort)}
              onChange={(e) => setForm({ ...form, smtpPort: e.target.value === '' ? 0 : Number(e.target.value) })}
            />
            <SelectField label="Encryption" value={form.smtpSecurity} onChange={(e) => setForm({ ...form, smtpSecurity: e.target.value as SmtpSecurity })}>
              {SMTP_SECURITY.map((s) => (
                <option key={s} value={s}>
                  {SECURITY_LABELS[s]}
                </option>
              ))}
            </SelectField>
          </div>
          <TextField
            label="User name"
            hint="Leave empty if the server accepts mail without signing in."
            autoComplete="off"
            maxLength={255}
            value={form.smtpUsername ?? ''}
            onChange={(e) => setForm({ ...form, smtpUsername: e.target.value })}
          />
          <div className="flex flex-col gap-1">
            {changePassword ? (
              <TextField
                label="Password"
                type="password"
                autoComplete="new-password"
                maxLength={500}
                hint={configured ? 'Leave empty to remove the stored password.' : undefined}
                value={form.smtpPassword ?? ''}
                onChange={(e) => setForm({ ...form, smtpPassword: e.target.value })}
                autoFocus
              />
            ) : (
              <>
                <span className="text-sm font-medium">Password</span>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted">{configured ? 'Stored (encrypted)' : 'Not set'}</span>
                  <Button size="sm" onClick={() => setChangePassword(true)}>
                    {configured ? 'Change' : 'Set password'}
                  </Button>
                </div>
              </>
            )}
          </div>
          <TextField
            label="From address"
            type="email"
            placeholder="easypatch@example.com"
            maxLength={254}
            value={form.fromAddress ?? ''}
            onChange={(e) => setForm({ ...form, fromAddress: e.target.value })}
          />
          <TextField label="From name" placeholder="EasyPatch" maxLength={100} value={form.fromName ?? ''} onChange={(e) => setForm({ ...form, fromName: e.target.value })} />
        </div>
        {form.smtpSecurity === 'None' ? (
          <Alert tone="warn">Without encryption the password and the messages cross the network in clear text. Use this only with a relay on a trusted network.</Alert>
        ) : (
          <div className="flex flex-col gap-2">
            <Checkbox
              label="Skip certificate validation"
              hint="Accept any certificate from the SMTP server, for example a self-signed certificate on an internal relay. Off by default."
              checked={form.smtpSkipCertificateValidation}
              onChange={(e) => setForm({ ...form, smtpSkipCertificateValidation: e.target.checked })}
            />
            {form.smtpSkipCertificateValidation && (
              <Alert tone="warn">
                The connection is still encrypted, but EasyPatch no longer checks that it is talking to your mail server. Anyone who can intercept or redirect
                the connection can read the SMTP password, alerts and monthly reports. Use this only on a network you trust, and prefer installing a trusted
                certificate on the server.
              </Alert>
            )}
          </div>
        )}
        <div className="border-t border-line pt-3">
          <Checkbox
            label="Allow webhooks to private network addresses"
            hint="Off by default: webhooks may only reach public internet addresses, so a channel cannot be used to probe your internal network. Turn on only for an on-premises PSA or chat server. Loopback, link-local and cloud metadata addresses stay blocked."
            checked={form.allowPrivateNetworkWebhooks}
            onChange={(e) => setForm({ ...form, allowPrivateNetworkWebhooks: e.target.checked })}
          />
        </div>
        <InlineError error={save.error} />
        <div className="flex justify-end">
          <Button type="submit" variant="primary" loading={save.isPending} icon={<Save className="size-4" aria-hidden />}>
            Save
          </Button>
        </div>
      </form>
    </Card>
  );
}

function ChannelsCard() {
  const toast = useToast();
  const list = useList<NotificationChannelDto>('/notifications/channels', undefined, { refetchInterval: 15_000 });
  const [editing, setEditing] = useState<NotificationChannelDto | 'new' | null>(null);
  const [deleting, setDeleting] = useState<NotificationChannelDto | null>(null);
  const [rotating, setRotating] = useState<NotificationChannelDto | null>(null);
  const [secret, setSecret] = useState<{ name: string; secret: string } | null>(null);
  const remove = useApiMutation((c: NotificationChannelDto) => api.del(`/notifications/channels/${c.id}`), {
    invalidate: ['/notifications', '/alert-rules'],
    onSuccess: (_, c) => {
      setDeleting(null);
      toast.success(`Channel ${c.name} deleted.`);
    },
  });
  const test = useApiMutation((c: NotificationChannelDto) => api.post<NotificationDeliveryDto>(`/notifications/channels/${c.id}/test`), {
    invalidate: ['/notifications'],
    onSuccess: (_, c) => toast.success(`Test notification queued for ${c.name}. The result appears under Recent deliveries within a minute.`),
  });
  const rotate = useApiMutation((c: NotificationChannelDto) => api.post<NotificationChannelSavedDto>(`/notifications/channels/${c.id}/rotate-secret`), {
    invalidate: ['/notifications/channels'],
    onSuccess: (r) => {
      setRotating(null);
      if (r.signingSecret) setSecret({ name: r.channel.name, secret: r.signingSecret });
    },
  });

  return (
    <Card
      title="Channels"
      padded={false}
      actions={
        <Button size="sm" variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setEditing('new')}>
          New channel
        </Button>
      }
    >
      {test.error && (
        <div className="px-4 pt-3">
          <InlineError error={test.error} />
        </div>
      )}
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.page.items.length === 0 ? (
        <EmptyState title="No channels" icon={<Send className="size-8" aria-hidden />}>
          Add an email or webhook channel, then select it in the alert rules that should notify it.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>Channel</th>
                <th>Destination</th>
                <th>Last delivery</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {list.page.items.map((c) => (
                <tr key={c.id}>
                  <td>
                    <div className="flex items-center gap-2">
                      {c.type === 'Email' ? <Mail className="size-4 text-subtle" aria-hidden /> : <Webhook className="size-4 text-subtle" aria-hidden />}
                      <span className="font-medium">{c.name}</span>
                      {!c.enabled && <Badge>Disabled</Badge>}
                    </div>
                  </td>
                  <td className="max-w-sm text-sm">
                    {c.type === 'Email' ? (
                      <span className="break-words">{c.emailRecipients.join(', ')}</span>
                    ) : (
                      <span>
                        {FORMAT_LABELS[c.webhookFormat ?? 'Generic']} · <span className="font-mono text-xs">{c.webhookHost}</span>
                      </span>
                    )}
                  </td>
                  <td className="text-sm">
                    {c.lastDelivery ? (
                      <div title={formatDateTime(c.lastDelivery.createdAt)}>
                        <Badge tone={deliveryTone[c.lastDelivery.status]}>{c.lastDelivery.status}</Badge>{' '}
                        <span className="text-xs text-muted">{formatRelative(c.lastDelivery.createdAt)}</span>
                        {c.lastDelivery.lastError && <div className="mt-0.5 text-xs text-danger">{c.lastDelivery.lastError}</div>}
                      </div>
                    ) : (
                      <span className="text-subtle">Never</span>
                    )}
                  </td>
                  <td>
                    <div className="flex justify-end gap-1">
                      <Button size="sm" variant="ghost" icon={<Send className="size-3.5" aria-hidden />} disabled={!c.enabled} loading={test.isPending && test.variables?.id === c.id} onClick={() => test.mutate(c)}>
                        Test
                      </Button>
                      {c.type === 'Webhook' && c.webhookFormat === 'Generic' && (
                        <Button size="sm" variant="ghost" icon={<KeyRound className="size-3.5" aria-hidden />} onClick={() => setRotating(c)}>
                          New secret
                        </Button>
                      )}
                      <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setEditing(c)}>
                        Edit
                      </Button>
                      <Button size="sm" variant="danger-ghost" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={() => setDeleting(c)}>
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <ChannelDialog
        channel={editing}
        onClose={() => setEditing(null)}
        onSecret={(name, s) => setSecret({ name, secret: s })}
      />
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && remove.mutate(deleting)}
        title={`Delete channel ${deleting?.name ?? ''}?`}
        confirmLabel="Delete channel"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        The channel is removed from every alert rule, and notifications not yet sent to it are discarded.
      </ConfirmDialog>
      <ConfirmDialog
        open={rotating !== null}
        onClose={() => setRotating(null)}
        onConfirm={() => rotating && rotate.mutate(rotating)}
        title={`New signing secret for ${rotating?.name ?? ''}?`}
        confirmLabel="Create new secret"
        loading={rotate.isPending}
        error={rotate.error}
      >
        The old secret stops working immediately: update the receiving system with the new secret, or it will reject EasyPatch notifications.
      </ConfirmDialog>
      <Dialog open={secret !== null} onClose={() => setSecret(null)} title={`Signing secret for ${secret?.name ?? ''}`} size="md">
        {secret && (
          <div className="flex flex-col gap-3">
            <OneTimeNotice>EasyPatch stores the secret encrypted and does not show it again. If it is lost, create a new one.</OneTimeNotice>
            <CodeBlock code={secret.secret} />
            <p className="text-xs text-muted">
              Each request carries <span className="font-mono">X-EasyPatch-Signature: t=&lt;unix time&gt;,v1=&lt;hex&gt;</span>, where v1 is HMAC-SHA256 of
              <span className="font-mono"> &lt;t&gt;.&lt;request body&gt;</span> with this secret. Reject requests with a wrong signature or an old timestamp.
            </p>
            <div className="flex justify-end">
              <Button variant="primary" onClick={() => setSecret(null)}>
                I have copied the secret
              </Button>
            </div>
          </div>
        )}
      </Dialog>
    </Card>
  );
}

function parseRecipients(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function ChannelDialog({ channel, onClose, onSecret }: {
  channel: NotificationChannelDto | 'new' | null;
  onClose: () => void;
  onSecret: (name: string, secret: string) => void;
}) {
  const toast = useToast();
  const isNew = channel === 'new';
  const existing = channel && channel !== 'new' ? channel : null;
  const [name, setName] = useState('');
  const [type, setType] = useState<NotificationChannelType>('Email');
  const [enabled, setEnabled] = useState(true);
  const [recipients, setRecipients] = useState('');
  const [format, setFormat] = useState<WebhookFormat>('Generic');
  const [webhookUrl, setWebhookUrl] = useState('');
  useEffect(() => {
    if (channel === null) return;
    setName(existing?.name ?? '');
    setType(existing?.type ?? 'Email');
    setEnabled(existing?.enabled ?? true);
    setRecipients(existing?.emailRecipients.join('\n') ?? '');
    setFormat(existing?.webhookFormat ?? 'Generic');
    setWebhookUrl('');
    // Reset only when the dialog opens for another channel.
  }, [channel]);
  const save = useApiMutation(
    (req: NotificationChannelRequest) =>
      isNew ? api.post<NotificationChannelSavedDto>('/notifications/channels', req) : api.put<NotificationChannelSavedDto>(`/notifications/channels/${existing?.id}`, req),
    {
      invalidate: ['/notifications/channels'],
      onSuccess: (r) => {
        toast.success(isNew ? `Channel ${r.channel.name} created.` : `Channel ${r.channel.name} saved.`);
        onClose();
        if (r.signingSecret) onSecret(r.channel.name, r.signingSecret);
      },
    },
  );
  const parsed = useMemo(() => parseRecipients(recipients), [recipients]);
  const urlError = webhookUrl.trim() && !/^https:\/\//i.test(webhookUrl.trim()) ? 'The URL must start with https://.' : null;
  const needsUrl = type === 'Webhook' && (isNew || existing?.type !== 'Webhook');
  const valid = name.trim().length > 0 && (type === 'Email' ? parsed.length > 0 && parsed.length <= 20 : (!needsUrl || webhookUrl.trim().length > 0) && !urlError);

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!valid) return;
    save.mutate({
      name: name.trim(),
      type,
      enabled,
      emailRecipients: type === 'Email' ? parsed : null,
      webhookFormat: type === 'Webhook' ? format : null,
      webhookUrl: type === 'Webhook' && webhookUrl.trim() ? webhookUrl.trim() : null,
    });
  }

  return (
    <Dialog open={channel !== null} onClose={onClose} title={isNew ? 'New notification channel' : `Edit channel ${existing?.name ?? ''}`} size="md">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <TextField label="Name" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        <SelectField label="Type" value={type} onChange={(e) => setType(e.target.value as NotificationChannelType)} disabled={!isNew}>
          <option value="Email">Email</option>
          <option value="Webhook">Webhook</option>
        </SelectField>
        {type === 'Email' ? (
          <div className="flex flex-col gap-1">
            <label htmlFor="channel-recipients" className="text-sm font-medium">
              Recipients
            </label>
            <Textarea
              id="channel-recipients"
              rows={4}
              value={recipients}
              placeholder={'oncall@example.com\nservicedesk@example.com'}
              onChange={(e) => setRecipients(e.target.value)}
            />
            <p className="text-xs text-muted">One address per line (up to 20). Plain addresses only, without display names.</p>
          </div>
        ) : (
          <>
            <SelectField label="Format" value={format} onChange={(e) => setFormat(e.target.value as WebhookFormat)}>
              {WEBHOOK_FORMATS.map((f) => (
                <option key={f} value={f}>
                  {FORMAT_LABELS[f]}
                </option>
              ))}
            </SelectField>
            <TextField
              label="Webhook URL"
              type="url"
              autoComplete="off"
              required={needsUrl}
              maxLength={2048}
              placeholder={needsUrl ? 'https://' : `Leave empty to keep the stored URL (${existing?.webhookHost ?? ''})`}
              error={urlError ?? undefined}
              hint={
                format === 'Teams'
                  ? 'Create it in Teams with the Workflows app (“Post to a channel when a webhook request is received”). The URL is stored encrypted.'
                  : format === 'Slack'
                    ? 'A Slack incoming webhook URL (https://hooks.slack.com/…). The URL is stored encrypted.'
                    : 'EasyPatch posts a JSON document signed with a secret that is shown once after saving. The URL is stored encrypted.'
              }
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
            />
          </>
        )}
        <Checkbox label="Enabled" hint="Disabled channels receive no notifications; queued ones fail." checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        <InlineError error={save.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!valid}>
            {isNew ? 'Create channel' : 'Save'}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function DeliveriesCard() {
  const [status, setStatus] = useState<DeliveryStatus | ''>('');
  const list = useList<NotificationDeliveryDto>('/notifications/deliveries', { status: status || undefined, pageSize: 25 }, { refetchInterval: 15_000, keepPrevious: true });
  return (
    <Card
      title="Recent deliveries"
      padded={false}
      actions={
        <select
          aria-label="Delivery status"
          className="rounded-md border border-line bg-surface px-2 py-1 text-xs"
          value={status}
          onChange={(e) => setStatus(e.target.value as DeliveryStatus | '')}
        >
          <option value="">All</option>
          <option value="Pending">Pending</option>
          <option value="Sent">Sent</option>
          <option value="Failed">Failed</option>
        </select>
      }
    >
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} compact onRetry={() => void list.refetch()} />
      ) : list.page.items.length === 0 ? (
        <EmptyState title="No notifications sent yet" />
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>Queued</th>
                <th>Channel</th>
                <th>Notification</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {list.page.items.map((d) => (
                <tr key={d.id}>
                  <td className="whitespace-nowrap text-sm" title={formatDateTime(d.createdAt)}>
                    {formatRelative(d.createdAt)}
                  </td>
                  <td className="text-sm">{d.channelName}</td>
                  <td className="max-w-md text-sm">
                    <div className="truncate" title={d.subject}>
                      {d.subject}
                    </div>
                    <div className="text-xs text-muted">{humanize(d.kind)}</div>
                  </td>
                  <td className="text-sm">
                    <Badge tone={deliveryTone[d.status]}>{d.status}</Badge>
                    {d.attempts > 0 && <span className="ml-1 text-xs text-muted">{d.attempts} failed attempt{d.attempts === 1 ? '' : 's'}</span>}
                    {d.status === 'Pending' && d.attempts > 0 && <div className="text-xs text-muted">Next try {formatRelative(d.nextAttemptAt)}</div>}
                    {d.lastError && d.status !== 'Sent' && <div className="mt-0.5 text-xs text-danger">{d.lastError}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Card>
  );
}
