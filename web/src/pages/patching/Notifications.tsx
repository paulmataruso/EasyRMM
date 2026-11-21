import { useState, type FormEvent } from "react";
import { ChevronLeft, ChevronRight, KeyRound, MailX, Pencil, Plus, Send, Trash2 } from "lucide-react";
import { api, ApiError, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { PatchChannel, PatchChannelInput, PatchChannelSaved, PatchDelivery, PatchDeliveryPage, PatchNotifications, PatchWebhookFormat } from "../../api/types";
import { CopyButton } from "../../components/Copy";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, IconButton, Mono, Select, SelectField, Spinner, TableWrap, TextareaField, TextField } from "../../components/ui";
import { formatDateTime, formatNumber, formatRelative, plural } from "../../lib/format";
import { DeliveryBadge } from "./patchAlertText";

// Settings → Patching → Notifications: the channels EasyPatch sends alerts to, the messages it
// sent, the mail server email channels use (EasyRMM's own), and whether webhooks may go to private networks.

const FORMATS: Record<PatchWebhookFormat, string> = {
  Generic: "Generic JSON, signed",
  Slack: "Slack",
  Teams: "Microsoft Teams (Workflows)",
};

const SECURITY: Record<string, string> = { StartTls: "STARTTLS", SslOnConnect: "TLS", None: "no encryption" };

const KINDS: Record<PatchDelivery["kind"], string> = {
  AlertsOpened: "Alerts opened",
  AlertsResolved: "Alerts resolved",
  AlertsReminder: "Reminder",
  Test: "Test",
};

/** EasyPatch's reason a message failed; its words for no mail server point at its own console, so EasyRMM's replace them. */
export function deliveryError(error: string): string {
  return error.startsWith("SMTP is not configured") ? "EasyRMM has no mail server: a super administrator sets one under Settings → Notifications → Mail server." : error;
}

function destination(c: PatchChannel): string {
  if (c.type === "Email") return c.emailRecipients.join(", ");
  return `${c.webhookFormat ? FORMATS[c.webhookFormat] : "Webhook"} to ${c.webhookHost || "its address"}`;
}

export function NotificationsPanel() {
  const view = useApi<PatchNotifications>("/patching/notifications");
  if (view.isPending) return <Spinner />;
  if (view.isError) return <ErrorState error={view.error} onRetry={() => void view.refetch()} />;
  return (
    <div className="flex flex-col gap-4">
      <Channels channels={view.data.channels} mailServer={view.data.mail.host !== ""} />
      <Delivery view={view.data} />
      <Messages channels={view.data.channels} />
    </div>
  );
}

function Channels({ channels, mailServer }: { channels: PatchChannel[]; mailServer: boolean }) {
  const toast = useToast();
  const [form, setForm] = useState<{ open: boolean; channel?: PatchChannel }>({ open: false });
  const [deleting, setDeleting] = useState<PatchChannel | null>(null);
  const [rotating, setRotating] = useState<PatchChannel | null>(null);
  const [secret, setSecret] = useState<{ name: string; key: string } | null>(null);
  const test = useApiMutation((c: PatchChannel) => api.post<PatchDelivery>(`/patching/notifications/channels/${c.id}/test`), {
    invalidate: ["/patching/notifications"],
    onSuccess: (_, c) => toast.success(`Test sent to ${c.name}. How it went shows under Messages in a moment.`),
  });
  const remove = useApiMutation((c: PatchChannel) => api.del(`/patching/notifications/channels/${c.id}`), {
    invalidate: ["/patching"],
    onSuccess: (_, c) => {
      toast.success(`${c.name} deleted.`);
      setDeleting(null);
    },
  });
  const rotate = useApiMutation((c: PatchChannel) => api.post<PatchChannelSaved>(`/patching/notifications/channels/${c.id}/rotate-secret`), {
    invalidate: ["/patching/notifications"],
    onSuccess: (saved) => {
      setRotating(null);
      if (saved.signingSecret) setSecret({ name: saved.channel.name, key: saved.signingSecret });
    },
  });

  return (
    <Card
      title="Notification channels"
      padded={false}
      actions={
        <Button size="sm" variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setForm({ open: true })}>
          Add channel
        </Button>
      }
    >
      <div className="border-b border-line px-4 py-3">
        <p className="max-w-3xl text-sm text-muted">
          Where alert rules send their alerts: email, or a webhook to Slack, Microsoft Teams or a system of your own. A rule sends to the
          channels it names; the patching engine tries a message that fails again, a few times.
        </p>
      </div>
      {channels.length === 0 ? (
        <EmptyState title="No channels" icon={<MailX className="size-8" aria-hidden />}>
          Until you add one, alerts show under Patching → Alerts only.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <caption className="sr-only">Notification channels</caption>
            <thead>
              <tr>
                <th scope="col">Channel</th>
                <th scope="col" className="hidden md:table-cell">
                  Last message
                </th>
                <th scope="col" className="w-0">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {channels.map((c) => (
                <tr key={c.id} className="align-top">
                  <td>
                    <span className="flex flex-wrap items-center gap-1.5">
                      <span className="font-medium">{c.name}</span>
                      {!c.enabled && <Badge tone="neutral">Off</Badge>}
                      {c.type === "Email" && !mailServer && <Badge tone="warn">No mail server</Badge>}
                    </span>
                    <span className="block max-w-xl text-xs break-words text-muted">{destination(c)}</span>
                    {/* On a phone, the last message goes under the channel. */}
                    <span className="mt-1.5 block md:hidden">
                      <LastMessage c={c} />
                    </span>
                  </td>
                  <td className="hidden md:table-cell">
                    <LastMessage c={c} />
                  </td>
                  <td className="whitespace-nowrap">
                    <span className="flex justify-end gap-1">
                      <IconButton label={`Send a test to ${c.name}`} onClick={() => test.mutate(c, { onError: (e) => toast.error(e.message) })} disabled={test.isPending}>
                        <Send className="size-4" aria-hidden />
                      </IconButton>
                      {c.hasSigningSecret && (
                        <IconButton label={`New signing key for ${c.name}`} onClick={() => setRotating(c)}>
                          <KeyRound className="size-4" aria-hidden />
                        </IconButton>
                      )}
                      <IconButton label={`Edit ${c.name}`} onClick={() => setForm({ open: true, channel: c })}>
                        <Pencil className="size-4" aria-hidden />
                      </IconButton>
                      <IconButton label={`Delete ${c.name}`} onClick={() => setDeleting(c)}>
                        <Trash2 className="size-4" aria-hidden />
                      </IconButton>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {/* Remounted on each opening, so it starts from the channel as it is then. */}
      <ChannelDialog
        key={form.open ? (form.channel?.id ?? "new") : "closed"}
        open={form.open}
        channel={form.channel}
        onClose={() => setForm({ open: false })}
        onSecret={(name, key) => setSecret({ name, key })}
      />
      <SecretDialog secret={secret} onClose={() => setSecret(null)} />
      <ConfirmDialog
        open={rotating !== null}
        onClose={() => {
          setRotating(null);
          rotate.reset();
        }}
        onConfirm={() => rotating && rotate.mutate(rotating)}
        title="New signing key"
        confirmLabel="Make a new key"
        tone="danger"
        loading={rotate.isPending}
        error={rotate.error}
      >
        <p>The current key stops working at once: the receiving system rejects messages until it has the new one.</p>
      </ConfirmDialog>
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => {
          setDeleting(null);
          remove.reset();
        }}
        onConfirm={() => deleting && remove.mutate(deleting)}
        title="Delete channel"
        confirmLabel="Delete channel"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        {deleting && <p>Rules stop sending to {deleting.name}, and its messages are deleted with it.</p>}
      </ConfirmDialog>
    </Card>
  );
}

function LastMessage({ c }: { c: PatchChannel }) {
  if (!c.lastDelivery) return <span className="text-xs text-subtle">Nothing sent yet</span>;
  return (
    <span className="flex flex-col items-start gap-0.5">
      <span className="flex items-center gap-1.5">
        <DeliveryBadge status={c.lastDelivery.status} />
        <span className="text-xs text-muted" title={formatDateTime(c.lastDelivery.createdAt)}>
          {formatRelative(c.lastDelivery.createdAt)}
        </span>
      </span>
      {c.lastDelivery.lastError && <span className="max-w-sm text-xs break-words text-danger">{deliveryError(c.lastDelivery.lastError)}</span>}
    </span>
  );
}

function SecretDialog({ secret, onClose }: { secret: { name: string; key: string } | null; onClose: () => void }) {
  return (
    <Dialog
      open={secret !== null}
      onClose={onClose}
      dismissible={false}
      title={secret ? `Signing key for ${secret.name}` : "Signing key"}
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      {secret && (
        <div className="flex flex-col gap-3 text-sm">
          <p>
            The patching engine signs each message to this webhook with HMAC-SHA256 of its body, in the <Mono>X-EasyPatch-Signature</Mono> header. Copy the key
            into the receiving system now: it is not shown again.
          </p>
          <div className="flex items-center gap-2">
            <Mono className="min-w-0 flex-1 rounded-md bg-raised px-2 py-1.5 break-all">{secret.key}</Mono>
            <CopyButton text={secret.key} label="Copy key" />
          </div>
        </div>
      )}
    </Dialog>
  );
}

function ChannelDialog({ open, channel, onClose, onSecret }: {
  open: boolean;
  channel?: PatchChannel;
  onClose: () => void;
  onSecret: (name: string, key: string) => void;
}) {
  const toast = useToast();
  const [name, setName] = useState(channel?.name ?? "");
  const [type, setType] = useState<PatchChannel["type"]>(channel?.type ?? "Email");
  const [recipients, setRecipients] = useState((channel?.emailRecipients ?? []).join("\n"));
  const [format, setFormat] = useState<PatchWebhookFormat>(channel?.webhookFormat ?? "Slack");
  const [address, setAddress] = useState("");
  const [enabled, setEnabled] = useState(channel?.enabled ?? true);
  const [tried, setTried] = useState(false);
  const save = useApiMutation(
    (body: PatchChannelInput) =>
      channel
        ? api.put<PatchChannelSaved>(`/patching/notifications/channels/${channel.id}`, body)
        : api.post<PatchChannelSaved>("/patching/notifications/channels", body),
    {
      invalidate: ["/patching"],
      onSuccess: (saved) => {
        toast.success(channel ? `${saved.channel.name} saved.` : `${saved.channel.name} added.`);
        onClose();
        if (saved.signingSecret) onSecret(saved.channel.name, saved.signingSecret);
      },
    },
  );
  const emails = recipients
    .split(/[\s,;]+/)
    .map((r) => r.trim())
    .filter(Boolean);
  const url = address.trim();
  const errors = {
    name: name.trim() === "" ? "Name the channel." : null,
    emailRecipients: type === "Email" && emails.length === 0 ? "Enter at least one email address." : type === "Email" && emails.length > 20 ? "Enter at most 20 email addresses." : null,
    webhookUrl:
      type === "Webhook" && (url !== "" || !channel) && !/^https:\/\/[^\s/@]+(\/|$|\?)/i.test(url) ? "Enter the webhook's https:// address." : null,
  };
  const blocked = Object.values(errors).some(Boolean);
  const show = (k: keyof typeof errors) => fieldError(save.error, k) ?? (tried ? errors[k] : null);

  function submit(e: FormEvent) {
    e.preventDefault();
    setTried(true);
    if (blocked) return;
    save.mutate({
      name: name.trim(),
      type,
      enabled,
      emailRecipients: type === "Email" ? emails : [],
      webhookFormat: type === "Webhook" ? format : null,
      webhookUrl: type === "Webhook" && url !== "" ? url : null,
    });
  }

  return (
    <Dialog
      open={open}
      onClose={() => {
        onClose();
        save.reset();
      }}
      title={channel ? "Edit channel" : "Add channel"}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="channel-form" loading={save.isPending}>
            {channel ? "Save channel" : "Add channel"}
          </Button>
        </>
      }
    >
      <form id="channel-form" onSubmit={submit} className="grid gap-3.5 sm:grid-cols-2" noValidate>
        <TextField label="Name" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} error={show("name")} required />
        <SelectField
          label="Sends by"
          value={type}
          onChange={(e) => setType(e.target.value as PatchChannel["type"])}
          disabled={channel !== undefined}
          hint={channel ? "A channel's type cannot change." : undefined}
          error={fieldError(save.error, "type")}
        >
          <option value="Email">Email</option>
          <option value="Webhook">Webhook</option>
        </SelectField>
        {type === "Email" ? (
          <TextareaField
            label="Recipients"
            rows={3}
            value={recipients}
            onChange={(e) => setRecipients(e.target.value)}
            hint="Up to 20 addresses, one per line or separated by commas."
            error={show("emailRecipients")}
            required
            className="sm:col-span-2"
          />
        ) : (
          <>
            <SelectField label="Format" value={format} onChange={(e) => setFormat(e.target.value as PatchWebhookFormat)} error={fieldError(save.error, "webhookFormat")}>
              {(Object.keys(FORMATS) as PatchWebhookFormat[]).map((f) => (
                <option key={f} value={f}>
                  {FORMATS[f]}
                </option>
              ))}
            </SelectField>
            <TextField
              label="Address"
              type="url"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              placeholder="https://"
              hint={
                channel?.webhookHost
                  ? `Leave empty to keep the address at ${channel.webhookHost}. It is never shown again.`
                  : "The patching engine keeps it encrypted and never shows it again: it is often the webhook's secret."
              }
              error={show("webhookUrl")}
              required={!channel}
              className="sm:col-span-2"
            />
          </>
        )}
        <label className="flex items-center gap-2 text-sm sm:col-span-2">
          <input type="checkbox" className="size-4 accent-accent" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Send messages to this channel
        </label>
        {save.error && !(save.error instanceof ApiError && Object.keys(save.error.fields).length > 0) && (
          <p className="text-sm text-danger sm:col-span-2">{save.error.message}</p>
        )}
      </form>
    </Dialog>
  );
}

function Delivery({ view }: { view: PatchNotifications }) {
  const toast = useToast();
  const { mail } = view;
  const set = useApiMutation((allow: boolean) => api.put<PatchNotifications>("/patching/notifications", { allowPrivateNetworkWebhooks: allow }), {
    invalidate: ["/patching/notifications"],
    onSuccess: (v) => toast.success(v.allowPrivateNetworkWebhooks ? "Webhooks to private networks allowed." : "Webhooks to private networks blocked."),
  });
  return (
    <Card title="Email and webhooks">
      <div className="flex flex-col gap-4 text-sm">
        {mail.host ? (
          <p className="max-w-3xl">
            Email channels send through EasyRMM&apos;s mail server, <Mono>{`${mail.host}:${mail.port}`}</Mono> ({SECURITY[mail.security] ?? mail.security}),
            from {mail.fromName ? `${mail.fromName} <${mail.fromAddress}>` : mail.fromAddress}. A super administrator sets it under Settings → Notifications → Mail server, and
            EasyRMM gives it to the patching engine at start and after every change.
          </p>
        ) : (
          <Alert tone="warn" title="No mail server">
            EasyRMM has no mail server, so email channels cannot send. A super administrator sets one under Settings → Notifications → Mail server.
          </Alert>
        )}
        <div className="flex flex-col gap-1">
          <label className="flex items-center gap-2 font-medium">
            <input
              type="checkbox"
              className="size-4 accent-accent"
              checked={set.isPending ? set.variables : view.allowPrivateNetworkWebhooks}
              disabled={set.isPending}
              onChange={(e) => set.mutate(e.target.checked)}
            />
            Allow webhooks to private network addresses
          </label>
          <p className="max-w-3xl pl-6 text-muted">
            Off, the patching engine only calls webhooks at public addresses. Turn it on for a PSA or chat server on a private network. Loopback, link-local
            and the subnets this server is on stay blocked: a webhook on the server&apos;s own subnet cannot be reached.
          </p>
          {set.error && <p className="pl-6 text-danger">{set.error.message}</p>}
        </div>
      </div>
    </Card>
  );
}

function Messages({ channels }: { channels: PatchChannel[] }) {
  const [channelId, setChannelId] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);
  const list = useApi<PatchDeliveryPage>(
    "/patching/notifications/deliveries",
    { channelId: channelId || undefined, status: status || undefined, page: page > 1 ? page : undefined },
    { keepPrevious: true, refetchInterval: 15_000 },
  );
  const pages = list.data ? Math.max(1, Math.ceil(list.data.totalCount / list.data.pageSize)) : 1;
  return (
    <Card
      title="Messages"
      padded={false}
      actions={
        <span className="flex flex-wrap items-center gap-2">
          <Select
            aria-label="Channel"
            value={channelId}
            onChange={(e) => {
              setChannelId(e.target.value);
              setPage(1);
            }}
            className="w-44"
          >
            <option value="">Every channel</option>
            {channels.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </Select>
          <Select
            aria-label="Result"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(1);
            }}
            className="w-32"
          >
            <option value="">Any result</option>
            <option value="Pending">Sending</option>
            <option value="Sent">Sent</option>
            <option value="Failed">Failed</option>
          </Select>
        </span>
      }
    >
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <div className="p-4">
          <ErrorState error={list.error} onRetry={() => void list.refetch()} compact />
        </div>
      ) : list.data.items.length === 0 ? (
        <EmptyState title={channelId || status ? "No messages match" : "No messages yet"} icon={<Send className="size-8" aria-hidden />} compact>
          {channelId || status ? undefined : "Alerts sent to channels, and tests, show here."}
        </EmptyState>
      ) : (
        <>
          <TableWrap className="rounded-none border-0">
            <table className="table-base">
              <caption className="sr-only">Messages to notification channels</caption>
              <thead>
                <tr>
                  <th scope="col">Message</th>
                  <th scope="col" className="hidden md:table-cell">
                    Channel
                  </th>
                  <th scope="col">Result</th>
                  <th scope="col" className="hidden sm:table-cell">
                    When
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((d) => (
                  <tr key={d.id} className="align-top">
                    <td>
                      <span className="font-medium">{KINDS[d.kind] ?? d.kind}</span>
                      <span className="block max-w-md text-xs break-words text-muted">{d.subject}</span>
                      <span className="block text-xs text-muted md:hidden">{d.channelName}</span>
                    </td>
                    <td className="hidden md:table-cell">{d.channelName}</td>
                    <td>
                      <span className="flex flex-col items-start gap-0.5">
                        <DeliveryBadge status={d.status} />
                        {d.attempts > 1 && <span className="text-xs text-muted">{plural(d.attempts, "attempt")}</span>}
                        {d.lastError && <span className="max-w-sm text-xs break-words text-danger">{deliveryError(d.lastError)}</span>}
                      </span>
                    </td>
                    <td className="hidden whitespace-nowrap text-muted sm:table-cell" title={formatDateTime(d.createdAt)}>
                      {formatRelative(d.createdAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <nav className="flex items-center justify-between gap-2 border-t border-line px-4 py-2 text-sm text-muted" aria-label="Messages pages">
            <span>
              {plural(list.data.totalCount, "message")}, newest first{pages > 1 ? `; page ${formatNumber(page)} of ${formatNumber(pages)}` : ""}
            </span>
            {pages > 1 && (
              <span className="flex items-center gap-1">
                <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => setPage(page - 1)}>
                  <ChevronLeft className="size-4" aria-hidden />
                  Newer
                </Button>
                <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => setPage(page + 1)}>
                  Older
                  <ChevronRight className="size-4" aria-hidden />
                </Button>
              </span>
            )}
          </nav>
        </>
      )}
    </Card>
  );
}
