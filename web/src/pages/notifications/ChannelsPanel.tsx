import { useState } from "react";
import { Bell, Eye, FlaskConical, KeyRound, Plus, Share2, ShieldCheck, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation, useOrganizations } from "../../api/hooks";
import type {
  ChannelSecrets,
  DeliveryLogRow,
  NotificationChannel,
  NotificationChannelInput,
  NotificationKind,
  NotificationQuota,
  NotificationTestResult,
  PlatformNotice,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, InlineError, Mono, SelectField, Spinner, TableWrap, TextareaField, TextField } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";

const CHANNELS = "/notifications/channels";
const NOTICES = "/notices";
const DELIVERIES = "/notifications/deliveries";

const STATE: Record<string, { label: string; tone: "ok" | "danger" | "warn" | "neutral" }> = {
  sending: { label: "Sending", tone: "ok" },
  failing: { label: "Failing", tone: "danger" },
  waiting_for_approval: { label: "Waiting for approval", tone: "warn" },
  off: { label: "Off", tone: "neutral" },
};

/**
 * Notification channels (ADR-0053): an organization's own, with the platform channels shared with it, or, with no
 * organization, the platform's and every organization's for a super administrator. Email and generic webhooks.
 * What is shown of a shared platform channel is its name and kind only.
 */
export function ChannelsPanel({ organizationId }: { organizationId: string | null }) {
  const { isSuperAdmin } = useAuth();
  const q = useApi<{ channels: NotificationChannel[] }>(CHANNELS, { organizationId }, { refetchInterval: 15_000 });
  const orgs = useOrganizations();
  const [adding, setAdding] = useState(false);
  const orgName = (id: string | null) => (id === null ? "Platform" : (orgs.data?.items.find((o) => o.id === id)?.name ?? "Organization"));
  const canManage = organizationId !== null || isSuperAdmin;

  return (
    <div className="flex flex-col gap-4">
      <NoticesCard organizationId={organizationId} />
      <Card
        title="Channels"
        actions={
          canManage && (
            <Button variant="primary" size="sm" icon={<Plus className="size-4" aria-hidden />} onClick={() => setAdding(true)}>
              Add channel
            </Button>
          )
        }
        padded={false}
      >
        {q.isPending ? (
          <div className="p-4">
            <Spinner />
          </div>
        ) : q.isError ? (
          <div className="p-4">
            <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
          </div>
        ) : q.data.channels.length === 0 ? (
          <EmptyState title="No notification channels" compact icon={<Bell className="size-5" aria-hidden />}>
            A channel is where EasyRMM sends its notifications: an email to a list of people, or a signed webhook for another system.
          </EmptyState>
        ) : (
          <TableWrap className="rounded-none border-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-muted">
                  <th className="px-4 py-2 font-medium">Name</th>
                  {organizationId === null && <th className="px-4 py-2 font-medium">Owner</th>}
                  <th className="px-4 py-2 font-medium">State</th>
                  <th className="px-4 py-2 font-medium">Destination</th>
                  <th className="px-4 py-2 font-medium">Last delivery</th>
                  <th className="px-4 py-2 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {q.data.channels.map((c) => (
                  <ChannelRow key={c.id} channel={c} ownerLabel={organizationId === null ? orgName(c.organizationId) : null} />
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>
      {isSuperAdmin && organizationId !== null && <QuotaCard organizationId={organizationId} />}
      <DeliveryLog organizationId={organizationId} />
      {adding && <ChannelDialog organizationId={organizationId} onClose={() => setAdding(false)} />}
    </div>
  );
}

function NoticesCard({ organizationId }: { organizationId: string | null }) {
  const toast = useToast();
  const q = useApi<{ notices: PlatformNotice[] }>(NOTICES, { organizationId }, { refetchInterval: 15_000 });
  const ack = useApiMutation((id: string) => api.post(`${NOTICES}/${id}/acknowledge`), {
    invalidate: [NOTICES],
    onSuccess: () => toast.success("Acknowledged."),
  });
  const open = q.data?.notices ?? [];
  if (open.length === 0) return null;
  return (
    <div className="flex flex-col gap-2" aria-label="Notices">
      {open.map((n) => (
        <Alert key={n.id} tone="warn" title={n.title}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span>
              {n.detail} <span className="text-muted">Since {formatRelative(n.openedAt)}.</span>
            </span>
            {!n.acknowledgedAt && (
              <Button size="sm" loading={ack.isPending} onClick={() => ack.mutate(n.id)}>
                Acknowledge
              </Button>
            )}
          </div>
        </Alert>
      ))}
    </div>
  );
}

function ChannelRow({ channel: c, ownerLabel }: { channel: NotificationChannel; ownerLabel: string | null }) {
  const toast = useToast();
  const { isSuperAdmin } = useAuth();
  const [secrets, setSecrets] = useState<ChannelSecrets | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [approving, setApproving] = useState(false);
  const [result, setResult] = useState<NotificationTestResult | null>(null);
  const readOnly = c.shared;
  // A platform channel is a super administrator's; an organization's own is its administrators'.
  const manage = !readOnly && (!c.platform || isSuperAdmin);
  const invalidate = [CHANNELS, "/audit"];

  const test = useApiMutation(() => api.post<NotificationTestResult>(`${CHANNELS}/${c.id}/test`), {
    invalidate: [CHANNELS, DELIVERIES],
    onSuccess: (r) => {
      setResult(r);
      if (r.status === "sent") toast.success("The test message was sent.");
    },
  });
  const reveal = useApiMutation(() => api.post<ChannelSecrets>(`${CHANNELS}/${c.id}/reveal`), {
    invalidate: ["/audit"],
    onSuccess: (s) => setSecrets(s),
  });
  const toggle = useApiMutation(() => api.put(`${CHANNELS}/${c.id}`, { enabled: !c.enabled }), { invalidate });
  const del = useApiMutation(() => api.del(`${CHANNELS}/${c.id}`), {
    invalidate,
    onSuccess: () => {
      setDeleting(false);
      toast.success("Channel deleted.");
    },
  });
  const ask = useApiMutation(() => api.post(`${CHANNELS}/${c.id}/approval`), {
    invalidate,
    onSuccess: () => toast.success("A super administrator has been asked to approve this destination."),
  });
  const state = c.state ? STATE[c.state] : undefined;

  return (
    <>
      <tr className="border-b border-line last:border-0">
        <td className="px-4 py-2 align-top">
          <div className="font-medium text-fg">{c.name}</div>
          <div className="text-xs text-muted">
            {c.kind === "email" ? "Email" : "Webhook"}
            {c.shared && " · shared by the platform"}
          </div>
        </td>
        {ownerLabel !== null && <td className="px-4 py-2 align-top text-muted">{ownerLabel}</td>}
        <td className="px-4 py-2 align-top">
          {state ? <Badge tone={state.tone}>{state.label}</Badge> : <span className="text-muted">-</span>}
          {c.state === "failing" && c.lastError && <div className="mt-1 max-w-xs text-xs text-danger">{c.lastError}</div>}
          {c.pending > 0 && <div className="mt-1 text-xs text-muted">{c.pending} waiting</div>}
        </td>
        <td className="px-4 py-2 align-top">
          {c.kind === "email" ? (
            <span title={c.recipients?.join(", ")}>{c.recipients ? `${c.recipients.length} recipient${c.recipients.length === 1 ? "" : "s"}` : "-"}</span>
          ) : c.host ? (
            <Mono>{c.port && c.port !== 443 ? `${c.host}:${c.port}` : c.host}</Mono>
          ) : (
            <span className="text-muted">-</span>
          )}
        </td>
        <td className="px-4 py-2 align-top text-muted">{c.lastSuccessAt ? formatRelative(c.lastSuccessAt) : "Never"}</td>
        <td className="px-4 py-2 align-top">
          <div className="flex flex-wrap justify-end gap-1.5">
            {manage && (
              <Button size="sm" icon={<FlaskConical className="size-3.5" aria-hidden />} loading={test.isPending} disabled={!c.enabled} onClick={() => test.mutate()} aria-label={`Test ${c.name}`}>
                Test
              </Button>
            )}
            {manage && c.kind === "webhook" && (
              <Button size="sm" icon={<Eye className="size-3.5" aria-hidden />} loading={reveal.isPending} onClick={() => reveal.mutate()} aria-label={`Show secret of ${c.name}`}>
                Show secret
              </Button>
            )}
            {manage && c.approval?.state === "requested" && isSuperAdmin && (
              <Button size="sm" variant="primary" icon={<ShieldCheck className="size-3.5" aria-hidden />} onClick={() => setApproving(true)} aria-label={`Approve ${c.name}`}>
                Approve
              </Button>
            )}
            {manage && !c.platform && c.kind === "webhook" && !c.approval && (
              <Button size="sm" loading={ask.isPending} onClick={() => ask.mutate()} aria-label={`Ask for approval of ${c.name}`} title="For a destination on a private network">
                Ask for approval
              </Button>
            )}
            {manage && c.platform && isSuperAdmin && (
              <Button size="sm" icon={<Share2 className="size-3.5" aria-hidden />} onClick={() => setSharing(true)} aria-label={`Share ${c.name}`}>
                Share
              </Button>
            )}
            {manage && (
              <Button size="sm" loading={toggle.isPending} onClick={() => toggle.mutate()} aria-label={`${c.enabled ? "Turn off" : "Turn on"} ${c.name}`}>
                {c.enabled ? "Turn off" : "Turn on"}
              </Button>
            )}
            {manage && (
              <Button size="sm" variant="danger-ghost" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={() => setDeleting(true)} aria-label={`Delete ${c.name}`}>
                Delete
              </Button>
            )}
          </div>
        </td>
      </tr>
      {(result || test.isError || reveal.isError || ask.isError || toggle.isError) && (
        <tr className="border-b border-line last:border-0">
          <td colSpan={ownerLabel !== null ? 6 : 5} className="px-4 pb-3">
            {result && (
              <Alert tone={result.status === "sent" ? "ok" : result.status === "pending" ? "info" : "danger"} title={result.status === "sent" ? "Test sent" : result.status === "pending" ? "Test not finished" : "Test failed"}>
                {result.message}
              </Alert>
            )}
            <InlineError error={test.error ?? reveal.error ?? ask.error ?? toggle.error} />
          </td>
        </tr>
      )}
      {secrets && <SecretsDialog channel={c} secrets={secrets} onClose={() => setSecrets(null)} />}
      {sharing && <ShareDialog channel={c} onClose={() => setSharing(false)} />}
      {approving && c.approval && <ApproveDialog channel={c} onClose={() => setApproving(false)} />}
      <ConfirmDialog open={deleting} onClose={() => setDeleting(false)} onConfirm={() => del.mutate()} title={`Delete ${c.name}?`} confirmLabel="Delete channel" tone="danger" loading={del.isPending} error={del.error}>
        Its waiting messages are dropped. Nothing is sent to it again.
      </ConfirmDialog>
    </>
  );
}

function SecretsDialog({ channel, secrets, onClose }: { channel: NotificationChannel; secrets: ChannelSecrets; onClose: () => void }) {
  const toast = useToast();
  const rotate = useApiMutation(() => api.post(`${CHANNELS}/${channel.id}/rotate-secret`), {
    invalidate: ["/audit"],
    onSuccess: () => {
      toast.success("The signing secret was replaced. Show it again to read the new one.");
      onClose();
    },
  });
  return (
    <Dialog open onClose={onClose} title={`${channel.name}: address and signing secret`} description="Shown because you manage this channel. The view is recorded in the audit log.">
      <div className="flex flex-col gap-3">
        <div>
          <div className="text-xs font-medium text-muted">Web address</div>
          <Mono className="break-all">{secrets.url}</Mono>
        </div>
        <div>
          <div className="text-xs font-medium text-muted">Signing secret</div>
          <Mono className="break-all">{secrets.secret}</Mono>
        </div>
        <p className="text-xs text-muted">
          Each request carries <Mono>X-EasyRMM-Signature: t=&lt;seconds&gt;,v1=&lt;hex&gt;</Mono>, the HMAC-SHA256 of the time, a dot and the body, keyed by this secret. Compare in constant time and refuse a
          time more than five minutes from your clock.
        </p>
        <InlineError error={rotate.error} />
        <div className="flex justify-end gap-2">
          <Button variant="danger-ghost" icon={<KeyRound className="size-4" aria-hidden />} loading={rotate.isPending} onClick={() => rotate.mutate()}>
            Replace secret
          </Button>
          <Button variant="primary" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function ShareDialog({ channel, onClose }: { channel: NotificationChannel; onClose: () => void }) {
  const orgs = useOrganizations();
  const shared = new Set((channel.sharedWith ?? []).map((s) => s.organizationId));
  const flip = useApiMutation(
    (orgId: string) => (shared.has(orgId) ? api.del(`${CHANNELS}/${channel.id}/shares/${orgId}`) : api.put(`${CHANNELS}/${channel.id}/shares/${orgId}`)),
    { invalidate: [CHANNELS, "/audit"] },
  );
  return (
    <Dialog open onClose={onClose} title={`Share ${channel.name}`} description="An organization's rules may use a platform channel once it is shared with that organization. Its administrators see the name and kind only. Unsharing takes it out of their rules.">
      <div className="flex flex-col gap-2">
        {orgs.isPending && <Spinner />}
        {(orgs.data?.items ?? []).map((o) => (
          <label key={o.id} className="flex items-center gap-2.5 text-sm">
            <input type="checkbox" className="size-4 accent-accent" checked={shared.has(o.id)} disabled={flip.isPending} onChange={() => flip.mutate(o.id)} />
            {o.name}
          </label>
        ))}
        <InlineError error={flip.error} />
        <div className="flex justify-end pt-1">
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function ApproveDialog({ channel, onClose }: { channel: NotificationChannel; onClose: () => void }) {
  const toast = useToast();
  const a = channel.approval!;
  const [prefixes, setPrefixes] = useState(a.proposed.join(", "));
  const approve = useApiMutation((list: string[]) => api.post(`${CHANNELS}/${channel.id}/approval/approve`, { prefixes: list }), {
    invalidate: [CHANNELS, "/audit", NOTICES],
    onSuccess: () => {
      toast.success("Approved. Waiting messages are tried now.");
      onClose();
    },
  });
  return (
    <Dialog
      open
      onClose={onClose}
      title={`Approve ${channel.name}`}
      description={`This webhook's destination, ${a.host}:${a.port}, is on a private or local network. EasyRMM sends to it only at the addresses you approve for this channel; loopback, link-local and cloud metadata addresses are never allowed.`}
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          approve.mutate(
            prefixes
              .split(/[\s,]+/)
              .map((p) => p.trim())
              .filter(Boolean),
          );
        }}
      >
        <TextField label="Addresses or networks" value={prefixes} onChange={(e) => setPrefixes(e.target.value)} hint={`The host resolves to ${a.proposed.join(", ") || "nothing"} now. Widen it only as far as you trust.`} error={fieldError(approve.error, "prefixes")} />
        <InlineError error={approve.error} fields={["prefixes"]} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={approve.isPending}>
            Approve
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function ChannelDialog({ organizationId, onClose }: { organizationId: string | null; onClose: () => void }) {
  const toast = useToast();
  const [kind, setKind] = useState<NotificationKind>("email");
  const [name, setName] = useState("");
  const [recipients, setRecipients] = useState("");
  const [url, setUrl] = useState("");
  const [authority, setAuthority] = useState("");
  const create = useApiMutation((input: NotificationChannelInput) => api.post<NotificationChannel>(CHANNELS, input), {
    invalidate: [CHANNELS, "/audit"],
    onSuccess: () => {
      toast.success("Channel added.");
      onClose();
    },
  });
  const submit = () => {
    const input: NotificationChannelInput = { organizationId, kind, name };
    if (kind === "email") input.recipients = recipients.split(/[\s,;]+/).filter(Boolean);
    else {
      input.url = url;
      if (authority.trim()) input.trustedAuthority = authority;
    }
    create.mutate(input);
  };
  return (
    <Dialog open onClose={onClose} title="Add a channel" description={organizationId === null ? "A platform channel is the platform's own; share it with organizations from its row." : undefined}>
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <SelectField label="Kind" value={kind} onChange={(e) => setKind(e.target.value as NotificationKind)}>
          <option value="email">Email</option>
          <option value="webhook">Webhook (signed JSON)</option>
        </SelectField>
        <TextField label="Name" required value={name} maxLength={100} onChange={(e) => setName(e.target.value)} error={fieldError(create.error, "name")} />
        {kind === "email" ? (
          <TextareaField label="Recipients" required value={recipients} onChange={(e) => setRecipients(e.target.value)} hint="One to 20 addresses, separated by commas or lines." error={fieldError(create.error, "recipients")} />
        ) : (
          <>
            <TextField label="Web address" required value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.example.com/easyrmm" hint="HTTPS only. Redirects are not followed. The address is stored sealed." error={fieldError(create.error, "url")} />
            <TextareaField label="Certificate authority to trust (optional)" value={authority} onChange={(e) => setAuthority(e.target.value)} hint="PEM, for a receiver with a private certificate. A self-signed certificate is its own authority." error={fieldError(create.error, "trustedAuthority")} />
          </>
        )}
        <InlineError error={create.error} fields={["name", "recipients", "url", "trustedAuthority", "kind"]} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending}>
            Add channel
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function QuotaCard({ organizationId }: { organizationId: string }) {
  const toast = useToast();
  const path = `/notifications/quotas/${organizationId}`;
  const q = useApi<NotificationQuota>(path);
  const [draft, setDraft] = useState<NotificationQuota | null>(null);
  const save = useApiMutation((v: NotificationQuota) => api.put<NotificationQuota>(path, v), {
    invalidate: [path],
    onSuccess: () => {
      setDraft(null);
      toast.success("Quotas saved.");
    },
  });
  if (!q.data) return null;
  const v = draft ?? q.data;
  const field = (key: keyof NotificationQuota, label: string) => (
    <TextField key={key} label={label} type="number" min={0} value={v[key]} onChange={(e) => setDraft({ ...v, [key]: Number(e.target.value) })} error={fieldError(save.error, key)} />
  );
  return (
    <Card title="Quotas">
      <form
        className="grid max-w-2xl grid-cols-2 gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(v);
        }}
      >
        {field("channels", "Channels")}
        {field("rules", "Rules")}
        {field("testsPerHour", "Tests an hour")}
        {field("messagesPerHour", "Messages an hour")}
        <div className="col-span-2 flex items-center gap-3">
          <Button type="submit" variant="primary" loading={save.isPending} disabled={draft === null}>
            Save quotas
          </Button>
          <span className="text-xs text-muted">A webhook delivery is one message; an email is one per recipient. Over the hour, messages wait for room.</span>
        </div>
        <InlineError error={save.error} fields={["channels", "rules", "testsPerHour", "messagesPerHour"]} />
      </form>
    </Card>
  );
}

function DeliveryLog({ organizationId }: { organizationId: string | null }) {
  const q = useApi<{ deliveries: DeliveryLogRow[]; retentionDays: number }>(DELIVERIES, { organizationId, limit: 50 }, { refetchInterval: 20_000 });
  const rows = q.data?.deliveries ?? [];
  return (
    <Card title="Delivery log" padded={false}>
      {q.isPending ? (
        <div className="p-4">
          <Spinner />
        </div>
      ) : q.isError ? (
        <div className="p-4">
          <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState title="Nothing has been sent yet" compact>
          Every message is kept here for {q.data.retentionDays} days, with each recipient&apos;s outcome.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs text-muted">
                <th className="px-4 py-2 font-medium">Queued</th>
                <th className="px-4 py-2 font-medium">Event</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Outcome</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.id} className="border-b border-line last:border-0">
                  <td className="whitespace-nowrap px-4 py-2 align-top">{formatDateTime(d.queuedAt)}</td>
                  <td className="px-4 py-2 align-top">{d.kind === "test" ? "Test" : d.event}</td>
                  <td className="px-4 py-2 align-top">
                    <Badge tone={d.status === "sent" ? "ok" : d.status === "pending" ? "info" : "danger"}>{d.status}</Badge>
                  </td>
                  <td className="px-4 py-2 align-top text-xs">
                    {d.recipients.length > 1 || (d.recipients[0] && d.recipients[0].recipient !== "(webhook)")
                      ? d.recipients.map((r) => (
                          <div key={r.recipient}>
                            {r.recipient}: {r.status}
                            {r.error ? ` (${r.error})` : ""}
                          </div>
                        ))
                      : d.lastError || ""}
                    {d.mailReply && <div className="text-muted">Mail server: {d.mailReply}</div>}
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
