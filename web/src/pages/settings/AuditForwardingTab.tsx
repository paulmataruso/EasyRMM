import { useId, useState, type ReactNode } from "react";
import { Send } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { AuditForwarding, AuditForwardingInput, AuditForwardingTest, SyslogTransport } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, Dot, ErrorState, InlineError, KeyValueList, Mono, SelectField, Spinner, TextField, TextareaField, type Tone } from "../../components/ui";
import { formatDateTime, formatNumber, formatRelative, plural } from "../../lib/format";

const DEFAULT_PORT: Record<SyslogTransport, number> = { tls: 6514, tcp: 514, udp: 514 };

const FACILITIES: [number, string][] = [
  [13, "log audit (13)"],
  [4, "auth (4)"],
  [10, "authpriv (10)"],
  ...Array.from({ length: 8 }, (_, i): [number, string] => [16 + i, `local${i} (${16 + i})`]),
];

const FIELDS = ["transport", "host", "port", "facility", "caCert", "clientCert", "clientKey", "startFrom"];

/** Platform settings: sending the audit log to a syslog collector (ADR-0023). */
export function AuditForwardingTab() {
  const settings = useApi<AuditForwarding>("/settings/audit-forwarding", undefined, { refetchInterval: 10_000 });
  if (settings.isPending) return <Spinner />;
  if (settings.isError) return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  return (
    <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
      <ForwardingForm settings={settings.data} className="xl:col-span-2" />
      <ForwardingStatus settings={settings.data} />
    </div>
  );
}

interface FormState {
  enabled: boolean;
  transport: SyslogTransport;
  host: string;
  port: string;
  facility: string;
  caCert: string;
  clientCert: string;
  clientKey: string;
  startFrom: "now" | "beginning";
}

function fromSettings(s: AuditForwarding): FormState {
  return {
    enabled: s.configured ? s.enabled : true,
    transport: s.transport,
    host: s.host,
    port: String(s.port),
    facility: String(s.facility),
    caCert: s.caCert,
    clientCert: s.clientCert,
    clientKey: "",
    startFrom: "beginning",
  };
}

function ForwardingForm({ settings, className }: { settings: AuditForwarding; className?: string }) {
  const toast = useToast();
  const [form, setForm] = useState<FormState>(() => fromSettings(settings));
  const set = <K extends keyof FormState>(key: K, value: FormState[K]) => setForm((f) => ({ ...f, [key]: value }));
  const turningOn = form.enabled && !(settings.configured && settings.enabled);
  const tls = form.transport === "tls";
  const keyStored = settings.clientKeySet && form.clientCert.trim() === settings.clientCert.trim() && form.clientCert.trim() !== "";
  const startId = useId();

  const input = (): AuditForwardingInput => ({
    enabled: form.enabled,
    transport: form.transport,
    host: form.host.trim(),
    port: Number(form.port) || 0,
    facility: Number(form.facility),
    caCert: tls ? form.caCert : "",
    clientCert: tls ? form.clientCert : "",
    clientKey: tls ? form.clientKey : "",
    startFrom: turningOn ? form.startFrom : "",
  });

  const save = useApiMutation((body: AuditForwardingInput) => api.put<AuditForwarding>("/settings/audit-forwarding", body), {
    invalidate: ["/settings/audit-forwarding", "/audit"],
    onSuccess: (s) => {
      setForm(fromSettings(s));
      toast.success(s.enabled ? `Forwarding the audit log to ${s.host}:${s.port}.` : "Saved. Audit forwarding is off.");
    },
  });
  const test = useApiMutation((body: AuditForwardingInput) => api.post<AuditForwardingTest>("/settings/audit-forwarding/test", body), {
    invalidate: ["/audit"],
  });
  const error = save.error ?? test.error;
  const err = (field: string) => fieldError(error, field);

  const changeTransport = (t: SyslogTransport) =>
    setForm((f) => ({ ...f, transport: t, port: f.port === "" || Number(f.port) === DEFAULT_PORT[f.transport] ? String(DEFAULT_PORT[t]) : f.port }));

  return (
    <Card title="Collector" className={className}>
      <form
        className="space-y-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          test.reset();
          save.mutate(input());
        }}
      >
        <label className="flex items-start gap-2.5 text-sm">
          <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} className="mt-0.5 size-4 accent-accent" />
          <span>
            <span className="font-medium">Forward the audit log</span>
            <span className="block text-muted">Every record, in order, as it is written: sign-ins, remote sessions, scripts, changes to settings.</span>
          </span>
        </label>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_7rem]">
          <TextField
            label="Collector"
            hint="Host name or IP address of your syslog server or SIEM."
            placeholder="siem.example.com"
            value={form.host}
            onChange={(e) => set("host", e.target.value)}
            error={err("host")}
            autoComplete="off"
            spellCheck={false}
            required
          />
          <TextField
            label="Port"
            inputMode="numeric"
            value={form.port}
            onChange={(e) => set("port", e.target.value.replace(/\D/g, "").slice(0, 5))}
            error={err("port")}
            required
          />
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <SelectField
            label="Transport"
            value={form.transport}
            onChange={(e) => changeTransport(e.target.value as SyslogTransport)}
            error={err("transport")}
            hint={
              form.transport === "udp"
                ? "No delivery confirmation and no encryption. Use only on a network you trust."
                : form.transport === "tcp"
                  ? "Not encrypted: records cross the network in clear text."
                  : "Encrypted, and the collector's certificate is checked."
            }
          >
            <option value="tls">TLS (RFC 5425)</option>
            <option value="tcp">TCP (RFC 6587)</option>
            <option value="udp">UDP (RFC 5426)</option>
          </SelectField>
          <SelectField label="Facility" value={form.facility} onChange={(e) => set("facility", e.target.value)} error={err("facility")}>
            {FACILITIES.map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </SelectField>
        </div>

        {tls && (
          <div className="space-y-3">
            <TextareaField
              label="CA certificate"
              hint="The authority that signed the collector's certificate, in PEM. Leave empty to trust the authorities this server trusts."
              placeholder="-----BEGIN CERTIFICATE-----"
              value={form.caCert}
              onChange={(e) => set("caCert", e.target.value)}
              error={err("caCert")}
              className="[&_textarea]:font-mono [&_textarea]:text-xs"
              rows={4}
              spellCheck={false}
            />
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              <TextareaField
                label="Client certificate"
                hint="Only for collectors that require one."
                placeholder="-----BEGIN CERTIFICATE-----"
                value={form.clientCert}
                onChange={(e) => set("clientCert", e.target.value)}
                error={err("clientCert")}
                className="[&_textarea]:font-mono [&_textarea]:text-xs"
                rows={4}
                spellCheck={false}
              />
              <TextareaField
                label="Client key"
                hint={keyStored ? "A key is stored, encrypted. Paste a new one to replace it." : "Unencrypted PEM. Stored encrypted and never shown again."}
                placeholder={keyStored ? "Stored" : "-----BEGIN PRIVATE KEY-----"}
                value={form.clientKey}
                onChange={(e) => set("clientKey", e.target.value)}
                error={err("clientKey")}
                className="[&_textarea]:font-mono [&_textarea]:text-xs"
                rows={4}
                spellCheck={false}
                autoComplete="off"
                disabled={!form.clientCert.trim()}
              />
            </div>
          </div>
        )}

        {turningOn && (
          <fieldset className="space-y-1.5" aria-describedby={startId}>
            <legend className="text-xs font-medium text-muted">Start with</legend>
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" name="startFrom" checked={form.startFrom === "beginning"} onChange={() => set("startFrom", "beginning")} className="size-4 accent-accent" />
              Every record in the log ({formatNumber(settings.status.stored)}
              {settings.status.storedMore ? "+" : ""})
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" name="startFrom" checked={form.startFrom === "now"} onChange={() => set("startFrom", "now")} className="size-4 accent-accent" />
              Only records written from now on
            </label>
            <p id={startId} className="text-xs text-subtle">
              Records the collector has not received yet are kept past the audit retention period.
            </p>
          </fieldset>
        )}

        <InlineError error={error} fields={FIELDS} />
        {test.data && !test.isPending && (
          <Alert tone={test.data.ok ? "ok" : "danger"} title={test.data.ok ? "Test message sent" : "The test message did not go"}>
            {test.data.message}
          </Alert>
        )}

        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line pt-4">
          <Button
            type="button"
            icon={<Send className="size-3.5" aria-hidden />}
            loading={test.isPending}
            disabled={save.isPending}
            onClick={() => {
              save.reset();
              test.mutate(input());
            }}
          >
            Send test message
          </Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={test.isPending}>
            Save
          </Button>
        </div>
      </form>
    </Card>
  );
}

function forwardingState(s: AuditForwarding): { label: string; tone: Tone } {
  if (s.configured && s.status.stopping) return { label: "Sending its last records", tone: "info" };
  if (!s.configured || !s.enabled) return { label: "Off", tone: "neutral" };
  const { lastErrorAt, lastSentAt, backlog } = s.status;
  if (lastErrorAt && (!lastSentAt || Date.parse(lastErrorAt) > Date.parse(lastSentAt))) return { label: "Failing", tone: "danger" };
  if (backlog > 500) return { label: "Catching up", tone: "info" };
  return { label: "Forwarding", tone: "ok" };
}

function When({ at }: { at?: string }) {
  return at ? <span title={formatDateTime(at)}>{formatRelative(at)}</span> : null;
}

function ForwardingStatus({ settings: s }: { settings: AuditForwarding }) {
  const state = forwardingState(s);
  const st = s.status;
  const recovered = st.lastErrorAt && st.lastSentAt && Date.parse(st.lastSentAt) > Date.parse(st.lastErrorAt);
  const items: [string, ReactNode][] = [
    [
      "State",
      <Badge key="s" tone={state.tone} icon={<Dot tone={state.tone} />}>
        {state.label}
      </Badge>,
    ],
  ];
  if (s.configured) {
    items.push(["Last sent", st.lastSentAt ? <When at={st.lastSentAt} /> : <span className="text-muted">Nothing yet</span>]);
  }
  if (s.configured && (s.enabled || st.stopping)) {
    items.push(
      [
        "Waiting",
        st.backlog > 0 ? (
          <span>
            {formatNumber(st.backlog)}
            {st.backlogMore ? "+" : ""} {plural(st.backlog, "record")}
            {st.oldestPendingAt && (
              <span className="block text-xs text-muted">
                oldest from <When at={st.oldestPendingAt} />
              </span>
            )}
          </span>
        ) : (
          <span className="text-muted">Nothing</span>
        ),
      ],
    );
  }
  if (s.configured) {
    if (st.lastError) {
      items.push([
        "Last error",
        <span key="e">
          <span className={recovered ? "block break-words text-muted" : "block break-words text-danger"}>{st.lastError}</span>
          <span className="text-xs text-muted">
            <When at={st.lastErrorAt} />
            {recovered && " · delivering again since"}
          </span>
        </span>,
      ]);
    }
    if (s.updatedAt) {
      items.push([
        "Changed",
        <span key="c">
          <When at={s.updatedAt} />
          {s.updatedBy && <span className="text-muted"> by {s.updatedBy}</span>}
        </span>,
      ]);
    }
  }
  items.push(["Sent as", <Mono key="h">{s.hostname}</Mono>]);

  return (
    <Card title="Status">
      <KeyValueList narrow items={items} />
      <div className="mt-4 space-y-2 border-t border-line pt-4 text-sm text-muted">
        <p>
          Each record goes as an RFC 5424 message from <Mono className="break-normal whitespace-nowrap">easyrmm</Mono>, with the action as its message ID and the record as JSON, including the hashes
          that chain it to the one before.
        </p>
        <p>Forwarding resumes where it stopped after an outage or a restart. A record can arrive twice after a failure; its id tells the copies apart.</p>
      </div>
    </Card>
  );
}
