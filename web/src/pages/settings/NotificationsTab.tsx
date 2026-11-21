import { useState, type ReactNode } from "react";
import { Send, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { MailSecurity, MailServer, MailServerInput, MailServerTest, MailServerTestInput, MailServerView, MailSignIn } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, Dot, ErrorState, InlineError, KeyValueList, Mono, SelectField, Spinner, TextField } from "../../components/ui";
import { formatDateTime, formatNumber, formatRelative, plural } from "../../lib/format";

const PATH = "/settings/mail-server";

const DEFAULT_PORT: Record<MailSecurity, number> = { starttls: 587, tls: 465, none: 25 };

const SECURITY: Record<MailSecurity, string> = {
  starttls: "STARTTLS",
  tls: "TLS from the first byte",
  none: "None (a relay on this machine)",
};

const FIELDS = ["host", "port", "security", "signIn", "username", "password", "fromAddress", "fromName", "to"];

/**
 * Settings → Notifications (ADR-0053). Its first part is the mail server, for super administrators: the one set here,
 * or .env's, which wins; its limits; and its test message.
 */
export function NotificationsTab() {
  const view = useApi<MailServerView>(PATH, undefined, { refetchInterval: 15_000 });
  if (view.isPending) return <Spinner />;
  if (view.isError) return <ErrorState error={view.error} onRetry={() => void view.refetch()} />;
  const v = view.data;
  return (
    <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
      <div className="space-y-5 xl:col-span-2">
        <InForce view={v} />
        {v.inForce === "env" && v.env ? <EnvServer server={v.env} /> : <MailServerForm view={v} />}
      </div>
      <Limits view={v} />
    </div>
  );
}

function InForce({ view }: { view: MailServerView }) {
  switch (view.inForce) {
    case "env":
      return (
        <Alert tone="info" title="The mail server comes from .env">
          EASYRMM_SMTP_HOST is set in .env, and wins over the console: invitations, password resets and the patching engine&apos;s email go through it. To set the mail server here,
          remove the EASYRMM_SMTP_ settings from .env and restart EasyRMM.
        </Alert>
      );
    case "none":
      return (
        <Alert tone="warn" title="No mail server">
          Until one is set, password reset is off, invitation and password links come back to whoever sends them, and the patching engine sends no email or monthly reports.
        </Alert>
      );
    default:
      return null;
  }
}

/** .env's mail server, read-only, with its test message. */
function EnvServer({ server }: { server: MailServer }) {
  return (
    <Card title="Mail server">
      <KeyValueList narrow items={serverItems(server)} />
      <div className="mt-4 border-t border-line pt-4">
        <TestMessage input={() => undefined} />
      </div>
    </Card>
  );
}

function serverItems(s: MailServer): [string, ReactNode][] {
  return [
    ["Server", <Mono key="h">{s.host.includes(":") ? `[${s.host}]:${s.port}` : `${s.host}:${s.port}`}</Mono>],
    ["Security", SECURITY[s.security]],
    ["Signs in", s.signIn === "password" ? <span key="u">as <Mono>{s.username}</Mono>{s.passwordSet ? ", with a password" : ""}</span> : "No"],
    ["Sends as", s.fromName ? `${s.fromName} <${s.fromAddress}>` : s.fromAddress],
  ];
}

interface FormState {
  host: string;
  port: string;
  security: MailSecurity;
  signIn: MailSignIn;
  username: string;
  password: string;
  fromAddress: string;
  fromName: string;
}

function fromServer(s?: MailServer): FormState {
  return {
    host: s?.host ?? "",
    port: String(s?.port ?? DEFAULT_PORT.starttls),
    security: s?.security ?? "starttls",
    signIn: s?.signIn ?? "password",
    username: s?.username ?? "",
    password: "",
    fromAddress: s?.fromAddress ?? "",
    fromName: s?.fromName ?? "EasyRMM",
  };
}

function MailServerForm({ view }: { view: MailServerView }) {
  const toast = useToast();
  const stored = view.console;
  const [form, setForm] = useState<FormState>(() => fromServer(stored));
  const [removing, setRemoving] = useState(false);
  const set = <K extends keyof FormState>(key: K, value: FormState[K]) => setForm((f) => ({ ...f, [key]: value }));
  const password = form.signIn === "password";
  // A stored password is kept only while the host and the user name stay the same.
  const keepsPassword =
    !!stored?.passwordSet && stored.host.toLowerCase() === form.host.trim().toLowerCase() && stored.username === form.username.trim() && password;

  const input = (): MailServerInput => ({
    host: form.host.trim(),
    port: Number(form.port) || 0,
    security: form.security,
    signIn: form.signIn,
    username: password ? form.username.trim() : "",
    password: password ? form.password : "",
    fromAddress: form.fromAddress.trim(),
    fromName: form.fromName.trim(),
  });

  const save = useApiMutation((body: MailServerInput) => api.put<MailServerView>(PATH, body), {
    invalidate: [PATH, "/audit", "/auth/options"],
    onSuccess: (v) => {
      setForm(fromServer(v.console));
      toast.success(`Saved. EasyRMM sends mail through ${v.console?.host ?? form.host.trim()}.`);
    },
  });
  const remove = useApiMutation(() => api.del<MailServerView>(PATH), {
    invalidate: [PATH, "/audit", "/auth/options"],
    onSuccess: () => {
      setRemoving(false);
      setForm(fromServer());
      toast.success("The mail server is removed.");
    },
  });
  const err = (field: string) => fieldError(save.error, field);

  const changeSecurity = (s: MailSecurity) =>
    setForm((f) => ({ ...f, security: s, port: f.port === "" || Number(f.port) === DEFAULT_PORT[f.security] ? String(DEFAULT_PORT[s]) : f.port }));

  return (
    <Card title="Mail server">
      <form
        className="space-y-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(input());
        }}
      >
        <p className="text-sm text-muted">
          Invitations, password resets and the patching engine&apos;s email and monthly reports go through it, as soon as it is saved. Each recipient gets a message of their own.
        </p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_7rem]">
          <TextField
            label="Server"
            hint="Host name or IP address of your mail server or relay."
            placeholder="smtp.example.com"
            value={form.host}
            onChange={(e) => set("host", e.target.value)}
            error={err("host")}
            autoComplete="off"
            spellCheck={false}
            required
          />
          <TextField label="Port" inputMode="numeric" value={form.port} onChange={(e) => set("port", e.target.value.replace(/\D/g, "").slice(0, 5))} error={err("port")} required />
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <SelectField
            label="Security"
            value={form.security}
            onChange={(e) => changeSecurity(e.target.value as MailSecurity)}
            error={err("security")}
            hint={
              form.security === "none"
                ? "Not encrypted, so only to a relay on this machine: localhost or a loopback address."
                : "Encrypted, and the server's certificate is checked against the authorities this server trusts."
            }
          >
            <option value="starttls">STARTTLS (usually port 587)</option>
            <option value="tls">TLS from the first byte (usually port 465)</option>
            <option value="none">None (a relay on this machine)</option>
          </SelectField>
          <SelectField label="Sign in" value={form.signIn} onChange={(e) => set("signIn", e.target.value as MailSignIn)} error={err("signIn")}>
            <option value="password">With a user name and password</option>
            <option value="none">Not at all</option>
          </SelectField>
        </div>
        {password && (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <TextField label="User name" value={form.username} onChange={(e) => set("username", e.target.value)} error={err("username")} autoComplete="off" spellCheck={false} required />
            <TextField
              label="Password"
              type="password"
              value={form.password}
              onChange={(e) => set("password", e.target.value)}
              error={err("password")}
              autoComplete="new-password"
              placeholder={keepsPassword ? "Stored" : ""}
              hint={keepsPassword ? "A password is stored, encrypted. Leave this empty to keep it." : "Stored encrypted and never shown again."}
            />
          </div>
        )}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <TextField
            label="Send from"
            type="email"
            placeholder="rmm@example.com"
            value={form.fromAddress}
            onChange={(e) => set("fromAddress", e.target.value)}
            error={err("fromAddress")}
            hint="The address messages come from. Your mail server must allow it."
            spellCheck={false}
            required
          />
          <TextField label="Sender's name" value={form.fromName} onChange={(e) => set("fromName", e.target.value)} error={err("fromName")} hint="Shown with the address." />
        </div>

        <InlineError error={save.error} fields={FIELDS} />

        <div className="border-t border-line pt-4">
          <TestMessage input={input} />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-4">
          <span className="text-xs text-muted">
            {stored?.updatedAt && (
              <>
                Changed <span title={formatDateTime(stored.updatedAt)}>{formatRelative(stored.updatedAt)}</span>
                {stored.updatedBy && <> by {stored.updatedBy}</>}
              </>
            )}
          </span>
          <div className="flex gap-2">
            {stored && (
              <Button type="button" variant="danger" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={() => setRemoving(true)} disabled={save.isPending}>
                Remove
              </Button>
            )}
            <Button type="submit" variant="primary" loading={save.isPending}>
              Save
            </Button>
          </div>
        </div>
      </form>
      <ConfirmDialog
        open={removing}
        onClose={() => setRemoving(false)}
        onConfirm={() => remove.mutate(undefined)}
        title="Remove the mail server?"
        confirmLabel="Remove"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        EasyRMM will send no mail: password reset stops, invitation and password links come back to whoever sends them, and the patching engine&apos;s email and monthly reports
        stop. The limits stay.
      </ConfirmDialog>
    </Card>
  );
}

/**
 * The test message: EasyRMM's own words, to an address the super administrator enters (their own at first), through the
 * form as it stands, or .env's mail server. One every 30 seconds.
 */
function TestMessage({ input }: { input: () => MailServerInput | undefined }) {
  const { session } = useAuth();
  const [to, setTo] = useState(session?.user.email ?? "");
  const test = useApiMutation((body: MailServerTestInput) => api.post<MailServerTest>(`${PATH}/test`, body), { invalidate: [PATH, "/audit"] });
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-2">
        <TextField
          label="Send a test message to"
          type="email"
          className="min-w-64 flex-1"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          error={fieldError(test.error, "to")}
          spellCheck={false}
        />
        <Button
          type="button"
          icon={<Send className="size-3.5" aria-hidden />}
          loading={test.isPending}
          onClick={() => {
            const server = input();
            test.mutate(server ? { to: to.trim(), server } : { to: to.trim() });
          }}
        >
          Send test message
        </Button>
      </div>
      <InlineError error={test.error} fields={FIELDS} />
      {test.data && !test.isPending && (
        <Alert tone={test.data.ok ? "ok" : "danger"} title={test.data.ok ? "Test message sent" : "The test message did not go"}>
          {test.data.message}
        </Alert>
      )}
    </div>
  );
}

function Limits({ view }: { view: MailServerView }) {
  const toast = useToast();
  const { limits, usage } = view;
  const [perMinute, setPerMinute] = useState(String(limits.perMinute));
  const [perDay, setPerDay] = useState(String(limits.perDay));
  const save = useApiMutation((body: { perMinute: number; perDay: number }) => api.put<MailServerView>(`${PATH}/limits`, body), {
    invalidate: [PATH, "/audit"],
    onSuccess: (v) => {
      setPerMinute(String(v.limits.perMinute));
      setPerDay(String(v.limits.perDay));
      toast.success(`Up to ${formatNumber(v.limits.perMinute)} messages a minute and ${formatNumber(v.limits.perDay)} a day.`);
    },
  });
  const full = usage.lastDay >= usage.otherDayLimit;
  const tone = full ? "warn" : "ok";
  return (
    <Card title="Limits">
      <form
        className="space-y-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate({ perMinute: Number(perMinute) || 0, perDay: Number(perDay) || 0 });
        }}
      >
        <div className="grid grid-cols-2 gap-3">
          <TextField
            label="A minute"
            inputMode="numeric"
            value={perMinute}
            onChange={(e) => setPerMinute(e.target.value.replace(/\D/g, "").slice(0, 5))}
            error={fieldError(save.error, "perMinute")}
          />
          <TextField label="A day" inputMode="numeric" value={perDay} onChange={(e) => setPerDay(e.target.value.replace(/\D/g, "").slice(0, 7))} error={fieldError(save.error, "perDay")} />
        </div>
        <InlineError error={save.error} fields={["perMinute", "perDay"]} />
        <div className="flex justify-end">
          <Button type="submit" loading={save.isPending}>
            Save limits
          </Button>
        </div>
      </form>
      <KeyValueList
        narrow
        className="mt-4 border-t border-line pt-4"
        items={[
          ["Last minute", `${formatNumber(usage.lastMinute)} of ${formatNumber(limits.perMinute)}`],
          [
            "Last 24 hours",
            <span key="d">
              <Badge tone={tone} icon={<Dot tone={tone} />}>
                {formatNumber(usage.lastDay)} of {formatNumber(limits.perDay)}
              </Badge>
              <span className="mt-1 block text-xs text-muted">
                {formatNumber(usage.accountLastDay)} {plural(usage.accountLastDay, "invitation or password reset", "invitations and password resets")}
              </span>
            </span>,
          ],
        ]}
      />
      <div className="mt-4 space-y-2 border-t border-line pt-4 text-sm text-muted">
        <p>
          They hold whichever mail server is in force, counted per recipient. Patching&apos;s email and monthly reports, which the patching engine still sends itself, are not
          counted. The defaults, 30 a minute and 9,000 a day, stay under Exchange Online&apos;s limits; set your own mail server&apos;s.
        </p>
        <p>
          Invitations and password resets go first: they may use the whole day, and wait up to a minute for room. Other mail stops at {formatNumber(usage.otherDayLimit)}, 90% of
          the day&apos;s limit.
        </p>
        {limits.updatedAt && (
          <p className="text-xs">
            Changed <span title={formatDateTime(limits.updatedAt)}>{formatRelative(limits.updatedAt)}</span>
            {limits.updatedBy && <> by {limits.updatedBy}</>}
          </p>
        )}
      </div>
    </Card>
  );
}
