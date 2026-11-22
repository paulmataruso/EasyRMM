import { useState, type ReactNode } from "react";
import { Send, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type {
  MailApplication,
  MailCertificate,
  MailCheck,
  MailCredential,
  MailSecurity,
  MailServer,
  MailServerInput,
  MailServerTest,
  MailServerTestInput,
  MailServerView,
  MailSignIn,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, Dot, ErrorState, InlineError, KeyValueList, Mono, SelectField, Spinner, TextareaField, TextField } from "../../components/ui";
import { formatDateTime, formatNumber, formatRelative, plural } from "../../lib/format";

const PATH = "/settings/mail-server";

const DEFAULT_PORT: Record<MailSecurity, number> = { starttls: 587, tls: 465, none: 25 };

const SECURITY: Record<MailSecurity, string> = {
  starttls: "STARTTLS",
  tls: "TLS from the first byte",
  none: "None (a relay on this machine)",
};

const FIELDS = ["host", "port", "security", "signIn", "username", "password", "fromAddress", "fromName", "to", "tenantId", "clientId", "credential", "clientSecret", "certificate", "certificateKey"];

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
        {v.engineWithheld && (
          <Alert tone="warn" title="Patching sends no email">
            {v.engineWithheld}
          </Alert>
        )}
        <LastCheck check={v.check} />
        {v.inForce === "env" && v.env ? (
          <>
            {v.envProblem && (
              <Alert tone="danger" title="The patching engine cannot be given .env's mail server">
                {v.envProblem}
              </Alert>
            )}
            <EnvServer server={v.env} />
            {v.console && <UnusedConsoleServer server={v.console} />}
          </>
        ) : (
          <MailServerForm view={v} />
        )}
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
          EASYRMM_SMTP_HOST is set in .env, and wins over the console: invitations, password resets
          {view.engineWithheld ? "" : " and the patching engine's email"} go through it. To set the mail server here, remove the EASYRMM_SMTP_ settings from .env and restart
          EasyRMM.
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

/** This server's last check of the mail server in force: at start, after every change, and daily. */
function LastCheck({ check }: { check?: MailCheck }) {
  if (!check) return null;
  return (
    <Alert tone={check.ok ? "ok" : "danger"} title={check.ok ? "The mail server passed this server's check" : "This server's check of the mail server failed"}>
      <span className="block break-words">{check.message}</span>
      <span className="mt-1 block text-xs">
        Checked <span title={formatDateTime(check.at)}>{formatRelative(check.at)}</span> by connecting and signing in, sending nothing: at start, after every change and
        daily. To check now, run <Mono>docker compose exec server easyrmm-server mail check</Mono>.
      </span>
    </Alert>
  );
}

/** The application's certificate has ended, or ends within 30 days. */
function CertificateWarning({ app }: { app?: MailApplication }) {
  if (!app?.certificateWarning) return null;
  const ended = !!app.certificate && new Date(app.certificate.notAfter).getTime() <= Date.now();
  return (
    <Alert tone={ended ? "danger" : "warn"} title={ended ? "The application's certificate cannot sign in" : "The application's certificate ends soon"}>
      {app.certificateWarning}
    </Alert>
  );
}

/** .env's mail server, read-only, with its test message. */
function EnvServer({ server }: { server: MailServer }) {
  return (
    <Card title="Mail server">
      <div className="space-y-4">
        <CertificateWarning app={server.application} />
        <KeyValueList narrow items={serverItems(server)} />
      </div>
      <div className="mt-4 border-t border-line pt-4">
        <TestMessage input={() => undefined} />
      </div>
    </Card>
  );
}

/**
 * The console's mail server, saved before .env set one: unused while .env's is in force. Removing it deletes its stored
 * password and changes nothing that is sent.
 */
function UnusedConsoleServer({ server }: { server: MailServer }) {
  const toast = useToast();
  const [removing, setRemoving] = useState(false);
  const remove = useApiMutation(() => api.del<MailServerView>(PATH), {
    invalidate: [PATH, "/audit"],
    onSuccess: () => {
      setRemoving(false);
      toast.success("The console's mail server is removed. .env's stays in force.");
    },
  });
  return (
    <Card title="Saved in the console, not in use">
      <p className="mb-3 text-sm text-muted">
        This mail server was saved here before .env set one. It is not used while .env&apos;s is in force, and would be again if EASYRMM_SMTP_HOST were removed from .env.
      </p>
      <KeyValueList narrow items={serverItems(server)} />
      <div className="mt-4 flex justify-end border-t border-line pt-4">
        <Button type="button" variant="danger" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={() => setRemoving(true)}>
          Remove
        </Button>
      </div>
      <ConfirmDialog
        open={removing}
        onClose={() => setRemoving(false)}
        onConfirm={() => remove.mutate(undefined)}
        title="Remove the console's mail server?"
        confirmLabel="Remove"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        Its settings and stored password, secret or key are deleted. This does not change the mail server in force: .env&apos;s stays, and mail goes on as before.
      </ConfirmDialog>
    </Card>
  );
}

function signsIn(s: MailServer): ReactNode {
  switch (s.signIn) {
    case "password":
      return (
        <span key="u">
          as <Mono>{s.username}</Mono>
          {s.passwordSet ? ", with a password" : ""}
        </span>
      );
    case "microsoft365":
      return (
        <span key="u">
          to <Mono>{s.fromAddress}</Mono>, with a Microsoft 365 application&apos;s token
        </span>
      );
    default:
      return "No";
  }
}

function CertificateSummary({ cert }: { cert: MailCertificate }) {
  return (
    <span>
      A certificate, thumbprint <Mono>{cert.thumbprint}</Mono>
      <span className="mt-1 block text-xs break-words text-muted">
        {cert.subject}; valid until {formatDateTime(cert.notAfter)}
      </span>
    </span>
  );
}

function serverItems(s: MailServer): [string, ReactNode][] {
  const items: [string, ReactNode][] = [
    ["Server", <Mono key="h">{s.host.includes(":") ? `[${s.host}]:${s.port}` : `${s.host}:${s.port}`}</Mono>],
    ["Security", SECURITY[s.security]],
    ["Signs in", signsIn(s)],
  ];
  const app = s.application;
  if (app) {
    items.push(
      ["Tenant", <Mono key="t">{app.tenantId}</Mono>],
      ["Application", <Mono key="a">{app.clientId}</Mono>],
      [
        "Credential",
        app.credential === "certificate" && app.certificate ? (
          <CertificateSummary key="c" cert={app.certificate} />
        ) : app.secretSet ? (
          "A client secret, never shown"
        ) : (
          "A client secret"
        ),
      ],
    );
  }
  items.push(["Sends as", s.fromName ? `${s.fromName} <${s.fromAddress}>` : s.fromAddress]);
  return items;
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
  tenantId: string;
  clientId: string;
  credential: MailCredential;
  clientSecret: string;
  certificate: string;
  certificateKey: string;
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
    tenantId: s?.application?.tenantId ?? "",
    clientId: s?.application?.clientId ?? "",
    credential: s?.application?.credential ?? "secret",
    clientSecret: "",
    certificate: "",
    certificateKey: "",
  };
}

/** Exchange Online's client submission, which a Microsoft 365 application signs in to. */
const EXCHANGE = { host: "smtp.office365.com", port: "587", security: "starttls" as MailSecurity };

function MailServerForm({ view }: { view: MailServerView }) {
  const toast = useToast();
  const stored = view.console;
  const [form, setForm] = useState<FormState>(() => fromServer(stored));
  const [removing, setRemoving] = useState(false);
  const set = <K extends keyof FormState>(key: K, value: FormState[K]) => setForm((f) => ({ ...f, [key]: value }));
  const password = form.signIn === "password";
  const application = form.signIn === "microsoft365";
  const sameServer =
    !!stored && stored.host.toLowerCase() === form.host.trim().toLowerCase() && stored.port === Number(form.port) && stored.security === form.security;
  // A stored password is kept only while the host, the port, the security and the user name stay the same.
  const keepsPassword = !!stored?.passwordSet && sameServer && stored.username === form.username.trim() && password;
  // A stored secret, or certificate and key, only while the server, the tenant, the application and the credential's kind do.
  const storedApp = stored?.signIn === "microsoft365" ? stored.application : undefined;
  const keepsApp =
    !!storedApp &&
    application &&
    sameServer &&
    storedApp.tenantId.toLowerCase() === form.tenantId.trim().toLowerCase() &&
    storedApp.clientId.toLowerCase() === form.clientId.trim().toLowerCase() &&
    storedApp.credential === form.credential;

  const input = (): MailServerInput => ({
    host: form.host.trim(),
    port: Number(form.port) || 0,
    security: form.security,
    signIn: form.signIn,
    username: password ? form.username.trim() : "",
    password: password ? form.password : "",
    fromAddress: form.fromAddress.trim(),
    fromName: form.fromName.trim(),
    ...(application && {
      tenantId: form.tenantId.trim(),
      clientId: form.clientId.trim(),
      credential: form.credential,
      clientSecret: form.credential === "secret" ? form.clientSecret.trim() : "",
      certificate: form.credential === "certificate" ? form.certificate.trim() : "",
      certificateKey: form.credential === "certificate" ? form.certificateKey.trim() : "",
    }),
  });

  const save = useApiMutation((body: MailServerInput) => api.put<MailServerView>(PATH, body), {
    invalidate: [PATH, "/audit", "/auth/options", "/patching/notifications"],
    onSuccess: (v) => {
      setForm(fromServer(v.console));
      toast.success(`Saved. EasyRMM sends mail through ${v.console?.host ?? form.host.trim()}.`);
    },
  });
  const remove = useApiMutation(() => api.del<MailServerView>(PATH), {
    invalidate: [PATH, "/audit", "/auth/options", "/patching/notifications"],
    onSuccess: () => {
      setRemoving(false);
      setForm(fromServer());
      toast.success("The mail server is removed.");
    },
  });
  const err = (field: string) => fieldError(save.error, field);

  const changeSecurity = (s: MailSecurity) =>
    setForm((f) => ({ ...f, security: s, port: f.port === "" || Number(f.port) === DEFAULT_PORT[f.security] ? String(DEFAULT_PORT[s]) : f.port }));
  // An application signs in only over TLS: a blank server becomes Exchange Online's, and no encryption STARTTLS.
  const changeSignIn = (s: MailSignIn) =>
    setForm((f) => {
      if (s !== "microsoft365") return { ...f, signIn: s };
      if (f.host.trim() === "") return { ...f, signIn: s, ...EXCHANGE };
      return f.security === "none" ? { ...f, signIn: s, security: "starttls", port: EXCHANGE.port } : { ...f, signIn: s };
    });

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
          Invitations, password resets{application ? "" : " and the patching engine's email and monthly reports"} go through it, as soon as it is saved. Each recipient gets a
          message of their own.
        </p>
        <CertificateWarning app={storedApp} />
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_7rem]">
          <TextField
            label="Server"
            hint={application ? "Exchange Online's is smtp.office365.com, port 587, STARTTLS." : "Host name or IP address of your mail server or relay."}
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
            <option value="none" disabled={application}>
              None (a relay on this machine)
            </option>
          </SelectField>
          <SelectField label="Sign in" value={form.signIn} onChange={(e) => changeSignIn(e.target.value as MailSignIn)} error={err("signIn")}>
            <option value="password">With a user name and password</option>
            <option value="microsoft365">With a Microsoft 365 application</option>
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
              maxLength={512}
              placeholder={keepsPassword ? "Stored" : ""}
              hint={
                keepsPassword
                  ? "A password is stored, encrypted. Leave this empty to keep it."
                  : stored?.passwordSet
                    ? "Enter it again: the stored one is kept only for the same server, port, security and user name."
                    : "Stored encrypted and never shown again."
              }
            />
          </div>
        )}
        {application && <ApplicationFields form={form} set={set} err={err} storedApp={storedApp} keeps={keepsApp} />}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <TextField
            label="Send from"
            type="email"
            placeholder="rmm@example.com"
            value={form.fromAddress}
            onChange={(e) => set("fromAddress", e.target.value)}
            error={err("fromAddress")}
            hint={application ? "The mailbox the application signs in to and sends as. It must be given to the application in Exchange Online." : "The address messages come from. Your mail server must allow it."}
            spellCheck={false}
            required
          />
          <TextField
            label="Sender's name"
            value={form.fromName}
            onChange={(e) => set("fromName", e.target.value)}
            error={err("fromName")}
            hint="Shown with the address."
            maxLength={100}
          />
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
 * A Microsoft 365 application's sign-in (ADR-0053, slice 2): the Entra application, with its client secret or its
 * certificate and private key, which are stored encrypted and never shown. Warned before saving: the patching engine
 * cannot sign in this way, so it is given no mail server.
 */
function ApplicationFields({
  form,
  set,
  err,
  storedApp,
  keeps,
}: {
  form: FormState;
  set: <K extends keyof FormState>(key: K, value: FormState[K]) => void;
  err: (field: string) => string | null | undefined;
  storedApp?: MailApplication;
  keeps: boolean;
}) {
  const storedCert = keeps ? storedApp?.certificate : undefined;
  return (
    <div className="space-y-4">
      <Alert tone="warn" title="Patching's email stops while an application signs in">
        The patching engine cannot sign in with a Microsoft 365 application, so once this is saved it is given no mail server: patching sends no email and no monthly reports
        until a later release moves them to EasyRMM. For patching&apos;s email meanwhile, send through a relay, or sign in with a password.
      </Alert>
      <p className="text-sm text-muted">
        An application registered in Microsoft Entra, with the Office 365 Exchange Online permission SMTP.SendAsApp, admin consent, and the Send from mailbox given to it in
        Exchange Online. EasyRMM gets a token for it and signs in with XOAUTH2. The steps are in the operations guide, docs/operations/mail.md.
      </p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <TextField
          label="Directory (tenant) ID"
          value={form.tenantId}
          onChange={(e) => set("tenantId", e.target.value)}
          error={err("tenantId")}
          hint="From the application's Overview page, or a domain name of the tenant."
          placeholder="00000000-0000-0000-0000-000000000000"
          autoComplete="off"
          spellCheck={false}
          required
        />
        <TextField
          label="Application (client) ID"
          value={form.clientId}
          onChange={(e) => set("clientId", e.target.value)}
          error={err("clientId")}
          hint="From the application's Overview page."
          placeholder="00000000-0000-0000-0000-000000000000"
          autoComplete="off"
          spellCheck={false}
          required
        />
      </div>
      <SelectField
        label="Credential"
        value={form.credential}
        onChange={(e) => set("credential", e.target.value as MailCredential)}
        error={err("credential")}
        hint="A certificate is the stronger: its key never leaves this server, and Microsoft never sees it."
      >
        <option value="secret">A client secret</option>
        <option value="certificate">A certificate and its private key</option>
      </SelectField>
      {form.credential === "secret" ? (
        <TextField
          label="Client secret"
          type="password"
          value={form.clientSecret}
          onChange={(e) => set("clientSecret", e.target.value)}
          error={err("clientSecret")}
          autoComplete="new-password"
          maxLength={1024}
          placeholder={keeps && storedApp?.secretSet ? "Stored" : ""}
          hint={
            keeps && storedApp?.secretSet
              ? "A secret is stored, encrypted. Leave this empty to keep it."
              : "The secret's Value from Certificates & secrets, not its Secret ID. Stored encrypted and never shown again."
          }
        />
      ) : (
        <>
          {storedCert && (
            <p className="text-sm">
              Stored: <CertificateSummary cert={storedCert} />
            </p>
          )}
          <TextareaField
            label="Certificate (PEM)"
            rows={4}
            value={form.certificate}
            onChange={(e) => set("certificate", e.target.value)}
            error={err("certificate")}
            placeholder="-----BEGIN CERTIFICATE-----"
            spellCheck={false}
            hint={
              storedCert
                ? "Leave this empty to keep the stored certificate, or paste its renewal: a renewal on the same key needs no key."
                : "The certificate uploaded to the application under Certificates & secrets."
            }
          />
          <TextareaField
            label="Private key (PEM)"
            rows={4}
            value={form.certificateKey}
            onChange={(e) => set("certificateKey", e.target.value)}
            error={err("certificateKey")}
            placeholder="-----BEGIN PRIVATE KEY-----"
            autoComplete="off"
            spellCheck={false}
            hint={keeps ? "A key is stored, encrypted. Leave this empty to keep it." : "The certificate's RSA private key, not encrypted. Stored encrypted and never shown again."}
          />
        </>
      )}
    </div>
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
  const account = limits.account;
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
          Invitations and password resets go first, and wait up to a minute for room. Password resets people ask for may use the whole day, at most{" "}
          {formatNumber(account.resetsPerHour)} an hour, and to one organization&apos;s accounts {formatNumber(account.organizationResetsPerHour)} an hour; nothing holds
          them for a day. Invitations and password links administrators send stop at {formatNumber(usage.adminDayLimit)}, 90% of the day&apos;s limit, at{" "}
          {formatNumber(account.adminPerHour)} an hour per administrator, and at {formatNumber(account.organizationPerDay)} a day per organization. One account gets at most{" "}
          {formatNumber(account.accountBurst)} password emails at once, then one every {formatNumber(account.accountEveryMinutes)} minutes. Other mail stops at{" "}
          {formatNumber(usage.otherDayLimit)}, 80%.
        </p>
        <p>The limits on invitations and password emails follow the day&apos;s limit: each is the smaller of a fixed number and a share of the day.</p>
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
