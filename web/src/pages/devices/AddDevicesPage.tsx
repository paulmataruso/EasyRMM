import { useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router";
import { Ban, Download, KeyRound, MonitorDown, ShieldCheck, SquareTerminal } from "lucide-react";
import { api, errorMessage, fieldError } from "../../api/client";
import { useApi, useApiMutation, useList, useSites } from "../../api/hooks";
import type {
  AgentBuild,
  AgentDownloads,
  ApprovalToken,
  ApprovalTokenInput,
  DeviceGroup,
  EnrollmentToken,
  EnrollmentTokenInput,
  NewApprovalToken,
  NewEnrollmentToken,
  ServerAddress,
  Site,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { CodeBlock, OneTimeNotice } from "../../components/Copy";
import { ConfirmDialog } from "../../components/Dialog";
import { TokenStatusBadge } from "../../components/StatusBadges";
import { useToast } from "../../components/Toast";
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  IconButton,
  InlineError,
  KeyValueList,
  Mono,
  PageHeader,
  Select,
  Segmented,
  SelectField,
  Spinner,
  TableWrap,
  TextField,
} from "../../components/ui";
import { formatDate, formatDateTime, formatRelative, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";

/** Where agents fetch the installer and binaries (agentproto.PathPrefix + v1). */
const AGENT_PATH = "/api/agent/v1";

const EXPIRY_CHOICES = [1, 7, 30, 90];

const ARCH_NAMES: Record<string, string> = {
  amd64: "x86-64",
  arm64: "ARM 64-bit",
  arm: "ARMv7 32-bit",
  "386": "x86 32-bit",
};

/** Most computers first. */
const ARCH_ORDER = ["amd64", "arm64", "arm", "386"];

/** Windows first, then Linux. */
const OS_ORDER = ["windows", "linux"];

export function byArch(a: AgentBuild, b: AgentBuild): number {
  const rank = (order: string[], v: string) => (order.includes(v) ? order.indexOf(v) : order.length);
  return (
    rank(OS_ORDER, a.os) - rank(OS_ORDER, b.os) || a.os.localeCompare(b.os) || rank(ARCH_ORDER, a.arch) - rank(ARCH_ORDER, b.arch) || a.file.localeCompare(b.file)
  );
}

export function archName(arch: string): string {
  return ARCH_NAMES[arch] ?? arch;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * The command that installs the agent on a Linux computer. The token travels in the environment: `export` is part of
 * the shell, so no process's command line (which every user on the computer can read) or sudo's log ever holds it.
 * An address with a pin uses the server's own certificate authority, which the computer does not trust yet: curl
 * checks the server's public key instead (--insecure skips only the certificate authority check).
 */
export function linuxInstallCommand(serverUrl: string, secret: string, pin?: string): string {
  const tls = pin ? `--insecure --pinnedpubkey '${pin}' ` : "";
  return `export EASYRMM_TOKEN='${secret}'; curl -fsSL ${tls}${serverUrl}${AGENT_PATH}/install.sh | sudo --preserve-env=EASYRMM_TOKEN sh; unset EASYRMM_TOKEN`;
}

/** How an address is listed: its host, marked when it is an IP address beside the public name. */
export function addressLabel(address: ServerAddress, primary: boolean): string {
  const host = new URL(address.url).host;
  return primary ? host : `${host} (IP address)`;
}

const TLS12 = "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072";

/**
 * The command that installs the agent on a Windows computer, for Windows PowerShell run as administrator. It turns on
 * TLS 1.2, which older Windows PowerShell leaves off, downloads install.ps1 and runs it with the token. An address with a
 * key pin uses the server's own certificate authority: the download trusts the server's public key, by its SHA-256, and
 * nothing else, and install.ps1 does the same for its own downloads (agentapi/install.ps1.tmpl).
 */
export function windowsInstallCommand(serverUrl: string, secret: string, keyPin?: string): string {
  const url = `${serverUrl}${AGENT_PATH}/install.ps1`;
  if (!keyPin) return `${TLS12}; & ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('${url}'))) -Token '${secret}'`;
  return [
    TLS12,
    `[Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s, $c) ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($c.GetPublicKey())) -replace '-') -eq '${keyPin}' }`,
    `try { $i = (New-Object Net.WebClient).DownloadString('${url}') } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $null }`,
    `& ([scriptblock]::Create($i)) -Token '${secret}'`,
  ].join("; ");
}

type Platform = "windows" | "linux";

const PLATFORMS: { value: Platform; label: string }[] = [
  { value: "windows", label: "Windows" },
  { value: "linux", label: "Linux" },
];

/** The server's addresses, and the one to offer first: the one this console was opened at. */
function useAddresses(fallback: string) {
  const downloads = useApi<AgentDownloads>("/agent-downloads", undefined, { staleTime: 60_000 });
  const listed = downloads.data?.addresses ?? [];
  const primary: ServerAddress = listed[0] ?? { url: fallback };
  const addresses = listed.length > 0 ? listed : [primary];
  const current = addresses.find((a) => a.url === downloads.data?.current) ?? primary;
  return { addresses, current };
}

/** Where a token's devices go: straight into its site, or into the approvals list (ADR-0024). */
type Mode = "site" | "approval";

const MODES: { value: Mode; label: string }[] = [
  { value: "site", label: "Join a chosen site" },
  { value: "approval", label: "Wait for approval" },
];

type Created = { kind: "site"; value: NewEnrollmentToken } | { kind: "approval"; value: NewApprovalToken };

export function AddDevicesPage() {
  const { can, canGlobal } = useAuth();
  const url = useUrlState();
  const approver = canGlobal("enrollment.manage");
  const mode: Mode = approver && url.get("mode") === "approval" ? "approval" : "site";
  const [created, setCreated] = useState<Created | null>(null);
  const top = useRef<HTMLDivElement>(null);
  // A token shown again from a list below fills the card at the top.
  const show = (c: Created) => {
    setCreated(c);
    top.current?.scrollIntoView?.({ block: "start", behavior: "smooth" });
  };

  const header = (
    <PageHeader
      breadcrumb={
        <Link to="/devices" className="hover:text-fg">
          Devices
        </Link>
      }
      title="Add devices"
      subtitle={
        approver
          ? "Install the EasyRMM agent with a deployment token. A token places new devices in its site, or holds them until you approve each one into a site."
          : "Install the EasyRMM agent with a deployment token. The token decides which site, and optionally which device group, a new device joins."
      }
    />
  );

  if (!can("enrollment.manage")) {
    return (
      <>
        {header}
        <EmptyState title="Not available to your role" icon={<KeyRound className="size-8" aria-hidden />}>
          Adding devices needs a role that manages enrollment, such as Organization or Site Administrator.
        </EmptyState>
      </>
    );
  }

  return (
    <>
      {header}
      <div ref={top} className="grid scroll-mt-4 grid-cols-1 items-start gap-5 xl:grid-cols-5">
        <Card title={created ? "Install the agent" : "New deployment token"} className="xl:col-span-3">
          {created?.kind === "site" ? (
            <SiteInstallSteps created={created.value} onDone={() => setCreated(null)} />
          ) : created?.kind === "approval" ? (
            <ApprovalInstallSteps created={created.value} onDone={() => setCreated(null)} />
          ) : (
            <div className="flex flex-col gap-4">
              {approver && (
                <Segmented
                  label="New devices"
                  options={MODES}
                  value={mode}
                  onChange={(m) => url.set({ mode: m === "approval" ? "approval" : null })}
                  className="self-start"
                />
              )}
              {mode === "approval" ? (
                <ApprovalTokenForm onCreated={(t) => setCreated({ kind: "approval", value: t })} />
              ) : (
                <TokenForm initialSiteId={url.get("siteId")} onCreated={(t) => setCreated({ kind: "site", value: t })} />
              )}
            </div>
          )}
        </Card>
        <div className="flex flex-col gap-5 xl:col-span-2">
          <DownloadsCard />
          <CertificateAuthorityCard />
        </div>
      </div>
      <TokensCard<EnrollmentToken, NewEnrollmentToken>
        title="Deployment tokens"
        path="/enrollment-tokens"
        onShown={(value) => show({ kind: "site", value })}
        place={{
          header: "Site",
          cell: (t) => (
            <>
              <span className="block truncate">
                {t.organizationName} <span className="text-subtle">/</span> {t.siteName}
              </span>
              {t.deviceGroupName && <span className="block truncate text-xs text-muted">{t.deviceGroupName}</span>}
            </>
          ),
        }}
        revokeNote={(t) => (
          <>
            No more devices can enroll with <strong>{t.name}</strong>. Devices that already enrolled with it keep working.
          </>
        )}
      />
      {approver && (
        <TokensCard<ApprovalToken, NewApprovalToken>
          title="Approval tokens"
          path="/approval-tokens"
          onShown={(value) => show({ kind: "approval", value })}
          place={{
            header: "Waiting",
            cell: (t) =>
              t.waiting > 0 ? (
                <Link to="/devices/approvals" className="font-medium text-accent tabular-nums hover:underline">
                  {plural(t.waiting, "device")}
                </Link>
              ) : (
                <span className="text-muted">None</span>
              ),
          }}
          revokeNote={(t) => (
            <>
              No more devices can ask to enroll with <strong>{t.name}</strong>. Devices already waiting can still be approved, and devices that enrolled
              with it keep working.
            </>
          )}
        />
      )}
    </>
  );
}

function ApprovalTokenForm({ onCreated }: { onCreated: (t: NewApprovalToken) => void }) {
  const [name, setName] = useState("");
  const [days, setDays] = useState(7);
  const [limit, setLimit] = useState("");
  const create = useApiMutation((input: ApprovalTokenInput) => api.post<NewApprovalToken>("/approval-tokens", input), {
    invalidate: ["/approval-tokens", "/audit"],
    onSuccess: onCreated,
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    create.mutate({ name: name.trim(), expiresInDays: days, maxUses: limit.trim() === "" ? null : Number(limit) });
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3.5">
      <p className="text-sm text-muted">
        One install command for every computer, whichever customer it belongs to. Each device waits under{" "}
        <Link to="/devices/approvals" className="font-medium text-accent hover:underline">
          Waiting for approval
        </Link>{" "}
        until you approve it into a site, and takes its computer&apos;s name.
      </p>
      <TextField
        label="Token name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        error={fieldError(create.error, "name")}
        hint="Something you will recognize later, for example “Spring rollout”."
        required
        maxLength={200}
      />
      <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
        <SelectField label="Expires after" value={String(days)} onChange={(e) => setDays(Number(e.target.value))} error={fieldError(create.error, "expiresInDays")}>
          {EXPIRY_CHOICES.map((d) => (
            <option key={d} value={d}>
              {plural(d, "day")}
            </option>
          ))}
        </SelectField>
        <TextField
          label="Device limit"
          type="number"
          inputMode="numeric"
          min={1}
          max={100000}
          value={limit}
          onChange={(e) => setLimit(e.target.value)}
          error={fieldError(create.error, "maxUses")}
          hint="Leave empty for no limit."
        />
      </div>
      <InlineError error={create.error} fields={["name", "expiresInDays", "maxUses"]} />
      <div className="flex justify-end pt-1">
        <Button type="submit" variant="primary" loading={create.isPending} disabled={!name.trim()}>
          Create token
        </Button>
      </div>
    </form>
  );
}

function TokenForm({ initialSiteId, onCreated }: { initialSiteId: string; onCreated: (t: NewEnrollmentToken) => void }) {
  const sites = useSites(null);
  const [siteId, setSiteId] = useState(initialSiteId);
  const [groupId, setGroupId] = useState("");
  const [name, setName] = useState("");
  const [days, setDays] = useState(7);
  const [limit, setLimit] = useState("");
  const groups = useList<DeviceGroup>(siteId ? `/sites/${siteId}/device-groups` : null);
  const create = useApiMutation((input: EnrollmentTokenInput) => api.post<NewEnrollmentToken>(`/sites/${siteId}/enrollment-tokens`, input), {
    invalidate: ["/enrollment-tokens", "/audit"],
    onSuccess: onCreated,
  });

  const byOrg = useMemo(() => {
    const m = new Map<string, Site[]>();
    for (const s of sites.items) m.set(s.organizationName, [...(m.get(s.organizationName) ?? []), s]);
    return [...m.entries()];
  }, [sites.items]);

  if (sites.isPending) return <Spinner />;
  if (sites.isError) return <ErrorState error={sites.error} onRetry={() => void sites.refetch()} compact />;
  if (sites.items.length === 0) {
    return (
      <EmptyState title="No sites yet" compact>
        A device joins a site.{" "}
        <Link to="/organizations" className="font-medium text-accent hover:underline">
          Add a site to an organization
        </Link>{" "}
        first.
      </EmptyState>
    );
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    create.mutate({ name: name.trim(), deviceGroupId: groupId || null, expiresInDays: days, maxUses: limit.trim() === "" ? null : Number(limit) });
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3.5">
      <SelectField
        label="Site"
        value={siteId}
        required
        onChange={(e) => {
          setSiteId(e.target.value);
          setGroupId("");
        }}
      >
        <option value="">Choose a site</option>
        {byOrg.map(([org, list]) => (
          <optgroup key={org} label={org}>
            {list.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </optgroup>
        ))}
      </SelectField>
      <SelectField
        label="Device group"
        value={groupId}
        onChange={(e) => setGroupId(e.target.value)}
        disabled={!siteId || groups.isPending}
        error={fieldError(create.error, "deviceGroupId")}
        hint="Optional. New devices can be moved later."
      >
        <option value="">None</option>
        {groups.items.map((g) => (
          <option key={g.id} value={g.id}>
            {g.name}
          </option>
        ))}
      </SelectField>
      <TextField
        label="Token name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        error={fieldError(create.error, "name")}
        hint="Something you will recognize later, for example “Head office rollout”."
        required
        maxLength={200}
      />
      <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
        <SelectField label="Expires after" value={String(days)} onChange={(e) => setDays(Number(e.target.value))} error={fieldError(create.error, "expiresInDays")}>
          {EXPIRY_CHOICES.map((d) => (
            <option key={d} value={d}>
              {plural(d, "day")}
            </option>
          ))}
        </SelectField>
        <TextField
          label="Device limit"
          type="number"
          inputMode="numeric"
          min={1}
          max={100000}
          value={limit}
          onChange={(e) => setLimit(e.target.value)}
          error={fieldError(create.error, "maxUses")}
          hint="Leave empty for no limit."
        />
      </div>
      <InlineError error={create.error} fields={["name", "deviceGroupId", "expiresInDays", "maxUses"]} />
      <div className="flex justify-end pt-1">
        <Button type="submit" variant="primary" loading={create.isPending} disabled={!siteId || !name.trim()}>
          Create token
        </Button>
      </div>
    </form>
  );
}

function SiteInstallSteps({ created, onDone }: { created: NewEnrollmentToken; onDone: () => void }) {
  const t = created.token;
  return (
    <InstallSteps
      secret={created.secret}
      serverUrl={created.serverUrl}
      onDone={onDone}
      notice={
        <>
          Anyone with it can add devices to {t.siteName} until it {t.maxUses ? "expires or is used up" : "expires"}. Revoke it once the rollout is done.
          Until then, Deployment tokens below shows it again.
        </>
      }
      details={[
        ["Token", t.name],
        ["Site", `${t.organizationName} / ${t.siteName}`],
        ["Device group", t.deviceGroupName || <span className="text-muted">None</span>],
        ["Expires", formatDateTime(t.expiresAt)],
        ["Device limit", t.maxUses ? t.maxUses.toLocaleString() : "No limit"],
      ]}
    />
  );
}

function ApprovalInstallSteps({ created, onDone }: { created: NewApprovalToken; onDone: () => void }) {
  const t = created.token;
  return (
    <InstallSteps
      secret={created.secret}
      serverUrl={created.serverUrl}
      onDone={onDone}
      notice={
        <>
          Anyone with it can ask to add devices until it {t.maxUses ? "expires or is used up" : "expires"}. Each one waits under{" "}
          <Link to="/devices/approvals" className="font-medium underline">
            Waiting for approval
          </Link>{" "}
          until you approve it into a site. Revoke the token once the rollout is done. Until then, Approval tokens below shows it again.
        </>
      }
      details={[
        ["Token", t.name],
        ["New devices", "Wait for approval"],
        ["Expires", formatDateTime(t.expiresAt)],
        ["Device limit", t.maxUses ? t.maxUses.toLocaleString() : "No limit"],
      ]}
    />
  );
}

function InstallSteps({ secret, serverUrl, notice, details, onDone }: {
  secret: string;
  serverUrl: string;
  notice: ReactNode;
  details: [ReactNode, ReactNode][];
  onDone: () => void;
}) {
  const { addresses, current } = useAddresses(serverUrl);
  const [chosen, setChosen] = useState<string | null>(null);
  const [platform, setPlatform] = useState<Platform>("windows");
  const address = addresses.find((a) => a.url === chosen) ?? current;
  return (
    <div className="flex flex-col gap-4">
      <OneTimeNotice title="Keep this command to the people installing the agent.">{notice}</OneTimeNotice>

      {addresses.length > 1 && (
        <SelectField
          label="Server address"
          value={address.url}
          onChange={(e) => setChosen(e.target.value)}
          hint="The address computers reach the server at. Use an IP address when they cannot look up the server's name."
        >
          {addresses.map((a, i) => (
            <option key={a.url} value={a.url}>
              {addressLabel(a, i === 0)}
            </option>
          ))}
        </SelectField>
      )}

      <section className="flex flex-col gap-2" aria-label="Install command">
        <Segmented label="Operating system" options={PLATFORMS} value={platform} onChange={setPlatform} className="self-start" />
        {platform === "windows" ? (
          <>
            <p className="text-sm text-muted">
              Run on each computer in <strong className="font-medium text-fg">Windows PowerShell</strong> started as administrator. Windows 10, Windows Server
              2016 or later. It installs the EasyRMM Agent service, which then installs MeshAgent for remote access.
            </p>
            {address.keyPin && (
              <p className="text-sm text-muted">
                This address uses the server&apos;s own certificate authority, so the command checks the server&apos;s public key itself and trusts nothing else;
                the agent trusts the server&apos;s certificate authority from then on. PowerShell 7 cannot run this check: use Windows PowerShell,{" "}
                <Mono className="whitespace-nowrap">powershell.exe</Mono>.
              </p>
            )}
            <CodeBlock code={windowsInstallCommand(address.url, secret, address.keyPin)} />
          </>
        ) : (
          <LinuxInstall address={address} secret={secret} />
        )}
      </section>

      <details className="group text-sm">
        <summary className="cursor-pointer text-muted select-none hover:text-fg">The token on its own, for scripted installs</summary>
        <div className="mt-2 flex flex-col gap-1.5">
          <CodeBlock code={secret} />
          <p className="text-xs text-muted">
            Pass it to{" "}
            <Mono>
              {platform === "windows" ? "easyrmm-agent.exe" : "easyrmm-agent"} install --server {address.url} --token …{address.pin ? " --ca-file easyrmm-ca.pem" : ""}
            </Mono>
            , or in the <Mono>EASYRMM_TOKEN</Mono> environment variable to keep it out of the process list.
            {address.pin && (
              <>
                {" "}
                <Mono>easyrmm-ca.pem</Mono> is the server&apos;s certificate authority, under Server certificate authority on this page.
              </>
            )}
          </p>
        </div>
      </details>

      <KeyValueList narrow items={details} />
      <div className="flex justify-end">
        <Button onClick={onDone}>Create another token</Button>
      </div>
    </div>
  );
}

function LinuxInstall({ address, secret }: { address: ServerAddress; secret: string }) {
  return (
    <>
      {address.pin ? (
        <p className="text-sm text-muted">
          Run on each computer as a user who can use sudo. The computer needs systemd and curl. This address uses the server&apos;s own certificate authority, so the
          command checks the server&apos;s public key instead (<Mono>--pinnedpubkey</Mono>); <Mono>--insecure</Mono> only skips the public certificate check. The
          agent trusts the server&apos;s certificate authority from then on.
        </p>
      ) : (
        <p className="text-sm text-muted">
          Run on each computer as a user who can use sudo. The computer needs systemd and curl; with wget instead, replace <Mono>curl -fsSL</Mono> with{" "}
          <Mono>wget -qO-</Mono>.
        </p>
      )}
      <CodeBlock code={linuxInstallCommand(address.url, secret, address.pin)} />
    </>
  );
}

function DownloadsCard() {
  const downloads = useApi<AgentDownloads>("/agent-downloads", undefined, { staleTime: 60_000 });
  const items = [...(downloads.data?.items ?? [])].sort(byArch);
  return (
    <Card title="Agent downloads" padded={false}>
      {downloads.isPending ? (
        <Spinner />
      ) : downloads.isError ? (
        <ErrorState error={downloads.error} onRetry={() => void downloads.refetch()} compact />
      ) : items.length === 0 ? (
        <EmptyState title="No agents on this server" icon={<MonitorDown className="size-8" aria-hidden />} compact>
          The server hands out agents from its agent directory (<Mono>EASYRMM_AGENT_DIR</Mono>), which is empty. The Docker image includes them; a server built from
          source needs <Mono>make build-agents</Mono>.
        </EmptyState>
      ) : (
        <>
          <ul className="divide-y divide-line">
            {items.map((b) => (
              <BuildRow key={b.file} build={b} />
            ))}
          </ul>
          <p className="border-t border-line px-4 py-2.5 text-xs text-muted">
            The install command downloads the right one and checks it against{" "}
            <a href={`${AGENT_PATH}/download/SHA256SUMS`} className="text-accent hover:underline">
              SHA256SUMS
            </a>
            . No macOS agent yet.
          </p>
        </>
      )}
    </Card>
  );
}

/**
 * The server's own certificate authority, shown when an address uses it (an IP
 * address, or a server without public DNS). Installing it in a browser or the
 * operating system ends the certificate warnings on those addresses.
 */
function CertificateAuthorityCard() {
  const downloads = useApi<AgentDownloads>("/agent-downloads", undefined, { staleTime: 60_000 });
  const ca = downloads.data?.certificateAuthority;
  if (!ca) return null;
  return (
    <Card title="Server certificate authority">
      <div className="flex flex-col gap-3">
        <p className="text-sm text-muted">
          No public certificate authority certifies an IP address, so EasyRMM runs its own for those addresses. Browsers warn about it until you trust it: install
          it in your browser or operating system after checking that its fingerprint matches the one here.
        </p>
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium text-muted">SHA-256 fingerprint</span>
          <span className="font-mono text-xs break-all text-fg">{ca.fingerprint}</span>
        </div>
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
          <a href={ca.certUrl} download="easyrmm-ca.crt" className="inline-flex items-center gap-1.5 rounded-sm text-sm font-medium text-accent hover:underline">
            <ShieldCheck className="size-4" aria-hidden />
            Download easyrmm-ca.crt
          </a>
          <a href={ca.url} download="easyrmm-ca.pem" className="inline-flex items-center gap-1.5 rounded-sm text-sm text-muted hover:text-fg hover:underline">
            <Download className="size-4" aria-hidden />
            easyrmm-ca.pem
          </a>
        </div>
        <p className="text-xs text-muted">
          The <Mono>.crt</Mono> file is for Windows and macOS; the <Mono>.pem</Mono> file holds the same certificate for Linux, Firefox and the agent&apos;s{" "}
          <Mono>--ca-file</Mono>.
        </p>
        <div className="flex flex-col gap-2 border-t border-line pt-3">
          <h3 className="text-sm font-medium text-fg">Install it on Windows</h3>
          <ol className="flex list-decimal flex-col gap-1 pl-5 text-sm text-muted marker:text-subtle">
            <li>
              Right-click <Mono>easyrmm-ca.crt</Mono> and choose <span className="text-fg">Install Certificate</span>.
            </li>
            <li>
              Choose <span className="text-fg">Local Machine</span> (for every user of the computer) and confirm the administrator prompt.
            </li>
            <li>
              Choose <span className="text-fg">Place all certificates in the following store</span>, then <span className="text-fg">Browse</span> and{" "}
              <span className="text-fg">Trusted Root Certification Authorities</span>. Letting Windows choose the store can put it where browsers do not trust it.
            </li>
            <li>Finish, then restart the browser. Edge and Chrome use the Windows store.</li>
          </ol>
          <p className="text-sm text-muted">Or, in PowerShell run as administrator, from the folder you downloaded it to:</p>
          <CodeBlock code={`Import-Certificate -FilePath .\\easyrmm-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root`} />
        </div>
      </div>
    </Card>
  );
}

function BuildRow({ build }: { build: AgentBuild }) {
  const os = build.os === "linux" ? "Linux" : build.os === "windows" ? "Windows" : build.os;
  return (
    <li className="flex flex-col gap-1 px-4 py-3">
      <div className="flex items-center justify-between gap-3">
        <span className="min-w-0 text-sm">
          <span className="font-medium text-fg">
            {os} {archName(build.arch)}
          </span>
          <span className="ml-2 text-xs text-muted tabular-nums">{formatBytes(build.size)}</span>
        </span>
        <a
          href={`${AGENT_PATH}/download/${encodeURIComponent(build.file)}`}
          download
          className="inline-flex shrink-0 items-center gap-1 rounded-sm text-xs font-medium text-accent hover:underline"
          aria-label={`Download ${build.file}`}
        >
          <Download className="size-3.5" aria-hidden />
          {build.file}
        </a>
      </div>
      <p className="text-[11px] leading-snug break-all text-muted">
        SHA-256 <span className="font-mono text-fg/80">{build.sha256}</span>
      </p>
    </li>
  );
}

/** What both kinds of token have in common, for their lists. */
interface TokenRow {
  id: string;
  name: string;
  createdByName?: string;
  createdAt: string;
  expiresAt: string;
  maxUses: number | null;
  uses: number;
  lastUsedAt: string | null;
  status: EnrollmentToken["status"];
  kept: boolean;
}

function TokensCard<T extends TokenRow, R>({ title, path, place, revokeNote, onShown }: {
  title: string;
  path: string;
  /** The column that differs: a deployment token's site, an approval token's waiting devices. */
  place: { header: string; cell: (t: T) => ReactNode };
  revokeNote: (t: T) => ReactNode;
  /** Receives an active token with its secret, shown again (ADR-0047). */
  onShown: (r: R) => void;
}) {
  const toast = useToast();
  const [all, setAll] = useState(false);
  const tokens = useList<T>(path, all ? undefined : { status: "active" }, { refetchInterval: 30_000, keepPrevious: true });
  const [revoking, setRevoking] = useState<T | null>(null);
  const revoke = useApiMutation((t: T) => api.post<T>(`${path}/${t.id}/revoke`), {
    invalidate: [path, "/audit"],
    onSuccess: (_, t) => {
      toast.success(`Token “${t.name}” revoked.`);
      setRevoking(null);
    },
  });
  const reveal = useApiMutation((t: T) => api.post<R>(`${path}/${t.id}/reveal`), {
    invalidate: ["/audit"],
    onSuccess: (r) => onShown(r),
  });
  const noun = title.toLowerCase();

  return (
    <Card
      title={title}
      padded={false}
      className="mt-5"
      actions={
        <Select aria-label={`Which ${noun}`} value={all ? "all" : "active"} onChange={(e) => setAll(e.target.value === "all")} className="h-8 py-0 text-xs">
          <option value="active">Usable tokens</option>
          <option value="all">All tokens</option>
        </Select>
      }
    >
      {tokens.isPending ? (
        <Spinner />
      ) : tokens.isError ? (
        <ErrorState error={tokens.error} onRetry={() => void tokens.refetch()} compact />
      ) : tokens.items.length === 0 ? (
        <EmptyState title={all ? `No ${noun} yet` : `No usable ${noun}`} compact>
          {all ? "Tokens you create are listed here, with how many devices used each." : "Expired, revoked and used-up tokens are under All tokens."}
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>Token</th>
                <th className="hidden md:table-cell">{place.header}</th>
                <th>Devices</th>
                <th className="hidden sm:table-cell">Expires</th>
                <th>Status</th>
                <th className="text-right">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {tokens.items.map((t) => (
                <tr key={t.id}>
                  <td>
                    <span className="font-medium">{t.name}</span>
                    <p className="text-xs text-muted">
                      {t.createdByName ? `${t.createdByName}, ` : ""}
                      <span title={formatDateTime(t.createdAt)}>{formatDate(t.createdAt)}</span>
                    </p>
                    {t.status === "active" && !t.kept && <p className="text-xs text-muted">Made before tokens could be shown again.</p>}
                  </td>
                  <td className="hidden max-w-64 md:table-cell">{place.cell(t)}</td>
                  <td className="whitespace-nowrap tabular-nums" title={t.lastUsedAt ? `Last used ${formatDateTime(t.lastUsedAt)}` : "Not used yet"}>
                    {t.maxUses ? `${t.uses.toLocaleString()} of ${t.maxUses.toLocaleString()}` : t.uses.toLocaleString()}
                  </td>
                  <td className="hidden whitespace-nowrap text-muted sm:table-cell" title={formatDateTime(t.expiresAt)}>
                    {t.status === "revoked" ? "—" : formatRelative(t.expiresAt)}
                  </td>
                  <td>
                    <TokenStatusBadge status={t.status} />
                  </td>
                  <td className="text-right whitespace-nowrap">
                    {t.status === "active" && t.kept && (
                      <IconButton
                        label={`Show install commands for ${t.name}`}
                        onClick={() => reveal.mutate(t, { onError: (err) => toast.error(errorMessage(err)) })}
                        disabled={reveal.isPending}
                        className="hover:text-accent"
                      >
                        <SquareTerminal className="size-4" aria-hidden />
                      </IconButton>
                    )}
                    {t.status === "active" && (
                      <IconButton label={`Revoke ${t.name}`} onClick={() => setRevoking(t)} className="hover:text-danger">
                        <Ban className="size-4" aria-hidden />
                      </IconButton>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <ConfirmDialog
        open={revoking !== null}
        onClose={() => {
          setRevoking(null);
          revoke.reset();
        }}
        onConfirm={() => revoking && revoke.mutate(revoking)}
        title={`Revoke ${noun.replace(/s$/, "")}`}
        confirmLabel="Revoke token"
        tone="danger"
        loading={revoke.isPending}
        error={revoke.error}
      >
        <p>{revoking && revokeNote(revoking)}</p>
      </ConfirmDialog>
    </Card>
  );
}
