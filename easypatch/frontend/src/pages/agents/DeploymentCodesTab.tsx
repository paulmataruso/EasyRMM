import { useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { FileCode2, Plus, Terminal } from 'lucide-react';
import { api } from '../../api/client';
import { useApi, useApiMutation, useList } from '../../api/hooks';
import { AGENT_PACKAGE_FORMATS, type AgentPackageDto, type CreateDeploymentCodeRequest, type DeploymentCodeDto, type InstallScriptResponse } from '../../api/types';
import { useAuth } from '../../auth/AuthContext';
import { CodeBlock, DownloadButton } from '../../components/Copy';
import { ConfirmDialog, Dialog } from '../../components/Dialog';
import { OrganizationSelect, SiteSelect } from '../../components/Filters';
import { StateBadge } from '../../components/StatusBadges';
import { useToast } from '../../components/Toast';
import {
  Alert,
  Button,
  Checkbox,
  EmptyState,
  ErrorState,
  Field,
  InlineError,
  Mono,
  Pagination,
  Select,
  Spinner,
  TableWrap,
  Tabs,
  Textarea,
  TextField,
  Toolbar,
} from '../../components/ui';
import { formatDateTime, formatRelative, MACOS_EXPERIMENTAL } from '../../lib/format';
import { useUrlState } from '../../lib/urlState';

export function DeploymentCodesTab() {
  const { canOperate } = useAuth();
  const toast = useToast();
  const url = useUrlState();
  const organizationId = url.get('organizationId');
  const includeInactive = url.get('inactive') === 'true';
  const list = useList<DeploymentCodeDto>('/deployment-codes', {
    organizationId: organizationId || undefined,
    includeInactive: includeInactive || undefined,
    page: url.page,
    pageSize: 50,
  }, { keepPrevious: true, refetchInterval: 30_000 });
  const [creating, setCreating] = useState(url.get('create') === '1' && canOperate);
  const [scriptFor, setScriptFor] = useState<DeploymentCodeDto | null>(null);
  const [revoking, setRevoking] = useState<DeploymentCodeDto | null>(null);
  const revoke = useApiMutation((id: string) => api.post(`/deployment-codes/${id}/revoke`), {
    invalidate: ['/deployment-codes'],
    onSuccess: () => {
      toast.success('Deployment code revoked.');
      setRevoking(null);
    },
  });
  const items = includeInactive ? list.page.items : list.page.items.filter((c) => c.state === 'Active');

  return (
    <>
      <Alert tone="info" className="mb-4" title="Tokenless installs for RMM tools">
        A deployment code is not a secret. The generated PowerShell script (Windows) or shell script (Linux, or the experimental macOS agent) downloads the
        agent, verifies its SHA-256 hash (on
        Windows optionally also its Authenticode signature), installs it, and the endpoint then waits in{' '}
        <Link to="/approvals" className="text-accent hover:underline">Pending Approvals</Link>. Nothing is managed until an administrator approves it.
        Restrict codes to your RMM’s egress IP ranges where possible.
      </Alert>
      <Toolbar>
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v })} />
        <Checkbox label="Show expired and revoked" checked={includeInactive} onChange={(e) => url.set({ inactive: e.target.checked })} className="pb-2" />
        <span className="flex-1" />
        {canOperate && (
          <Button variant="primary" className="mb-0.5" icon={<Plus className="size-4" aria-hidden />} onClick={() => setCreating(true)}>
            Create deployment code
          </Button>
        )}
      </Toolbar>
      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState title="No active deployment codes" icon={<Terminal className="size-8" aria-hidden />} />
      ) : (
        <>
          <TableWrap>
            <table className="table-base">
              <thead>
                <tr>
                  <th>Name / code</th>
                  <th>Organization / site</th>
                  <th className="text-right">Pending</th>
                  <th className="text-right">Approved</th>
                  <th>Source restriction</th>
                  <th>Expires</th>
                  <th>State</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <div className="font-medium">{c.name}</div>
                      <Mono>{c.code}</Mono>
                    </td>
                    <td className="whitespace-nowrap">
                      {c.organizationName}
                      {c.siteName && <span className="text-muted"> · {c.siteName}</span>}
                    </td>
                    <td className="text-right tabular-nums">
                      {c.pendingCount > 0 ? (
                        <Link to="/approvals" className="font-medium text-warn hover:underline">
                          {c.pendingCount}
                        </Link>
                      ) : (
                        0
                      )}
                      <span className="text-xs text-subtle"> / {c.maxPendingRequests}</span>
                    </td>
                    <td className="text-right tabular-nums">{c.approvedCount}</td>
                    <td className="text-xs">{c.allowedSourceCidrs.length ? <span className="font-mono">{c.allowedSourceCidrs.join(', ')}</span> : <span className="text-muted">Any address</span>}</td>
                    <td className="whitespace-nowrap" title={c.expiresAt ? formatDateTime(c.expiresAt) : undefined}>
                      {c.expiresAt ? formatRelative(c.expiresAt) : 'Never'}
                    </td>
                    <td>
                      <StateBadge state={c.state} />
                    </td>
                    <td>
                      <div className="flex justify-end gap-1">
                        {c.state === 'Active' && (
                          <Button size="sm" icon={<FileCode2 className="size-3.5" aria-hidden />} onClick={() => setScriptFor(c)}>
                            Install script
                          </Button>
                        )}
                        {canOperate && c.state === 'Active' && (
                          <Button size="sm" variant="danger-ghost" onClick={() => setRevoking(c)}>
                            Revoke
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <Pagination page={list.page.page} pageSize={list.page.pageSize} totalCount={list.page.totalCount} onPage={(p) => url.set({ page: p })} />
        </>
      )}

      <CreateCodeDialog
        open={creating}
        defaultOrganizationId={organizationId}
        onClose={() => {
          setCreating(false);
          url.set({ create: null }, { resetPage: false });
        }}
        onCreated={(code) => {
          setCreating(false);
          url.set({ create: null }, { resetPage: false });
          setScriptFor(code);
        }}
      />
      <InstallScriptDialog code={scriptFor} onClose={() => setScriptFor(null)} />
      <ConfirmDialog
        open={revoking !== null}
        onClose={() => setRevoking(null)}
        onConfirm={() => revoking && revoke.mutate(revoking.id)}
        loading={revoke.isPending}
        error={revoke.error}
        tone="danger"
        title={`Revoke deployment code ${revoking?.name ?? ''}?`}
        confirmLabel="Revoke code"
      >
        Scripts using this code stop creating enrollment requests. Endpoints already approved are not affected; pending requests can still be approved or rejected.
      </ConfirmDialog>
    </>
  );
}

function CreateCodeDialog({ open, defaultOrganizationId, onClose, onCreated }: {
  open: boolean;
  defaultOrganizationId: string;
  onClose: () => void;
  onCreated: (code: DeploymentCodeDto) => void;
}) {
  const [org, setOrg] = useState(defaultOrganizationId);
  const [site, setSite] = useState('');
  const [name, setName] = useState('');
  const [expires, setExpires] = useState('90');
  const [cidrs, setCidrs] = useState('');
  const [maxPending, setMaxPending] = useState('500');
  useEffect(() => {
    if (open) {
      setOrg(defaultOrganizationId);
      setSite('');
      setName('');
      setExpires('90');
      setCidrs('');
      setMaxPending('500');
    }
  }, [open, defaultOrganizationId]);

  const create = useApiMutation((req: CreateDeploymentCodeRequest) => api.post<DeploymentCodeDto>('/deployment-codes', req), {
    invalidate: ['/deployment-codes'],
    onSuccess: onCreated,
  });
  const cidrList = cidrs
    .split(/[\s,;]+/)
    .map((c) => c.trim())
    .filter(Boolean);
  const badCidr = cidrList.find((c) => !/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(c));

  function submit(e: FormEvent) {
    e.preventDefault();
    if (!org || !name.trim() || badCidr) return;
    create.mutate({
      organizationId: org,
      siteId: site || null,
      name: name.trim(),
      expiresInDays: expires === '' ? null : Number(expires),
      allowedSourceCidrs: cidrList.length ? cidrList : null,
      maxPendingRequests: maxPending === '' ? null : Number(maxPending),
    });
  }

  return (
    <Dialog open={open} onClose={onClose} title="Create deployment code">
      <form onSubmit={submit} className="flex flex-col gap-3.5">
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2">
          <OrganizationSelect value={org} onChange={(v) => { setOrg(v); setSite(''); }} required />
          <SiteSelect organizationId={org} value={site} onChange={setSite} allLabel="No site" />
        </div>
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} placeholder="e.g. NinjaOne rollout – Main office" />
        <div className="grid grid-cols-2 gap-3.5">
          <TextField label="Expires in (days)" type="number" min={1} max={3650} value={expires} onChange={(e) => setExpires(e.target.value)} hint="Leave empty for no expiry." />
          <TextField label="Max pending requests" type="number" min={1} max={10000} value={maxPending} onChange={(e) => setMaxPending(e.target.value)} hint="Limits abuse of a leaked code." />
        </div>
        <Field label="Allowed source networks (CIDR)" htmlFor="code-cidrs" hint="Optional. One per line or comma separated, e.g. 203.0.113.0/24. Requests from other addresses are refused." error={badCidr ? `“${badCidr}” is not a valid IP address or CIDR range.` : null}>
          <Textarea id="code-cidrs" value={cidrs} onChange={(e) => setCidrs(e.target.value)} className="min-h-16 font-mono text-xs" aria-invalid={badCidr ? true : undefined} />
        </Field>
        <InlineError error={create.error} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending} disabled={!org || !name.trim() || !!badCidr}>
            Create and show script
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

type ScriptPlatform = 'windows' | 'linux' | 'macos';

function InstallScriptDialog({ code, onClose }: { code: DeploymentCodeDto | null; onClose: () => void }) {
  const [platform, setPlatform] = useState<ScriptPlatform>('windows');
  return (
    <Dialog open={code !== null} onClose={onClose} size="xl" title={code ? `Install script: ${code.name}` : ''} description={code ? `${code.organizationName}${code.siteName ? ` · ${code.siteName}` : ''} · code ${code.code}` : undefined}>
      {code && (
        <>
          <Tabs
            active={platform}
            onChange={(id) => setPlatform(id as ScriptPlatform)}
            tabs={[
              { id: 'windows', label: 'Windows (PowerShell)' },
              { id: 'linux', label: 'Linux (shell)' },
              { id: 'macos', label: 'macOS (experimental)' },
            ]}
          />
          {platform === 'windows' ? (
            <WindowsScript key={code.id} code={code} />
          ) : platform === 'linux' ? (
            <LinuxScript key={code.id} code={code} />
          ) : (
            <MacScript key={code.id} code={code} />
          )}
        </>
      )}
    </Dialog>
  );
}

function WindowsScript({ code }: { code: DeploymentCodeDto }) {
  const [pkg, setPkg] = useState('');
  const [requireSignature, setRequireSignature] = useState(false);
  const [skipCertificateCheck, setSkipCertificateCheck] = useState(false);
  const packages = useList<AgentPackageDto>('/agent-packages');
  const script = useApi<InstallScriptResponse>(`/deployment-codes/${code.id}/install-script`, {
    package: pkg || undefined,
    requireSignature: requireSignature || undefined,
    skipCertificateCheck: skipCertificateCheck || undefined,
  });
  const s = script.data;
  // The PowerShell script installs MSI packages only.
  const msiPackages = packages.page.items.filter((p) => (p.format ?? AGENT_PACKAGE_FORMATS.msi) === AGENT_PACKAGE_FORMATS.msi);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-4">
        <Field label="Agent package" htmlFor="script-pkg" className="min-w-64">
          <Select id="script-pkg" value={pkg} onChange={(e) => setPkg(e.target.value)}>
            <option value="">Latest x64 package</option>
            {msiPackages.map((p) => (
              <option key={p.fileName} value={p.fileName}>
                {p.fileName}
              </option>
            ))}
          </Select>
        </Field>
        <div className="flex max-w-xl flex-col gap-2 pb-1">
          <Checkbox
            label="Require a valid Authenticode signature"
            hint="Enable when your MSI is code-signed. The script refuses to install an unsigned or tampered package."
            checked={requireSignature}
            onChange={(e) => setRequireSignature(e.target.checked)}
          />
          <Checkbox
            label="Skip certificate check"
            hint="For a server with a private CA, such as the lab setup. The downloads don't check the certificate, so use it only on a network you trust. The agent then trusts that CA for its EasyPatch connection only."
            checked={skipCertificateCheck}
            onChange={(e) => setSkipCertificateCheck(e.target.checked)}
          />
        </div>
      </div>
      {script.isPending ? (
        <Spinner label="Generating script…" />
      ) : script.isError ? (
        <ErrorState error={script.error} compact onRetry={() => void script.refetch()} />
      ) : (
        s && (
          <>
            <div>
              <p className="mb-1 text-sm font-medium">One-liner for your RMM (run as SYSTEM or Administrator)</p>
              <CodeBlock code={s.oneLiner} />
              <p className="mt-1 text-xs text-muted">
                Downloads the script from <span className="font-mono">{s.scriptUrl}</span>. If your RMM can run a script file directly, use the full script below
                instead.
              </p>
            </div>
            <div>
              <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
                <p className="text-sm font-medium">Full PowerShell script</p>
                <DownloadButton fileName={`EasyPatch-Install-${code.code}.ps1`} text={s.script} label="Download .ps1" />
              </div>
              <CodeBlock code={s.script} wrap={false} maxHeight="22rem" />
            </div>
            <p className="text-xs text-muted">
              Package <span className="font-mono">{s.packageFileName}</span> (version {s.packageVersion}), SHA-256 <span className="font-mono break-all">{s.sha256}</span>.
              The script contains no secrets.
            </p>
          </>
        )
      )}
    </div>
  );
}

function LinuxScript({ code }: { code: DeploymentCodeDto }) {
  const script = useApi<InstallScriptResponse>(`/deployment-codes/${code.id}/install-script`, { platform: 'linux' });
  const s = script.data;
  // For Linux the response lists every package the script can install (comma separated, in the same order).
  const files = s ? s.packageFileName.split(', ') : [];
  const hashes = s ? s.sha256.split(', ') : [];

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted">
        For Debian, Ubuntu, RHEL, Rocky Linux, AlmaLinux and Oracle Linux with systemd (x64 or arm64). The script picks the .deb or .rpm package for the
        distribution and CPU, verifies its SHA-256 hash and installs it with apt or dnf.
      </p>
      {script.isPending ? (
        <Spinner label="Generating script…" />
      ) : script.isError ? (
        <ErrorState error={script.error} compact onRetry={() => void script.refetch()} />
      ) : (
        s && (
          <>
            <div>
              <p className="mb-1 text-sm font-medium">One-liner for your RMM or SSH session (runs as root through sudo)</p>
              <CodeBlock code={s.oneLiner} />
              <p className="mt-1 text-xs text-muted">
                Downloads the script from <span className="font-mono">{s.scriptUrl}</span>. If your tool can run a script file directly, use the full script below
                instead (run it as root).
              </p>
            </div>
            <div>
              <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
                <p className="text-sm font-medium">Full shell script</p>
                <DownloadButton fileName={`easypatch-install-${code.code}.sh`} text={s.script} label="Download .sh" mime="text/x-shellscript" />
              </div>
              <CodeBlock code={s.script} wrap={false} maxHeight="22rem" />
            </div>
            <div className="text-xs text-muted">
              <p>Packages (version {s.packageVersion}); the script contains no secrets:</p>
              <ul className="mt-1 flex flex-col gap-0.5">
                {files.map((file, i) => (
                  <li key={file}>
                    <span className="font-mono">{file}</span>
                    {hashes[i] && (
                      <>
                        {' '}
                        SHA-256 <span className="font-mono break-all">{hashes[i]}</span>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          </>
        )
      )}
    </div>
  );
}

/** What to know before installing the experimental macOS agent (deployment codes, enrollment tokens and packages). */
export function MacOSExperimentalNotice({ className }: { className?: string }) {
  return (
    <Alert tone="warn" className={className} title={MACOS_EXPERIMENTAL}>
      <ul className="mt-1 flex list-disc flex-col gap-0.5 pl-5">
        <li>
          On Apple silicon Macs the agent cannot install macOS updates that need a restart: Apple requires a volume owner’s password or an MDM. Those
          updates fail (<span className="font-mono">macos_owner_required</span>); install them on the Mac or through your MDM. Intel Macs install them, and
          they complete at the next restart.
        </li>
        <li>Restarts give signed-in users no on-screen warning, and the agent cannot show messages to users.</li>
        <li>
          The package is not signed or notarized by Apple. Downloaded with a browser and opened, macOS blocks it until you allow it in System Settings ›
          Privacy &amp; Security.
        </li>
        <li>Requires macOS 14 (Sonoma) or later on Intel (x64) or Apple silicon (arm64).</li>
      </ul>
    </Alert>
  );
}

function MacScript({ code }: { code: DeploymentCodeDto }) {
  const script = useApi<InstallScriptResponse>(`/deployment-codes/${code.id}/install-script`, { platform: 'macOS' });
  const s = script.data;
  // As for Linux, the response lists every package the script can install (comma separated, in the same order).
  const files = s ? s.packageFileName.split(', ') : [];
  const hashes = s ? s.sha256.split(', ') : [];

  return (
    <div className="flex flex-col gap-4">
      <MacOSExperimentalNotice />
      <p className="text-sm text-muted">
        The script checks for macOS 14 or later, picks the .pkg package for the Mac’s CPU (Apple silicon or Intel), verifies its SHA-256 hash, writes{' '}
        <span className="font-mono">/Library/EasyPatch/agent.conf</span> and installs the package with <span className="font-mono">installer</span>. The Mac must
        trust the server’s certificate.
      </p>
      {script.isPending ? (
        <Spinner label="Generating script…" />
      ) : script.isError ? (
        <ErrorState error={script.error} compact onRetry={() => void script.refetch()} />
      ) : (
        s && (
          <>
            <div>
              <p className="mb-1 text-sm font-medium">One-liner for your RMM or a Terminal session (runs as root through sudo)</p>
              <CodeBlock code={s.oneLiner} />
              <p className="mt-1 text-xs text-muted">
                Downloads the script from <span className="font-mono">{s.scriptUrl}</span>. If your tool can run a script file directly, use the full script below
                instead (run it as root).
              </p>
            </div>
            <div>
              <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
                <p className="text-sm font-medium">Full shell script</p>
                <DownloadButton fileName={`easypatch-install-macos-${code.code}.sh`} text={s.script} label="Download .sh" mime="text/x-shellscript" />
              </div>
              <CodeBlock code={s.script} wrap={false} maxHeight="22rem" />
            </div>
            <div className="text-xs text-muted">
              <p>Packages (version {s.packageVersion}); the script contains no secrets:</p>
              <ul className="mt-1 flex flex-col gap-0.5">
                {files.map((file, i) => (
                  <li key={file}>
                    <span className="font-mono">{file}</span>
                    {hashes[i] && (
                      <>
                        {' '}
                        SHA-256 <span className="font-mono break-all">{hashes[i]}</span>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          </>
        )
      )}
    </div>
  );
}
