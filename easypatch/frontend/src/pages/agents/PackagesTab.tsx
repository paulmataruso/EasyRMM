import { Download, Package } from 'lucide-react';
import { useList } from '../../api/hooks';
import { AGENT_PACKAGE_FORMATS, type AgentPackageDto, type AgentVersionCountDto } from '../../api/types';
import { CopyButton } from '../../components/Copy';
import { Badge, buttonClasses, Card, EmptyState, ErrorState, ProgressBar, Spinner, TableWrap } from '../../components/ui';
import { formatBytes, formatDateTime, formatPackageFormat, MACOS_EXPERIMENTAL } from '../../lib/format';
import { MacOSExperimentalNotice } from './DeploymentCodesTab';

export function PackagesTab() {
  const packages = useList<AgentPackageDto>('/agent-packages');
  const versions = useList<AgentVersionCountDto>('/agent-versions', undefined, { refetchInterval: 60_000 });
  const total = versions.page.items.reduce((sum, v) => sum + v.count, 0);
  const macPackages = packages.page.items.some((p) => p.format === AGENT_PACKAGE_FORMATS.pkg);

  return (
    <div className="flex flex-col gap-5">
      <Card title="Agent packages" padded={false}>
        <p className="px-4 pt-3 text-sm text-muted">
          Agent packages found in the server’s agent-packages directory, named{' '}
          <span className="font-mono">EasyPatchAgent-&lt;version&gt;-&lt;x64|arm64&gt;.&lt;msi|deb|rpm|pkg&gt;</span>: MSI for Windows, DEB for Debian and Ubuntu, RPM
          for RHEL-family distributions, PKG for the experimental macOS agent. Publish a new agent version by copying the package and its <span className="font-mono">.sig</span> release signature
          there. Agents update themselves only to signed packages of their own format, and check the signature against the release key built into them.
        </p>
        <div className="p-4">
          {macPackages && <MacOSExperimentalNotice className="mb-4" />}
          {packages.isPending ? (
            <Spinner />
          ) : packages.isError ? (
            <ErrorState error={packages.error} compact onRetry={() => void packages.refetch()} />
          ) : packages.page.items.length === 0 ? (
            <EmptyState title="No agent packages available" icon={<Package className="size-8" aria-hidden />}>
              Build the MSI, DEB or RPM packages (see docs/agent-installation.md) and place them in the agent-packages directory on the server.
            </EmptyState>
          ) : (
            <TableWrap>
              <table className="table-base">
                <thead>
                  <tr>
                    <th>File</th>
                    <th>Version</th>
                    <th>Format</th>
                    <th>Architecture</th>
                    <th className="text-right">Size</th>
                    <th>SHA-256</th>
                    <th>Release signature</th>
                    <th>Modified</th>
                    <th className="text-right">Download</th>
                  </tr>
                </thead>
                <tbody>
                  {packages.page.items.map((p) => (
                    <tr key={p.fileName}>
                      <td className="font-mono text-xs whitespace-nowrap">{p.fileName}</td>
                      <td className="whitespace-nowrap">
                        {p.version} {p.isLatest && <Badge tone="ok">latest</Badge>}
                      </td>
                      <td>
                        {p.format === AGENT_PACKAGE_FORMATS.pkg ? (
                          <Badge tone="warn" title={MACOS_EXPERIMENTAL}>
                            {formatPackageFormat(p.format)} · experimental
                          </Badge>
                        ) : (
                          <Badge tone={p.format === AGENT_PACKAGE_FORMATS.msi ? 'neutral' : 'info'}>{formatPackageFormat(p.format)}</Badge>
                        )}
                      </td>
                      <td>{p.architecture}</td>
                      <td className="text-right whitespace-nowrap tabular-nums">{formatBytes(p.sizeBytes)}</td>
                      <td>
                        <div className="flex items-center gap-2">
                          <span className="max-w-56 truncate font-mono text-xs" title={p.sha256}>
                            {p.sha256}
                          </span>
                          <CopyButton text={p.sha256} label="Copy" />
                        </div>
                      </td>
                      <td className="whitespace-nowrap">
                        {p.releaseKeyId ? (
                          <span className="flex items-center gap-1.5">
                            <Badge tone="ok">signed</Badge>
                            <span className="font-mono text-xs text-muted" title="Release key ID">
                              {p.releaseKeyId}
                            </span>
                          </span>
                        ) : p.signatureProblem ? (
                          <Badge tone="danger" title={p.signatureProblem}>
                            invalid
                          </Badge>
                        ) : (
                          <Badge tone="neutral">not signed</Badge>
                        )}
                      </td>
                      <td className="whitespace-nowrap text-muted">{formatDateTime(p.modifiedAt)}</td>
                      <td className="text-right">
                        <a href={p.downloadUrl} className={buttonClasses('secondary', 'sm')} download>
                          <Download className="size-3.5" aria-hidden />
                          {(p.format ?? AGENT_PACKAGE_FORMATS.msi).toUpperCase()}
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </div>
      </Card>

      <Card title="Agent versions in use">
        {versions.isPending ? (
          <Spinner />
        ) : versions.isError ? (
          <ErrorState error={versions.error} compact />
        ) : versions.page.items.length === 0 ? (
          <p className="text-sm text-muted">No endpoints have reported an agent version yet.</p>
        ) : (
          <ul className="flex flex-col gap-3">
            {[...versions.page.items]
              .sort((a, b) => b.count - a.count)
              .map((v) => (
                <li key={v.version} className="grid grid-cols-[8rem_1fr_5rem] items-center gap-3 text-sm">
                  <span className="font-mono">
                    {v.version} {v.isLatest && <Badge tone="ok">latest</Badge>}
                  </span>
                  <ProgressBar value={total ? (v.count / total) * 100 : 0} tone={v.isLatest ? 'ok' : 'warn'} label={`Endpoints on ${v.version}`} />
                  <span className="text-right tabular-nums text-muted">
                    {v.count} ({total ? Math.round((v.count / total) * 100) : 0}%)
                  </span>
                </li>
              ))}
          </ul>
        )}
        <p className="mt-4 text-xs text-muted">
          Endpoints running an older version are flagged as outdated. Agents 1.2.0 and newer update themselves to the newest signed package when the
          “Agent updates” policy is Automatic, or when you choose Update agent; older agents need the new MSI installed once.
        </p>
      </Card>
    </div>
  );
}
