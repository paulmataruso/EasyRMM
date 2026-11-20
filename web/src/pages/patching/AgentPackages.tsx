import { Download, Package } from "lucide-react";
import { useApi } from "../../api/hooks";
import type { PatchAgentPackage } from "../../api/types";
import { CopyButton } from "../../components/Copy";
import { Badge, Card, EmptyState, ErrorState, Mono, Spinner, TableWrap } from "../../components/ui";
import { formatSize } from "../../lib/format";

// Settings → Patching → Agent packages: the EasyPatch agent packages the server holds, which
// EasyRMM's agent installs and EasyPatch's agents update to.

const FORMATS: Record<string, string> = {
  msi: "Windows",
  deb: "Debian and Ubuntu",
  rpm: "Red Hat family",
  pkg: "macOS",
};

function Signature({ p }: { p: PatchAgentPackage }) {
  if (p.signatureProblem) {
    return (
      <>
        <Badge tone="danger">Not trusted</Badge>
        <span className="mt-1 block max-w-xs text-xs break-words text-muted">{p.signatureProblem}</span>
      </>
    );
  }
  if (!p.releaseKeyId) return <Badge tone="warn">Unsigned</Badge>;
  return (
    <Badge tone="ok" title={`Release key ${p.releaseKeyId}`}>
      Signed
    </Badge>
  );
}

export function AgentPackagesPanel() {
  const list = useApi<{ items: PatchAgentPackage[] }>("/patching/agent-packages");
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  const items = list.data.items;
  return (
    <Card title="EasyPatch agent packages" padded={false}>
      <p className="max-w-3xl border-b border-line px-4 py-3 text-sm text-muted">
        The packages the patching engine holds. EasyRMM&apos;s agent installs the newest one for a device&apos;s system and
        architecture, checking its size and SHA-256; EasyPatch&apos;s agents update to it after checking its release signature.
      </p>
      {items.length === 0 ? (
        <EmptyState title="No agent packages" icon={<Package className="size-8" aria-hidden />}>
          The patching engine holds no agent packages, so EasyRMM cannot install its agent on devices.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <caption className="sr-only">EasyPatch agent packages</caption>
            <thead>
              <tr>
                <th scope="col">Package</th>
                <th scope="col">For</th>
                <th scope="col" className="hidden text-right sm:table-cell">
                  Size
                </th>
                <th scope="col">Signature</th>
                <th scope="col" className="hidden lg:table-cell">
                  SHA-256
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((p) => (
                <tr key={p.fileName} className="align-top">
                  <td>
                    {p.url ? (
                      <a href={p.url} download className="inline-flex items-center gap-1.5 font-medium break-all text-accent hover:underline">
                        <Download className="size-3.5 shrink-0" aria-hidden />
                        {p.fileName}
                      </a>
                    ) : (
                      <span className="font-medium break-all">{p.fileName}</span>
                    )}
                    <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-muted">
                      Version {p.version}
                      {p.isLatest && <Badge tone="accent">Newest</Badge>}
                    </span>
                  </td>
                  <td className="whitespace-nowrap">
                    {FORMATS[p.format] ?? p.format.toUpperCase()}
                    <span className="block text-xs text-muted">{p.architecture}</span>
                  </td>
                  <td className="hidden text-right whitespace-nowrap tabular-nums sm:table-cell">{formatSize(p.sizeBytes)}</td>
                  <td>
                    <Signature p={p} />
                  </td>
                  <td className="hidden lg:table-cell">
                    <span className="flex items-center gap-1" title={p.sha256}>
                      <Mono className="inline-block max-w-40 truncate">{p.sha256}</Mono>
                      <CopyButton text={p.sha256} label="Copy" />
                    </span>
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
