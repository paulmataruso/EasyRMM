import { RefreshCw } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { AgentFileEntry, AgentFiles, Platform } from "../../api/types";
import { CopyButton } from "../../components/Copy";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, EmptyState, ErrorState, Mono, Spinner, TableWrap } from "../../components/ui";
import { formatDateTime, formatSize } from "../../lib/format";
import { platformName } from "../devices/platform";

/** Where each value comes from. */
export const SOURCE_NAMES: Record<AgentFileEntry["source"], string> = {
  server: "Served by this server",
  meshcentral: "MeshCentral",
  patching: "Patching engine",
};

/**
 * Every file this server hands out or the agents install, with MD5 and SHA-256 (ADR-0070). Read-only: it follows what
 * it describes. MD5 is here because some allow lists still ask for it; nothing is trusted by it.
 */
export function AgentFilesTab() {
  const files = useApi<AgentFiles>("/settings/agent-files", undefined, { refetchInterval: 60_000 });
  const toast = useToast();
  const refresh = useApiMutation(() => api.post<AgentFiles>("/settings/agent-files/refresh"), {
    invalidate: ["/settings/agent-files"],
    onSuccess: () => toast.success("The list was computed again."),
  });
  if (files.isPending) return <Spinner />;
  if (files.isError) return <ErrorState error={files.error} onRetry={() => void files.refetch()} />;
  const { entries, canRefresh } = files.data;
  return (
    <Card
      title="Agent files"
      padded={false}
      actions={
        canRefresh && (
          <Button size="sm" onClick={() => refresh.mutate(undefined)} loading={refresh.isPending} icon={<RefreshCw className="size-3.5" aria-hidden />}>
            Refresh
          </Button>
        )
      }
    >
      <div className="space-y-3 p-4">
        <p className="text-sm text-muted">
          Every file this server hands out or the agents install, for allow-listing by hash in Microsoft Defender for Endpoint and elsewhere. It is rebuilt when
          the server starts, when a signed build is accepted or removed, and when a device reports a version it lacks. MD5 is shown because some allow lists ask
          for it; it is never used to trust a file.
        </p>
        {entries.some((e) => e.stale) && (
          <Alert tone="warn" title="Some values are out of date">
            A source could not be read the last time, so its last values are shown and marked stale.
          </Alert>
        )}
      </div>
      {entries.length === 0 ? (
        <EmptyState compact title="No files listed yet">
          The list is computed when the server starts. Try again in a moment.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-x-0 border-b-0">
          <table className="w-full text-left text-sm">
            <thead className="bg-surface-2 text-xs text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">File</th>
                <th className="px-4 py-2 font-medium">Platform</th>
                <th className="px-4 py-2 font-medium">Version</th>
                <th className="px-4 py-2 font-medium">Size</th>
                <th className="px-4 py-2 font-medium">MD5</th>
                <th className="px-4 py-2 font-medium">SHA-256</th>
                <th className="px-4 py-2 font-medium">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {entries.map((e) => (
                <tr key={e.id}>
                  <td className="px-4 py-2 align-top">
                    <Mono>{e.name}</Mono>
                    {e.signer && <span className="block text-xs text-muted">Signed by {e.signer}</span>}
                  </td>
                  <td className="px-4 py-2 align-top">
                    {platformName(e.platform as Platform)} {e.arch}
                  </td>
                  <td className="px-4 py-2 align-top">{e.version || <span className="text-muted">—</span>}</td>
                  <td className="px-4 py-2 align-top whitespace-nowrap">{formatSize(e.size)}</td>
                  <td className="px-4 py-2 align-top">
                    <HashCell value={e.md5} />
                  </td>
                  <td className="px-4 py-2 align-top">
                    <HashCell value={e.sha256} />
                  </td>
                  <td className="px-4 py-2 align-top text-xs">
                    {SOURCE_NAMES[e.source]}
                    <span className="block text-muted">Computed {formatDateTime(e.computedAt)}</span>
                    {e.stale && (
                      <Badge tone="warn" title={e.staleReason}>
                        Stale
                      </Badge>
                    )}
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

/** A hash, shortened to what fits, whole on hover and in what Copy copies. */
export function HashCell({ value }: { value: string }) {
  if (!value) return <span className="text-muted">—</span>;
  return (
    <span className="flex items-center gap-2">
      <Mono className="text-xs">
        <span title={value}>{value.slice(0, 12)}…</span>
      </Mono>
      <CopyButton text={value} label="Copy" className="shrink-0" />
    </span>
  );
}
