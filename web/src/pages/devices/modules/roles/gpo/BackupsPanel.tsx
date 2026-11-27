import { useState } from "react";
import { useApi } from "../../../../../api/hooks";
import type { Device } from "../../../../../api/types";
import { Alert, Badge, Button, Card, EmptyState, InlineError, TableWrap } from "../../../../../components/ui";
import { formatDateTime } from "../../../../../lib/format";
import { SkeletonTable } from "../../skeletons";
import { useWinmodRead } from "../../winmod";
import { RestoreDialog } from "./GpoDialogs";
import { MODULE } from "./gpoText";
import type { Gpo, GpoBackup, GpoPage } from "./types";

/** The automatic backups (ADR-0083 section 7): one is taken before every change, kept on the server, and restored from here. */
export function BackupsPanel({ device, perms, writable }: { device: Device; perms: { manage: boolean }; writable: boolean }) {
  const read = useApi<GpoBackup[]>(`/devices/${device.id}/gpo/backups`, undefined, { refetchInterval: 20_000 });
  const gpos = useWinmodRead<GpoPage>(device.id, `${MODULE}.gpo_list`, { offset: 0, pageSize: 60 });
  const [restore, setRestore] = useState<GpoBackup | null>(null);
  const list = read.data ?? null;
  const exists = (id: string): Gpo | null => gpos.data?.data?.items.find((g) => g.id === id) ?? null;
  return (
    <Card title="Backups" padded={false}>
      <InlineError error={read.error} />
      <p className="border-b border-line px-4 py-2 text-xs text-muted">
        A backup of a GPO is taken before every change to it and kept here (the newest 20 of each GPO, and any under 90 days old).
        Backups that are too large to keep stop the change, so nothing is changed without one.
      </p>
      {!list ? <SkeletonTable columns={4} rows={4} /> : list.length === 0 ? (
        <EmptyState compact title="No backups yet">The first change to a GPO, or a manual backup, makes one.</EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr><th scope="col">GPO</th><th scope="col">Taken</th><th scope="col">Before</th><th scope="col" className="hidden md:table-cell">By</th><th scope="col"><span className="sr-only">Actions</span></th></tr>
            </thead>
            <tbody>
              {list.map((b) => (
                <tr key={b.id}>
                  <td className="font-medium">{b.gpoName} {b.kind === "manual" && <Badge>manual</Badge>}</td>
                  <td title={formatDateTime(b.createdAt)}>{formatDateTime(b.createdAt)}</td>
                  <td>{b.action.replace("group_policy.", "").replaceAll("_", " ")}<div className="text-xs text-muted">{b.reason}</div></td>
                  <td className="hidden md:table-cell">{b.actorLabel}</td>
                  <td className="text-right whitespace-nowrap">
                    {perms.manage && (
                      <>
                        <a className="text-accent hover:underline mr-2 text-sm" href={`/api/v1/devices/${device.id}/gpo/backups/${b.id}/download`} download>Download</a>
                        {writable && <Button size="sm" variant="danger-ghost" onClick={() => setRestore(b)}>Restore</Button>}
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {restore && <RestoreDialog device={device} backup={restore} current={exists(restore.gpoId)} onClose={() => setRestore(null)} />}
      {!writable && <Alert tone="info" className="m-3">Restore from the controller the domain&apos;s changes go through.</Alert>}
    </Card>
  );
}
