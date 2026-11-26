import { useCallback, useState } from "react";
import { Lock } from "lucide-react";
import { Dialog } from "../../../../components/Dialog";
import { Alert, Badge, Button, Card, InlineError, TableWrap } from "../../../../components/ui";
import type { GroupPage, GroupRow, MemberPage } from "./types";
import { useWinmod } from "./useWinmod";

/** The groups of the domain, and who is directly in each. Reading only: membership changes are not offered here. */
export function GroupsCard({ deviceId }: { deviceId: string }) {
  const run = useWinmod(deviceId);
  const [rows, setRows] = useState<GroupRow[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [open, setOpen] = useState<GroupRow | null>(null);

  const load = useCallback(
    async (after?: string) => {
      setBusy(true);
      setError(null);
      setProblem(null);
      try {
        const r = await run<GroupPage>("group_list", { scope: "subtree", pageSize: 100, ...(after ? { after } : {}) });
        if (!r.ok || !r.data) {
          setProblem(r.failure?.message ?? "The controller did not answer.");
          return;
        }
        const page = r.data;
        setRows((old) => (after && old ? [...old, ...page.items] : page.items));
        setNext(page.next);
      } catch (e) {
        setError(e);
      } finally {
        setBusy(false);
      }
    },
    [run],
  );

  return (
    <Card title="Groups">
      {!rows && (
        <Button size="sm" onClick={() => void load()} loading={busy}>
          List groups
        </Button>
      )}
      <InlineError error={error} />
      {problem && <Alert tone="warn">{problem}</Alert>}
      {rows && (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Kind</th>
                <th scope="col">Description</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((g) => (
                <tr key={g.id}>
                  <td>
                    {g.name}{" "}
                    {g.protection === "protected" && (
                      <Badge tone="info" icon={<Lock className="size-3" aria-hidden />} title={`Protected: ${g.reason}. EasyRMM never changes it.`}>
                        Protected
                      </Badge>
                    )}
                  </td>
                  <td>
                    {g.category}, {g.scope}
                  </td>
                  <td className="text-muted">{g.description}</td>
                  <td className="text-right">
                    <Button size="sm" onClick={() => setOpen(g)}>
                      Members
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {next && (
        <Button className="mt-3" size="sm" onClick={() => void load(next)} loading={busy}>
          Show more
        </Button>
      )}
      <MembersDialog deviceId={deviceId} group={open} onClose={() => setOpen(null)} />
    </Card>
  );
}

function MembersDialog({ deviceId, group, onClose }: { deviceId: string; group: GroupRow | null; onClose: () => void }) {
  const run = useWinmod(deviceId);
  const [page, setPage] = useState<MemberPage | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [loadedFor, setLoadedFor] = useState<string | null>(null);
  if (group && loadedFor !== group.id) {
    // Read the members when the dialog opens for a group.
    setLoadedFor(group.id);
    setPage(null);
    setError(null);
    setProblem(null);
    void run<MemberPage>("group_members", { id: group.id, pageSize: 100 })
      .then((r) => (r.ok && r.data ? setPage(r.data) : setProblem(r.failure?.message ?? "The controller did not answer.")))
      .catch(setError);
  }
  if (!group && loadedFor !== null) setLoadedFor(null);
  return (
    <Dialog open={group !== null} onClose={onClose} title={group ? `Members of ${group.name}` : ""} footer={<Button onClick={onClose}>Close</Button>}>
      <InlineError error={error} />
      {problem && <Alert tone="warn">{problem}</Alert>}
      {!page && !problem && !error && <p className="text-sm text-muted">Reading…</p>}
      {page && (
        <>
          <p className="mb-2 text-xs text-muted">
            {page.total} direct member{page.total === 1 ? "" : "s"}
            {page.next ? "; the first 100 are shown" : ""}.
          </p>
          <ul className="flex flex-col gap-1 text-sm">
            {page.items.map((m) => (
              <li key={m.id}>
                {m.name} <span className="text-xs text-muted">({m.kind})</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Dialog>
  );
}
