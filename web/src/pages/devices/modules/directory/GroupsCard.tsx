import { useCallback, useEffect, useRef, useState } from "react";
import { Lock } from "lucide-react";
import { Dialog } from "../../../../components/Dialog";
import { AddMemberDialog, CreateGroupDialog, DeleteGroupDialog, RemoveMemberDialog } from "./GroupDialogs";
import { Alert, Badge, Button, Card, InlineError, TableWrap } from "../../../../components/ui";
import type { GroupMember, GroupPage, GroupRow, MemberPage } from "./types";
import { useWinmod } from "./useWinmod";
import { useFirstPage } from "./useFirstPage";
import { SkeletonGrid } from "../skeletons";

/** The groups of the domain, and who is directly in each. Reading only: membership changes are not offered here. */
export function GroupsCard({ deviceId, canManage, recycleBin, minLength }: { deviceId: string; canManage: boolean; recycleBin: boolean; minLength?: number }) {
  void minLength;
  const run = useWinmod(deviceId);
  const first = useFirstPage<GroupPage>(deviceId, "group_list", { scope: "subtree", pageSize: 100 });
  const asked = useRef(false);
  const [rows, setRows] = useState<GroupRow[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [open, setOpen] = useState<GroupRow | null>(null);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<GroupRow | null>(null);

  const load = useCallback(
    async (after?: string) => {
      setBusy(true);
      setError(null);
      setProblem(null);
      try {
        asked.current = Boolean(after);
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

  useEffect(() => {
    if (first.page && !asked.current) {
      setRows(first.page.items);
      setNext(first.page.next);
    }
  }, [first.page]);

  return (
    <Card title="Groups">
      <div className="mb-3 flex gap-2">
        {canManage && (
          <Button size="sm" onClick={() => setCreating(true)}>
            Create group
          </Button>
        )}
      </div>
      <InlineError error={error} />
      {(problem ?? first.problem) && !rows && <Alert tone="warn">{problem ?? first.problem}</Alert>}
      {problem && rows && <Alert tone="warn">{problem}</Alert>}
      {!rows && first.loading && !problem && <SkeletonGrid columns={4} rows={5} />}
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
                    <span className="inline-flex gap-1">
                      <Button size="sm" onClick={() => setOpen(g)}>
                        Members
                      </Button>
                      {canManage && g.protection !== "protected" && (
                        <Button size="sm" variant="danger-ghost" onClick={() => setDeleting(g)}>
                          Delete
                        </Button>
                      )}
                    </span>
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
      <MembersDialog deviceId={deviceId} group={open} canManage={canManage} onClose={() => setOpen(null)} />
      <CreateGroupDialog deviceId={deviceId} open={creating} onClose={(c) => { setCreating(false); if (c) void load(); }} />
      <DeleteGroupDialog deviceId={deviceId} group={deleting} recycleBin={recycleBin} onClose={(c) => { setDeleting(null); if (c) { setRows(null); void load(); } }} />
    </Card>
  );
}

function MembersDialog({ deviceId, group, canManage, onClose }: { deviceId: string; group: GroupRow | null; canManage: boolean; onClose: () => void }) {
  const run = useWinmod(deviceId);
  const [page, setPage] = useState<MemberPage | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<GroupMember | null>(null);
  const [tick, setTick] = useState(0);
  const id = group?.id;
  useEffect(() => {
    if (!id) return;
    let live = true;
    setPage(null);
    setError(null);
    setProblem(null);
    run<MemberPage>("group_members", { id, pageSize: 100 })
      .then((r) => live && (r.ok && r.data ? setPage(r.data) : setProblem(r.failure?.message ?? "The controller did not answer.")))
      .catch((e) => live && setError(e));
    return () => {
      live = false;
    };
  }, [id, run, tick]);
  const editable = canManage && group !== null && group.protection !== "protected";
  return (
    <Dialog open={group !== null} onClose={onClose} title={group ? `Members of ${group.name}` : ""} footer={<Button onClick={onClose}>Close</Button>}>
      <InlineError error={error} />
      {problem && <Alert tone="warn">{problem}</Alert>}
      {!page && !problem && !error && <p className="text-sm text-muted">Reading…</p>}
      {group && editable && (
        <Button className="mb-2" size="sm" onClick={() => setAdding(true)}>
          Add member
        </Button>
      )}
      {page && (
        <>
          <p className="mb-2 text-xs text-muted">
            {page.total} direct member{page.total === 1 ? "" : "s"}
            {page.next ? "; the first 100 are shown" : ""}.
          </p>
          <ul className="flex flex-col gap-1 text-sm">
            {page.items.map((m) => (
              <li key={m.id} className="flex items-center gap-2">
                <span>
                  {m.name} <span className="text-xs text-muted">({m.kind})</span>
                </span>
                {editable && (
                  <Button size="sm" variant="danger-ghost" onClick={() => setRemoving(m)}>
                    Remove
                  </Button>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
      <AddMemberDialog deviceId={deviceId} group={adding ? group : null} onClose={(c) => { setAdding(false); if (c) setTick((t) => t + 1); }} />
      {group && <RemoveMemberDialog deviceId={deviceId} group={group} member={removing} onClose={(c) => { setRemoving(null); if (c) setTick((t) => t + 1); }} />}
    </Dialog>
  );
}
