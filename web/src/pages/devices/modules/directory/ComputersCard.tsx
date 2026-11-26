import { useCallback, useState } from "react";
import { Alert, Badge, Button, Card, InlineError, TableWrap } from "../../../../components/ui";
import { ActionDialog, Done } from "./ActionDialog";
import type { ComputerPage, ComputerRow } from "./types";
import { confirmFor, useWinmod } from "./useWinmod";

/** The computer accounts of the domain. A domain controller is shown and never offered a change. */
export function ComputersCard({ deviceId, canManage }: { deviceId: string; canManage: boolean }) {
  const run = useWinmod(deviceId);
  const [rows, setRows] = useState<ComputerRow[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [disabling, setDisabling] = useState<ComputerRow | null>(null);
  const load = useCallback(
    async (after?: string) => {
      setBusy(true);
      setError(null);
      setProblem(null);
      try {
        const r = await run<ComputerPage>("computer_list", { scope: "subtree", pageSize: 100, ...(after ? { after } : {}) });
        if (!r.ok || !r.data) return setProblem(r.failure?.message ?? "The controller did not answer.");
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
    <Card title="Computers">
      {!rows && (
        <Button size="sm" onClick={() => void load()} loading={busy}>
          List computers
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
                <th scope="col">Operating system</th>
                <th scope="col">State</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id}>
                  <td>{c.dnsName || c.name}</td>
                  <td className="text-muted">{c.os}</td>
                  <td className="space-x-1">
                    <Badge tone={c.enabled ? "ok" : "neutral"}>{c.enabled ? "Enabled" : "Disabled"}</Badge>
                    {c.controller && <Badge tone="info">Domain controller</Badge>}
                  </td>
                  <td className="text-right">
                    {canManage && c.enabled && !c.controller && (
                      <Button size="sm" onClick={() => setDisabling(c)}>
                        Disable
                      </Button>
                    )}
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
      {disabling && (
        <ActionDialog
          open
          title={`Disable ${disabling.name}`}
          description="The computer can no longer sign in to the domain."
          verb="Disable"
          danger
          confirmWord={disabling.sam}
          submit={() => run("computer_disable", { id: disabling.id }, confirmFor("computer_disable", disabling.id))}
          done={() => <Done>The computer account was disabled.</Done>}
          onClose={(c) => {
            setDisabling(null);
            if (c) void load();
          }}
        />
      )}
    </Card>
  );
}
