import { useState } from "react";
import { Alert, Badge, Button, Card, InlineError } from "../../../../components/ui";
import { formatDateTime } from "../../../../lib/format";
import type { Privileged } from "./types";
import { useWinmod } from "./useWinmod";

/** Who is in the groups that hold the domain (read only; EasyRMM never adds anyone to one). */
export function PrivilegedCard({ deviceId }: { deviceId: string }) {
  const run = useWinmod(deviceId);
  const [data, setData] = useState<Privileged | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const load = async () => {
    setBusy(true);
    setError(null);
    setProblem(null);
    try {
      const r = await run<Privileged>("privileged_members");
      if (r.ok && r.data) setData(r.data);
      else setProblem(r.failure?.message ?? "The controller did not answer.");
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Privileged groups">
      {!data && (
        <Button size="sm" onClick={() => void load()} loading={busy}>
          Show who is in them
        </Button>
      )}
      <InlineError error={error} />
      {problem && <Alert tone="warn">{problem}</Alert>}
      {data && (
        <div className="flex flex-col gap-4">
          {data.groups.map((g) => (
            <div key={g.id}>
              <h3 className="text-sm font-medium">
                {g.name} <Badge tone={g.tier === 1 ? "danger" : "neutral"}>{g.tier === 1 ? "Holds the domain" : "Privileged"}</Badge>
              </h3>
              <p className="text-xs text-muted">
                {g.total} direct member{g.total === 1 ? "" : "s"}
                {g.changedAt ? `; changed ${formatDateTime(g.changedAt)}` : ""}
              </p>
              <ul className="mt-1 text-sm">
                {g.members.map((m) => (
                  <li key={m.id}>
                    {m.name} <span className="text-xs text-muted">({m.kind})</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
