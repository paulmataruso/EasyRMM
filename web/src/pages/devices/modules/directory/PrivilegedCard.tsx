import { Alert, Badge, Card, InlineError } from "../../../../components/ui";
import { formatDateTime } from "../../../../lib/format";
import { SkeletonGrid } from "../skeletons";
import type { Privileged } from "./types";
import { useFirstPage } from "./useFirstPage";

/** Who is in the groups that hold the domain (read only; EasyRMM never adds anyone to one). Read by itself when it opens. */
export function PrivilegedCard({ deviceId }: { deviceId: string }) {
  const read = useFirstPage<Privileged>(deviceId, "privileged_members", {});
  const data = read.page;
  return (
    <Card title="Privileged groups">
      <InlineError error={read.error} />
      {read.problem && !data && <Alert tone="warn">{read.problem}</Alert>}
      {!data && read.loading && <SkeletonGrid columns={2} rows={3} />}
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
