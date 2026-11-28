import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { AgentSettingsListing, AgentSettingsProblemDevice, AgentSettingsProblems } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Button, Card, EmptyState, ErrorState, Field, InlineError, Input, Skeleton, TableWrap } from "../../components/ui";
import { AgentSettingsPanel } from "../agentsettings/AgentSettingsPanel";

/**
 * Settings > Agent settings (ADR-0058, slice 3), for super administrators: the platform's own values, the shortest
 * interval anything below may set, and the devices that do not take settings or have not applied them.
 */
export function AgentSettingsPlatform() {
  const problems = useApi<AgentSettingsProblems>("/settings/agent-settings/problems", undefined, { refetchInterval: 60_000 });
  return (
    <div className="flex flex-col gap-5">
      <AgentSettingsPanel base="/settings/agent-settings" scope="platform" header={(l) => <Limits limits={l.limits} />} />
      {problems.isPending ? (
        <Skeleton className="h-32 w-full" />
      ) : problems.isError ? (
        <ErrorState error={problems.error} onRetry={() => void problems.refetch()} />
      ) : (
        <>
          <DeviceList
            title="Not applied"
            empty="Every device that takes settings has applied what was sent to it."
            devices={problems.data.notApplied}
            filter="/devices?settings=not_applied"
          />
          <DeviceList title="Agent does not take settings" empty="Every enrolled agent takes settings." devices={problems.data.unsupported} />
        </>
      )}
    </div>
  );
}

function Limits({ limits }: { limits: AgentSettingsListing["limits"] }) {
  const toast = useToast();
  const [draft, setDraft] = useState(String(limits.minHeartbeatSeconds));
  const save = useApiMutation((n: number) => api.put("/settings/agent-settings/limits", { minHeartbeatSeconds: n }), {
    invalidate: ["/settings/agent-settings"],
    onSuccess: () => toast.success("Saved."),
  });
  const n = Number(draft);
  const valid = draft.trim() !== "" && Number.isInteger(n) && n >= 30 && n <= 300;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (valid) save.mutate(n);
  };
  return (
    <Card title="Limits">
      <form className="flex flex-col gap-3" onSubmit={submit}>
        <div className="flex flex-wrap items-end gap-3">
          <Field
            label="Shortest heartbeat interval (seconds)"
            htmlFor="min-heartbeat"
            hint="The shortest interval an organization, site or device may set: 30 to 300."
            error={draft !== "" && !valid ? "Use a whole number from 30 to 300." : null}
          >
            <Input id="min-heartbeat" type="number" min={30} max={300} step={1} className="w-28" value={draft} onChange={(e) => setDraft(e.target.value)} />
          </Field>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!valid || n === limits.minHeartbeatSeconds}>
            Save limit
          </Button>
        </div>
        <InlineError error={save.error} />
      </form>
    </Card>
  );
}

function DeviceList({ title, empty, devices, filter }: { title: string; empty: string; devices: AgentSettingsProblemDevice[]; filter?: string }) {
  return (
    <Card title={`${title} (${devices.length})`} actions={filter && devices.length > 0 ? <Link to={filter} className="text-sm text-accent hover:underline">Open in Devices</Link> : undefined} padded={devices.length === 0}>
      {devices.length === 0 ? (
        <EmptyState compact title={empty} />
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="data-table">
            <thead>
              <tr>
                <th>Device</th>
                <th>Organization</th>
                <th>Agent</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id}>
                  <td>
                    <Link to={`/devices/${d.id}?tab=settings`} className="text-accent hover:underline">
                      {d.name}
                    </Link>
                  </td>
                  <td>{d.organizationName}</td>
                  <td>{d.agentVersion || "unknown"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Card>
  );
}
