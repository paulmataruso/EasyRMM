import { useId, useState, type ReactNode } from "react";
import { ArrowUpCircle } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { AgentUpdateMode, AgentUpdatePolicy, AgentUpdateSettings, AgentUpdateStatus } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Alert, Button, Card, ErrorState, InlineError, KeyValueList, Mono, Spinner, TextField } from "../../components/ui";
import { formatDateTime, formatNumber, formatRelative, plural } from "../../lib/format";
import { AgentUpdateBadge } from "../devices/agentUpdate";
import { archName, byArch } from "../devices/AddDevicesPage";
import { platformName } from "../devices/platform";

const MODES: { mode: AgentUpdateMode; label: string; detail: string }[] = [
  { mode: "automatic", label: "Automatically", detail: "Every agent that runs another build than this server's is updated." },
  { mode: "manual", label: "When asked", detail: "Agents are updated when someone asks: on a device's page, or for all of them here." },
  { mode: "off", label: "Off", detail: "No updates start. Updates already under way finish." },
];

/** The order the fleet's states are listed in. */
const ORDER: AgentUpdateStatus[] = ["current", "updating", "queued", "available", "failed", "unsupported"];

/** Platform settings: rolling the server's agent build out to enrolled agents (ADR-0027). */
export function AgentUpdatesTab() {
  const settings = useApi<AgentUpdateSettings>("/settings/agent-updates", undefined, { refetchInterval: 15_000 });
  if (settings.isPending) return <Spinner />;
  if (settings.isError) return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  return (
    <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
      <RolloutForm settings={settings.data} className="xl:col-span-2" />
      <Fleet settings={settings.data} />
    </div>
  );
}

function RolloutForm({ settings, className }: { settings: AgentUpdateSettings; className?: string }) {
  const toast = useToast();
  const [mode, setMode] = useState<AgentUpdateMode>(settings.mode);
  const [max, setMax] = useState(String(settings.maxConcurrent));
  const name = useId();
  const save = useApiMutation((body: AgentUpdatePolicy) => api.put<AgentUpdateSettings>("/settings/agent-updates", body), {
    invalidate: ["/settings/agent-updates", "/audit"],
    onSuccess: (s) => {
      setMode(s.mode);
      setMax(String(s.maxConcurrent));
      toast.success(s.mode === "off" ? "Saved. Agent updates are off." : "Saved.");
    },
  });
  const noBuilds = settings.builds.length === 0;

  return (
    <Card title="Rollout" className={className}>
      <form
        className="space-y-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate({ mode, maxConcurrent: Number(max) || 0 });
        }}
      >
        {noBuilds && (
          <Alert tone="warn" title="No agent builds">
            This server has no agent builds to hand out, so it updates no agents. The server image ships them; a server run from source serves them from{" "}
            <Mono>EASYRMM_AGENT_DIR</Mono>.
          </Alert>
        )}
        <fieldset className="space-y-2.5">
          <legend className="mb-1.5 text-xs font-medium text-muted">Update agents</legend>
          {MODES.map((m) => (
            <label key={m.mode} className="flex items-start gap-2.5 text-sm">
              <input type="radio" name={name} checked={mode === m.mode} onChange={() => setMode(m.mode)} className="mt-0.5 size-4 accent-accent" />
              <span>
                <span className="font-medium">{m.label}</span>
                <span className="block text-muted">{m.detail}</span>
              </span>
            </label>
          ))}
        </fieldset>
        <TextField
          label="Devices at once"
          hint="How many agents may update at the same time. The next starts when one comes back with the new build, or after 15 minutes."
          inputMode="numeric"
          value={max}
          onChange={(e) => setMax(e.target.value.replace(/\D/g, "").slice(0, 4))}
          error={fieldError(save.error, "maxConcurrent")}
          className="max-w-xs"
          required
        />
        <InlineError error={save.error} fields={["maxConcurrent"]} />
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-4">
          <span className="text-xs text-muted">
            {settings.updatedAt ? (
              <>
                Changed <span title={formatDateTime(settings.updatedAt)}>{formatRelative(settings.updatedAt)}</span>
                {settings.updatedBy && <> by {settings.updatedBy}</>}
              </>
            ) : (
              "The default setting applies."
            )}
          </span>
          <Button type="submit" variant="primary" loading={save.isPending}>
            Save
          </Button>
        </div>
      </form>
    </Card>
  );
}

function Fleet({ settings: s }: { settings: AgentUpdateSettings }) {
  const toast = useToast();
  const all = useApiMutation(() => api.post<{ requested: number }>("/settings/agent-updates/request-all"), {
    invalidate: ["/settings/agent-updates", "/devices", "/audit"],
    onSuccess: (r) =>
      toast.success(r.requested === 0 ? "Every agent that can update is up to date." : `Asked ${plural(r.requested, "agent")} to update.`),
  });
  const count = (k: AgentUpdateStatus | "none") => s.fleet[k] ?? 0;
  const outdated = count("available") + count("failed");
  const builds = [...s.builds].sort(byArch);

  const items: [ReactNode, ReactNode][] = [
    ["Build", s.version ? <Mono key="v">{s.version}</Mono> : <span className="text-muted">Version unknown</span>],
  ];
  if (builds.length > 0) {
    items.push([
      "Platforms",
      <span key="p" className="block">
        {builds.map((b) => (
          <span key={b.file} className="block" title={`SHA-256 ${b.sha256}`}>
            {platformName(b.os as "windows" | "linux")} {archName(b.arch)}
          </span>
        ))}
      </span>,
    ]);
  }
  for (const k of ORDER) {
    if (k === "current" || count(k) > 0) items.push([<AgentUpdateBadge key={k} status={k} />, formatNumber(count(k))]);
  }
  if (count("none") > 0) items.push([<span key="n" className="text-muted">No build for the platform</span>, formatNumber(count("none"))]);

  return (
    <Card title="Agents">
      <KeyValueList narrow items={items} />
      {outdated > 0 && (
        <div className="mt-4 space-y-2 border-t border-line pt-4">
          <Button icon={<ArrowUpCircle className="size-3.5" aria-hidden />} loading={all.isPending} onClick={() => all.mutate(undefined)}>
            Update {plural(outdated, "outdated agent")}
          </Button>
          {s.mode === "off" && <p className="text-xs text-muted">Updates are off: asked-for updates wait until they are on again.</p>}
          {all.error && <p className="text-xs text-danger">{all.error.message}</p>}
        </div>
      )}
      <div className="mt-4 space-y-2 border-t border-line pt-4 text-sm text-muted">
        <p>
          An agent downloads the new build from this server, checks it against the signed instruction, and restarts into it. A build that does not reach the server within ten minutes
          is undone.
        </p>
        {count("unsupported") > 0 && <p>Agents that cannot update themselves predate self-update: run the install command on them once more.</p>}
      </div>
    </Card>
  );
}
