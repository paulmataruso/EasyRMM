import { useId, useRef, useState, type ReactNode } from "react";
import { ArrowUpCircle, Download, Trash2, Upload } from "lucide-react";
import { api, apiUrl, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { AgentBuild, AgentUpdateMode, AgentUpdatePolicy, AgentUpdateSettings, AgentUpdateStatus, SignedAgentBuild } from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, ErrorState, InlineError, KeyValueList, Mono, Spinner, TableWrap, TextField } from "../../components/ui";
import { formatDate, formatDateTime, formatNumber, formatRelative, plural } from "../../lib/format";
import { AgentUpdateBadge, commonName } from "../devices/agentUpdate";
import { archName, byArch } from "../devices/AddDevicesPage";
import { platformName } from "../devices/platform";

const MODES: { mode: AgentUpdateMode; label: string; detail: string }[] = [
  { mode: "automatic", label: "Automatically", detail: "Every agent that runs another build than this server's is updated." },
  { mode: "manual", label: "When asked", detail: "Agents are updated when someone asks: on a device's page, or for all of them here." },
  { mode: "off", label: "Off", detail: "No updates start. Updates already under way finish." },
];

/** The order the fleet's states are listed in. */
const ORDER: AgentUpdateStatus[] = ["current", "updating", "queued", "available", "failed", "waiting", "unsupported"];

/** Platform settings: rolling the server's agent build out to enrolled agents (ADR-0027). */
export function AgentUpdatesTab() {
  const settings = useApi<AgentUpdateSettings>("/settings/agent-updates", undefined, { refetchInterval: 15_000 });
  if (settings.isPending) return <Spinner />;
  if (settings.isError) return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  const windows = settings.data.release.some((b) => b.os === "windows");
  return (
    <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
      <div className="space-y-5 xl:col-span-2">
        <RolloutForm settings={settings.data} windows={windows} />
        {windows && <SignedBuilds settings={settings.data} />}
      </div>
      <Fleet settings={settings.data} />
    </div>
  );
}

function RolloutForm({ settings, windows }: { settings: AgentUpdateSettings; windows: boolean }) {
  const toast = useToast();
  const [mode, setMode] = useState<AgentUpdateMode>(settings.mode);
  const [max, setMax] = useState(String(settings.maxConcurrent));
  const [signedOnly, setSignedOnly] = useState(settings.signedOnly);
  const name = useId();
  const save = useApiMutation((body: AgentUpdatePolicy) => api.put<AgentUpdateSettings>("/settings/agent-updates", body), {
    invalidate: ["/settings/agent-updates", "/devices", "/audit"],
    onSuccess: (s) => {
      setMode(s.mode);
      setMax(String(s.maxConcurrent));
      setSignedOnly(s.signedOnly);
      toast.success(s.mode === "off" ? "Saved. Agent updates are off." : "Saved.");
    },
  });
  const noBuilds = settings.release.length === 0;

  return (
    <Card title="Rollout">
      <form
        className="space-y-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate({ mode, maxConcurrent: Number(max) || 0, signedOnly });
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
        {windows && (
          <label className="flex items-start gap-2.5 text-sm">
            <input type="checkbox" checked={signedOnly} onChange={(e) => setSignedOnly(e.target.checked)} className="mt-0.5 size-4 accent-accent" />
            <span>
              <span className="font-medium">Hand out signed Windows builds only</span>
              <span className="block text-muted">
                Windows computers install and update to builds you signed, never an unsigned one. After an upgrade they keep the older signed build until
                you sign the new one.
              </span>
            </span>
          </label>
        )}
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

/** Windows builds signed with the operator's own certificate (ADR-0049). */
function SignedBuilds({ settings: s }: { settings: AgentUpdateSettings }) {
  const toast = useToast();
  const input = useRef<HTMLInputElement>(null);
  const [removing, setRemoving] = useState<SignedAgentBuild | null>(null);
  const upload = useApiMutation((file: File) => api.upload<SignedAgentBuild>("/settings/agent-updates/signed", file), {
    invalidate: ["/settings/agent-updates", "/devices", "/audit"],
    onSuccess: (b) =>
      toast.success(
        b.served
          ? `Uploaded. Windows ${archName(b.arch)} agents update to the signed build.`
          : `Uploaded. It is kept, but the server hands out another build for Windows ${archName(b.arch)}.`,
      ),
  });
  const remove = useApiMutation((id: string) => api.del(`/settings/agent-updates/signed/${id}`), {
    invalidate: ["/settings/agent-updates", "/devices", "/audit"],
    onSuccess: () => {
      setRemoving(null);
      toast.success("Removed the signed build.");
    },
  });
  const release = s.release.filter((b) => b.os === "windows").sort(byArch);

  return (
    <Card
      title="Signed Windows builds"
      padded={false}
      actions={
        <Button size="sm" variant="primary" icon={<Upload className="size-3.5" aria-hidden />} loading={upload.isPending} onClick={() => input.current?.click()}>
          Upload a signed build
        </Button>
      }
    >
      <input
        ref={input}
        type="file"
        accept=".exe"
        className="sr-only"
        tabIndex={-1}
        aria-hidden
        data-testid="signed-build-file"
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = "";
          if (file) upload.mutate(file);
        }}
      />
      <div className="space-y-3 border-b border-line px-4 py-3">
        <p className="max-w-3xl text-sm text-muted">
          Sign the Windows agent with your own code signing certificate, so that Windows and security tools name you as its publisher. Download each build,
          sign it with your own tools (signtool, jsign or osslsigncode, with your token or cloud key), and upload it. EasyRMM checks that it is this
          server&apos;s build with only a signature added, hands it out in its place, and agents update to it. EasyRMM never holds your key.
        </p>
        <InlineError error={upload.error} />
      </div>
      <TableWrap className="rounded-none border-0">
        <table className="table-base">
          <thead>
            <tr>
              <th>Build</th>
              <th>Handed out</th>
            </tr>
          </thead>
          <tbody>
            {release.map((r) => (
              <ReleaseRow key={r.file} release={r} served={s.builds.find((b) => b.file === r.file)} withheld={s.withheld.includes(r.arch)} />
            ))}
          </tbody>
        </table>
      </TableWrap>
      {s.signed.length > 0 && (
        <div className="border-t border-line">
          <h3 className="px-4 pt-3 pb-1 text-xs font-medium text-muted">Uploaded</h3>
          <ul className="divide-y divide-line">
            {s.signed.map((b) => (
              <SignedRow key={b.id} build={b} onRemove={() => setRemoving(b)} />
            ))}
          </ul>
        </div>
      )}
      <ConfirmDialog
        open={removing !== null}
        onClose={() => setRemoving(null)}
        onConfirm={() => removing && remove.mutate(removing.id)}
        title={removing ? `Remove the signed ${archName(removing.arch)} build of ${removing.version}?` : ""}
        confirmLabel="Remove"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
      >
        {removing?.served
          ? s.signedOnly
            ? "Windows computers get an older signed build instead, if one is kept, or none."
            : "The release's unsigned build is handed out again, and Windows agents update back to it."
          : "It is not handed out now; nothing changes on Windows computers."}
      </ConfirmDialog>
    </Card>
  );
}

/** One Windows architecture: the release's build and what is handed out for it. */
function ReleaseRow({ release: r, served, withheld }: { release: AgentBuild; served?: AgentBuild; withheld: boolean }) {
  let state: ReactNode;
  if (withheld || !served) {
    state = (
      <span className="block space-y-1">
        <Badge tone="warn">None</Badge>
        <span className="block text-xs text-muted">Only signed builds are handed out, and this one is not signed yet.</span>
      </span>
    );
  } else if (served.signed) {
    const older = served.version !== r.version;
    state = (
      <span className="block space-y-1">
        <Badge tone={older ? "warn" : "ok"}>{older ? `Signed ${served.version}` : "Signed"}</Badge>
        <span className="block text-xs text-muted">
          By {commonName(served.signed.subject)}
          {older && `; waiting for a signed build of ${r.version || "this version"}`}
        </span>
      </span>
    );
  } else {
    state = <span className="text-muted">The release&apos;s build, unsigned</span>;
  }
  return (
    <tr>
      <td className="align-top">
        <span className="block font-medium">Windows {archName(r.arch)}</span>
        <Mono className="text-xs whitespace-nowrap text-muted">{r.version || "version unknown"}</Mono>
        <a
          href={apiUrl(`/settings/agent-updates/release/${r.file}`)}
          download={r.file}
          className="mt-1.5 flex w-fit items-center gap-1.5 text-sm font-medium whitespace-nowrap text-accent hover:underline"
          title={`SHA-256 ${r.sha256}`}
        >
          <Download className="size-3.5 shrink-0" aria-hidden />
          Download to sign
        </a>
      </td>
      <td className="align-top">{state}</td>
    </tr>
  );
}

/** A signed build the server keeps, with its signer. */
function SignedRow({ build: b, onRemove }: { build: SignedAgentBuild; onRemove: () => void }) {
  const expired = new Date(b.signer.notAfter).getTime() < Date.now();
  return (
    <li className="flex items-start gap-4 px-4 py-3">
      <div className="min-w-0 flex-1 space-y-1 text-sm">
        <p className="flex flex-wrap items-center gap-2">
          <span className="font-medium">
            Windows {archName(b.arch)} <Mono className="whitespace-nowrap">{b.version}</Mono>
          </span>
          {b.served && <Badge tone="ok">Handed out</Badge>}
        </p>
        <p className="text-muted">
          Signed by {commonName(b.signer.subject)}, issued by {commonName(b.signer.issuer)}
        </p>
        <p className="text-xs text-muted">
          Thumbprint <Mono className="break-all">{b.signer.thumbprint}</Mono>
        </p>
        <p className="text-xs">
          {b.signer.timestamped ? (
            <span className="text-muted">Timestamped: stays valid after the certificate expires on {formatDate(b.signer.notAfter)}.</span>
          ) : expired ? (
            <span className="text-danger">
              Not timestamped, and the certificate expired on {formatDate(b.signer.notAfter)}: Windows no longer trusts this signature. Sign it again with a
              timestamp.
            </span>
          ) : (
            <span className="text-warn">
              Not timestamped: Windows stops trusting this signature when the certificate expires on {formatDate(b.signer.notAfter)}. Sign with a timestamp
              server.
            </span>
          )}
        </p>
        <p className="text-xs text-muted">
          Uploaded <span title={formatDateTime(b.uploadedAt)}>{formatRelative(b.uploadedAt)}</span>
          {b.uploadedBy && <> by {b.uploadedBy}</>}
        </p>
      </div>
      <Button size="sm" variant="ghost" className="shrink-0" icon={<Trash2 className="size-3.5" aria-hidden />} onClick={onRemove}>
        Remove
      </Button>
    </li>
  );
}
