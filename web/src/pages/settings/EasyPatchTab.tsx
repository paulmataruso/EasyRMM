import { useEffect, useId, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { Loader2, RefreshCw } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation, useList, useOrganizations } from "../../api/hooks";
import type { EasyPatchConnection, EasyPatchConnectionInput, EasyPatchDeviceLink, EasyPatchOrganizations, PatchingSync } from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import {
  Alert,
  Badge,
  Button,
  Card,
  Dot,
  EmptyState,
  ErrorState,
  InlineError,
  KeyValueList,
  Mono,
  Select,
  Spinner,
  TableWrap,
  TextField,
  TextareaField,
  type Tone,
} from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { LinkBadge, OpenEasyPatch } from "../patching/patchText";
import { EasyPatchSignIn } from "./EasyPatchSignIn";

const KEYS = ["/settings/easypatch", "/patching", "/audit"];

/** Platform settings: the EasyPatch server patching goes through, and which organizations it patches (ADR-0030). */
export function EasyPatchTab() {
  const conn = useApi<EasyPatchConnection>("/settings/easypatch", undefined, { refetchInterval: 30_000 });
  if (conn.isPending) return <Spinner />;
  if (conn.isError) return <ErrorState error={conn.error} onRetry={() => void conn.refetch()} />;
  const c = conn.data;
  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
        {c.bundled ? <EngineCard conn={c} className="xl:col-span-2" /> : <ServerForm conn={c} className="xl:col-span-2" />}
        <ServerStatus conn={c} />
      </div>
      {c.configured && !c.bundled && <EasyPatchSignIn />}
      {c.configured && <OrganizationLinks bundled={c.bundled} />}
      {c.configured && <DeviceProblems />}
    </div>
  );
}

function ServerForm({ conn, className }: { conn: EasyPatchConnection; className?: string }) {
  const toast = useToast();
  const [url, setUrl] = useState(conn.url);
  const [token, setToken] = useState("");
  const [caCert, setCaCert] = useState(conn.caCert);
  const [removing, setRemoving] = useState(false);
  useEffect(() => {
    setUrl(conn.url);
    setCaCert(conn.caCert);
  }, [conn.url, conn.caCert]);
  const sameServer = conn.configured && url.trim().replace(/\/+$/, "").toLowerCase() === conn.url.toLowerCase();

  const save = useApiMutation((body: EasyPatchConnectionInput) => api.put<EasyPatchConnection>("/settings/easypatch", body), {
    invalidate: KEYS,
    onSuccess: (c) => {
      setToken("");
      toast.success(
        `Connected to EasyPatch ${c.serverVersion}${c.canOperate ? "" : ". The token is read-only: EasyRMM can show patch status but not scan or install."}`,
      );
    },
  });
  const remove = useApiMutation(() => api.del("/settings/easypatch"), {
    invalidate: KEYS,
    onSuccess: () => {
      setRemoving(false);
      setUrl("");
      setCaCert("");
      toast.success("EasyPatch removed. Its organization and device links are forgotten.");
    },
  });
  const err = (f: string) => fieldError(save.error, f);

  return (
    <Card title="Server" className={className}>
      <form
        className="space-y-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate({ url: url.trim(), token: token.trim(), caCert });
        }}
      >
        <TextField
          label="Address"
          hint="EasyPatch's https address, as administrators open it."
          placeholder="https://patch.example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          error={err("url")}
          autoComplete="off"
          spellCheck={false}
          inputMode="url"
          required
        />
        <TextField
          label="API token"
          type="password"
          hint={
            sameServer
              ? "A token is stored, encrypted. Paste a new one to replace it."
              : "Create one in EasyPatch under Settings → API tokens, for the organizations EasyRMM patches. Operator lets EasyRMM scan and install; Read only, only look."
          }
          placeholder={sameServer ? "Stored" : "ept_…"}
          value={token}
          onChange={(e) => setToken(e.target.value)}
          error={err("token")}
          autoComplete="off"
          spellCheck={false}
          required={!sameServer}
        />
        <TextareaField
          label="CA certificate"
          hint="Only when EasyPatch's certificate is signed by an authority this server does not trust, such as your own. PEM."
          placeholder="-----BEGIN CERTIFICATE-----"
          value={caCert}
          onChange={(e) => setCaCert(e.target.value)}
          error={err("caCert")}
          className="[&_textarea]:font-mono [&_textarea]:text-xs"
          rows={4}
          spellCheck={false}
        />
        <InlineError error={save.error} fields={["url", "token", "caCert"]} />
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-4">
          <p className="text-xs text-muted">EasyRMM checks the address and token with EasyPatch before saving anything.</p>
          <div className="flex gap-2">
            {conn.configured && (
              <Button type="button" variant="danger-ghost" onClick={() => setRemoving(true)} disabled={save.isPending}>
                Remove
              </Button>
            )}
            <Button type="submit" variant="primary" loading={save.isPending}>
              {conn.configured ? "Save" : "Connect"}
            </Button>
          </div>
        </div>
      </form>
      <ConfirmDialog
        open={removing}
        onClose={() => setRemoving(false)}
        onConfirm={() => remove.mutate()}
        loading={remove.isPending}
        error={remove.error}
        tone="danger"
        title="Remove EasyPatch?"
        confirmLabel="Remove"
      >
        Patching disappears from EasyRMM and every organization and device link is forgotten. EasyPatch keeps patching on its own schedules; nothing changes on
        the devices.
      </ConfirmDialog>
    </Card>
  );
}

/** Patching from the engine in this deployment (EASYRMM_PATCHING=bundled, ADR-0038): there is nothing to enter here. */
function EngineCard({ conn, className }: { conn: EasyPatchConnection; className?: string }) {
  return (
    <Card title="Patching engine" className={className}>
      <div className="max-w-prose space-y-2 text-sm">
        <p>
          Patching runs in this deployment. EasyRMM calls the patching engine on this server and signs each call with the role and organizations of the person
          acting, so the engine checks them a second time.
        </p>
        <p className="text-muted">The deployment sets it up: there is no address or token to enter, and nothing to remove here.</p>
      </div>
      <KeyValueList
        narrow
        className="mt-4 border-t border-line pt-4"
        items={[
          [
            "Address",
            <span key="a">
              <Mono>{conn.url}</Mono> <span className="text-muted">(this server only)</span>
            </span>,
          ],
          ["Set by", <Mono key="s">EASYRMM_PATCHING=bundled</Mono>],
        ]}
      />
    </Card>
  );
}

function connState(c: EasyPatchConnection): { label: string; tone: Tone } {
  if (!c.configured) return { label: "Not set up", tone: "neutral" };
  if (c.lastErrorAt && (!c.checkedAt || Date.parse(c.lastErrorAt) > Date.parse(c.checkedAt))) return { label: "Failing", tone: "danger" };
  if (c.bundled) return { label: "Running", tone: "ok" };
  return c.canOperate ? { label: "Connected", tone: "ok" } : { label: "Connected, read-only", tone: "info" };
}

function When({ at }: { at?: string }) {
  return at ? <span title={formatDateTime(at)}>{formatRelative(at)}</span> : null;
}

function ServerStatus({ conn: c }: { conn: EasyPatchConnection }) {
  const check = useApiMutation(() => api.post<EasyPatchConnection>("/settings/easypatch/check"), { invalidate: KEYS });
  const state = connState(c);
  const items: [string, ReactNode][] = [
    [
      "State",
      <Badge key="s" tone={state.tone} icon={<Dot tone={state.tone} />}>
        {state.label}
      </Badge>,
    ],
  ];
  if (c.configured) {
    items.push(["Version", c.serverVersion || "—"]);
    if (c.bundled) {
      items.push(["Calls", "Signed one by one, with the person's role and organizations"]);
    } else {
      if (c.publicUrl && c.publicUrl.replace(/\/+$/, "") !== c.url) items.push(["Public address", <Mono key="p">{c.publicUrl}</Mono>]);
      const consoleUrl = [c.publicUrl, c.url].find((u) => u?.startsWith("https://"));
      if (consoleUrl) items.push(["Console", <OpenEasyPatch key="c" />]);
      items.push(["Token", c.canOperate ? "Operator: views, scans and installs" : "Read only: views"]);
    }
    items.push([
      "Install later",
      c.capabilities.includes("scheduled-installs") ? (
        "Supported"
      ) : (
        <span key="c" className="text-muted">
          Not supported by this EasyPatch: installs start at once
        </span>
      ),
    ]);
    items.push([
      "Who acted",
      c.bundled ? (
        "The engine records the EasyRMM user"
      ) : c.capabilities.includes("on-behalf-of") ? (
        "EasyPatch records the EasyRMM user"
      ) : (
        <span key="o" className="text-muted">
          EasyPatch records the token; EasyRMM's audit log records the user
        </span>
      ),
    ]);
    items.push(["Checked", <When key="w" at={c.checkedAt} />]);
    if (c.lastError) {
      const recovered = c.checkedAt && c.lastErrorAt && Date.parse(c.checkedAt) > Date.parse(c.lastErrorAt);
      items.push([
        "Last error",
        <span key="e">
          <span className={recovered ? "block break-words text-muted" : "block break-words text-danger"}>{c.lastError}</span>
          <span className="text-xs text-muted">
            <When at={c.lastErrorAt} />
          </span>
        </span>,
      ]);
    }
    if (c.updatedAt) {
      items.push([
        "Changed",
        <span key="c">
          <When at={c.updatedAt} />
          {c.updatedBy && <span className="text-muted"> by {c.updatedBy}</span>}
        </span>,
      ]);
    }
  }
  return (
    <Card
      title="Status"
      actions={
        c.configured && (
          <Button size="sm" variant="ghost" icon={<RefreshCw className="size-3.5" aria-hidden />} loading={check.isPending} onClick={() => check.mutate()}>
            Check now
          </Button>
        )
      }
    >
      <KeyValueList narrow items={items} />
      <InlineError error={check.error} />
      <div className="mt-4 space-y-2 border-t border-line pt-4 text-sm text-muted">
        {c.bundled ? (
          <p>The engine keeps patch data in its own database, beside EasyRMM's. EasyRMM reads it when someone looks, after checking the user's own role.</p>
        ) : (
          <p>
            EasyPatch stays where patch data lives. EasyRMM reads it when someone looks, and sends scans and installs with this token after checking the user's
            own role.
          </p>
        )}
        <p>EasyRMM checks {c.bundled ? "the engine" : "the server"} every 10 minutes.</p>
      </div>
    </Card>
  );
}

/** Which EasyPatch organization patches each EasyRMM organization. */
function OrganizationLinks({ bundled }: { bundled: boolean }) {
  const toast = useToast();
  const orgs = useOrganizations();
  const links = useApi<EasyPatchOrganizations>("/settings/easypatch/organizations", undefined, { refetchInterval: 60_000 });
  const sync = useApi<PatchingSync>("/settings/easypatch/sync", undefined, { enabled: bundled, refetchInterval: 60_000 });
  const [unlinking, setUnlinking] = useState<{ id: string; name: string; ep: string } | null>(null);
  const link = useApiMutation(
    ({ id, easyPatchId }: { id: string; easyPatchId: string; name: string }) => api.put(`/settings/easypatch/organizations/${id}`, { easyPatchId }),
    {
      invalidate: ["/settings/easypatch", "/patching", "/audit"],
      onSuccess: (_, v) => toast.success(`${v.name} is linked. EasyRMM checks its devices within a minute.`),
    },
  );
  const unlink = useApiMutation((id: string) => api.del(`/settings/easypatch/organizations/${id}`), {
    invalidate: ["/settings/easypatch", "/patching", "/audit"],
    onSuccess: () => {
      toast.success(`${unlinking?.name ?? "The organization"} is no longer patched from EasyRMM.`);
      setUnlinking(null);
    },
  });
  const auto = useApiMutation(
    ({ id, on }: { id: string; on: boolean; name: string }) => api.patch(`/settings/easypatch/organizations/${id}`, { autoInstall: on }),
    {
      invalidate: ["/settings/easypatch", "/patching", "/audit"],
      onSuccess: (_, v) =>
        toast.success(
          v.on
            ? `EasyRMM installs the EasyPatch agent on devices in ${v.name} that have none, within a few minutes.`
            : `EasyRMM no longer installs the EasyPatch agent in ${v.name} by itself.`,
        ),
    },
  );

  if (links.isPending || orgs.isPending) return <Spinner />;
  if (links.isError) return <ErrorState error={links.error} onRetry={() => void links.refetch()} />;
  if (orgs.isError) return <ErrorState error={orgs.error} onRetry={() => void orgs.refetch()} />;
  const byOrg = new Map(links.data.links.map((l) => [l.organizationId, l]));
  const taken = new Map(links.data.links.map((l) => [l.easyPatchId, l.organizationName]));

  return (
    <Card title="Organizations" padded={false}>
      {bundled ? (
        <div className="border-b border-line px-4 py-3 text-sm text-muted">
          <p>
            Every organization and site has its own in the patching engine. EasyRMM creates, renames and archives them as you change yours, so there is nothing
            to link. With <span className="font-medium text-fg">Install automatically</span>, on for new organizations, EasyRMM's agent installs and enrolls the
            EasyPatch agent on the organization's Windows and Linux devices that have none. To keep one device unpatched, stop patching on its Patches tab.
          </p>
          {sync.data && <SyncLine sync={sync.data} />}
        </div>
      ) : (
        <p className="border-b border-line px-4 py-3 text-sm text-muted">
          Link each EasyRMM organization to the EasyPatch organization its devices are enrolled in. A device is patched from EasyRMM once EasyRMM confirms its
          EasyPatch agent belongs to the linked organization. With <span className="font-medium text-fg">Install automatically</span>, EasyRMM's agent installs
          and enrolls the EasyPatch agent on the organization's Windows and Linux devices that have none, new ones included.
        </p>
      )}
      {links.data.error && (
        <Alert tone="danger" className="m-4" title="EasyPatch's organizations could not be read">
          {links.data.error}
        </Alert>
      )}
      <InlineError error={link.error} />
      <InlineError error={auto.error} />
      {orgs.items.length === 0 ? (
        <EmptyState title="No organizations" compact />
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>EasyRMM organization</th>
                <th>EasyPatch organization</th>
                <th className="hidden md:table-cell">Devices</th>
                <th>EasyPatch agent</th>
              </tr>
            </thead>
            <tbody>
              {orgs.items.map((o) => {
                const l = byOrg.get(o.id);
                return (
                  <OrgRow
                    key={o.id}
                    fixed={bundled}
                    name={o.name}
                    linked={l?.easyPatchId ?? ""}
                    linkedName={l?.easyPatchName}
                    choices={links.data.easyPatch.filter((e) => e.id === l?.easyPatchId || !taken.has(e.id))}
                    busy={(link.isPending && link.variables?.id === o.id) || (unlink.isPending && unlinking?.id === o.id)}
                    devices={l?.devices}
                    autoInstall={l?.autoInstall}
                    autoBusy={auto.isPending && auto.variables?.id === o.id}
                    onAutoInstall={(on) => auto.mutate({ id: o.id, on, name: o.name })}
                    onLink={(easyPatchId) => link.mutate({ id: o.id, easyPatchId, name: o.name })}
                    onUnlink={() => l && setUnlinking({ id: o.id, name: o.name, ep: l.easyPatchName })}
                  />
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
      <ConfirmDialog
        open={unlinking !== null}
        onClose={() => setUnlinking(null)}
        onConfirm={() => unlinking && unlink.mutate(unlinking.id)}
        loading={unlink.isPending}
        error={unlink.error}
        tone="danger"
        title={`Stop patching ${unlinking?.name ?? ""} from EasyRMM?`}
        confirmLabel="Unlink"
      >
        Its devices leave Patching. They stay in {unlinking?.ep} in EasyPatch, which keeps patching them on its own schedules.
      </ConfirmDialog>
    </Card>
  );
}

function OrgRow({
  fixed,
  name,
  linked,
  linkedName,
  choices,
  busy,
  devices,
  autoInstall,
  autoBusy,
  onAutoInstall,
  onLink,
  onUnlink,
}: {
  /** Links are EasyRMM's own (bundled mode, ADR-0040): shown, not chosen. */
  fixed: boolean;
  name: string;
  linked: string;
  linkedName?: string;
  choices: { id: string; name: string; isActive: boolean }[];
  busy: boolean;
  devices?: { linked: number; unlinked: number; pending: number };
  /** Undefined while the organization is not linked. */
  autoInstall?: boolean;
  autoBusy: boolean;
  onAutoInstall: (on: boolean) => void;
  onLink: (easyPatchId: string) => void;
  onUnlink: () => void;
}) {
  const id = useId();
  const autoId = useId();
  const missing = linked !== "" && !choices.some((c) => c.id === linked);
  return (
    <tr>
      <td className="font-medium">{fixed ? name : <label htmlFor={id}>{name}</label>}</td>
      <td>
        {fixed ? (
          linked ? (
            <span>{linkedName}</span>
          ) : (
            <span className="text-muted">Being created</span>
          )
        ) : (
          <div className="flex items-center gap-2">
            <Select id={id} value={linked} disabled={busy} className="max-w-64" onChange={(e) => (e.target.value ? onLink(e.target.value) : onUnlink())}>
              <option value="">Not linked</option>
              {missing && <option value={linked}>{linkedName} (not found in EasyPatch)</option>}
              {choices.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                  {c.isActive ? "" : " (inactive)"}
                </option>
              ))}
            </Select>
            {busy && <Loader2 className="size-4 animate-spin text-muted" aria-label="Saving" />}
          </div>
        )}
      </td>
      <td className="hidden text-muted md:table-cell">
        {devices ? (
          <>
            {plural(devices.linked, "device")} patched
            {devices.unlinked > 0 && <span className="text-warn">, {devices.unlinked.toLocaleString()} not linked</span>}
            {devices.pending > 0 && <>, {devices.pending.toLocaleString()} being checked</>}
          </>
        ) : (
          "—"
        )}
      </td>
      <td>
        {autoInstall === undefined ? (
          <span className="text-subtle">—</span>
        ) : (
          <label htmlFor={autoId} className="flex items-center gap-2 text-sm whitespace-nowrap">
            <input
              id={autoId}
              type="checkbox"
              checked={autoInstall}
              disabled={autoBusy}
              onChange={(e) => onAutoInstall(e.target.checked)}
              className="size-4 accent-accent"
              aria-label={`Install the EasyPatch agent automatically in ${name}`}
            />
            Install automatically
          </label>
        )}
      </td>
    </tr>
  );
}

/** How keeping the patching engine in step goes: when it last was, what it could not do, and what is waiting. */
function SyncLine({ sync }: { sync: PatchingSync }) {
  const waiting = [
    sync.archiving > 0 && `archiving ${plural(sync.archiving, "deleted organization or site", "deleted organizations and sites")}`,
    sync.removing > 0 && `removing the EasyPatch agent from ${plural(sync.removing, "device")}`,
  ].filter(Boolean);
  return (
    <div className="mt-2" role="status">
      {sync.problems.length > 0 ? (
        <Alert tone="warn" title="The patching engine is not fully in step yet">
          <ul className="list-disc space-y-0.5 pl-4">
            {sync.problems.slice(0, 5).map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
          <p className="mt-1">EasyRMM tries again every minute.</p>
        </Alert>
      ) : (
        <p className="text-xs text-subtle">
          {sync.at ? (
            <>
              In step <span title={formatDateTime(sync.at)}>{formatRelative(sync.at)}</span>
            </>
          ) : (
            "Not compared yet; EasyRMM does within a minute of starting"
          )}
          {waiting.length > 0 && <>; {waiting.join(" and ")}</>}.
        </p>
      )}
    </div>
  );
}

/** Devices with an EasyPatch agent that EasyRMM does not patch, and why. */
function DeviceProblems() {
  const list = useList<EasyPatchDeviceLink>("/settings/easypatch/devices", undefined, { refetchInterval: 60_000 });
  if (list.isPending) return <Spinner />;
  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;
  return (
    <Card title="Devices not linked" padded={false}>
      {list.items.length === 0 ? (
        <EmptyState title="Every device with an EasyPatch agent is linked" compact>
          Devices whose EasyPatch agent EasyRMM cannot match to an EasyPatch endpoint are listed here with the reason.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th>Device</th>
                <th>Why</th>
                <th className="hidden md:table-cell">Checked</th>
              </tr>
            </thead>
            <tbody>
              {list.items.map((d) => (
                <tr key={d.deviceId}>
                  <td className="align-top">
                    <Link to={`/devices/${d.deviceId}?tab=patches`} className="font-medium hover:text-accent">
                      {d.deviceName}
                    </Link>
                    <p className="text-xs text-muted">{d.organizationName}</p>
                  </td>
                  <td className="align-top">{d.reason ? <span className="text-sm">{d.reason}</span> : <LinkBadge link={d.state} />}</td>
                  <td className="hidden align-top whitespace-nowrap text-muted md:table-cell">
                    <When at={d.checkedAt} />
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
