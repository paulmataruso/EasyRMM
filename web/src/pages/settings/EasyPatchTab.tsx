import { useId, type ReactNode } from "react";
import { Link } from "react-router";
import { RefreshCw } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation, useList, useOrganizations } from "../../api/hooks";
import type { EasyPatchConnection, EasyPatchDeviceLink, EasyPatchOrganizations, PatchingSync } from "../../api/types";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, Dot, EmptyState, ErrorState, InlineError, KeyValueList, Mono, Spinner, TableWrap, type Tone } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { LinkBadge, NoPatchingEngine } from "../patching/patchText";

const KEYS = ["/settings/easypatch", "/patching", "/audit"];

/**
 * Platform settings: the patching engine in this deployment (ADR-0038), the devices it cannot match. It is the Engine view of Settings → Patching (ADR-0072). The deployment sets the engine up; there is nothing to connect (ADR-0046).
 */
export function EasyPatchTab() {
  const conn = useApi<EasyPatchConnection>("/settings/easypatch", undefined, { refetchInterval: 30_000 });
  if (conn.isPending) return <Spinner />;
  if (conn.isError) return <ErrorState error={conn.error} onRetry={() => void conn.refetch()} />;
  const c = conn.data;
  if (!c.configured) return <NoEngine />;
  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
        <EngineCard conn={c} className="xl:col-span-2" />
        <ServerStatus conn={c} />
      </div>
      <SyncStatus />
      <DeviceProblems />
    </div>
  );
}

/** A deployment without the patching engine: nothing can be set up from here. */
function NoEngine() {
  return (
    <Card>
      <NoPatchingEngine />
    </Card>
  );
}

/** The engine EasyRMM calls (ADR-0038): there is nothing to enter here. */
function EngineCard({ conn, className }: { conn: EasyPatchConnection; className?: string }) {
  return (
    <Card title="In this deployment" className={className}>
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
          ["Calls signed with", <Mono key="s">EASYRMM_PATCHING_KEY</Mono>],
        ]}
      />
    </Card>
  );
}

function connState(c: EasyPatchConnection): { label: string; tone: Tone } {
  if (c.lastErrorAt && (!c.checkedAt || Date.parse(c.lastErrorAt) > Date.parse(c.checkedAt))) return { label: "Failing", tone: "danger" };
  return { label: "Running", tone: "ok" };
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
    ["Version", c.serverVersion || "—"],
    ["Calls", "Signed one by one, with the person's role and organizations"],
    ["Who acted", "The engine records the EasyRMM user"],
    ["Checked", <When key="w" at={c.checkedAt} />],
  ];
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
  return (
    <Card
      title="Status"
      actions={
        <Button size="sm" variant="ghost" icon={<RefreshCw className="size-3.5" aria-hidden />} loading={check.isPending} onClick={() => check.mutate()}>
          Check now
        </Button>
      }
    >
      <KeyValueList narrow items={items} />
      <InlineError error={check.error} />
      <div className="mt-4 space-y-2 border-t border-line pt-4 text-sm text-muted">
        <p>The engine keeps patch data in its own database, beside EasyRMM's. EasyRMM reads it when someone looks, after checking the user's own role.</p>
        <p>EasyRMM checks the engine every 10 minutes.</p>
      </div>
    </Card>
  );
}

/** How keeping the engine's organizations in step with EasyRMM's goes (ADR-0040). Each organization's automatic agent install is on its own page. */
function SyncStatus() {
  const sync = useApi<PatchingSync>("/settings/easypatch/sync", undefined, { refetchInterval: 60_000 });
  if (!sync.data) return null;
  return (
    <Card title="Keeping the engine in step">
      <div className="text-sm text-muted">
        <p>
          EasyRMM creates, renames and archives each organization and site in the patching engine as you change yours, so there is nothing to link. Whether it
          installs the EasyPatch agent by itself is set on each organization&apos;s page, under Patching.
        </p>
        <SyncLine sync={sync.data} />
      </div>
    </Card>
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
          Devices whose EasyPatch agent EasyRMM cannot match to an endpoint in the patching engine are listed here with the reason.
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
