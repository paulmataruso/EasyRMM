import { useState } from "react";
import { RefreshCw } from "lucide-react";
import type { Device, NtpStatus } from "../../../api/types";
import { useAuth } from "../../../auth/AuthContext";
import { useToast } from "../../../components/Toast";
import { Dialog } from "../../../components/Dialog";
import { Badge, Button, Card, Field, InlineError, Input, KeyValueList, Select, TableWrap, type Tone } from "../../../components/ui";
import { formatDateTime, formatRelative } from "../../../lib/format";
import { ModuleTab } from "./ModuleTab";
import { Loading, SkeletonKeyValue, SkeletonTable } from "./skeletons";
import { failureText, useWinmodChange, useWinmodRead } from "./winmod";

const SVC_TONE: Record<string, Tone> = { running: "ok", stopped: "danger" };

type ActiveDialog = null | "timezone" | "ntp-server";

export function NtpTab({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const toast = useToast();
  const configure = canAt("device.configure", { organizationId: device.organizationId, siteId: device.siteId });
  const status = useWinmodRead<NtpStatus>(device.id, "ntp.status", {});
  const change = useWinmodChange(device.id, "ntp");

  const st = status.data?.data ?? null;
  const failure = status.data?.failure ?? null;
  const lost = status.data?.lost ?? null;
  const loading = !st && !failure && !lost && !status.error;
  const [dialog, setDialog] = useState<ActiveDialog>(null);

  const open = (d: ActiveDialog) => {
    change.reset();
    setDialog(d);
  };
  const close = () => setDialog(null);

  const forceSync = async () => {
    change.reset();
    try {
      await change.mutateAsync({ action: "ntp.force_sync", params: {} });
      toast.success("Time resync triggered.");
    } catch {
      // InlineError shows it
    }
  };

  return (
    <ModuleTab
      name="Time Configuration"
      asOf={st ? (status.data?.finishedAt ?? null) : null}
      refreshing={status.isFetching}
      loading={loading}
      skeleton={
        <Loading name="Time Configuration">
          <SkeletonKeyValue title="Timezone" rows={4} />
          <SkeletonKeyValue title="Windows Time Service" rows={4} />
          <SkeletonTable title="NTP Peers" columns={4} rows={3} />
        </Loading>
      }
      offline={status.data?.offline}
      unavailable={failure ? failureText(failure) : (lost ?? undefined)}
    >
      <InlineError error={status.error} />
      {st && (
        <>
          <Card
            title="Timezone"
            actions={configure && <Button size="sm" onClick={() => open("timezone")}>Change</Button>}
          >
            <KeyValueList
              items={[
                ["Timezone", st.timezone.displayName],
                ["ID", st.timezone.id],
                ["UTC offset", st.timezone.utcOffset],
                ["DST", st.timezone.supportsDst ? <Badge key="dst" tone={st.timezone.isDst ? "info" : "neutral"}>{st.timezone.isDst ? "Active" : "Inactive"}</Badge> : <Badge key="dst" tone="neutral">Not supported</Badge>],
                ["System time (UTC)", st.systemTimeUtc],
              ]}
            />
          </Card>
          <Card
            title="Windows Time Service"
            actions={configure && (
              <Button size="sm" icon={<RefreshCw className="size-3.5" aria-hidden />} loading={change.isPending} onClick={forceSync}>Force sync</Button>
            )}
          >
            <KeyValueList
              items={[
                ["Service", <Badge key="s" tone={SVC_TONE[st.service.state] ?? "warn"}>{st.service.state}</Badge>],
                ["Source", st.service.source || "—"],
                ["Last sync", st.service.lastSync ? <span key="ls" title={formatDateTime(st.service.lastSync)}>{formatRelative(st.service.lastSync)}</span> : "Never"],
                ...(st.service.lastSyncError ? [["Last sync error", st.service.lastSyncError] as [string, string]] : []),
              ]}
            />
            <InlineError error={change.error} />
          </Card>
          {st.peers.length > 0 && (
            <Card title="NTP Peers" padded={false}>
              <TableWrap className="rounded-none border-0">
                <table className="table-base">
                  <thead>
                    <tr>
                      <th scope="col">Name</th>
                      <th scope="col">State</th>
                      <th scope="col" className="hidden sm:table-cell">Last Sync</th>
                      <th scope="col" className="hidden sm:table-cell">Poll Interval</th>
                    </tr>
                  </thead>
                  <tbody>
                    {st.peers.map((p) => (
                      <tr key={p.name}>
                        <td className="font-medium">{p.name}</td>
                        <td>{p.state}</td>
                        <td className="hidden sm:table-cell">{p.lastSync ? <span title={formatDateTime(p.lastSync)}>{formatRelative(p.lastSync)}</span> : "—"}</td>
                        <td className="hidden sm:table-cell">{p.pollInterval > 0 ? `${p.pollInterval}s` : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </Card>
          )}
          <Card
            title="Configuration"
            actions={configure && <Button size="sm" onClick={() => open("ntp-server")}>Change</Button>}
          >
            <KeyValueList
              items={[
                ["NTP server", st.config.ntpServer || "—"],
                ["Sync type", st.config.type || "—"],
              ]}
            />
          </Card>
        </>
      )}
      {dialog === "timezone" && <TimezoneDialog device={device} change={change} onClose={close} onSuccess={(msg) => { close(); toast.success(msg); }} />}
      {dialog === "ntp-server" && <NtpServerDialog device={device} current={st?.config ?? null} change={change} onClose={close} onSuccess={(msg) => { close(); toast.success(msg); }} />}
    </ModuleTab>
  );
}

function TimezoneDialog({ device, change, onClose, onSuccess }: { device: Device; change: ReturnType<typeof useWinmodChange>; onClose: () => void; onSuccess: (msg: string) => void }) {
  const [tz, setTz] = useState("");
  const submit = async () => {
    if (!tz.trim()) return;
    try {
      await change.mutateAsync({ action: "ntp.set_timezone", params: { timezoneId: tz.trim() } });
      onSuccess(`Timezone set to ${tz.trim()}.`);
    } catch {
      // shown inline
    }
  };
  return (
    <Dialog open onClose={onClose} title="Set timezone" description={`Change the timezone on ${device.name}. Use a Windows timezone ID, e.g. "Eastern Standard Time".`}>
      <Field label="Timezone ID" htmlFor="tz-id">
        <Input id="tz-id" value={tz} onChange={(e) => setTz(e.target.value)} placeholder="Eastern Standard Time" autoFocus />
      </Field>
      <InlineError error={change.error} />
      <div className="mt-4 flex justify-end gap-2 border-t border-line pt-3">
        <Button onClick={onClose} disabled={change.isPending}>Cancel</Button>
        <Button variant="primary" loading={change.isPending} disabled={!tz.trim()} onClick={submit}>Set timezone</Button>
      </div>
    </Dialog>
  );
}

function NtpServerDialog({ device, current, change, onClose, onSuccess }: { device: Device; current: { ntpServer: string; type: string } | null; change: ReturnType<typeof useWinmodChange>; onClose: () => void; onSuccess: (msg: string) => void }) {
  const [server, setServer] = useState(current?.ntpServer ?? "");
  const [syncType, setSyncType] = useState(current?.type ?? "NTP");
  const submit = async () => {
    if (!server.trim()) return;
    try {
      await change.mutateAsync({ action: "ntp.set_ntp_server", params: { server: server.trim(), syncType } });
      onSuccess(`NTP server set to ${server.trim()}.`);
    } catch {
      // shown inline
    }
  };
  return (
    <Dialog open onClose={onClose} title="Set NTP server" description={`Change the NTP server on ${device.name}.`}>
      <Field label="NTP server" htmlFor="ntp-srv">
        <Input id="ntp-srv" value={server} onChange={(e) => setServer(e.target.value)} placeholder="time.windows.com" autoFocus />
      </Field>
      <Field label="Sync type" htmlFor="sync-type" className="mt-3">
        <Select id="sync-type" value={syncType} onChange={(e) => setSyncType(e.target.value)}>
          <option value="NTP">NTP</option>
          <option value="NT5DS">NT5DS (domain hierarchy)</option>
          <option value="AllSync">AllSync</option>
        </Select>
      </Field>
      <InlineError error={change.error} />
      <div className="mt-4 flex justify-end gap-2 border-t border-line pt-3">
        <Button onClick={onClose} disabled={change.isPending}>Cancel</Button>
        <Button variant="primary" loading={change.isPending} disabled={!server.trim()} onClick={submit}>Set NTP server</Button>
      </div>
    </Dialog>
  );
}
