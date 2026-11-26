import { useState } from "react";
import { Lock, Plus } from "lucide-react";
import type { Device, DnsRecord, DnsRecordList, DnsStatus, DnsZone, DnsZoneList } from "../../../../../api/types";
import { useAuth } from "../../../../../auth/AuthContext";
import { Alert, Badge, Button, Card, EmptyState, InlineError, KeyValueList, TableWrap } from "../../../../../components/ui";
import { ModuleTab } from "../../ModuleTab";
import { failureText, useWinmodChange, useWinmodRead } from "../../winmod";
import { CreateZoneDialog, RecordDialog, RemoveAllDialog, RemoveRecordDialog, RemoveZoneDialog, UpdateDialog } from "./DnsDialogs";
import { isProtectedRecord, isProtectedZone, storage, ttlText } from "./dnsText";

type Dialog =
  | { kind: "add" }
  | { kind: "edit"; record: DnsRecord }
  | { kind: "remove"; record: DnsRecord }
  | { kind: "removeAll"; name: string }
  | { kind: "createZone" }
  | { kind: "removeZone"; zone: DnsZone }
  | { kind: "update"; zone: DnsZone };

const STATE_TONE = { running: "ok", stopped: "danger", absent: "neutral" } as const;

/** The DNS Server module (ADR-0076, section 4): the server's state, its zones and the records of a zone. */
export function DnsView({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const manage = canAt("dns.manage", { organizationId: device.organizationId, siteId: device.siteId });
  const [started, setStarted] = useState(false);
  const [zoneName, setZoneName] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const status = useWinmodRead<DnsStatus>(device.id, "dns.status", {}, started);
  const zones = useWinmodRead<DnsZoneList>(device.id, "dns.zone_list", {}, started);
  const records = useWinmodRead<DnsRecordList>(device.id, "dns.record_list", { zone: zoneName ?? "", offset }, started && zoneName !== null);
  const change = useWinmodChange(device.id, "dns");

  const reads = [status, zones, ...(zoneName ? [records] : [])];
  const refreshing = reads.some((r) => r.isFetching);
  const refresh = () => {
    if (!started) setStarted(true);
    else reads.forEach((r) => void r.refetch());
  };
  const failure = reads.map((r) => r.data?.failure).find(Boolean);
  const lost = reads.map((r) => r.data?.lost).find(Boolean);
  const st = status.data?.data ?? null;
  const zoneList = zones.data?.data ?? null;
  const zone = zoneList?.zones.find((z) => z.name === zoneName) ?? null;
  const open = (d: Dialog) => {
    change.reset();
    setDialog(d);
  };
  const close = () => setDialog(null);

  return (
    <ModuleTab
      name="DNS Server"
      asOf={st ? (status.data?.finishedAt ?? null) : null}
      onRefresh={refresh}
      refreshing={refreshing}
      unavailable={failure ? failureText(failure) : (lost ?? undefined)}
    >
      <InlineError error={status.error ?? zones.error ?? records.error} />
      {st && (
        <Card title="Server">
          <KeyValueList
            items={[
              ["Service", <Badge key="s" tone={STATE_TONE[st.serviceState as keyof typeof STATE_TONE] ?? "warn"}>{st.serviceState}</Badge>],
              ["Zones", `${st.zoneCount} (${st.adIntegratedCount} in Active Directory)`],
              ["Recursion", st.recursionEnabled === null ? "—" : st.recursionEnabled ? "On" : "Off"],
              ["Forwarders", st.forwarders.length ? st.forwarders.join(", ") : "None"],
              ["Listening on", st.listenAddresses.length ? st.listenAddresses.join(", ") : "All addresses"],
              ["Scavenging", st.scavengingHours === null ? "—" : st.scavengingHours === 0 ? "Off" : `every ${st.scavengingHours} h`],
            ]}
          />
          {st.transferAnyZones.length > 0 && (
            <Alert tone="warn" className="mt-3" title="Zone transfers are open to any server">
              {st.transferAnyZones.join(", ")} can be copied by anyone who asks. Restrict transfers to the listed name servers in the DNS console.
            </Alert>
          )}
        </Card>
      )}
      {zoneList && (
        <Card
          title="Zones"
          padded={false}
          actions={manage && <Button size="sm" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => open({ kind: "createZone" })}>Add zone</Button>}
        >
          {zoneList.zones.length === 0 ? (
            <EmptyState compact title="No zones">This server holds no zones yet.</EmptyState>
          ) : (
            <TableWrap className="rounded-none border-0">
              <table className="table-base">
                <thead>
                  <tr>
                    <th scope="col">Zone</th>
                    <th scope="col">Type</th>
                    <th scope="col" className="hidden md:table-cell">Stored in</th>
                    <th scope="col" className="hidden sm:table-cell">Dynamic updates</th>
                    <th scope="col"><span className="sr-only">Actions</span></th>
                  </tr>
                </thead>
                <tbody>
                  {zoneList.zones.map((z) => (
                    <tr key={z.name} aria-selected={z.name === zoneName}>
                      <td className="font-medium">{z.name}{z.reverse && <Badge className="ml-2">reverse</Badge>}{z.paused && <Badge tone="warn" className="ml-2">paused</Badge>}</td>
                      <td>{z.type}</td>
                      <td className="hidden md:table-cell">{storage(z)}</td>
                      <td className="hidden sm:table-cell">{z.dynamicUpdate || "—"}</td>
                      <td className="text-right whitespace-nowrap">
                        <Button size="sm" variant="ghost" onClick={() => { setZoneName(z.name); setOffset(0); }}>Records</Button>
                        {manage && z.type === "primary" && <Button size="sm" variant="ghost" onClick={() => open({ kind: "update", zone: z })}>Updates</Button>}
                        {manage && !isProtectedZone(z.name) && <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "removeZone", zone: z })}>Remove</Button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
          {zoneList.truncated && <p className="px-4 py-2 text-xs text-muted">Only the first 300 zones are shown.</p>}
        </Card>
      )}
      {zone && (
        <Card
          title={`Records of ${zone.name}`}
          padded={false}
          actions={manage && zone.type === "primary" && <Button size="sm" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => open({ kind: "add" })}>Add record</Button>}
        >
          {zone.adIntegrated && (
            <p className="border-b border-line px-4 py-2 text-xs text-muted">
              Stored in Active Directory ({storage(zone)}): a change is replicated to the other servers in its scope.
            </p>
          )}
          <RecordTable zone={zone} list={records.data?.data ?? null} manage={manage} offset={offset} setOffset={setOffset} open={open} />
        </Card>
      )}
      {dialog?.kind === "add" && zoneName && <RecordDialog zone={zoneName} record={null} change={change} onClose={close} />}
      {dialog?.kind === "edit" && zoneName && <RecordDialog zone={zoneName} record={dialog.record} change={change} onClose={close} />}
      {dialog?.kind === "remove" && zoneName && <RemoveRecordDialog zone={zoneName} record={dialog.record} change={change} onClose={close} />}
      {dialog?.kind === "removeAll" && zoneName && <RemoveAllDialog zone={zoneName} name={dialog.name} change={change} onClose={close} />}
      {dialog?.kind === "createZone" && <CreateZoneDialog change={change} onClose={close} />}
      {dialog?.kind === "removeZone" && <RemoveZoneDialog zone={dialog.zone} change={change} onClose={() => { if (zoneName === dialog.zone.name) setZoneName(null); close(); }} />}
      {dialog?.kind === "update" && <UpdateDialog zone={dialog.zone} change={change} onClose={close} />}
    </ModuleTab>
  );
}

function RecordTable({
  zone,
  list,
  manage,
  offset,
  setOffset,
  open,
}: {
  zone: DnsZone;
  list: DnsRecordList | null;
  manage: boolean;
  offset: number;
  setOffset: (n: number) => void;
  open: (d: Dialog) => void;
}) {
  if (!list) return <p className="p-4 text-sm text-muted">Reading the records…</p>;
  if (list.records.length === 0) return <EmptyState compact title="No records">This zone has no records.</EmptyState>;
  const editable = manage && zone.type === "primary";
  return (
    <>
      <TableWrap className="rounded-none border-0">
        <table className="table-base">
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Type</th>
              <th scope="col">Data</th>
              <th scope="col" className="hidden sm:table-cell">TTL</th>
              <th scope="col"><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {list.records.map((r) => {
              const locked = isProtectedRecord(zone.name, r.name) || r.type === "SOA" || (r.name === "@" && zone.adIntegrated && ["A", "AAAA", "NS"].includes(r.type));
              return (
                <tr key={`${r.name}|${r.type}|${r.data}`}>
                  <td className="font-medium">{r.name}</td>
                  <td>{r.type}</td>
                  <td className="break-all">{r.data}</td>
                  <td className="hidden sm:table-cell">{ttlText(r.ttl)}</td>
                  <td className="text-right whitespace-nowrap">
                    {locked ? (
                      <Badge icon={<Lock className="size-3" aria-hidden />} title="Active Directory maintains this record">Protected</Badge>
                    ) : (
                      editable && (
                        <>
                          <Button size="sm" variant="ghost" onClick={() => open({ kind: "edit", record: r })}>Edit</Button>
                          <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "remove", record: r })}>Remove</Button>
                          {r.name !== "@" && <Button size="sm" variant="danger-ghost" onClick={() => open({ kind: "removeAll", name: r.name })}>Remove all named this</Button>}
                        </>
                      )
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableWrap>
      <div className="flex items-center justify-between gap-2 border-t border-line px-4 py-2 text-xs text-muted">
        <span>
          {list.offset + 1}–{list.offset + list.records.length} of {list.total}
        </span>
        <span className="flex gap-2">
          <Button size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 80))}>Previous</Button>
          <Button size="sm" disabled={list.next === null} onClick={() => list.next !== null && setOffset(list.next)}>Next</Button>
        </span>
      </div>
    </>
  );
}
