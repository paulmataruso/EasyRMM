import type { ReactNode } from "react";
import type { Device, DeviceInventory, Inventory } from "../../api/types";
import { UsageMeter } from "../../components/Meter";
import { Badge, Card, EmptyState, KeyValueList, Mono, TableWrap } from "../../components/ui";
import { formatDateTime, formatRelative, formatSize, plural } from "../../lib/format";
import { DisksCard } from "./DeviceDisks";
import { byFullness, percentOf } from "./DeviceHealth";

const VIRTUALIZATION: Record<string, string> = { container: "Container", vm: "Virtual machine" };

const none = <span className="text-muted">Not reported</span>;
const or = (v: string | number | null | undefined): ReactNode => (v === "" || v === 0 || v === null || v === undefined ? none : v);

/** What the agent last reported about the machine: hardware, storage with each disk's health, filesystems and network. */
export function HardwarePanel({ data, device }: { data: DeviceInventory; device: Pick<Device, "id" | "agent"> }) {
  const inv = data.inventory;
  if (!inv) {
    return (
      <Card>
        <EmptyState title="No inventory yet">
          The agent reports this device’s hardware and installed software shortly after it starts, then once an hour.
        </EmptyState>
      </Card>
    );
  }
  return (
    <div className="flex flex-col gap-5">
      <p className="text-xs text-muted">
        Reported <span title={formatDateTime(inv.receivedAt)}>{formatRelative(inv.receivedAt)}</span>. The agent checks again every hour and sends
        only what changed.
      </p>
      <div className="grid grid-cols-1 items-start gap-5 lg:grid-cols-2">
        <SystemCard inv={inv} />
        <Card title="Operating system">
          <KeyValueList
            items={[
              ["Name", or(inv.os.name)],
              ["Version", or(inv.os.version)],
              [inv.os.id === "windows" ? "Build" : "Kernel", inv.os.kernel ? <Mono key="k">{inv.os.kernel}</Mono> : none],
              ["Time zone", or(inv.os.timezone)],
              [
                "Software",
                inv.packageManager === "windows"
                  ? plural(inv.packageCount, "installed program")
                  : inv.packageManager
                    ? `${plural(inv.packageCount, "package")} (${inv.packageManager})`
                    : none,
              ],
            ]}
          />
        </Card>
      </div>
      <DisksCard device={device} disks={inv.disks} />
      {data.metrics && data.metrics.filesystems.length > 0 && <FilesystemsCard data={data} />}
      <NetworkCard inv={inv} />
    </div>
  );
}

function SystemCard({ inv }: { inv: Inventory }) {
  const s = inv.system;
  const cpu = inv.cpu;
  const bios = [s.biosVendor, s.biosVersion, s.biosDate && `(${s.biosDate})`].filter(Boolean).join(" ");
  const cores = cpu.threads
    ? [cpu.sockets > 1 && plural(cpu.sockets, "socket"), cpu.cores && plural(cpu.cores, "core"), plural(cpu.threads, "thread")].filter(Boolean).join(", ")
    : "";
  return (
    <Card title="System">
      <KeyValueList
        items={[
          ["Manufacturer", or(s.manufacturer)],
          ["Model", or(s.model)],
          ["Serial number", s.serial ? <Mono key="sn">{s.serial}</Mono> : none],
          ["Runs as", s.virtualization ? (VIRTUALIZATION[s.virtualization] ?? s.virtualization) : "Physical machine"],
          ["Firmware", or(bios)],
          ["Processor", or(cpu.model)],
          ["Cores", or(cores)],
          ["Memory", inv.memoryBytes ? formatSize(inv.memoryBytes) : none],
        ]}
      />
    </Card>
  );
}

function FilesystemsCard({ data }: { data: DeviceInventory }) {
  const metrics = data.metrics;
  if (!metrics) return null;
  return (
    <Card
      title="Filesystems"
      padded={false}
      actions={
        <span className="text-xs text-muted" title={formatDateTime(metrics.at)}>
          Measured {formatRelative(metrics.at)}
        </span>
      }
    >
      <TableWrap className="rounded-none border-0">
        <table className="table-base">
          <thead>
            <tr>
              <th scope="col">Mounted at</th>
              <th scope="col" className="hidden sm:table-cell">Device</th>
              <th scope="col" className="w-2/5 min-w-48">Used</th>
              <th scope="col" className="text-right">Free</th>
              <th scope="col" className="hidden text-right sm:table-cell">Size</th>
            </tr>
          </thead>
          <tbody>
            {byFullness(metrics.filesystems).map((f) => (
              <tr key={f.mount}>
                <td className="font-medium break-all">{f.mount}</td>
                <td className="hidden text-muted sm:table-cell">
                  <span className="break-all">{f.device}</span> <span className="whitespace-nowrap">({f.type})</span>
                </td>
                <td>
                  <UsageMeter label={`Used on ${f.mount}`} percent={percentOf(f.usedBytes, f.totalBytes)} detail={formatSize(f.usedBytes)} hideLabel />
                </td>
                <td className="text-right whitespace-nowrap tabular-nums">{formatSize(f.totalBytes - f.usedBytes)}</td>
                <td className="hidden text-right whitespace-nowrap tabular-nums sm:table-cell">{formatSize(f.totalBytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Card>
  );
}

function NetworkCard({ inv }: { inv: Inventory }) {
  return (
    <Card title="Network" padded={false}>
      {inv.interfaces.length === 0 ? (
        <EmptyState title="No network interfaces reported" compact />
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th scope="col">Interface</th>
                <th scope="col">State</th>
                <th scope="col">Addresses</th>
                <th scope="col" className="hidden sm:table-cell">MAC address</th>
                <th scope="col" className="hidden text-right md:table-cell">Speed</th>
              </tr>
            </thead>
            <tbody>
              {inv.interfaces.map((n) => (
                <tr key={n.name}>
                  <td className="font-medium whitespace-nowrap">{n.name}</td>
                  <td>
                    <Badge tone={n.up ? "ok" : "neutral"}>{n.up ? "Up" : "Down"}</Badge>
                  </td>
                  <td>
                    {n.addresses.length === 0 ? (
                      <span className="text-muted">None</span>
                    ) : (
                      <ul className="flex flex-col gap-0.5 font-mono text-xs">
                        {n.addresses.map((a) => (
                          <li key={a} className="whitespace-nowrap">{a}</li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td className="hidden font-mono text-xs whitespace-nowrap sm:table-cell">{n.mac || <span className="font-sans text-muted">—</span>}</td>
                  <td className="hidden text-right whitespace-nowrap tabular-nums md:table-cell">
                    {n.speedMbps > 0 ? (n.speedMbps >= 1000 ? `${n.speedMbps / 1000} Gbit/s` : `${n.speedMbps} Mbit/s`) : <span className="text-muted">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <div className="border-t border-line px-4 py-3">
        <KeyValueList
          items={[
            ["Default gateways", inv.gateways.length ? <AddressList key="g" items={inv.gateways} /> : none],
            ["DNS servers", inv.dnsServers.length ? <AddressList key="d" items={inv.dnsServers} /> : none],
          ]}
        />
      </div>
    </Card>
  );
}

function AddressList({ items }: { items: string[] }) {
  return <span className="font-mono text-xs">{items.join(", ")}</span>;
}
