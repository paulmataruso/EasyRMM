import type { ReactNode } from "react";
import type { DeviceInventory, Disk, Inventory, PowerShellInstall } from "../../api/types";
import { UsageMeter } from "../../components/Meter";
import { Badge, Card, EmptyState, KeyValueList, Mono, TableWrap } from "../../components/ui";
import { formatDateTime, formatRelative, formatSize, plural } from "../../lib/format";
import { installName, NOT_REPORTED } from "../scripts/scriptText";
import { byFullness, percentOf } from "./DeviceHealth";

const VIRTUALIZATION: Record<string, string> = { container: "Container", vm: "Virtual machine" };
const DISK_KINDS: Record<Disk["kind"], string> = { "": "Unknown", ssd: "SSD", hdd: "Hard disk", nvme: "NVMe SSD" };

const none = <span className="text-muted">Not reported</span>;
const or = (v: string | number | null | undefined): ReactNode => (v === "" || v === 0 || v === null || v === undefined ? none : v);

/** What the agent last reported about the machine: hardware, storage, filesystems and network. */
export function HardwarePanel({ data }: { data: DeviceInventory }) {
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
      {inv.os.id === "windows" && <PowerShellCard installs={inv.powerShell} />}
      <DisksCard disks={inv.disks} />
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

/**
 * Windows PowerShell and the PowerShell 7 installs the agent found (ADR-0064): the one PowerShell 7 scripts run in, the
 * ones found and not used with the reason, and an agent too old to say.
 */
function PowerShellCard({ installs }: { installs: PowerShellInstall[] | undefined }) {
  if (!installs) {
    return (
      <Card title="PowerShell">
        <p className="text-sm text-muted">{NOT_REPORTED}. Agents report their PowerShell installs from the release that runs PowerShell 7 scripts.</p>
      </Card>
    );
  }
  const chosen = installs.find((i) => i.edition === "Core" && i.usable);
  const blocked = !chosen && installs.some((i) => i.edition === "Core" && i.blocked);
  return (
    <Card title="PowerShell" padded={false}>
      <TableWrap className="rounded-none border-0">
        <table className="table-base">
          <thead>
            <tr>
              <th scope="col">Program</th>
              <th scope="col">State</th>
              <th scope="col" className="hidden md:table-cell">
                Path
              </th>
            </tr>
          </thead>
          <tbody>
            {installs.map((i) => (
              <tr key={i.path}>
                <td className="font-medium whitespace-nowrap">
                  {installName(i)}
                  {i.preview && <Badge className="ml-2">Preview</Badge>}
                  {i.store && <Badge className="ml-2">Microsoft Store</Badge>}
                </td>
                <td>
                  <InstallState install={i} chosen={i === chosen} />
                </td>
                <td className="hidden md:table-cell">
                  <Mono>{i.path}</Mono>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      {blocked && (
        <p className="border-t border-line px-4 py-3 text-xs text-muted">
          PowerShell 7 was found, not usable: what it would load fails the agent&rsquo;s check, as its reason says. PowerShell 7 scripts fail here, and
          do not run in Windows PowerShell 5.1 instead, since Windows PowerShell loads from the same module folders. Make what the reason names
          changeable by administrators only, then restart the computer; the next inventory shows the result.
        </p>
      )}
      {!chosen && !blocked && (
        <p className="border-t border-line px-4 py-3 text-xs text-muted">
          No usable PowerShell 7 was found, so PowerShell 7 scripts fail here, or run in Windows PowerShell 5.1 where the script allows it. Install it with
          Microsoft&rsquo;s MSI, or with <Mono>winget install --id Microsoft.PowerShell --installer-type wix</Mono>; a Microsoft Store install is not used.
        </p>
      )}
    </Card>
  );
}

function InstallState({ install: i, chosen }: { install: PowerShellInstall; chosen: boolean }) {
  if (i.edition === "Desktop") return <span>Runs Windows PowerShell 5.1 scripts</span>;
  if (chosen) return <Badge tone="ok">Runs PowerShell 7 scripts</Badge>;
  if (i.usable) return <span className="text-muted">Installed, not chosen: an older version or another architecture</span>;
  return (
    <>
      {i.blocked ? <Badge tone="danger">Found, not usable</Badge> : <Badge tone="warn">Not used</Badge>}
      {i.reason && <span className="mt-1 block text-xs break-words text-muted">{i.reason}</span>}
    </>
  );
}

function DisksCard({ disks }: { disks: Disk[] }) {
  return (
    <Card title="Disks" padded={false}>
      {disks.length === 0 ? (
        <EmptyState title="No disks reported" compact>
          Containers and some virtual machines do not show their disks to the agent.
        </EmptyState>
      ) : (
        <TableWrap className="rounded-none border-0">
          <table className="table-base">
            <thead>
              <tr>
                <th scope="col">Disk</th>
                <th scope="col">Model</th>
                <th scope="col">Type</th>
                <th scope="col" className="text-right">Size</th>
                <th scope="col" className="hidden sm:table-cell">Serial number</th>
              </tr>
            </thead>
            <tbody>
              {disks.map((d) => (
                <tr key={d.name}>
                  <td className="font-medium whitespace-nowrap">
                    {d.name}
                    {d.removable && <Badge className="ml-2">Removable</Badge>}
                  </td>
                  <td>{d.model || <span className="text-muted">—</span>}</td>
                  <td className="whitespace-nowrap">{DISK_KINDS[d.kind] ?? d.kind}</td>
                  <td className="text-right whitespace-nowrap tabular-nums">{formatSize(d.sizeBytes)}</td>
                  <td className="hidden sm:table-cell">{d.serial ? <Mono>{d.serial}</Mono> : <span className="text-muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
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
