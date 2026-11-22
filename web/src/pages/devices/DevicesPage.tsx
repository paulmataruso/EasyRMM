import { useId, useMemo, useRef } from "react";
import { Link, useNavigate } from "react-router";
import { ArrowDown, ArrowUp, ArrowUpDown, Monitor, Plus } from "lucide-react";
import { useApi, useList, usePrefetch } from "../../api/hooks";
import type { Device, RemoteAccessStatus } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { OrganizationSelect, SearchInput, SiteSelect } from "../../components/Filters";
import { DeviceStatusBadge } from "../../components/StatusBadges";
import { Alert, buttonClasses, EmptyState, ErrorState, Field, PageHeader, Select, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useRowKeys } from "../../lib/rowKeys";
import { useUrlState } from "../../lib/urlState";
import { DiskHealthCell } from "./DeviceDisks";
import { deviceDiskHealth, DISK_FILTERS } from "./diskHealthText";
import { HardeningCell } from "./hardeningParts";
import { FILTERS } from "./hardeningText";
import { platformName } from "./platform";

/** The server's cap on one list response (devices.MaxList). */
const MAX_DEVICES = 5000;

export function DevicesPage() {
  const { can } = useAuth();
  const url = useUrlState();
  const navigate = useNavigate();
  const prefetch = usePrefetch();
  const tableRef = useRef<HTMLDivElement>(null);
  const search = url.get("q");
  const organizationId = url.get("organizationId");
  const siteId = url.get("siteId");
  const status = url.get("status");
  const hardening = url.get("hardening");
  const diskHealth = url.get("diskHealth");
  const sort = parseSort(url.get("sort"));
  const filtered = Boolean(search || organizationId || siteId || status || hardening || diskHealth);

  const params = {
    q: search || undefined,
    organizationId: organizationId || undefined,
    siteId: siteId || undefined,
    status: status || undefined,
    hardening: hardening || undefined,
    diskHealth: diskHealth || undefined,
  };
  const list = useList<Device>("/devices", params, { refetchInterval: 30_000, keepPrevious: true });
  // The server lists by name; sorting by disk health keeps that order among devices with the same label.
  const devices = useMemo(() => sortDevices(list.items, sort), [list.items, sort]);
  const canEnroll = can("enrollment.manage");
  const addLink = (
    <Link to={siteId ? `/devices/add?siteId=${encodeURIComponent(siteId)}` : "/devices/add"} className={buttonClasses("primary")}>
      <Plus className="size-4" aria-hidden />
      Add devices
    </Link>
  );

  useRowKeys(tableRef, (link) => link.dataset.id && prefetch(`/devices/${link.dataset.id}`));
  // Hardening covers Linux (ADR-0051): its column shows when the list has a Linux device.
  const linux = list.items.some((d) => d.platform === "linux");
  // Disk health comes from the EasyRMM agent (ADR-0065): its column shows when the list has a device with one, or when
  // it filters or sorts by it.
  const showDiskHealth = Boolean(diskHealth) || sort !== null || list.items.some((d) => d.agent !== null || d.diskHealth !== null);

  return (
    <>
      <PageHeader
        title="Devices"
        subtitle="Computers in the organizations you support. Status refreshes every 30 seconds."
        actions={canEnroll ? addLink : undefined}
      />
      <RemoteAccessWarning />
      <Toolbar>
        <SearchInput value={search} onChange={(v) => url.set({ q: v })} placeholder="Name or hostname" className="max-w-xs" />
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null })} />
        <SiteSelect organizationId={organizationId} value={siteId} onChange={(v) => url.set({ siteId: v })} />
        <StatusSelect value={status} onChange={(v) => url.set({ status: v })} />
        <HardeningSelect value={hardening} onChange={(v) => url.set({ hardening: v })} />
        <DiskHealthSelect value={diskHealth} onChange={(v) => url.set({ diskHealth: v })} />
      </Toolbar>

      {list.isPending ? (
        <Spinner />
      ) : list.isError ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : list.items.length === 0 ? (
        <EmptyState
          title={filtered ? "No devices match these filters" : "No devices yet"}
          icon={<Monitor className="size-8" aria-hidden />}
          action={!filtered && canEnroll ? addLink : undefined}
        >
          {!filtered &&
            (canEnroll
              ? "Install the EasyRMM agent on a computer with a deployment token, and it appears here in the token's site."
              : "A device appears here once the EasyRMM agent is installed on it. Ask an administrator who manages enrollment for a deployment token.")}
        </EmptyState>
      ) : (
        <>
          <TableWrap>
            <div ref={tableRef}>
              <table className="table-base">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Status</th>
                    <th className="hidden md:table-cell">Organization / site</th>
                    <th className="hidden lg:table-cell">Operating system</th>
                    <th className="hidden sm:table-cell">Last seen</th>
                    {showDiskHealth && (
                      <th className="hidden lg:table-cell" aria-sort={sort === "worst" ? "ascending" : sort === "best" ? "descending" : "none"}>
                        <SortButton sort={sort} onChange={(next) => url.set({ sort: next })} />
                      </th>
                    )}
                    {linux && <th className="hidden lg:table-cell">Hardening</th>}
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d.id} className="cursor-pointer" onClick={() => navigate(`/devices/${d.id}`)} onMouseEnter={() => prefetch(`/devices/${d.id}`)}>
                      <td>
                        <Link
                          to={`/devices/${d.id}`}
                          className="rounded-sm font-medium hover:text-accent"
                          data-row-link
                          data-id={d.id}
                          onClick={(e) => e.stopPropagation()}
                          onFocus={() => prefetch(`/devices/${d.id}`)}
                        >
                          {d.name}
                        </Link>
                        {d.hostname && d.hostname.toLowerCase() !== d.name.toLowerCase() && <p className="max-w-52 truncate text-xs text-muted">{d.hostname}</p>}
                        <p className="max-w-52 truncate text-xs text-muted md:hidden">
                          {d.organizationName} / {d.siteName}
                        </p>
                      </td>
                      <td>
                        <DeviceStatusBadge device={d} />
                      </td>
                      <td className="hidden max-w-72 truncate md:table-cell">
                        {d.organizationName} <span className="text-subtle">/</span> {d.siteName}
                      </td>
                      <td className="hidden max-w-72 truncate text-muted lg:table-cell" title={d.osDescription || undefined}>
                        {d.osDescription || platformName(d.platform)}
                      </td>
                      <td className="hidden whitespace-nowrap text-muted sm:table-cell" title={formatDateTime(d.lastSeenAt)}>
                        {d.online ? "Now" : formatRelative(d.lastSeenAt)}
                      </td>
                      {showDiskHealth && (
                        <td className="hidden whitespace-nowrap lg:table-cell">
                          <DiskHealthCell device={d} />
                        </td>
                      )}
                      {linux && (
                        <td className="hidden whitespace-nowrap lg:table-cell">
                          <HardeningCell device={d} />
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </TableWrap>
          <p className="mt-2 text-xs text-muted">
            {list.items.length >= MAX_DEVICES
              ? `Showing the first ${plural(list.items.length, "device")}; filter to narrow the list`
              : `${plural(list.items.length, "device")}, ${list.items.filter((d) => d.online).length.toLocaleString()} online`}
            <span className="hidden sm:inline">
              . Press <kbd>j</kbd> and <kbd>k</kbd> to move between rows, <kbd>/</kbd> to search.
            </span>
          </p>
        </>
      )}
    </>
  );
}

/** Tells administrators when MeshCentral cannot be reached; everyone else finds out when a session cannot start. */
export function RemoteAccessWarning() {
  const { can, session } = useAuth();
  const enabled = can("settings.manage") && session?.features.remoteAccess === true;
  const status = useApi<RemoteAccessStatus>(enabled ? "/remote-access/status" : null, undefined, { refetchInterval: 60_000 });
  if (!status.data || status.data.connected) return null;
  return (
    <Alert tone="warn" title="Remote access is unavailable" className="mb-4">
      EasyRMM cannot reach MeshCentral, so remote sessions cannot start and remote-access status may be out of date.{" "}
      <Link to="/settings?tab=remote" className="font-medium text-accent hover:underline">
        View details
      </Link>
    </Alert>
  );
}

/** Linux devices by what their hardening checks found (ADR-0051), so drift across a fleet shows. */
function HardeningSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const id = useId();
  return (
    <Field label="Hardening" htmlFor={id} className="min-w-40">
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Any hardening</option>
        {FILTERS.map((f) => (
          <option key={f.value} value={f.value}>
            {f.label}
          </option>
        ))}
      </Select>
    </Field>
  );
}

/** Devices by their disks' health (ADR-0065). Unavailable and Unsupported find a device with any disk in that state. */
function DiskHealthSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const id = useId();
  return (
    <Field label="Disk health" htmlFor={id} className="min-w-40">
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Any disk health</option>
        {DISK_FILTERS.map((f) => (
          <option key={f.value} value={f.value}>
            {f.label}
          </option>
        ))}
      </Select>
    </Field>
  );
}

/** The list's order by disk health: worst first, best first, or none (by name). */
type DiskSort = "worst" | "best" | null;

/** ?sort=diskHealth lists the worst first; ?sort=-diskHealth the best. */
function parseSort(v: string): DiskSort {
  return v === "diskHealth" ? "worst" : v === "-diskHealth" ? "best" : null;
}

/** Devices by their disk health's rank (failing, warning, unknown, unavailable, healthy, unsupported, not reported),
 * keeping the server's order by name among equals. */
export function sortDevices(items: Device[], sort: DiskSort): Device[] {
  if (!sort) return items;
  const sign = sort === "worst" ? 1 : -1;
  return [...items].sort((a, b) => sign * (deviceDiskHealth(a.diskHealth).rank - deviceDiskHealth(b.diskHealth).rank));
}

/** The disk health column's header: each press goes from the name's order to worst first, best first, and back. */
function SortButton({ sort, onChange }: { sort: DiskSort; onChange: (next: string | null) => void }) {
  const next = sort === null ? "diskHealth" : sort === "worst" ? "-diskHealth" : null;
  const Icon = sort === "worst" ? ArrowDown : sort === "best" ? ArrowUp : ArrowUpDown;
  return (
    <button
      type="button"
      onClick={() => onChange(next)}
      title={next === "diskHealth" ? "Sort by disk health, worst first" : next === "-diskHealth" ? "Sort by disk health, best first" : "Sort by name"}
      className="inline-flex items-center gap-1 rounded-sm font-[inherit] hover:text-fg"
    >
      Disk health
      <Icon className="size-3.5" aria-hidden />
    </button>
  );
}

function StatusSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const id = useId();
  return (
    <Field label="Status" htmlFor={id} className="min-w-32">
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Any status</option>
        <option value="online">Online</option>
        <option value="offline">Offline</option>
      </Select>
    </Field>
  );
}
