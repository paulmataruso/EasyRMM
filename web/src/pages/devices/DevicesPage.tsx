import { useId, useRef } from "react";
import { Link, useNavigate } from "react-router";
import { Monitor, Plus } from "lucide-react";
import { useApi, useList, usePrefetch, useSites } from "../../api/hooks";
import type { Device, RemoteAccessStatus } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { OrganizationSelect, SearchInput } from "../../components/Filters";
import { DeviceStatusBadge } from "../../components/StatusBadges";
import { Alert, buttonClasses, EmptyState, ErrorState, Field, PageHeader, Select, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useRowKeys } from "../../lib/rowKeys";
import { useUrlState } from "../../lib/urlState";
import { DeviceTreeToggle } from "./DeviceTree";
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
  const filtered = Boolean(search || organizationId || siteId || status);

  const params = { q: search || undefined, organizationId: organizationId || undefined, siteId: siteId || undefined, status: status || undefined };
  const list = useList<Device>("/devices", params, { refetchInterval: 30_000, keepPrevious: true });
  const canEnroll = can("enrollment.manage");
  const addLink = (
    <Link to={siteId ? `/devices/add?siteId=${encodeURIComponent(siteId)}` : "/devices/add"} className={buttonClasses("primary")}>
      <Plus className="size-4" aria-hidden />
      Add devices
    </Link>
  );

  useRowKeys(tableRef, (link) => link.dataset.id && prefetch(`/devices/${link.dataset.id}`));

  return (
    <>
      <PageHeader
        title="Devices"
        subtitle="Computers in the organizations you support. Status refreshes every 30 seconds."
        actions={
          <>
            <DeviceTreeToggle />
            {canEnroll && addLink}
          </>
        }
      />
      <RemoteAccessWarning />
      <Toolbar>
        <SearchInput value={search} onChange={(v) => url.set({ q: v })} placeholder="Name or hostname" className="max-w-xs" />
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v, siteId: null })} />
        <SiteSelect organizationId={organizationId} value={siteId} onChange={(v) => url.set({ siteId: v })} />
        <StatusSelect value={status} onChange={(v) => url.set({ status: v })} />
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
                  </tr>
                </thead>
                <tbody>
                  {list.items.map((d) => (
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

function SiteSelect({ organizationId, value, onChange }: { organizationId: string; value: string; onChange: (v: string) => void }) {
  const sites = useSites(organizationId || null);
  const id = useId();
  return (
    <Field label="Site" htmlFor={id} className="min-w-40">
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)} disabled={sites.isPending}>
        <option value="">All sites</option>
        {sites.items.map((s) => (
          <option key={s.id} value={s.id}>
            {organizationId ? s.name : `${s.organizationName} / ${s.name}`}
          </option>
        ))}
      </Select>
    </Field>
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
