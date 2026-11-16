import { Fragment, useState } from "react";
import { Link } from "react-router";
import { ChevronRight, Package } from "lucide-react";
import { useApi, useList } from "../../api/hooks";
import type { SoftwareDevice, SoftwareSearch, SoftwareSummary } from "../../api/types";
import { OrganizationSelect, SearchInput } from "../../components/Filters";
import { EmptyState, ErrorState, PageHeader, Spinner, TableWrap, Toolbar, cx } from "../../components/ui";
import { plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";

/** The server lists at most this many package versions per search, and this many devices per version. */
export const MAX_VERSIONS = 500;
export const MAX_DEVICES = 1000;

const keyOf = (s: Pick<SoftwareSummary, "name" | "version">) => `${s.name}\u0000${s.version}`;

/** Every package version installed across the devices the caller supports, and where each one is. */
export function SoftwarePage() {
  const url = useUrlState();
  const search = url.get("q");
  const organizationId = url.get("organizationId");
  const filtered = Boolean(search || organizationId);
  const result = useApi<SoftwareSearch>("/software", { q: search || undefined, organizationId: organizationId || undefined }, { keepPrevious: true });
  const [open, setOpen] = useState<string | null>(null);
  const items = result.data?.items ?? [];

  return (
    <>
      <PageHeader title="Software" subtitle="Packages installed on your Linux devices, from each agent’s latest inventory. Agents report changes within the hour." />
      <Toolbar>
        <SearchInput value={search} onChange={(v) => url.set({ q: v })} label="Package" placeholder="Name contains…" className="max-w-xs" />
        <OrganizationSelect value={organizationId} onChange={(v) => url.set({ organizationId: v })} />
      </Toolbar>

      {result.isPending ? (
        <Spinner />
      ) : result.isError ? (
        <ErrorState error={result.error} onRetry={() => void result.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState title={filtered ? "No packages match" : "No software reported yet"} icon={<Package className="size-8" aria-hidden />}>
          {filtered
            ? search
              ? `No device here has a package whose name contains “${search}”.`
              : "No device in this organization has reported its software yet."
            : "Linux devices with the EasyRMM agent report their installed packages shortly after they enroll."}
        </EmptyState>
      ) : (
        <>
          <TableWrap className={cx("transition-opacity", result.isPlaceholderData && "opacity-60")}>
            <table className="table-base">
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Version</th>
                  <th className="text-right">Devices</th>
                </tr>
              </thead>
              <tbody>
                {items.map((s, i) => {
                  const key = keyOf(s);
                  const expanded = open === key;
                  const first = i === 0 || items[i - 1]?.name !== s.name;
                  // Versions of one package read as a group: no rule between them.
                  const grouped = !expanded && items[i + 1]?.name === s.name;
                  const panel = `software-${i}`;
                  return (
                    <Fragment key={key}>
                      <tr className={cx(grouped && "[&>td]:border-b-0")}>
                        <td className="font-medium break-all">
                          {first ? s.name : <span className="sr-only">{s.name}</span>}
                        </td>
                        <td className="font-mono text-xs break-all">{s.version}</td>
                        <td className="text-right whitespace-nowrap">
                          <button
                            type="button"
                            aria-expanded={expanded}
                            aria-controls={expanded ? panel : undefined}
                            onClick={() => setOpen(expanded ? null : key)}
                            className="inline-flex items-center gap-1 rounded-sm text-sm text-accent tabular-nums hover:underline"
                          >
                            {plural(s.devices, "device")}
                            <ChevronRight className={cx("size-3.5 transition-transform", expanded && "rotate-90")} aria-hidden />
                          </button>
                        </td>
                      </tr>
                      {expanded && (
                        <tr id={panel} className="hover:bg-transparent">
                          <td colSpan={3} className="bg-raised">
                            <Holders name={s.name} version={s.version} organizationId={organizationId} />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
          <p className="mt-2 text-xs text-muted">
            {result.data?.truncated
              ? `Showing the first ${MAX_VERSIONS.toLocaleString()} package versions. Search by name to narrow the list.`
              : plural(items.length, "package version")}
          </p>
        </>
      )}
    </>
  );
}

/** The devices with one version of a package, each linking to that device’s software. */
function Holders({ name, version, organizationId }: { name: string; version: string; organizationId: string }) {
  const devices = useList<SoftwareDevice>("/software/devices", { name, version, organizationId: organizationId || undefined });
  if (devices.isPending) return <Spinner label="Loading devices…" />;
  if (devices.isError) return <ErrorState error={devices.error} onRetry={() => void devices.refetch()} compact />;
  if (devices.items.length === 0) return <p className="py-1 text-sm text-muted">No device has this version any more.</p>;
  return (
    <>
      <ul className="grid grid-cols-1 gap-x-6 gap-y-1.5 py-1 sm:grid-cols-2 xl:grid-cols-3">
        {devices.items.map((d) => (
          <li key={`${d.deviceId}\u0000${d.arch}`} className="min-w-0 text-sm">
            <Link to={`/devices/${d.deviceId}?tab=software`} className="font-medium text-accent hover:underline">
              {d.deviceName}
            </Link>
            <span className="block text-xs break-words text-muted">
              {d.organizationName} / {d.siteName}
              {d.arch && <> · {d.arch}</>}
            </span>
          </li>
        ))}
      </ul>
      {devices.items.length >= MAX_DEVICES && (
        <p className="mt-2 text-xs text-muted">Showing the first {MAX_DEVICES.toLocaleString()} devices. Choose an organization to narrow the list.</p>
      )}
    </>
  );
}
