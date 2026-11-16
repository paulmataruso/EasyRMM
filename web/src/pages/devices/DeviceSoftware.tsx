import { useMemo, useState } from "react";
import { useList } from "../../api/hooks";
import type { Inventory, Package } from "../../api/types";
import { SearchInput } from "../../components/Filters";
import { Card, EmptyState, ErrorState, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";

/** Rows drawn at once; a filter narrows the rest. A server lists up to 20,000 packages. */
export const SHOWN_PACKAGES = 300;

const MANAGERS: Record<string, string> = {
  windows: "Windows' installed programs",
  dpkg: "dpkg (Debian, Ubuntu)",
  rpm: "RPM",
  apk: "apk (Alpine)",
  pacman: "pacman (Arch)",
};

/** The packages installed on one device, as its agent last reported them. */
export function SoftwarePanel({ deviceId, inventory }: { deviceId: string; inventory: Inventory | null }) {
  const packages = useList<Package>(`/devices/${deviceId}/software`, undefined, { enabled: inventory !== null, staleTime: 60_000 });
  const [filter, setFilter] = useState("");
  const windows = inventory?.packageManager === "windows";
  const noun = windows ? "program" : "package";
  const matches = useMemo(() => {
    const q = filter.toLowerCase();
    return q
      ? packages.items.filter((p) => [p.name, p.version, p.publisher ?? ""].some((v) => v.toLowerCase().includes(q)))
      : packages.items;
  }, [packages.items, filter]);

  if (!inventory) {
    return (
      <Card>
        <EmptyState title="No inventory yet">The agent reports the installed software shortly after it starts, then once an hour.</EmptyState>
      </Card>
    );
  }
  if (packages.isPending) return <Spinner />;
  if (packages.isError) return <ErrorState error={packages.error} onRetry={() => void packages.refetch()} />;
  if (packages.items.length === 0) {
    return (
      <Card>
        <EmptyState title={windows ? "No programs found" : "No packages found"}>
          {windows
            ? "The agent reads the programs listed in Windows' Apps & features. This device reported none."
            : "The agent reads dpkg, RPM, apk and pacman databases. This device has none it recognises, or software installed some other way."}
        </EmptyState>
      </Card>
    );
  }

  const shown = matches.slice(0, SHOWN_PACKAGES);
  const readout = filter
    ? `${matches.length.toLocaleString()} of ${plural(packages.items.length, noun)}`
    : plural(packages.items.length, noun);
  return (
    <>
      <p className="mb-3 text-xs text-muted">
        From {MANAGERS[inventory.packageManager] ?? inventory.packageManager}, reported{" "}
        <span title={formatDateTime(inventory.receivedAt)}>{formatRelative(inventory.receivedAt)}</span>.
      </p>
      <Toolbar>
        <SearchInput
          value={filter}
          onChange={setFilter}
          delay={0}
          label={`Filter ${noun}s`}
          placeholder={windows ? "Name, version or publisher" : "Name or version"}
          className="max-w-md"
          readout={readout}
        />
      </Toolbar>
      {matches.length === 0 ? (
        <Card>
          <EmptyState title={`No ${noun}s match`} compact>
            Nothing installed here has “{filter}” in its {windows ? "name, version or publisher" : "name or version"}.
          </EmptyState>
        </Card>
      ) : (
        <TableWrap>
          <table className="table-base">
            <thead>
              <tr>
                <th scope="col">{windows ? "Program" : "Package"}</th>
                <th scope="col">Version</th>
                {windows && <th scope="col">Publisher</th>}
                <th scope="col">Architecture</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((p) => (
                <tr key={`${p.name}\u0000${p.version}\u0000${p.arch}`}>
                  <td className="font-medium break-all">{p.name}</td>
                  <td className="font-mono text-xs break-all">{p.version}</td>
                  {windows && <td className="text-muted">{p.publisher || "—"}</td>}
                  <td className="text-muted">{p.arch || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {matches.length > shown.length && (
            <p className="border-t border-line px-4 py-2.5 text-xs text-muted">
              Showing the first {SHOWN_PACKAGES.toLocaleString()} of {matches.length.toLocaleString()}. Filter by name to find the rest.
            </p>
          )}
        </TableWrap>
      )}
    </>
  );
}
