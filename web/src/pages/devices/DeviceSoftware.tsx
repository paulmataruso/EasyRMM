import { useMemo, useState, type ReactNode } from "react";
import { PackagePlus } from "lucide-react";
import { useList } from "../../api/hooks";
import type { Device, Inventory, Package } from "../../api/types";
import { SearchInput } from "../../components/Filters";
import { Button, Card, EmptyState, ErrorState, Spinner, TableWrap, Toolbar } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { SoftwareDialog, type SoftwarePreset } from "../software/SoftwareDialog";
import { rowsAreManaged } from "../software/softwareText";

/** Rows drawn at once; a filter narrows the rest. A server lists up to 20,000 packages. */
export const SHOWN_PACKAGES = 300;

const MANAGERS: Record<string, string> = {
  windows: "Windows' installed programs",
  dpkg: "dpkg (Debian, Ubuntu)",
  rpm: "RPM",
  apk: "apk (Alpine)",
  pacman: "pacman (Arch)",
};

/**
 * The packages installed on one device, as its agent last reported them, and
 * where the caller may, the way to install, update and remove them (ADR-0028).
 */
export function SoftwarePanel({ device, inventory }: { device: Device; inventory: Inventory | null }) {
  const [preset, setPreset] = useState<SoftwarePreset | null>(null);
  const manage = device.canManageSoftware;
  const install = manage ? (
    <Button icon={<PackagePlus className="size-4" aria-hidden />} onClick={() => setPreset({})}>
      Install software
    </Button>
  ) : null;
  return (
    <>
      <Packages device={device} inventory={inventory} install={install} onAction={manage ? setPreset : undefined} />
      {manage && <SoftwareDialog open={preset !== null} onClose={() => setPreset(null)} device={device} preset={preset ?? undefined} />}
    </>
  );
}

function Packages({ device, inventory, install, onAction }: {
  device: Device;
  inventory: Inventory | null;
  install: ReactNode;
  /** Set where packages can be updated or removed. */
  onAction?: (preset: SoftwarePreset) => void;
}) {
  const packages = useList<Package>(`/devices/${device.id}/software`, undefined, { enabled: inventory !== null, staleTime: 60_000 });
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
        <EmptyState title="No inventory yet" action={install}>
          The agent reports the installed software shortly after it starts, then once an hour.
        </EmptyState>
      </Card>
    );
  }
  if (packages.isPending) return <Spinner />;
  if (packages.isError) return <ErrorState error={packages.error} onRetry={() => void packages.refetch()} />;
  if (packages.items.length === 0) {
    return (
      <Card>
        <EmptyState title={windows ? "No programs found" : "No packages found"} action={install}>
          {windows
            ? "The agent reads the programs listed in Windows' Apps & features. This device reported none."
            : "The agent reads dpkg, RPM, apk and pacman databases. This device has none it recognises, or software installed some other way."}
        </EmptyState>
      </Card>
    );
  }

  const rowActions = onAction && rowsAreManaged(inventory, device) ? onAction : undefined;
  const shown = matches.slice(0, SHOWN_PACKAGES);
  const readout = filter
    ? `${matches.length.toLocaleString()} of ${plural(packages.items.length, noun)}`
    : plural(packages.items.length, noun);
  return (
    <>
      <p className="mb-3 text-xs text-muted">
        From {MANAGERS[inventory.packageManager] ?? inventory.packageManager}, reported{" "}
        <span title={formatDateTime(inventory.receivedAt)}>{formatRelative(inventory.receivedAt)}</span>.
        {install && " After a software job ends, the agent reports again at its next check-in."}
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
        {install && <div className="ml-auto self-center">{install}</div>}
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
                {rowActions && (
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {shown.map((p) => (
                <tr key={`${p.name}\u0000${p.version}\u0000${p.arch}`}>
                  <td className="font-medium break-all">{p.name}</td>
                  <td className="font-mono text-xs break-all">{p.version}</td>
                  {windows && <td className="text-muted">{p.publisher || "—"}</td>}
                  <td className="text-muted">{p.arch || "—"}</td>
                  {rowActions && (
                    <td className="text-right whitespace-nowrap">
                      <Button size="sm" variant="ghost" aria-label={`Update ${p.name}`} onClick={() => rowActions({ action: "upgrade", manager: "system", package: p.name })}>
                        Update
                      </Button>
                      <Button
                        size="sm"
                        variant="danger-ghost"
                        aria-label={`Uninstall ${p.name}`}
                        onClick={() => rowActions({ action: "uninstall", manager: "system", package: p.name })}
                      >
                        Uninstall
                      </Button>
                    </td>
                  )}
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
      {windows && install && (
        <p className="mt-3 text-xs text-muted">
          Windows lists programs by display name. To update or remove one, use Install software with its winget or Chocolatey package ID.
        </p>
      )}
    </>
  );
}
