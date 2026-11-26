import { Link, useParams } from "react-router";
import { useApi } from "../../api/hooks";
import type { Device } from "../../api/types";
import { EmptyState, ErrorState, PageHeader, Spinner } from "../../components/ui";
import { PatchesPanel } from "../devices/DevicePatches";

/**
 * One device's patching, in the Patching section (ADR-0072): the same panel as the Patches tab of the device page, in
 * a frame of its own so the sidebar keeps the Patching tree.
 */
export function PatchingDevicePage() {
  const { id = "" } = useParams();
  const device = useApi<Device>(`/devices/${encodeURIComponent(id)}`, undefined, { refetchInterval: 30_000 });
  if (device.isPending) return <Spinner />;
  if (device.isError) return <ErrorState error={device.error} onRetry={() => void device.refetch()} />;
  const d = device.data;
  const site = `/patching?${new URLSearchParams({ organizationId: d.organizationId, siteId: d.siteId })}`;
  return (
    <>
      <PageHeader
        breadcrumb={
          <>
            <Link to="/patching" className="hover:text-fg">
              Patching
            </Link>
            <span className="mx-1.5" aria-hidden>
              /
            </span>
            <Link to={site} className="hover:text-fg">
              {d.organizationName} / {d.siteName}
            </Link>
          </>
        }
        title={`Patching · ${d.name}`}
        subtitle={
          <>
            {d.osDescription || d.hostname} ·{" "}
            <Link to={`/devices/${encodeURIComponent(d.id)}`} className="hover:text-fg underline">
              Open the device page
            </Link>
          </>
        }
      />
      {d.agent ? (
        <PatchesPanel device={d} />
      ) : (
        <EmptyState title="No EasyRMM agent on this device">
          Patching needs the EasyRMM agent. Install it from Add devices, then the patching agent can follow.
        </EmptyState>
      )}
    </>
  );
}
