import { useState } from "react";
import type { Device, DeviceRoles } from "../../../../api/types";
import { useApi } from "../../../../api/hooks";
import { useAuth } from "../../../../auth/AuthContext";
import { Segmented } from "../../../../components/ui";
import { ROLE_VIEWS } from "./registry";

/**
 * The device page's "Roles" tab (ADR-0076): one view per detected role that is on for the site and that the viewer
 * may see. Each view is its own module's frame (name, when it was read, refresh), so the tab only chooses.
 */
export function RolesTab({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const roles = useApi<DeviceRoles>(`/devices/${device.id}/roles`, undefined, { staleTime: 60_000 });
  const [chosen, setChosen] = useState<string | null>(null);
  const shown = ROLE_VIEWS.filter(
    (v) =>
      canAt(v.permission, { organizationId: device.organizationId, siteId: device.siteId }) &&
      roles.data?.roles.some((r) => r.module === v.module && r.enabled),
  );
  const view = shown.find((v) => v.module === chosen) ?? shown[0];
  if (!view) return null;
  const View = view.component;
  return (
    <div className="flex flex-col gap-4">
      {shown.length > 1 && (
        <Segmented
          label="Role"
          value={view.module}
          onChange={setChosen}
          options={shown.map((v) => ({ value: v.module, label: v.label }))}
        />
      )}
      <View key={view.module} device={device} />
    </div>
  );
}
