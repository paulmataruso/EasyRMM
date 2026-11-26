import { useApi } from "../../../api/hooks";
import type { Site } from "../../../api/types";
import { AddDevices } from "../../devices/AddDevicesPage";
import type { LevelTabProps } from "../levelTabs";

/**
 * The Add devices screen for this organization or site (ADR-0072): tokens and install commands that place new
 * devices here. Approval tokens belong to no organization and stay on Devices > Add devices.
 */
export function InstallTab({ level, id }: LevelTabProps) {
  // The site page already fetched the site, so this shares its cache entry.
  const site = useApi<Site>(level === "site" ? `/sites/${id}` : null);
  if (level === "organization") return <AddDevices scope={{ organizationId: id }} />;
  if (!site.data) return null;
  return <AddDevices scope={{ organizationId: site.data.organizationId, siteId: id }} />;
}
