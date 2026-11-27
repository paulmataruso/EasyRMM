import { useApi } from "../../../api/hooks";
import type { DeviceGroupDetail, Site } from "../../../api/types";
import { Spinner } from "../../../components/ui";
import { AssetsList } from "../../assets/AssetsList";
import type { LevelTabProps } from "../levelTabs";

/** The assets of an organization, a site or a device group (ADR-0066, slice 2). */
export function AssetsTab({ level, id }: LevelTabProps) {
  const site = useApi<Site>(level === "site" ? `/sites/${id}` : null);
  const group = useApi<DeviceGroupDetail>(level === "group" ? `/device-groups/${id}` : null);
  if (level === "organization") return <AssetsList organizationId={id} />;
  if (level === "site") return site.data ? <AssetsList organizationId={site.data.organizationId} siteId={id} /> : <Spinner />;
  return group.data ? <AssetsList organizationId={group.data.organizationId} groupId={id} /> : <Spinner />;
}
