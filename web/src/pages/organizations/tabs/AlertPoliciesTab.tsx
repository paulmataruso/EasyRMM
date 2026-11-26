import { useApi } from "../../../api/hooks";
import type { Organization, Site } from "../../../api/types";
import { Spinner } from "../../../components/ui";
import { PolicyTable } from "../../alerts/PolicyTable";
import type { LevelTabProps } from "../levelTabs";

/** The alert policies of the organization or site (ADR-0072): its own, not the shared ones, which are in Settings. */
export function AlertPoliciesTab({ level, id }: LevelTabProps) {
  const org = useApi<Organization>(level === "organization" ? `/organizations/${id}` : null);
  const site = useApi<Site>(level === "site" ? `/sites/${id}` : null);
  if (level === "organization" && org.data) {
    return <PolicyTable scope={{ level: "organization", organizationId: id, name: org.data.name }} />;
  }
  if (level === "site" && site.data) {
    return <PolicyTable scope={{ level: "site", organizationId: site.data.organizationId, siteId: id, name: site.data.name }} />;
  }
  return level === "group" ? null : <Spinner />;
}
