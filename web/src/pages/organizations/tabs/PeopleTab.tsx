import { UsersTab } from "../../settings/UsersTab";
import type { LevelTabProps } from "../levelTabs";

/** Who holds a role in this organization: the Settings > Users list with its scope fixed (ADR-0072). */
export function PeopleTab({ id }: LevelTabProps) {
  return <UsersTab organizationId={id} />;
}
