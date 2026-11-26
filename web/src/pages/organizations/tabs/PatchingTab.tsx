import { AgentInstallCard } from "../../patching/AgentInstall";
import { PolicyPanel } from "../../patching/PolicyEditor";
import { ReportSchedules } from "../../patching/ReportSchedules";
import { TagsField } from "../../patching/Tags";
import { useAuth } from "../../../auth/AuthContext";
import type { LevelTabProps } from "../levelTabs";

/**
 * Patching settings of the organization or site (ADR-0072): its patch policy and tags, and for an organization its
 * monthly report schedule and whether EasyRMM installs the patching agent by itself. Needs patch.configure.
 */
export function PatchingTab({ level, id }: LevelTabProps) {
  const { can } = useAuth();
  if (level === "group") return null;
  return (
    <div className="flex flex-col gap-5">
      <PolicyPanel level={level} id={id} intro={<TagsField level={level} id={id} />} />
      {level === "organization" && (
        <>
          {can("report.view") && <ReportSchedules organizationId={id} />}
          <AgentInstallCard organizationId={id} />
        </>
      )}
    </div>
  );
}
