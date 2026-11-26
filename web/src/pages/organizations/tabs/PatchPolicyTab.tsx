import { PolicyPanel } from "../../patching/PolicyEditor";
import { TagsField } from "../../patching/Tags";
import type { LevelTabProps } from "../levelTabs";

/** The patch policy (and tags) of the organization or site. */
export function PatchPolicyTab({ level, id }: LevelTabProps) {
  if (level === "group") return null;
  return (
    <PolicyPanel
      level={level}
      id={id}
      intro={<TagsField level={level} id={id} />}
    />
  );
}
