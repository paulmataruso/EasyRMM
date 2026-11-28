import { useAuth } from "../../../auth/AuthContext";
import { AgentSettingsPanel } from "../../agentsettings/AgentSettingsPanel";
import type { LevelTabProps } from "../levelTabs";

/**
 * The "Agent settings" tab of an organization or a site (ADR-0058, slice 3): each key's value here, where it comes
 * from, and an editor with the "Enforce for everything below" switch where the key allows it.
 */
export function AgentSettingsTab({ level, id }: LevelTabProps) {
  const { can } = useAuth();
  if (level === "group") return null;
  const base = level === "organization" ? `/organizations/${id}/agent-settings` : `/sites/${id}/agent-settings`;
  // The server judges the write per scope; this only hides the editor from who can never use it.
  return <AgentSettingsPanel base={base} scope={level} editable={can("device.configure")} />;
}
