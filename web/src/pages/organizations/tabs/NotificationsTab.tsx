import { ChannelsPanel } from "../../notifications/ChannelsPanel";
import { RulesPanel } from "../../notifications/RulesPanel";
import { WindowsPanel } from "../../notifications/WindowsPanel";
import type { LevelTabProps } from "../levelTabs";

/**
 * The "Notifications" tab of an organization (ADR-0053, ADR-0072): its own channels, the platform channels shared with
 * it (name and kind only), what it is told about them, and the delivery log. `notification.manage` shows it.
 */
export function NotificationsTab({ level, id }: LevelTabProps) {
  if (level !== "organization") return null;
  return (
    <div className="flex flex-col gap-4">
      <ChannelsPanel organizationId={id} />
      <RulesPanel organizationId={id} />
      <WindowsPanel organizationId={id} />
    </div>
  );
}
