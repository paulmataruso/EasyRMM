import { ChannelsPanel } from "../../notifications/ChannelsPanel";
import type { LevelTabProps } from "../levelTabs";

/**
 * The "Notifications" tab of an organization (ADR-0053, ADR-0072): its own channels, the platform channels shared with
 * it (name and kind only), what it is told about them, and the delivery log. `notification.manage` shows it.
 */
export function NotificationsTab({ level, id }: LevelTabProps) {
  if (level !== "organization") return null;
  return <ChannelsPanel organizationId={id} />;
}
