import type { ReactNode } from "react";
import { FolderOpen, MonitorPlay, SquareTerminal } from "lucide-react";
import type { Device, RemoteKind } from "../../api/types";

/** Remote session kinds: what the caller may open on a device, and why a device cannot take one now. */

export const KIND_ICONS: Record<RemoteKind, ReactNode> = {
  desktop: <MonitorPlay className="size-4" aria-hidden />,
  terminal: <SquareTerminal className="size-4" aria-hidden />,
  files: <FolderOpen className="size-4" aria-hidden />,
};

/** The session kinds the caller may open on a device, in display order. */
export function allowedKinds(d: Pick<Device, "canDesktop" | "canTerminal" | "canFiles">): RemoteKind[] {
  return (["desktop", "terminal", "files"] as const).filter((k) => (k === "desktop" ? d.canDesktop : k === "terminal" ? d.canTerminal : d.canFiles));
}

/** Why sessions cannot start on a device right now, or null when they can. */
export function unavailableReason(d: Pick<Device, "remoteAgent" | "remoteOnline" | "online">): string | null {
  if (!d.remoteAgent) return "Remote access is not set up on this device.";
  if (!d.remoteOnline) return d.online ? "Remote access is not connected." : "The device is offline.";
  return null;
}
