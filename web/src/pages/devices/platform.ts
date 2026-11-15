import type { Platform, RemoteKind } from "../../api/types";

const PLATFORMS: Record<Platform, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  other: "Other",
};

export function platformName(p: Platform): string {
  return PLATFORMS[p] ?? p;
}

export const REMOTE_KINDS: RemoteKind[] = ["desktop", "terminal", "files"];

export function isRemoteKind(value: string | undefined): value is RemoteKind {
  return REMOTE_KINDS.includes(value as RemoteKind);
}
