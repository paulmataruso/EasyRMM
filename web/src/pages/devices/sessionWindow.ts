import type { RemoteKind } from "../../api/types";

/**
 * Remote sessions can open in a browser window of their own. Each device gets one window, named after it, so
 * asking again brings that window forward instead of stacking up windows (and sessions).
 */
export const SESSION_WINDOW_PREFIX = "easyrmm-session-";

const windows = new Map<string, Window>();

export function sessionPath(deviceId: string, kind: RemoteKind): string {
  return `/devices/${encodeURIComponent(deviceId)}/remote/${kind}`;
}

/** Whether this page runs in a session window that the console opened. */
export function inSessionWindow(): boolean {
  return window.name.startsWith(SESSION_WINDOW_PREFIX);
}

/**
 * Opens a device's session in its own window, or brings its open window forward (switching it to `kind` if it shows
 * another session type). Returns false when the browser blocked the window.
 */
export function openSessionWindow(deviceId: string, kind: RemoteKind): boolean {
  const path = sessionPath(deviceId, kind);
  const name = SESSION_WINDOW_PREFIX + deviceId;
  const existing = windows.get(name);
  if (existing && !existing.closed) {
    if (existing.location.pathname !== path) existing.location.assign(path);
    existing.focus();
    return true;
  }
  const { availWidth, availHeight, availLeft, availTop } = window.screen as Screen & { availLeft?: number; availTop?: number };
  const width = Math.max(800, Math.min(1440, availWidth - 64));
  const height = Math.max(600, Math.min(960, availHeight - 64));
  const left = (availLeft ?? 0) + Math.max(0, Math.round((availWidth - width) / 2));
  const top = (availTop ?? 0) + Math.max(0, Math.round((availHeight - height) / 2));
  const opened = window.open(path, name, `popup=yes,width=${width},height=${height},left=${left},top=${top}`);
  if (!opened) return false;
  windows.set(name, opened);
  opened.focus();
  return true;
}
