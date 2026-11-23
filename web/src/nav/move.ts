import { api } from "../api/client";
import { useApiMutation } from "../api/hooks";
import type { Device } from "../api/types";

/** Moving devices between groups, sites and organizations (ADR-0069). */

/** The part of a device a move needs. */
export type Movable = Pick<Device, "id" | "name" | "organizationId" | "organizationName" | "siteId" | "siteName" | "deviceGroupId">;

/** Where devices go: a site, and a device group of it or none. */
export interface MoveTarget {
  organizationId: string;
  organizationName: string;
  siteId: string;
  siteName: string;
  groupId: string | null;
  groupName: string;
}

export interface MoveResult {
  moved: number;
  unchanged: number;
  otherOrganization: number;
  canceledRuns: number;
}

/** What a move changes for a device, widest first. */
export type MoveKind = "organization" | "site" | "group" | "none";

export function moveKind(d: Movable, t: MoveTarget): MoveKind {
  if (d.organizationId !== t.organizationId) return "organization";
  if (d.siteId !== t.siteId) return "site";
  return (d.deviceGroupId ?? null) === t.groupId ? "none" : "group";
}

/** The widest change among the devices. */
export function widest(devices: Movable[], t: MoveTarget): MoveKind {
  const kinds = new Set(devices.map((d) => moveKind(d, t)));
  return kinds.has("organization") ? "organization" : kinds.has("site") ? "site" : kinds.has("group") ? "group" : "none";
}

const noun = (n: number, one: string, many: string) => (n === 1 ? one : many);

/**
 * What follows a move to another site or organization, in words, for the confirmation. A move within a site needs
 * none.
 */
export function consequences(devices: Movable[], t: MoveTarget): string[] {
  const kind = widest(devices, t);
  if (kind === "none" || kind === "group") return [];
  const these = noun(devices.length, "its", "their");
  const out = [
    `Remote access follows ${these} site: ${noun(devices.length, "the device joins", "the devices join")} ${t.siteName}'s device group in MeshCentral, and its agent reconnects there.`,
    `Alert policies, scripts and patching policies of ${t.siteName} apply from now on.`,
  ];
  if (kind === "organization") {
    out.push(
      `Queued jobs of the old organization are canceled, and a device running one cannot move until it finishes. Open remote sessions end and its alerts are removed.`,
      `Job runs, patch history and audit records stay with the old organization; ${t.organizationName} does not see them.`,
      `Patching: where automatic installs are on, the device's patching agent is enrolled in ${t.organizationName}'s patching organization.`,
    );
  }
  return out;
}

/** The one move a mutation makes. */
export interface MoveRequest {
  devices: Movable[];
  target: MoveTarget;
}

/** POST /devices/move, then everything a device's place shows refreshes. */
export function useMoveDevices(onDone?: (r: MoveResult, req: MoveRequest) => void) {
  return useApiMutation(
    (req: MoveRequest) => api.post<MoveResult>("/devices/move", { deviceIds: req.devices.map((d) => d.id), siteId: req.target.siteId, groupId: req.target.groupId }),
    {
      invalidate: ["/devices", "/device-tree", "/alerts", "/jobs", "/job-runs", "/sites", "/organizations", "/patching", "/audit"],
      onSuccess: (r, req) => onDone?.(r, req),
    },
  );
}

/** The summary a toast gives a finished move. */
export function movedText(r: MoveResult, req: MoveRequest): string {
  const where = req.target.groupName ? `${req.target.siteName} / ${req.target.groupName}` : req.target.siteName;
  if (r.moved === 0) return `Already in ${where}.`;
  const who = r.moved === 1 && req.devices.length === 1 ? req.devices[0]!.name : `${r.moved.toLocaleString()} ${noun(r.moved, "device", "devices")}`;
  return `${who} moved to ${where}.`;
}

/** Drag and drop carries the devices in a type of its own, so nothing else is taken for a device. */
export const DRAG_TYPE = "application/x-easyrmm-devices";

let dragging: Movable[] | null = null;

/** Starts dragging devices; the payload is also kept here, since a browser hides it from dragover. */
export function startDrag(dt: DataTransfer, devices: Movable[]) {
  dragging = devices;
  dt.effectAllowed = "move";
  dt.setData(DRAG_TYPE, JSON.stringify(devices.map((d) => d.id)));
  dt.setData("text/plain", devices.map((d) => d.name).join(", "));
}

export function endDrag() {
  dragging = null;
}

/** Whether what is dragged is devices. */
export function draggingDevices(dt: DataTransfer | null): boolean {
  return dragging !== null && (dt?.types.includes(DRAG_TYPE) ?? true);
}

export function dragged(): Movable[] {
  return dragging ?? [];
}
