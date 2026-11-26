import type { RegistryHive, RegistryState, RegistryValue, RegistryView } from "../../../api/types";

/** Registry Editor's names for the value types, by Windows' type number. */
const TYPE_NAMES: Record<number, string> = {
  0: "REG_NONE",
  1: "REG_SZ",
  2: "REG_EXPAND_SZ",
  3: "REG_BINARY",
  4: "REG_DWORD",
  5: "REG_DWORD_BIG_ENDIAN",
  6: "REG_LINK",
  7: "REG_MULTI_SZ",
  8: "REG_RESOURCE_LIST",
  9: "REG_FULL_RESOURCE_DESCRIPTOR",
  10: "REG_RESOURCE_REQUIREMENTS_LIST",
  11: "REG_QWORD",
};

export function typeName(type: number): string {
  return TYPE_NAMES[type] ?? `Type ${type}`;
}

export const HIVE_NAMES: Record<RegistryHive, string> = {
  HKLM: "HKEY_LOCAL_MACHINE",
  HKU: "HKEY_USERS",
  HKCR: "HKEY_CLASSES_ROOT",
  HKCC: "HKEY_CURRENT_CONFIG",
};

export interface Location {
  hive: RegistryHive;
  path: string[];
}

export const same = (a: Location, b: Location) => a.hive === b.hive && a.path.length === b.path.length && a.path.every((n, i) => n === b.path[i]);

/** A location as Registry Editor writes it, with the hive's full name. */
export function locationText(l: Location): string {
  return [HIVE_NAMES[l.hive], ...l.path].join("\\");
}

/** A key for maps: names may hold anything but a backslash and NUL. */
export const locationKey = (l: Location) => `${l.hive}\u0000${l.path.join("\u0000")}`;

export function viewName(v: RegistryView): string {
  return v === "32" ? "32-bit view" : "64-bit view";
}

function hex(bytes: string, limit = 64): string {
  let raw: string;
  try {
    raw = atob(bytes);
  } catch {
    return "";
  }
  const out: string[] = [];
  for (let i = 0; i < Math.min(raw.length, limit); i++) out.push(raw.charCodeAt(i).toString(16).padStart(2, "0"));
  return out.join(" ") + (raw.length > limit ? " …" : "");
}

/** What the list shows for a value's data: text as it is, numbers with their hex, bytes in hex, "Masked" for a masked one. */
export function valueData(v: RegistryValue): string {
  if (v.masked) return "Masked";
  if (v.denied) return "Access denied";
  if (v.noData) return `${v.size.toLocaleString("en-US")} bytes (read the value to see it)`;
  if (v.odd) return v.display ?? (v.raw ? hex(v.raw) : "");
  if (v.text !== undefined) return v.text;
  if (v.items) return v.items.join(" | ");
  if (v.number !== undefined) return `0x${v.number.toString(16).padStart(8, "0")} (${v.number})`;
  if (v.decimal !== undefined) return `0x${BigInt(v.decimal).toString(16).padStart(16, "0")} (${v.decimal})`;
  if (v.base64 !== undefined) return v.size === 0 ? "(zero-length binary value)" : hex(v.base64);
  if (v.raw) return hex(v.raw);
  return "";
}

/** The name shown for a value: the default value is "(Default)". */
export const valueName = (v: RegistryValue) => (v.name === "" ? "(Default)" : v.name);

export const STATE_TEXT: Record<RegistryState, string> = {
  reported: "Read",
  unavailable: "Unavailable: access denied",
  not_found: "Not found",
  refused: "Refused by EasyRMM",
  unknown: "Unknown",
};

/** Why a search or an export stopped early, in words. */
export function stoppedText(by: string | undefined): string {
  switch (by) {
    case "depth":
      return "the depth limit";
    case "matches":
      return "the limit of 500 matches";
    case "keys":
      return "the limit of 100,000 keys";
    case "time":
      return "the time limit";
    case "size":
      return "the size limit of the result";
    case "exportKeys":
      return "the limit of 5,000 keys";
    default:
      return "";
  }
}
