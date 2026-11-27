import type { Tone } from "../../components/ui";
import type { Asset } from "../../api/assetTypes";

export const ASSET_KINDS: [string, string][] = [
  ["workstation", "Workstation"],
  ["laptop", "Laptop"],
  ["server", "Server"],
  ["virtual_machine", "Virtual machine"],
  ["virtualization_host", "Virtualization host"],
  ["firewall", "Firewall"],
  ["router", "Router"],
  ["switch", "Switch"],
  ["wireless_access_point", "Wireless access point"],
  ["network_device", "Other network device"],
  ["printer", "Printer"],
  ["ups", "UPS"],
  ["storage", "Storage system"],
  ["mobile_device", "Phone or mobile device"],
  ["internet_connection", "Internet connection"],
  ["licence", "Licence"],
  ["other", "Other"],
];

export const ASSET_STATUSES: [string, string][] = [
  ["ordered", "Ordered"],
  ["in_stock", "In stock"],
  ["in_use", "In use"],
  ["in_repair", "In repair"],
  ["retired", "Retired"],
  ["disposed", "Disposed"],
  ["lost", "Lost"],
];

export const kindLabel = (k: string) => ASSET_KINDS.find(([v]) => v === k)?.[1] ?? k;
export const statusLabel = (s: string) => ASSET_STATUSES.find(([v]) => v === s)?.[1] ?? s;

/** What the asset is called: its name, else its model, else its serial. */
export function assetTitle(a: Asset): string {
  return a.name || [a.manufacturer, a.model].filter(Boolean).join(" ") || a.serialNumber || kindLabel(a.kind);
}

export function warrantyBadge(state: Asset["warrantyState"]): { tone: Tone; label: string } {
  switch (state) {
    case "active":
      return { tone: "ok", label: "In warranty" };
    case "expiring":
      return { tone: "warn", label: "Expiring soon" };
    case "expired":
      return { tone: "danger", label: "Out of warranty" };
    default:
      return { tone: "neutral", label: "No warranty date" };
  }
}

export function ageBadge(state: Asset["ageStatus"]): { tone: Tone; label: string } | null {
  switch (state) {
    case "ok":
      return { tone: "ok", label: "Current" };
    case "aging":
      return { tone: "warn", label: "Aging" };
    case "end_of_life":
      return { tone: "danger", label: "End of life" };
    default:
      return null;
  }
}

export function osSupportBadge(state: Asset["osSupport"]): { tone: Tone; label: string } | null {
  switch (state) {
    case "supported":
      return { tone: "ok", label: "OS supported" };
    case "ending":
      return { tone: "warn", label: "OS support ending" };
    case "ended":
      return { tone: "danger", label: "OS support ended" };
    default:
      return null;
  }
}
