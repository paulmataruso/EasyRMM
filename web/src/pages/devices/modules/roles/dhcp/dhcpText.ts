/** The options the console sets by value (ADR-0076, section 5). 3 and 6 reach every client and ask for a second factor. */
export const OPTIONS = [
  { id: 3, label: "Router (default gateway)", network: true, hint: "IPv4 addresses, comma-separated" },
  { id: 6, label: "DNS servers", network: true, hint: "IPv4 addresses, comma-separated" },
  { id: 15, label: "DNS domain name", network: false, hint: "Such as corp.example.com" },
  { id: 42, label: "NTP servers", network: false, hint: "IPv4 addresses, comma-separated" },
  { id: 51, label: "Lease time (seconds)", network: false, hint: "60 to 31536000" },
  { id: 66, label: "Boot server host name", network: false, hint: "A host name or address" },
  { id: 67, label: "Boot file name", network: false, hint: "Such as pxe/boot.wim" },
] as const;

export const optionAction = (id: number) => (OPTIONS.find((o) => o.id === id)?.network ? "dhcp.option_set_network" : "dhcp.option_set");

/** A scope's fill: warn from 90 percent, danger from 95. */
export function fillTone(pct: number): "ok" | "warn" | "danger" {
  return pct >= 95 ? "danger" : pct >= 90 ? "warn" : "ok";
}

/** A lease time in the largest whole unit. */
export function leaseText(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400} d`;
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  return `${Math.round(seconds / 60)} min`;
}

const MAC = /^([0-9a-f]{2}([-:]?)){5}[0-9a-f]{2}$/i;
/** A hardware address as the server accepts it: twelve hex digits, with - or : between bytes or none. */
export const isMac = (s: string) => MAC.test(s.trim()) && (s.trim().length === 12 || s.trim().length === 17);

const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
export const isIPv4 = (s: string) => V4.test(s.trim());

/** Fixed addresses and ranges are shown as written; this is the one-line summary of a scope's range. */
export const rangeText = (s: { startRange: string; endRange: string }) => `${s.startRange} – ${s.endRange}`;
