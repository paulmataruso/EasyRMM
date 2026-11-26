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

const toInt = (ip: string) => ip.trim().split(".").reduce((n, o) => n * 256 + Number(o), 0);

/**
 * Why a new address range for a scope cannot be applied, or null when it can: both ends are addresses, the start is not
 * after the end, the range stays inside the scope's own subnet (Windows cannot change a scope's network or mask in
 * place) and no exclusion falls outside it. The server and the script check the same, and Windows checks again.
 */
export function rangeProblem(
  scope: { scopeId: string; subnetMask: string; startRange: string; endRange: string },
  start: string,
  end: string,
  exclusions: { startRange: string; endRange: string }[],
): string | null {
  if (!isIPv4(start) || !isIPv4(end)) return "Use IPv4 addresses such as 192.0.2.10.";
  const lo = toInt(start);
  const hi = toInt(end);
  if (lo > hi) return "The range ends before it starts.";
  const mask = toInt(scope.subnetMask);
  const net = (toInt(scope.scopeId) & mask) >>> 0;
  if (((lo & mask) >>> 0) !== net || ((hi & mask) >>> 0) !== net) return `The range must stay inside the scope's network, ${scope.scopeId} with mask ${scope.subnetMask}.`;
  if (start.trim() === scope.startRange && end.trim() === scope.endRange) return "This is the range the scope has now.";
  const clash = exclusions.find((x) => toInt(x.startRange) < lo || toInt(x.endRange) > hi);
  if (clash) return `The exclusion ${clash.startRange} to ${clash.endRange} would fall outside the new range. Remove or change it first.`;
  return null;
}
