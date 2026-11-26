// What the DNS view knows about names. The server refuses protected names itself (ADR-0076, section 4); this is the
// same list, so the view can say why a record has no Edit or Remove button instead of letting a person find out.

const SPECIAL = ["_msdcs", "domaindnszones", "forestdnszones"];
const LOCATOR = ["_ldap", "_kerberos", "_kpasswd", "_gc"];

const labels = (n: string) => n.replace(/\.$/, "").toLowerCase().split(".").filter(Boolean);

/** A record name relative to its zone: "@" for the apex, "" when an absolute name is outside the zone. */
export function relName(zone: string, name: string): string {
  const z = zone.replace(/\.$/, "").toLowerCase();
  if (name === "@") return "@";
  if (!name.endsWith(".")) return name;
  const n = name.replace(/\.$/, "").toLowerCase();
  if (n === z) return "@";
  return n.endsWith(`.${z}`) ? n.slice(0, n.length - z.length - 1) : "";
}

/** The _msdcs, DomainDnsZones and ForestDnsZones trees and the names under which domain controllers are found. */
export function isProtectedRecord(zone: string, rel: string): boolean {
  const zl = labels(zone);
  if (zl.length > 0 && SPECIAL.includes(zl[0]!)) return true;
  const fl = labels(rel === "@" ? zone : `${rel}.${zone}`);
  if (fl.some((l) => SPECIAL.includes(l))) return true;
  if (fl.length >= 2 && LOCATOR.includes(fl[0]!) && (fl[1] === "_tcp" || fl[1] === "_udp")) return true;
  return fl.length >= 1 && LOCATOR.includes(fl[0]!) && fl.includes("_sites");
}

/** A zone the module never removes. */
export function isProtectedZone(zone: string): boolean {
  const zl = labels(zone);
  return zl.length > 0 && SPECIAL.includes(zl[0]!);
}

export const RECORD_TYPES = ["A", "AAAA", "CNAME", "PTR", "MX", "TXT", "SRV", "NS"] as const;

/** What a type's data looks like, for the form. */
export const DATA_HINT: Record<string, string> = {
  A: "IPv4 address, such as 192.0.2.10",
  AAAA: "IPv6 address, such as 2001:db8::1",
  CNAME: "Host name, such as host.example.com.",
  PTR: "Host name, such as host.example.com.",
  NS: "Name server, such as ns1.example.com.",
  MX: "Preference and host, such as 10 mail.example.com.",
  SRV: "Priority, weight, port and host, such as 0 5 5060 sip.example.com.",
  TXT: "Text, up to 255 characters",
};

/** The zone's storage in words: file-backed, or Active Directory with the replication scope. */
export function storage(z: { adIntegrated: boolean; replicationScope: string }): string {
  if (!z.adIntegrated) return "File";
  const scope = z.replicationScope.toLowerCase();
  const label = scope === "domain" ? "domain" : scope === "forest" ? "forest" : scope === "legacy" ? "custom" : scope;
  return label ? `AD-integrated (${label})` : "AD-integrated";
}

/** A TTL in the largest whole unit. */
export function ttlText(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400} d`;
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} s`;
}
