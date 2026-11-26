import type { Gpo, GpoVersion } from "./types";

export const MODULE = "group_policy";

export const STATUS_LABEL: Record<Gpo["status"], string> = {
  AllSettingsEnabled: "Enabled",
  UserSettingsDisabled: "User settings disabled",
  ComputerSettingsDisabled: "Computer settings disabled",
  AllSettingsDisabled: "All settings disabled",
};

export const KIND_LABEL = { domain: "Domain", ou: "OU", site: "Site" } as const;

export const SENSITIVITY_TEXT: Record<string, string> = {
  default_policy: "a Default policy",
  sensitive_link: "the domain root, the Domain Controllers OU or a site",
  organization: "this organization's rule that every change is approved",
};

/** A version pair reads "3" when the directory and SYSVOL agree, "3 / 2" while they differ (a write or replication is under way). */
export function versionText(v: GpoVersion): string {
  return v.directory === v.sysvol ? String(v.directory) : `${v.directory} / ${v.sysvol}`;
}

/** The domain root of a distinguished name: DC=corp,DC=test -> corp.test. */
export function dnToDomain(dn: string): string {
  return dn
    .split(",")
    .filter((p) => p.trim().toUpperCase().startsWith("DC="))
    .map((p) => p.trim().slice(3))
    .join(".");
}

/** A readable path for a distinguished name: OU=East,OU=Sales,DC=corp,DC=test -> corp.test/Sales/East. */
export function dnToPath(dn: string): string {
  const parts = dn.split(",").map((p) => p.trim());
  const names = parts.filter((p) => !p.toUpperCase().startsWith("DC=")).map((p) => p.slice(p.indexOf("=") + 1));
  return [dnToDomain(dn), ...names.reverse()].filter(Boolean).join("/");
}

/** Where a request for approval is needed, in the words of the ADR. */
export const APPROVAL_CODE = "approval_required";
