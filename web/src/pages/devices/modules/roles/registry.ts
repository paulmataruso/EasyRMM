import type { ComponentType } from "react";
import type { Device, Permission } from "../../../../api/types";
import { DirectoryTab } from "../directory/DirectoryTab";
import { DhcpView } from "./dhcp/DhcpView";
import { DnsView } from "./dns/DnsView";
import { CaView } from "./ca/CaView";
import { PrintView } from "./print/PrintView";
import { SharesView } from "./shares/SharesView";
import { GpoView } from "./gpo/GpoView";

/** One role's view in the device's "Roles" tab (ADR-0076, section 8). */
export interface RoleView {
  /** The module, as `Catalog` names it on the server. */
  module: string;
  label: string;
  permission: Permission;
  component: ComponentType<{ device: Device }>;
}

/** The registry. A role (ADR-0076) adds one line here and one folder beside this file. */
export const ROLE_VIEWS: readonly RoleView[] = [
  { module: "active_directory", label: "Active Directory", permission: "ad.view", component: DirectoryTab },
  { module: "dns", label: "DNS", permission: "dns.view", component: DnsView },
  { module: "dhcp", label: "DHCP", permission: "dhcp.view", component: DhcpView },
  { module: "certificate_authority", label: "Certificate authority", permission: "ca.view", component: CaView },
  { module: "file_shares", label: "File shares", permission: "shares.view", component: SharesView },
  { module: "print", label: "Print", permission: "print.view", component: PrintView },
  { module: "group_policy", label: "Group Policy", permission: "gpo.view", component: GpoView },
];
