import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {
  DeviceRole,
  DeviceRoles,
  DhcpLeaseList,
  DhcpScopeList,
  DhcpStatus,
  DnsRecordList,
  DnsStatus,
  DnsZoneList,
} from "../../../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../../../test/fakeApi";
import { device, history, inventory, metrics } from "../../../../test/fixtures";
import { renderApp } from "../../../../test/render";
import { DEVICE_MODULE_TABS, moduleTabState } from "../moduleTabs";
import { isProtectedRecord, isProtectedZone, relName, storage } from "./dns/dnsText";
import { fillTone, isMac, optionAction } from "./dhcp/dhcpText";

// The server roles' tab (ADR-0076): the tab rule, the DNS view and the DHCP view.

const AGENT = {
  version: "1.5.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z",
  enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null,
};
const SERVER = device("d1", "DC1", { platform: "windows", osDescription: "Windows Server 2025", agent: AGENT });
const role = (module: string, label: string, enabled = true): DeviceRole => ({ name: module, state: "present", module, label, enabled });
const DNS_ROLE = role("dns", "DNS");
const DHCP_ROLE = role("dhcp", "DHCP");
const roles = (r: DeviceRole[], known = true): DeviceRoles => ({ known, reportedAt: "2026-11-26T10:00:00Z", roles: r });

const MANAGER = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "dns.view", "dns.manage", "dhcp.view", "dhcp.manage"],
});
const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "dhcp.view"] });

const DNS_STATUS: DnsStatus = {
  serviceState: "running", zoneCount: 2, adIntegratedCount: 1, recursionEnabled: true, forwarders: ["192.0.2.53"],
  listenAddresses: [], scavengingHours: 168, transferAnyZones: ["corp.example.com"],
};
const ZONES: DnsZoneList = {
  truncated: false,
  zones: [
    { name: "corp.example.com", type: "primary", adIntegrated: true, replicationScope: "Domain", dynamicUpdate: "Secure", reverse: false, paused: false, shutdown: false, signed: false, agingEnabled: true },
    { name: "_msdcs.corp.example.com", type: "primary", adIntegrated: true, replicationScope: "Forest", dynamicUpdate: "Secure", reverse: false, paused: false, shutdown: false, signed: false, agingEnabled: false },
  ],
};
const RECORDS: DnsRecordList = {
  total: 3, offset: 0, next: null,
  records: [
    { name: "_ldap._tcp", type: "SRV", ttl: 600, data: "0 100 389 dc1.corp.example.com.", timestamp: null, static: true },
    { name: "www", type: "A", ttl: 3600, data: "192.0.2.10", timestamp: null, static: true },
    { name: "mail", type: "MX", ttl: 300, data: "10 mx.corp.example.com.", timestamp: null, static: true },
  ],
};
const DHCP_STATUS: DhcpStatus = {
  serviceState: "running", domainJoined: true, authorized: false, conflictDetectionAttempts: 0,
  bindings: [{ interface: "Ethernet", address: "192.168.1.2", enabled: true }], scopeCount: 2, activeScopeCount: 1,
};
const SCOPES: DhcpScopeList = {
  truncated: false,
  scopes: [
    { scopeId: "192.168.1.0", name: "Office", description: "", state: "Active", startRange: "192.168.1.10", endRange: "192.168.1.200", subnetMask: "255.255.255.0", leaseDurationSeconds: 28800, free: 6, inUse: 94, percentageInUse: 94 },
    { scopeId: "192.168.2.0", name: "Guests", description: "", state: "InActive", startRange: "192.168.2.10", endRange: "192.168.2.50", subnetMask: "255.255.255.0", leaseDurationSeconds: 3600, free: 41, inUse: 0, percentageInUse: 0 },
  ],
};
const LEASES: DhcpLeaseList = {
  total: 1, offset: 0, next: null,
  leases: [{ ipAddress: "192.168.1.50", clientId: "00-11-22-33-44-55", hostName: "laptop-7", state: "Active", expires: "2026-11-27T10:00:00Z" }],
};

type Results = Record<string, unknown>;

/** One fake for every winmod action: a run is named by its action, and its result is the test's. */
function routes(session: ReturnType<typeof sessionView>, r: DeviceRoles, results: Results) {
  return {
    ...baseRoutes(session),
    "GET /devices/:id": ok(SERVER),
    "GET /devices/:id/roles": ok(r),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/disks": ok({ items: [] }),
    "GET /devices/:id/defender": fail(404, "not_found", "none"),
    "POST /devices/:id/winmod/:action": (req: { params: Record<string, string> }) =>
      ok({ jobId: "j", runId: req.params.action, action: req.params.action, status: "queued", expiresAt: "2026-11-26T11:00:00Z" }),
    "GET /winmod/runs/:id": (req: { params: Record<string, string> }) => {
      const data = results[req.params.id!];
      return ok({
        runId: req.params.id, deviceId: "d1", action: req.params.id, version: 1, status: "succeeded", finishedAt: "2026-11-26T10:00:00Z",
        ok: true, data: data ?? { count: 1 },
      });
    },
  } as Parameters<typeof installFakeApi>[0];
}

const tab = DEVICE_MODULE_TABS.find((t) => t.id === "roles")!;
const can = (p: string) => p === "dns.view" || p === "dhcp.view";

describe("the Roles tab rule", () => {
  it("is shown when any role is found and on, off when only off ones are, absent otherwise", () => {
    expect(moduleTabState(tab, roles([DNS_ROLE]), can)).toBe("shown");
    expect(moduleTabState(tab, roles([DNS_ROLE, { ...DHCP_ROLE, enabled: false }]), can)).toBe("shown");
    expect(moduleTabState(tab, roles([{ ...DNS_ROLE, enabled: false }]), can)).toBe("off");
    expect(moduleTabState(tab, roles([]), can)).toBe("absent");
    expect(moduleTabState(tab, roles([DNS_ROLE], false), can)).toBe("absent");
    expect(moduleTabState(tab, roles([DNS_ROLE]), (p) => p === "dhcp.view")).toBe("absent");
    expect(moduleTabState(tab, roles([DHCP_ROLE]), (p) => p === "dhcp.view")).toBe("shown");
  });
});

describe("DNS names", () => {
  it("protects the names that find domain controllers and nothing else", () => {
    expect(isProtectedRecord("corp.example.com", "_ldap._tcp")).toBe(true);
    expect(isProtectedRecord("corp.example.com", "_gc._tcp.Default-First-Site-Name._sites")).toBe(true);
    expect(isProtectedRecord("corp.example.com", "gc._msdcs")).toBe(true);
    expect(isProtectedRecord("_msdcs.corp.example.com", "@")).toBe(true);
    expect(isProtectedRecord("corp.example.com", "DomainDnsZones")).toBe(true);
    expect(isProtectedRecord("example.com", "_dmarc")).toBe(false);
    expect(isProtectedRecord("example.com", "_sip._tcp")).toBe(false);
    expect(isProtectedRecord("example.com", "www")).toBe(false);
    expect(isProtectedZone("ForestDnsZones.corp.example.com")).toBe(true);
    expect(isProtectedZone("corp.example.com")).toBe(false);
    expect(relName("example.com", "www.example.com.")).toBe("www");
    expect(relName("example.com", "www.other.org.")).toBe("");
    expect(storage({ adIntegrated: true, replicationScope: "Forest" })).toBe("AD-integrated (forest)");
    expect(storage({ adIntegrated: false, replicationScope: "" })).toBe("File");
  });
  it("reads DHCP values", () => {
    expect(isMac("00-11-22-33-44-55")).toBe(true);
    expect(isMac("0011.2233.4455")).toBe(false);
    expect(fillTone(96)).toBe("danger");
    expect(fillTone(40)).toBe("ok");
    expect(optionAction(6)).toBe("dhcp.option_set_network");
    expect(optionAction(15)).toBe("dhcp.option_set");
  });
});

describe("the DNS view", () => {
  const results: Results = { "dns.status": DNS_STATUS, "dns.zone_list": ZONES, "dns.record_list": RECORDS };

  async function open() {
    const api = installFakeApi(routes(MANAGER, roles([DNS_ROLE]), results));
    renderApp("/devices/d1?tab=roles");
    await screen.findByRole("tab", { name: "Roles" });
    await userEvent.click(await screen.findByRole("button", { name: "Read now" }));
    await screen.findByText("Zones", { selector: "h2" });
    return api;
  }

  it("reads on request, and warns about a zone open to transfer", async () => {
    const api = await open();
    expect(await screen.findByText(/can be copied by anyone who asks/)).toBeInTheDocument();
    expect(screen.getByText("AD-integrated (domain)")).toBeInTheDocument();
    expect(api.callsTo("POST /devices/:id/winmod/:action").map((c) => c.params.action)).toEqual(expect.arrayContaining(["dns.status", "dns.zone_list"]));
  });

  it("locks the protected records and the protected zone", async () => {
    await open();
    const row = screen.getByText("corp.example.com").closest("tr")!;
    expect(within(row).getByRole("button", { name: "Remove" })).toBeInTheDocument();
    const msdcs = screen.getByText("_msdcs.corp.example.com").closest("tr")!;
    expect(within(msdcs).queryByRole("button", { name: "Remove" })).toBeNull();
    await userEvent.click(within(row).getByRole("button", { name: "Records" }));
    const ldap = (await screen.findByText("_ldap._tcp")).closest("tr")!;
    expect(within(ldap).getByText("Protected")).toBeInTheDocument();
    expect(within(ldap).queryByRole("button", { name: "Edit" })).toBeNull();
    const www = screen.getByText("www").closest("tr")!;
    expect(within(www).getByRole("button", { name: "Edit" })).toBeInTheDocument();
  });

  it("adds a record with its typed parameters", async () => {
    const api = await open();
    await userEvent.click(within(screen.getByText("corp.example.com").closest("tr")!).getByRole("button", { name: "Records" }));
    await userEvent.click(await screen.findByRole("button", { name: "Add record" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/^Name/), "app");
    await userEvent.type(within(dialog).getByLabelText(/^Data/), "192.0.2.77");
    await userEvent.click(within(dialog).getByRole("button", { name: "Add record" }));
    await screen.findByText("Zones", { selector: "h2" });
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.params.action === "dns.record_add")!;
    expect(call.body).toEqual({ params: { zone: "corp.example.com", name: "app", type: "A", data: "192.0.2.77", ttl: 3600 } });
  });

  it("removes every record of a name only when its name is typed, and sends the confirmation text", async () => {
    const api = await open();
    await userEvent.click(within(screen.getByText("corp.example.com").closest("tr")!).getByRole("button", { name: "Records" }));
    await userEvent.click((await screen.findAllByRole("button", { name: /Remove all named this/ }))[0]!);
    const dialog = await screen.findByRole("dialog");
    const go = within(dialog).getByRole("button", { name: "Remove all" });
    expect(go).toBeDisabled();
    const name = "www";
    await userEvent.type(within(dialog).getByLabelText(/Type/), name);
    expect(go).toBeEnabled();
    await userEvent.click(go);
    await screen.findByText("Zones", { selector: "h2" });
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.params.action === "dns.record_remove_all")!;
    expect(call.body).toEqual({ params: { zone: "corp.example.com", name }, confirm: `dns.record_remove_all:${name}` });
  });

  it("says why when the DNS tools are missing", async () => {
    installFakeApi({
      ...routes(MANAGER, roles([DNS_ROLE]), results),
      "GET /winmod/runs/:id": ok({ runId: "x", deviceId: "d1", action: "dns.status", version: 1, status: "succeeded", finishedAt: "2026-11-26T10:00:00Z", ok: false, failure: { code: "module_missing", message: "x" } }),
    });
    renderApp("/devices/d1?tab=roles");
    await userEvent.click(await screen.findByRole("button", { name: "Read now" }));
    await screen.findByText(/management tools for this role are not installed/);
  });
});

describe("the DHCP view", () => {
  const results: Results = {
    "dhcp.status": DHCP_STATUS,
    "dhcp.scope_list": SCOPES,
    "dhcp.lease_list": LEASES,
    "dhcp.reservation_list": { reservations: [] },
    "dhcp.exclusion_list": { exclusions: [] },
    "dhcp.option_list": { options: [] },
  };

  async function open(session = MANAGER) {
    const api = installFakeApi(routes(session, roles([DHCP_ROLE]), results));
    renderApp("/devices/d1?tab=roles");
    await userEvent.click(await screen.findByRole("button", { name: "Read now" }));
    await screen.findByText("Scopes", { selector: "h2" });
    return api;
  }

  it("shows the fill of each scope and the authorization command, with no button to authorize", async () => {
    await open();
    expect(await screen.findByText("Not authorized in Active Directory")).toBeInTheDocument();
    expect(screen.getByText(/Add-DhcpServerInDC/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /authorize/i })).toBeNull();
    expect(screen.getByRole("meter", { name: "192.168.1.0 in use" })).toBeInTheDocument();
    expect(screen.getByText("Inactive")).toBeInTheDocument();
  });

  it("creates a scope inactive: the dialog says so and sends the typed parameters", async () => {
    const api = await open();
    await userEvent.click(screen.getByRole("button", { name: "Add scope" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/created inactive/)).toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText(/^Name/), "Lab");
    await userEvent.type(within(dialog).getByLabelText(/First address/), "10.1.0.10");
    await userEvent.type(within(dialog).getByLabelText(/Last address/), "10.1.0.99");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create scope" }));
    await screen.findByText("Scopes", { selector: "h2" });
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.params.action === "dhcp.scope_create")!;
    expect(call.body).toEqual({ params: { name: "Lab", startRange: "10.1.0.10", endRange: "10.1.0.99", subnetMask: "255.255.255.0", leaseHours: 8 } });
  });

  it("deactivates a scope only when its ID is typed, with the confirmation text", async () => {
    const api = await open();
    await userEvent.click(screen.getByRole("button", { name: "Deactivate" }));
    const dialog = await screen.findByRole("dialog");
    const go = within(dialog).getByRole("button", { name: "Deactivate" });
    expect(go).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Type/), "192.168.1.0");
    await userEvent.click(go);
    await screen.findByText("Scopes", { selector: "h2" });
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.params.action === "dhcp.scope_deactivate")!;
    expect(call.body).toEqual({ params: { scopeId: "192.168.1.0" }, confirm: "dhcp.scope_deactivate:192.168.1.0" });
  });

  it("sets the gateway or DNS servers through the confirmed action", async () => {
    const api = await open();
    await userEvent.click(within(screen.getByText("Office").closest("tr")!).getByRole("button", { name: "Open" }));
    await userEvent.click(await screen.findByRole("radio", { name: "Options" }));
    await userEvent.click(await screen.findByRole("button", { name: "Set an option" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.selectOptions(within(dialog).getByLabelText("Option"), "6");
    await userEvent.type(within(dialog).getByLabelText(/^Value/), "192.168.1.2");
    const go = within(dialog).getByRole("button", { name: "Set option" });
    expect(go).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/^Level/), "192.168.1.0");
    await userEvent.click(go);
    await screen.findByText("Scopes", { selector: "h2" });
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.params.action === "dhcp.option_set_network")!;
    expect(call.body).toEqual({ params: { scopeId: "192.168.1.0", optionId: 6, value: "192.168.1.2" }, confirm: "dhcp.option_set_network:192.168.1.0" });
  });

  it("gives a Technician the state but no changes and no leases", async () => {
    const api = await open(TECH);
    expect(screen.queryByRole("button", { name: "Add scope" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Deactivate" })).toBeNull();
    await userEvent.click(within(screen.getByText("Office").closest("tr")!).getByRole("button", { name: "Open" }));
    await screen.findByRole("radio", { name: "Reservations" });
    expect(screen.queryByRole("radio", { name: "Leases" })).toBeNull();
    expect(api.callsTo("POST /devices/:id/winmod/:action").some((c) => c.params.action === "dhcp.lease_list")).toBe(false);
  });

  it("reads leases for a manager, on request", async () => {
    await open();
    await userEvent.click(within(screen.getByText("Office").closest("tr")!).getByRole("button", { name: "Open" }));
    await userEvent.click(await screen.findByRole("radio", { name: "Leases" }));
    expect(await screen.findByText("laptop-7")).toBeInTheDocument();
    expect(screen.getByText(/kept for 15 minutes/)).toBeInTheDocument();
  });
});
