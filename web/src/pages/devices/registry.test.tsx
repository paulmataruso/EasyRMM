import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { RegistryQuery, RegistryResult, RegistryRun } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { device, history, inventory, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { locationText, stoppedText, typeName, valueData } from "./registry/registryText";

const AGENT = { version: "1.5.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-26T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
const PC = device("d1", "PC-12", { platform: "windows", agent: AGENT, online: true });
const LINUX = device("d2", "TUX", { platform: "linux", agent: AGENT, online: true });

const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "log.view", "registry.view", "job.view", "job.view_sensitive"] });
const READ_ONLY = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "job.view"] });

function list(path: string[], extra: Partial<RegistryResult> = {}): RegistryResult {
  return {
    state: "reported",
    complete: true,
    kind: "registry_query",
    runStatus: "succeeded",
    op: "list",
    hive: "HKLM",
    view: "64",
    path,
    readAt: "2026-11-26T14:02:11Z",
    key: { kernel: `\\REGISTRY\\MACHINE\\${path.join("\\")}`, subkeys: 4, values: 6, readAt: "2026-11-26T14:02:11Z" },
    subkeys: [
      { name: "Vendor", subkeys: 2, values: 0 },
      { name: "SAM", subkeys: -1, values: -1, state: "refused", rule: "the local accounts database" },
      { name: "Lnk", subkeys: -1, values: -1, state: "link", target: "\\Registry\\Machine\\SOFTWARE\\Vendor" },
      { name: "Locked", subkeys: -1, values: -1, state: "denied" },
    ],
    values: [
      { name: "", type: 1, size: 12, text: "the default" },
      { name: "Count", type: 4, size: 4, number: 255 },
      { name: "DefaultPassword", type: 1, size: 16, masked: true },
      { name: "Big", type: 3, size: 5000, noData: true },
      { name: "Blob", type: 3, size: 3, base64: "AQID" },
      { name: "Quad", type: 11, size: 8, decimal: "9223372036854775807" },
    ],
    end: { complete: true, elapsedMs: 12 },
    ...extra,
  };
}

function routes(session: ReturnType<typeof sessionView>, dev = PC, handlers: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(session),
    "GET /devices/:id": ok(dev),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "POST /devices/:id/registry/query": (req: { body: unknown }): ReturnType<typeof ok> => {
      const q = req.body as RegistryQuery;
      const run: RegistryRun = { jobId: "j1", runId: `r-${q.op}`, op: q.op, hive: q.hive ?? "HKLM", view: q.view, path: q.path ?? ["SOFTWARE"], expiresAt: "2026-11-26T14:04:00Z" };
      return ok(run);
    },
    "GET /job-runs": ok({ items: [] }),
    "GET /job-runs/:id/result": ok(list(["SOFTWARE"])),
    ...handlers,
  } as Parameters<typeof installFakeApi>[0];
}

describe("the Registry tab", () => {
  it("is for a Windows device and a holder of registry.view", async () => {
    installFakeApi(routes(READ_ONLY));
    renderApp("/devices/d1");
    await screen.findByRole("tab", { name: "Overview" });
    expect(screen.queryByRole("tab", { name: "Registry" })).not.toBeInTheDocument();
  });

  it("is not on a Linux device", async () => {
    installFakeApi(routes(TECH, LINUX));
    renderApp("/devices/d2");
    await screen.findByRole("tab", { name: "Overview" });
    expect(screen.queryByRole("tab", { name: "Registry" })).not.toBeInTheDocument();
  });

  it("shows the device, the view and the roots, and nothing is read before a key is chosen", async () => {
    const server = installFakeApi(routes(TECH));
    renderApp("/devices/d1?tab=registry");
    const header = await screen.findByRole("group", { name: "Registry header" });
    expect(within(header).getByText("PC-12")).toBeInTheDocument();
    expect(within(header).getByText("64-bit view")).toBeInTheDocument();
    expect(within(header).getByText("Online")).toBeInTheDocument();
    const tree = screen.getByRole("tree", { name: "Registry keys" });
    for (const root of ["HKEY_LOCAL_MACHINE", "HKEY_USERS", "HKEY_CLASSES_ROOT (the computer's part)", "HKEY_CURRENT_CONFIG", "HKEY_CURRENT_USER (choose a user)"]) {
      expect(within(tree).getByText(root)).toBeInTheDocument();
    }
    expect(server.callsTo("POST /devices/:id/registry/query")).toHaveLength(0);
  });

  it("reads a key, with its values by type, masked data masked, links and refused keys marked, and when it was read", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(TECH));
    renderApp("/devices/d1?tab=registry");
    const tree = await screen.findByRole("tree", { name: "Registry keys" });
    await user.click(within(tree).getByText("HKEY_LOCAL_MACHINE"));
    const q = server.callsTo("POST /devices/:id/registry/query").at(-1)!;
    expect(q.body).toMatchObject({ op: "list", view: "64", hive: "HKLM", path: [] });
    const table = await screen.findByRole("table");
    expect(within(table).getByText("(Default)")).toBeInTheDocument();
    expect(within(table).getByText("the default")).toBeInTheDocument();
    expect(within(table).getByText("REG_DWORD")).toBeInTheDocument();
    expect(within(table).getByText("0x000000ff (255)")).toBeInTheDocument();
    expect(within(table).getByText("0x7fffffffffffffff (9223372036854775807)")).toBeInTheDocument();
    expect(within(table).getByText("01 02 03")).toBeInTheDocument();
    // A masked value shows Masked, never its data.
    const row = within(table).getByText("DefaultPassword").closest("tr")!;
    expect(within(row).getByText("Masked")).toBeInTheDocument();
    expect(within(row).queryByText(/hunter/)).not.toBeInTheDocument();
    // A value over a page says so, and can be read.
    expect(within(table).getByText(/5,000 bytes/)).toBeInTheDocument();
    expect(within(table).getByRole("button", { name: "Read" })).toBeInTheDocument();
    // Refused, a link, and a denied key.
    const subs = screen.getByRole("list", { name: "Subkeys" });
    expect(within(subs).getByRole("button", { name: /SAM.*Refused by EasyRMM/ })).toBeDisabled();
    expect(within(subs).getByRole("button", { name: /Lnk.*link/ })).toBeEnabled();
    expect(within(subs).getByRole("button", { name: /Locked.*access denied/ })).toBeDisabled();
    expect(within(subs).getByRole("button", { name: "Vendor" })).toBeEnabled();
    expect(screen.getByText(/Read at \d\d:\d\d:\d\d/)).toBeInTheDocument();
    expect(screen.getByText(/Physical key/)).toBeInTheDocument();
  });

  it("switches views and reads again in the 32-bit view", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(TECH));
    renderApp("/devices/d1?tab=registry");
    const tree = await screen.findByRole("tree", { name: "Registry keys" });
    await user.click(within(tree).getByText("HKEY_LOCAL_MACHINE"));
    await screen.findByRole("table");
    await user.click(screen.getByRole("radio", { name: "32-bit" }));
    await waitFor(() => expect(server.callsTo("POST /devices/:id/registry/query").at(-1)!.body).toMatchObject({ view: "32" }));
    expect(screen.getByText("32-bit view")).toBeInTheDocument();
  });

  it("takes any spelling in the address bar and shows the key the server read", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(TECH));
    renderApp("/devices/d1?tab=registry");
    await user.type(await screen.findByLabelText("Address"), "Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft{enter}");
    const q = server.callsTo("POST /devices/:id/registry/query").at(-1)!;
    expect(q.body).toMatchObject({ op: "list", text: "Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft" });
  });

  it("says plainly when the server refuses a path", async () => {
    const user = userEvent.setup();
    installFakeApi(
      routes(TECH, PC, { "POST /devices/:id/registry/query": fail(422, "validation_failed", "Refused by EasyRMM: the local accounts database. The registry editor never reads it.") }),
    );
    renderApp("/devices/d1?tab=registry");
    await user.type(await screen.findByLabelText("Address"), "HKLM\\SAM{enter}");
    expect(await screen.findByText(/Refused by EasyRMM: the local accounts database/)).toBeInTheDocument();
  });

  it("shows each state of a read: unavailable, not found, unknown with its reason", async () => {
    const user = userEvent.setup();
    const result = vi.fn<() => RegistryResult>();
    installFakeApi(routes(TECH, PC, { "GET /job-runs/:id/result": () => ok(result()) }));
    renderApp("/devices/d1?tab=registry");
    const tree = await screen.findByRole("tree", { name: "Registry keys" });
    result.mockReturnValue({ ...list([]), state: "unavailable", reason: "Windows denied access to the key.", subkeys: [], values: [] });
    await user.click(within(tree).getByText("HKEY_USERS"));
    expect(await screen.findByText("Unavailable: access denied")).toBeInTheDocument();
    result.mockReturnValue({ ...list([]), state: "not_found", reason: "The key is not there: it may have been removed since it was listed.", subkeys: [], values: [] });
    await user.click(within(tree).getByText("HKEY_CURRENT_CONFIG"));
    expect(await screen.findByText("Not found")).toBeInTheDocument();
    result.mockReturnValue({ state: "unknown", reason: "The device did not answer in time.", complete: false, kind: "registry_query", runStatus: "expired" });
    await user.click(within(tree).getByText("HKEY_CLASSES_ROOT (the computer's part)"));
    expect(await screen.findByText("The device did not answer in time.")).toBeInTheDocument();
  });

  it("waits out a read that is still open", async () => {
    const user = userEvent.setup();
    let calls = 0;
    installFakeApi(
      routes(TECH, PC, {
        "GET /job-runs/:id/result": () => (++calls < 3 ? fail(409, "run_open", "The run has not finished") : ok(list(["SOFTWARE"]))),
      }),
    );
    renderApp("/devices/d1?tab=registry");
    const tree = await screen.findByRole("tree", { name: "Registry keys" });
    await user.click(within(tree).getByText("HKEY_LOCAL_MACHINE"));
    expect(await screen.findByRole("table", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(calls).toBe(3);
  });

  it("searches below the chosen key, listing matches and the bound that stopped it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(TECH, PC, {
        "GET /job-runs/:id/result": (req: { params: Record<string, string> }) =>
          ok(
            req.params.id === "r-search"
              ? {
                  ...list([]),
                  op: "search",
                  subkeys: undefined,
                  values: undefined,
                  matches: [
                    { kind: "key", path: ["SOFTWARE", "Vendor", "marker key"] },
                    { kind: "valueName", path: ["SOFTWARE", "Vendor"], name: "MarkerName" },
                    { kind: "data", path: ["SOFTWARE", "Vendor"], name: "Plain", type: 1 },
                    { kind: "link", path: ["SOFTWARE", "Lnk"], name: "\\Registry\\Machine\\SOFTWARE" },
                  ],
                  end: { complete: false, stoppedBy: "time", firstUnvisited: ["SOFTWARE", "Zed"], visited: 4321, matches: 4, elapsedMs: 45000 },
                }
              : list(["SOFTWARE"]),
          ),
      }),
    );
    renderApp("/devices/d1?tab=registry");
    const tree = await screen.findByRole("tree", { name: "Registry keys" });
    await user.click(within(tree).getByText("HKEY_LOCAL_MACHINE"));
    await screen.findByRole("table");
    await user.type(screen.getByLabelText("Search term"), "marker");
    await user.click(screen.getByRole("button", { name: /Search below this key/ }));
    const matches = await screen.findByRole("list", { name: "Search matches" });
    expect(within(matches).getAllByRole("listitem")).toHaveLength(4);
    expect(screen.getByText(/Stopped at the time limit/)).toBeInTheDocument();
    expect(screen.getByText("SOFTWARE\\Zed")).toBeInTheDocument();
    expect(within(matches).getByText("Link, not followed")).toBeInTheDocument();
    const q = server.callsTo("POST /devices/:id/registry/query").at(-1)!;
    expect(q.body).toMatchObject({ op: "search", term: "marker" });
  });

  it("exports a key as .reg or JSON, and says when the export was too big", async () => {
    const user = userEvent.setup();
    const clicked: string[] = [];
    const click = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
      clicked.push(this.href);
    };
    try {
      let complete = true;
      installFakeApi(
        routes(TECH, PC, {
          "GET /job-runs/:id/result": (req: { params: Record<string, string> }) =>
            ok(req.params.id === "r-export" ? { ...list(["SOFTWARE"]), op: "export", complete, exportKeys: 3 } : list(["SOFTWARE"])),
        }),
      );
      renderApp("/devices/d1?tab=registry");
      const tree = await screen.findByRole("tree", { name: "Registry keys" });
      await user.click(within(tree).getByText("HKEY_LOCAL_MACHINE"));
      await screen.findByRole("table");
      await user.click(screen.getByRole("button", { name: /Export \.reg/ }));
      await waitFor(() => expect(clicked).toHaveLength(1));
      expect(clicked[0]).toContain("/job-runs/r-export/export?format=reg");
      await user.click(screen.getByRole("button", { name: "Export JSON" }));
      await waitFor(() => expect(clicked).toHaveLength(2));
      expect(clicked[1]).toContain("format=json");
      complete = false;
      await user.click(screen.getByRole("button", { name: /Export \.reg/ }));
      expect(await screen.findByText(/export a smaller key/)).toBeInTheDocument();
      expect(clicked).toHaveLength(2);
    } finally {
      HTMLAnchorElement.prototype.click = click;
    }
  });

  it("sends no reads while the device is offline, and says when it was last seen", async () => {
    installFakeApi(routes(TECH, { ...PC, online: false, lastSeenAt: "2026-11-26T09:00:00Z" }));
    renderApp("/devices/d1?tab=registry");
    expect(await screen.findByText("This device is offline")).toBeInTheDocument();
    expect(screen.getByLabelText("Address")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Go" })).toBeDisabled();
  });

  it("offers HKEY_CURRENT_USER as a choice of loaded user hives", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(TECH, PC, {
        "GET /job-runs/:id/result": ok({
          ...list([]),
          hive: "HKU",
          subkeys: [
            { name: "S-1-5-21-1-2-3-1001", subkeys: 1, values: 0, label: "LAB\\ana" },
            { name: "S-1-5-21-1-2-3-1001_Classes", subkeys: 1, values: 0 },
            { name: ".DEFAULT", subkeys: 1, values: 0 },
          ],
        }),
      }),
    );
    renderApp("/devices/d1?tab=registry");
    const tree = await screen.findByRole("tree", { name: "Registry keys" });
    await user.click(within(tree).getByRole("button", { name: /Expand HKEY_CURRENT_USER/ }));
    const choice = await within(tree).findByRole("button", { name: "LAB\\ana, loaded" });
    expect(within(tree).queryByText(/_Classes/)).not.toBeInTheDocument();
    server.on("GET /job-runs/:id/result", ok({ ...list(["S-1-5-21-1-2-3-1001"]), hive: "HKU" }));
    await user.click(choice);
    await waitFor(() => expect(server.callsTo("POST /devices/:id/registry/query").at(-1)!.body).toMatchObject({ hive: "HKU", path: ["S-1-5-21-1-2-3-1001"] }));
  });
});

describe("the registry text helpers", () => {
  it("name the types and write locations as Registry Editor does", () => {
    expect(typeName(1)).toBe("REG_SZ");
    expect(typeName(11)).toBe("REG_QWORD");
    expect(typeName(99)).toBe("Type 99");
    expect(locationText({ hive: "HKLM", path: ["SOFTWARE", "A"] })).toBe("HKEY_LOCAL_MACHINE\\SOFTWARE\\A");
    expect(locationText({ hive: "HKU", path: [] })).toBe("HKEY_USERS");
  });

  it("show odd data as its escaped text and never a masked value's data", () => {
    expect(valueData({ name: "a", type: 1, size: 8, odd: true, display: "a\\0b\\0", raw: "AAAA" })).toBe("a\\0b\\0");
    expect(valueData({ name: "a", type: 1, size: 8, masked: true, text: "secret" })).toBe("Masked");
    expect(valueData({ name: "a", type: 7, size: 8, items: ["a", "b"] })).toBe("a | b");
    expect(valueData({ name: "a", type: 3, size: 0, base64: "" })).toBe("(zero-length binary value)");
    expect(valueData({ name: "a", type: 1, size: 8, denied: true })).toBe("Access denied");
  });

  it("say which bound stopped a search or an export", () => {
    expect(stoppedText("keys")).toBe("the limit of 100,000 keys");
    expect(stoppedText("exportKeys")).toBe("the limit of 5,000 keys");
    expect(stoppedText("size")).toBe("the size limit of the result");
    expect(stoppedText(undefined)).toBe("");
  });
});
