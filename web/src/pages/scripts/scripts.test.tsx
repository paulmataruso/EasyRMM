import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Script } from "../../api/types";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { device, job, org, script, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const location = () => screen.getByTestId("location").textContent;

const AGENT = { version: "1.4.0", arch: "amd64", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z" };

const SCRIPTS: Script[] = [
  script("sc1", "Disk usage", { description: "Shows free space on every mount.", body: "df -h\n" }),
  script("sc2", "Restart print spooler", {
    level: "site",
    organizationId: "o1",
    organizationName: "Northwind Traders",
    siteId: "s1",
    siteName: "Head office",
    shell: "sh",
    timeoutSeconds: 60,
  }),
];

const ADMIN = sessionView({
  permissions: ["org.view", "site.view", "site.manage", "device.view", "script.view", "script.manage", "script.run", "job.view", "job.manage"],
});
const TECHNICIAN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "script.view", "script.run", "job.view", "job.manage"] });

const lists = {
  "GET /organizations": ok({ items: [org("o1", "Northwind Traders"), org("o2", "Contoso Dental Group", { canManage: false })] }),
  "GET /sites": (r: FakeRequest) =>
    ok({
      items: [site("s1", "o1", "Head office"), site("s2", "o1", "Warehouse", { canManage: false })].filter((s) => s.organizationId === r.query.get("organizationId")),
    }),
};

function scriptList(r: FakeRequest) {
  const q = (r.query.get("q") ?? "").toLowerCase();
  return ok({
    items: SCRIPTS.filter(
      (s) =>
        (!q || s.name.toLowerCase().includes(q)) &&
        (r.query.get("level") !== "shared" || s.level === "shared") &&
        (!r.query.get("organizationId") || s.organizationId === r.query.get("organizationId")),
    ).map(({ body: _body, ...rest }) => rest),
  });
}

describe("scripts", () => {
  it("lists the library and filters it on the server", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...baseRoutes(ADMIN), ...lists, "GET /scripts": scriptList });
    renderApp("/scripts");

    const table = await screen.findByRole("table");
    expect(within(table).getByRole("link", { name: "Disk usage" })).toBeInTheDocument();
    expect(within(table).getByText("Shows free space on every mount.")).toBeInTheDocument();
    expect(within(table).getAllByText("Northwind Traders / Head office").length).toBeGreaterThan(0);
    expect(within(table).getByText("1 minute")).toBeInTheDocument();
    expect(within(screen.getByRole("main")).getByText("2 scripts")).toBeInTheDocument();
    expect(within(screen.getByRole("main")).getByRole("link", { name: "New script" })).toHaveAttribute("href", "/scripts/new");

    await user.selectOptions(screen.getByLabelText("Library"), "Shared library");
    await waitFor(() => expect(within(screen.getByRole("table")).queryByText("Restart print spooler")).not.toBeInTheDocument());
    expect(server.callsTo("GET /scripts").at(-1)?.query.get("level")).toBe("shared");
    expect(location()).toBe("/scripts?library=shared");

    await user.selectOptions(screen.getByLabelText("Library"), "Northwind Traders");
    await waitFor(() => expect(server.callsTo("GET /scripts").at(-1)?.query.get("organizationId")).toBe("o1"));

    await user.type(screen.getByLabelText("Search"), "zzz");
    expect(await screen.findByText("No scripts match these filters")).toBeInTheDocument();
  });

  it("tells people who cannot write scripts who adds them", async () => {
    installFakeApi({ ...baseRoutes(TECHNICIAN), ...lists, "GET /scripts": ok({ items: [] }) });
    renderApp("/scripts");
    expect(await screen.findByText("No scripts yet")).toBeInTheDocument();
    expect(screen.getByText(/An administrator adds scripts to the library/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "New script" })).not.toBeInTheDocument();
    // The sidebar offers scripts and jobs to roles that see them.
    await userEvent.click(screen.getByRole("button", { name: "Back to the main menu" }));
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Scripts" })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Jobs" })).toBeInTheDocument();
  });

  it("adds a site script, checking what is missing first", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(ADMIN),
      ...lists,
      "POST /scripts": (r) => ({ status: 201, body: script("new1", (r.body as Script).name, { ...(r.body as Script), level: "site" }) }),
      "GET /scripts/:id": (r) => ok(script(r.params.id ?? "", "Clear temp", { body: "rm -rf /tmp/app-cache\n" })),
      "GET /jobs": ok({ items: [] }),
    });
    renderApp("/scripts/new");

    await user.click(await screen.findByRole("button", { name: "Add script" }));
    expect(screen.getByText("Enter a name.")).toBeInTheDocument();
    expect(screen.getByText("Enter the script.")).toBeInTheDocument();
    expect(server.callsTo("POST /scripts")).toHaveLength(0);

    await user.type(screen.getByLabelText(/^Name/), "Clear temp");
    await user.selectOptions(screen.getByLabelText("Runs in"), "One site");
    const orgSelect = screen.getByLabelText(/^Organization/);
    // Every organization can hold site scripts; sites are limited to the ones the caller manages.
    expect(within(orgSelect).getAllByRole("option").map((o) => o.textContent)).toEqual(["Choose…", "Northwind Traders", "Contoso Dental Group"]);
    await user.selectOptions(orgSelect, "Northwind Traders");
    const siteSelect = screen.getByLabelText(/^Site/);
    await waitFor(() => expect(within(siteSelect).getAllByRole("option").map((o) => o.textContent)).toEqual(["Choose…", "Head office"]));
    await user.selectOptions(siteSelect, "Head office");
    // New scripts start as PowerShell, for Windows; each shell says where it runs and how.
    const shellSelect = screen.getByLabelText("Shell");
    expect(shellSelect).toHaveValue("powershell");
    expect(within(shellSelect).getAllByRole("option").map((o) => o.textContent)).toEqual(["PowerShell", "Command Prompt (cmd)", "Bash", "POSIX sh", "Python 3"]);
    expect(screen.getByText("Runs on Windows devices.")).toBeInTheDocument();
    expect(screen.getByText(/Windows PowerShell 5\.1 as Local System/)).toBeInTheDocument();
    await user.selectOptions(shellSelect, "Command Prompt (cmd)");
    expect(screen.getByText(/cannot contain double quotes/)).toBeInTheDocument();
    await user.selectOptions(shellSelect, "POSIX sh");
    expect(screen.getByText("Runs on Linux devices.")).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Timeout"));
    await user.type(screen.getByLabelText("Timeout"), "2");
    await user.selectOptions(screen.getByLabelText("Timeout unit"), "hours");
    await user.type(screen.getByLabelText(/^Body/), "rm -rf /tmp/app-cache");
    expect(screen.getByText("21 bytes of 64 KiB.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add script" }));

    await waitFor(() => expect(location()).toBe("/scripts/new1"));
    expect(server.call("POST /scripts").body).toEqual({
      organizationId: "o1",
      siteId: "s1",
      name: "Clear temp",
      description: "",
      shell: "sh",
      body: "rm -rf /tmp/app-cache",
      timeoutSeconds: 7200,
    });
    expect(await screen.findByText("Added Clear temp to the library.")).toBeInTheDocument();
  });

  it("shows the server's field errors and refuses oversized scripts", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(ADMIN),
      ...lists,
      "POST /scripts": fail(422, "validation_failed", "Check the highlighted fields.", { name: "A script with this name already exists here." }),
    });
    renderApp("/scripts/new");
    await user.type(await screen.findByLabelText(/^Name/), "Disk usage");
    await user.type(screen.getByLabelText(/^Body/), "df");
    await user.click(screen.getByRole("button", { name: "Add script" }));
    expect(await screen.findByText("A script with this name already exists here.")).toBeInTheDocument();
    expect(screen.getByLabelText(/^Name/)).toHaveAttribute("aria-invalid", "true");
  });

  it("edits a script, and tells those who may not", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(ADMIN),
      ...lists,
      "GET /scripts/:id": ok(SCRIPTS[0]),
      "PATCH /scripts/:id": (r) => ok({ ...SCRIPTS[0], ...(r.body as object) }),
      "GET /jobs": ok({ items: [] }),
    });
    const { unmount } = renderApp("/scripts/sc1/edit");
    expect(await screen.findByRole("heading", { name: "Edit Disk usage" })).toBeInTheDocument();
    expect(screen.getByText("All organizations")).toBeInTheDocument();
    expect(screen.queryByLabelText("Runs in")).not.toBeInTheDocument();
    const body = screen.getByLabelText(/^Body/);
    await user.clear(body);
    await user.type(body, "df -h /");
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(location()).toBe("/scripts/sc1"));
    expect(server.call("PATCH /scripts/:id").body).toEqual({ name: "Disk usage", description: "Shows free space on every mount.", shell: "bash", body: "df -h /", timeoutSeconds: 300 });
    unmount();

    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /scripts/:id": ok({ ...SCRIPTS[1], canEdit: false }) });
    renderApp("/scripts/sc2/edit");
    expect(await screen.findByText("You can run this script but not change it")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save changes" })).not.toBeInTheDocument();
  });

  it("shows a script with its jobs, and deletes it after the name is typed", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(ADMIN),
      "GET /scripts/:id": ok({ ...SCRIPTS[0], body: "#!/bin/bash\ndf -h\n" }),
      "GET /jobs": ok({ items: [job("j1", "Disk usage")] }),
      "DELETE /scripts/:id": noContent,
      "GET /scripts": scriptList,
      "GET /organizations": lists["GET /organizations"],
    });
    renderApp("/scripts/sc1");
    const code = await screen.findByLabelText("Disk usage script");
    expect(code).toHaveTextContent("1#!/bin/bash");
    expect(code).toHaveTextContent("2df -h");
    expect(screen.getByText("All organizations")).toBeInTheDocument();
    expect(screen.getByText("120 bytes")).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "Disk usage" })).toHaveAttribute("href", "/jobs/j1");
    expect(server.call("GET /jobs").query.get("scriptId")).toBe("sc1");

    await user.click(screen.getByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete Disk usage?" });
    const confirm = within(dialog).getByRole("button", { name: "Delete script" });
    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Type/), "Disk usage");
    await user.click(confirm);
    await waitFor(() => expect(location()).toBe("/scripts"));
    expect(server.callsTo("DELETE /scripts/:id")).toHaveLength(1);
  });

  it("runs a script on the devices chosen, with arguments", async () => {
    const user = userEvent.setup();
    const linux = { platform: "linux" as const, agent: AGENT, canRunScripts: true };
    const server = installFakeApi({
      ...baseRoutes(ADMIN),
      "GET /scripts/:id": ok({ ...SCRIPTS[1], body: "lpstat -p\n" }),
      "GET /jobs": ok({ items: [] }),
      "GET /devices": ok({
        items: [
          device("d1", "PRINT-01", linux),
          device("d2", "PRINT-02", { ...linux, online: false, remoteOnline: false }),
          device("d3", "FRONT-DESK"), // Windows, no agent: listed as excluded
          device("d4", "WAREHOUSE-01", { ...linux, siteId: "s2" }), // another site: not covered
        ],
      }),
      "POST /jobs": (r) => ({ status: 201, body: job("j9", "Restart print spooler", { total: (r.body as { deviceIds: string[] }).deviceIds.length }) }),
      "GET /jobs/:id": ok(job("j9", "Restart print spooler", { runs: [] })),
      "GET /scripts/sc1": fail(404, "not_found", "Not found."),
    });
    renderApp("/scripts/sc2");
    await user.click(await screen.findByRole("button", { name: "Run" }));
    const dialog = await screen.findByRole("dialog", { name: "Run Restart print spooler" });
    const list = await within(dialog).findByRole("list", { name: "Devices" });
    expect(within(list).getAllByRole("checkbox")).toHaveLength(2);
    expect(within(dialog).getByText(/1 other device where it could run is not listed/)).toBeInTheDocument();
    expect(within(list).getByText("Offline")).toBeInTheDocument();

    // Nothing chosen yet.
    await user.click(within(dialog).getByRole("button", { name: "Run" }));
    expect(within(dialog).getByText("Choose at least one device.")).toBeInTheDocument();

    await user.type(within(dialog).getByPlaceholderText(/Filter by name/), "02");
    await user.click(within(dialog).getByRole("checkbox", { name: "All 1 shown" }));
    await user.clear(within(dialog).getByPlaceholderText(/Filter by name/));
    await user.click(within(list).getByRole("checkbox", { name: /PRINT-01/ }));
    expect(within(dialog).getByText("2 devices selected")).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Arguments"), "--force{Enter}{Enter}queue one");
    await user.selectOptions(within(dialog).getByLabelText("Wait for offline devices"), "3 days");
    await user.click(within(dialog).getByRole("button", { name: "Run on 2 devices" }));

    await waitFor(() => expect(location()).toBe("/jobs/j9"));
    expect(server.call("POST /jobs").body).toEqual({ scriptId: "sc2", deviceIds: ["d2", "d1"], args: ["--force", "queue one"], timeoutSeconds: 60, waitHours: 72 });
  });

  it("says when no device can run a script", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /scripts/:id": ok({ ...SCRIPTS[0], body: "df\n", canEdit: false }),
      "GET /jobs": ok({ items: [] }),
      "GET /devices": ok({ items: [device("d3", "FRONT-DESK")] }),
    });
    renderApp("/scripts/sc1");
    expect(await screen.findByText("This script has not run yet.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Edit" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run" }));
    expect(await screen.findByText("No devices can run this script")).toBeInTheDocument();
  });
});
