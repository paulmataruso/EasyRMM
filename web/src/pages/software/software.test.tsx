import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Device, Job, Package } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { counts, device, history, inventory, job, jobRun, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const location = () => screen.getByTestId("location").textContent;

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
const LINUX: Partial<Device> = { platform: "linux", osDescription: "Debian GNU/Linux 13 (trixie)", agent: AGENT, canManageSoftware: true };
const SERVER = device("d1", "DB-01", LINUX);
const WINDOWS_PC = device("d2", "FRONT-DESK", { agent: AGENT, canManageSoftware: true });

const TECHNICIAN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "software.view", "software.manage", "job.view", "job.manage"],
});

const PACKAGES: Package[] = [
  { name: "bash", version: "5.2.37-2", arch: "amd64" },
  { name: "jq", version: "1.7.1-3", arch: "amd64" },
];

/** A software job as the server returns it. */
function softwareJob(id: string, extra: Partial<Job> = {}): Job {
  return job(id, "Uninstall jq", {
    kind: "software",
    software: { action: "uninstall", manager: "system", package: "jq" },
    scriptId: null,
    shell: "sh",
    argCount: 2,
    canViewArguments: true,
    timeoutSeconds: 3600,
    body: "#!/bin/sh\nset -eu\n",
    ...extra,
  });
}

function deviceRoutes(d = SERVER, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(TECHNICIAN),
    "GET /devices/:id": ok(d),
    "GET /devices/:id/inventory": ok({ inventory: inventory(d.platform === "windows" ? { packageManager: "windows" } : {}), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/software": ok({ items: PACKAGES }),
    "POST /jobs/software": (r: { body: unknown }) => ({ status: 201, body: softwareJob("j9", { total: (r.body as { deviceIds: string[] }).deviceIds.length }) }),
    "GET /jobs/:id": ok(softwareJob("j9", { runs: [] })),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

describe("software on a device", () => {
  it("removes a package from its row", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(deviceRoutes());
    renderApp("/devices/d1?tab=software");
    const table = await screen.findByRole("table");
    await user.click(within(table).getByRole("button", { name: "Uninstall jq" }));

    const dialog = await screen.findByRole("dialog", { name: "Uninstall jq" });
    expect(within(dialog).getByText(/On DB-01, through its package manager/)).toBeInTheDocument();
    expect(within(dialog).getByRole("radio", { name: "Uninstall" })).toBeChecked();
    expect(within(dialog).getByRole("textbox", { name: /^Package/ })).toHaveValue("jq");
    expect(within(dialog).queryByLabelText("Version")).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("list", { name: "Devices" })).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Uninstall" }));

    await waitFor(() => expect(location()).toBe("/jobs/j9"));
    expect(server.call("POST /jobs/software").body).toEqual({
      deviceIds: ["d1"],
      action: "uninstall",
      manager: "system",
      package: "jq",
      timeoutSeconds: 3600,
      waitHours: 24,
    });
  });

  it("installs a version and checks the name first", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(deviceRoutes());
    renderApp("/devices/d1?tab=software");
    await user.click(await screen.findByRole("button", { name: "Install software" }));
    const dialog = await screen.findByRole("dialog", { name: "Install, update or remove software" });
    expect(within(dialog).queryByRole("combobox", { name: "Package manager" })).not.toBeInTheDocument();
    expect(within(dialog).getByText(/The device's own apt-get, dnf, yum or zypper installs it/)).toBeInTheDocument();

    const submit = () => user.click(within(dialog).getByRole("button", { name: "Install" }));
    await submit();
    expect(within(dialog).getByText("Enter the package's name.")).toBeInTheDocument();
    await user.type(within(dialog).getByRole("textbox", { name: /^Package/ }), "jq; reboot");
    await submit();
    expect(within(dialog).getByText(/Use the name exactly as the package manager writes it/)).toBeInTheDocument();
    expect(server.callsTo("POST /jobs/software")).toHaveLength(0);

    await user.clear(within(dialog).getByRole("textbox", { name: /^Package/ }));
    await user.type(within(dialog).getByRole("textbox", { name: /^Package/ }), "jq");
    await user.type(within(dialog).getByLabelText("Version"), "1.7.1-3");
    await submit();
    await waitFor(() => expect(location()).toBe("/jobs/j9"));
    expect(server.call("POST /jobs/software").body).toMatchObject({ action: "install", manager: "system", package: "jq", version: "1.7.1-3" });
  });

  it("shows what the server refuses beside its field", async () => {
    const user = userEvent.setup();
    installFakeApi(
      deviceRoutes(SERVER, {
        "POST /jobs/software": fail(422, "validation_failed", "Check the highlighted fields.", { deviceIds: "You cannot manage software on DB-01." }),
      }),
    );
    renderApp("/devices/d1?tab=software");
    await user.click(await screen.findByRole("button", { name: "Update jq" }));
    const dialog = await screen.findByRole("dialog", { name: "Update jq" });
    await user.click(within(dialog).getByRole("button", { name: "Update" }));
    expect(await within(dialog).findByText("You cannot manage software on DB-01.")).toBeInTheDocument();
  });

  it("offers nothing to someone who only reads", async () => {
    installFakeApi(deviceRoutes({ ...SERVER, canManageSoftware: false }));
    renderApp("/devices/d1?tab=software");
    const table = await screen.findByRole("table");
    expect(within(table).queryByRole("button")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Install software" })).not.toBeInTheDocument();
  });

  it("uses winget or Chocolatey on Windows, by package ID", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(deviceRoutes(WINDOWS_PC));
    renderApp("/devices/d2?tab=software");
    const table = await screen.findByRole("table");
    // Windows lists display names, which no package manager takes.
    expect(within(table).queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByText(/use Install software with its winget or Chocolatey package ID/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Install software" }));
    const dialog = await screen.findByRole("dialog");
    const manager = within(dialog).getByRole("combobox", { name: "Package manager" });
    expect(within(manager).getAllByRole("option").map((o) => o.textContent)).toEqual(["winget (Windows)", "Chocolatey (Windows)"]);
    await user.selectOptions(manager, "chocolatey");
    await user.click(within(dialog).getByRole("radio", { name: "Update" }));
    await user.type(within(dialog).getByRole("textbox", { name: /^Package/ }), "7zip");
    await user.click(within(dialog).getByRole("button", { name: "Update" }));
    await waitFor(() => expect(location()).toBe("/jobs/j9"));
    expect(server.call("POST /jobs/software").body).toMatchObject({ deviceIds: ["d2"], action: "upgrade", manager: "chocolatey", package: "7zip" });
  });
});

describe("software across devices", () => {
  const DEVICES = [
    SERVER,
    device("d3", "WEB-01", LINUX),
    device("d4", "LAB-01", { ...LINUX, canManageSoftware: false }),
    WINDOWS_PC,
  ];

  it("installs on the chosen devices of one platform", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...deviceRoutes(), "GET /jobs": ok({ items: [] }), "GET /devices": ok({ items: DEVICES }) });
    renderApp("/jobs");
    await user.click(await screen.findByRole("button", { name: "Install software" }));
    const dialog = await screen.findByRole("dialog", { name: "Install, update or remove software" });

    // winget first: only the Windows device.
    let list = await within(dialog).findByRole("list", { name: "Devices" });
    expect(within(list).getAllByRole("checkbox")).toHaveLength(1);
    await user.click(within(list).getByRole("checkbox", { name: /FRONT-DESK/ }));
    expect(within(dialog).getByText("1 device selected")).toBeInTheDocument();

    // Another platform starts the choice again.
    await user.selectOptions(within(dialog).getByRole("combobox", { name: "Package manager" }), "system");
    expect(within(dialog).getByText("0 devices selected")).toBeInTheDocument();
    list = within(dialog).getByRole("list", { name: "Devices" });
    expect(within(list).getAllByRole("checkbox").map((c) => c.closest("label")?.textContent)).toEqual([
      expect.stringContaining("DB-01"),
      expect.stringContaining("WEB-01"),
    ]);
    expect(within(dialog).getByText(/1 other device running Linux is not listed/)).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Install" }));
    expect(within(dialog).getByText("Choose at least one device.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("checkbox", { name: "All" }));
    await user.type(within(dialog).getByRole("textbox", { name: /^Package/ }), "curl");
    await user.click(within(dialog).getByRole("button", { name: "Install on 2 devices" }));
    await waitFor(() => expect(location()).toBe("/jobs/j9"));
    expect(server.call("POST /jobs/software").body).toMatchObject({ deviceIds: ["d1", "d3"], action: "install", manager: "system", package: "curl" });
  });

  it("is not offered without software.manage", async () => {
    installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "job.view"] })),
      "GET /jobs": ok({ items: [] }),
    });
    renderApp("/jobs");
    expect(await screen.findByText(/No jobs yet/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Install software" })).not.toBeInTheDocument();
  });

  it("filters jobs by kind", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /jobs": (r) => ok({ items: r.query.get("kind") === "software" ? [softwareJob("j1")] : [softwareJob("j1"), job("j2", "Disk usage")] }),
    });
    renderApp("/jobs");
    expect(await screen.findByText("2 jobs")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Kind"), "Software");
    await waitFor(() => expect(screen.getByText("1 job")).toBeInTheDocument());
    expect(server.callsTo("GET /jobs").at(-1)?.query.get("kind")).toBe("software");
    expect(location()).toBe("/jobs?kind=software");
    expect(screen.getByRole("link", { name: "Uninstall jq" })).toHaveAttribute("href", "/jobs/j1");
  });
});

describe("a software job", () => {
  it("says what it asked for and runs again from the same form", async () => {
    const user = userEvent.setup();
    const done = softwareJob("j1", {
      counts: counts({ succeeded: 2 }),
      total: 2,
      runs: [jobRun("r1", "d1", "DB-01", "succeeded"), jobRun("r2", "d3", "WEB-01", "succeeded")],
    });
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /jobs/:id": (r) => ok(r.params.id === "j1" ? done : softwareJob("j9", { runs: [] })),
      "GET /devices": ok({ items: [SERVER, device("d3", "WEB-01", LINUX)] }),
      "POST /jobs/software": { status: 201, body: softwareJob("j9") },
      "GET /scripts/:id": () => {
        throw new Error("a software job has no library script");
      },
    });
    renderApp("/jobs/j1");
    const details = (await screen.findByRole("heading", { name: "Details" })).closest("section") as HTMLElement;
    expect(within(details).getByText("Action").nextSibling?.textContent).toBe("Uninstall");
    expect(within(details).getByText("Package manager").nextSibling?.textContent).toBe("Linux package manager");
    expect(within(details).queryByText("Arguments")).not.toBeInTheDocument();
    expect(screen.getByText(/EasyRMM’s own script for the Linux package manager/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Run again" }));
    const dialog = await screen.findByRole("dialog", { name: "Uninstall jq" });
    expect(await within(dialog).findByText("2 devices selected")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Uninstall on 2 devices" }));
    await waitFor(() => expect(location()).toBe("/jobs/j9"));
    expect(server.call("POST /jobs/software").body).toEqual({
      deviceIds: ["d1", "d3"],
      action: "uninstall",
      manager: "system",
      package: "jq",
      timeoutSeconds: 3600,
      waitHours: 24,
    });
  });
});
