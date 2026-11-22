import { describe, expect, it } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DeviceHardening, JobRun } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { device, job, jobRun, org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { RECOMMENDED } from "./hardeningText";

const location = () => screen.getByTestId("location").textContent;

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
const SERVER = device("d1", "DB-01", { platform: "linux", osDescription: "Ubuntu 26.10", agent: AGENT, canRunScripts: true, canCheckHardening: true });

const TECHNICIAN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "script.run", "job.view"] });
const READ_ONLY = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "job.view"] });

const EARLIER = "2026-11-01T09:00:00Z";
const LATEST = "2026-11-01T10:00:00Z";

const NONE: DeviceHardening = { platform: null, jobId: null, checkedAt: null, modules: [] };

const FOUND: DeviceHardening = {
  platform: { id: "ubuntu", versionId: "26.10", family: "debian", container: "lxc", support: "check_only" },
  jobId: "j2",
  checkedAt: LATEST,
  modules: [
    {
      module: "ssh",
      state: "partly",
      reason: "Some of the settings this module checks are in place.",
      missing: ["PermitRootLogin prohibit-password (now yes)"],
      changes: ["PermitRootLogin prohibit-password", "The settings go in /etc/ssh/sshd_config.d/00-easyrmm-hardening.conf"],
      jobId: "j2",
      checkedAt: LATEST,
    },
    {
      module: "firewall",
      state: "not_in_place",
      reason: "None of the settings this module checks is in place.",
      missing: ["nftables table inet easyrmm loaded"],
      changes: ["Install nftables"],
      ports: { tcp: ["22", "443", "9000-9100"], udp: ["53"], docker: ["tcp/8080"], unknown: ["minidlna.service"] },
      jobId: "j2",
      checkedAt: LATEST,
    },
    { module: "kernel", state: "in_place", reason: "Everything this module checks is in place.", jobId: "j1", checkedAt: EARLIER },
    { module: "sudo", state: "not_supported", reason: "sudo here is sudo-rs, which EasyRMM has not been tested with yet.", jobId: "j2", checkedAt: LATEST },
  ],
};

const hardeningRun = (id: string, jobId: string, status: JobRun["status"], extra: Partial<JobRun> = {}) =>
  jobRun(id, "d1", "DB-01", status, { jobId, scriptName: "Check hardening: ssh, firewall, sudo", ...extra });

function routes(session = TECHNICIAN, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(session),
    ...unreportedRoutes(),
    "GET /devices/:id": ok(SERVER),
    "GET /devices/:id/hardening": ok(FOUND),
    "GET /job-runs": ok({ items: [hardeningRun("r2", "j2", "succeeded"), hardeningRun("r1", "j1", "failed", { error: "The script finished, but its output does not end with a result." })] }),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

/** The module's entry in the Modules list. */
const moduleItem = (name: string) => screen.getByRole("heading", { name, level: 3 }).closest("li") as HTMLElement;

describe("a device's hardening", () => {
  it("shows what the last checks found, module by module, with when, by which job, and the platform", async () => {
    const server = installFakeApi(routes());
    renderApp("/devices/d1?tab=hardening");
    expect(await screen.findByRole("tab", { name: "Hardening" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("1 of 3 in place")).toHaveAttribute("title", "1 in place, 1 partly in place, 1 not in place, 1 not supported on this version");
    // The device's own hardening runs, for its job names and the Checks card.
    expect(server.call("GET /job-runs").query.get("kind")).toBe("hardening");
    expect(server.call("GET /job-runs").query.get("deviceId")).toBe("d1");

    const ssh = moduleItem("SSH");
    expect(within(ssh).getByText("Partly in place")).toBeInTheDocument();
    expect(within(ssh).getByText("Some of the settings this module checks are in place.")).toBeInTheDocument();
    expect(within(within(ssh).getByRole("heading", { name: "Missing" }).parentElement!).getByText("PermitRootLogin prohibit-password (now yes)")).toBeInTheDocument();
    const changes = within(within(ssh).getByRole("heading", { name: "Apply would change" }).parentElement!).getAllByRole("listitem");
    expect(changes.map((li) => li.textContent)).toEqual(["PermitRootLogin prohibit-password", "The settings go in /etc/ssh/sshd_config.d/00-easyrmm-hardening.conf"]);

    // The firewall lists the ports it would leave open, what Docker publishes past it, and services whose ports are unknown.
    const firewall = moduleItem("Firewall");
    expect(within(firewall).getByText("Not in place")).toBeInTheDocument();
    expect(within(firewall).getByText("Ports the firewall would leave open")).toBeInTheDocument();
    expect(within(firewall).getByText("22, 443, 9000-9100")).toBeInTheDocument();
    expect(within(firewall).getByText("53")).toBeInTheDocument();
    expect(within(firewall).getByText("tcp/8080")).toBeInTheDocument();
    expect(within(firewall).getByText(/which the firewall does not filter/)).toBeInTheDocument();
    expect(within(firewall).getByText("minidlna.service")).toBeInTheDocument();
    expect(within(firewall).getByText(/would be cut off when they start/)).toBeInTheDocument();
    // Only the firewall has ports.
    expect(within(ssh).queryByText("Ports the firewall would leave open")).not.toBeInTheDocument();

    // A module the latest job did not cover shows the earlier job that did.
    const kernel = moduleItem("Kernel parameters");
    expect(within(kernel).getByText("In place")).toBeInTheDocument();
    expect(within(kernel).getByText(/From an earlier check/)).toBeInTheDocument();
    expect(within(kernel).getByRole("link", { name: "View the job" })).toHaveAttribute("href", "/jobs/j1");
    expect(within(ssh).queryByText(/From an earlier check/)).not.toBeInTheDocument();

    expect(within(moduleItem("sudo")).getByText("Not supported on this version")).toBeInTheDocument();
    expect(within(moduleItem("sudo")).getByText(/sudo-rs/)).toBeInTheDocument();
    expect(screen.getByText(/^Not checked yet: fail2ban, Audit rules, File permissions, Legacy services, Kernel modules, Time synchronisation, Shared memory/)).toBeInTheDocument();

    // When, by which job, and the platform with its support level explained.
    const last = screen.getByRole("heading", { name: "Last check" }).closest("section") as HTMLElement;
    expect(within(last).getByRole("link", { name: "Check hardening: ssh, firewall, sudo" })).toHaveAttribute("href", "/jobs/j2");
    expect(within(last).getByText("Ubuntu 26.10")).toBeInTheDocument();
    expect(within(last).getByText("Check only")).toBeInTheDocument();
    expect(within(last).getByText(/^Not supported on this version: the release is newer than those/)).toBeInTheDocument();
    expect(within(last).getByText("LXC container")).toBeInTheDocument();
    expect(within(last).getByText(/belong to the host/)).toBeInTheDocument();

    // The device's checks, with why one failed.
    const checks = screen.getByRole("heading", { name: "Checks" }).closest("section") as HTMLElement;
    expect(within(checks).getAllByRole("link", { name: /Check hardening: ssh, firewall, sudo/ }).map((a) => a.getAttribute("href"))).toEqual([
      "/jobs/j2/runs/r2",
      "/jobs/j1/runs/r1",
    ]);
    expect(within(checks).getByText("Succeeded")).toBeInTheDocument();
    expect(within(checks).getByText(/does not end with a result/)).toBeInTheDocument();
    expect(within(checks).getByRole("link", { name: "All hardening jobs" })).toHaveAttribute("href", "/jobs?kind=hardening&deviceId=d1");
  });

  it("runs a check with the recommended modules chosen, and reads the findings once it ends", async () => {
    const user = userEvent.setup();
    const state: { hardening: DeviceHardening; runs: JobRun[] } = { hardening: NONE, runs: [] };
    const server = installFakeApi(
      routes(TECHNICIAN, {
        "GET /devices/:id/hardening": () => ok(state.hardening),
        "GET /job-runs": () => ok({ items: state.runs }),
        "POST /jobs/hardening": () => {
          state.runs = [hardeningRun("r3", "j3", "queued")];
          return { status: 201, body: job("j3", "Check hardening (every module)", { kind: "hardening" }) };
        },
      }),
    );
    const { client } = renderApp("/devices/d1?tab=hardening");
    expect(await screen.findByText("Not checked yet")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run check…" }));

    const dialog = await screen.findByRole("dialog", { name: "Check hardening" });
    expect(within(dialog).getByText(/A check changes nothing/)).toBeInTheDocument();
    // Recommended modules are chosen; the others are not, each with its risk beside it.
    expect(within(dialog).getByRole("checkbox", { name: /^SSH/ })).toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: /^Time synchronisation/ })).toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: /^USB storage/ })).not.toBeChecked();
    expect(within(dialog).getByText("When applied: USB disks and backup drives stop working.")).toBeInTheDocument();
    expect(within(dialog).getByText("10 of 14 modules")).toBeInTheDocument();

    // None at all is refused before anything is sent.
    await user.click(within(dialog).getByRole("checkbox", { name: /^Recommended/ }));
    expect(within(dialog).getByText("0 of 14 modules")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Run check" }));
    expect(within(dialog).getByText("Choose at least one module.")).toBeInTheDocument();
    expect(server.callsTo("POST /jobs/hardening")).toHaveLength(0);

    await user.click(within(dialog).getByRole("checkbox", { name: /^Recommended/ }));
    await user.click(within(dialog).getByRole("checkbox", { name: /^SSH/ }));
    // Partly chosen, the group's box is neither ticked nor clear.
    expect(within(dialog).getByRole("checkbox", { name: /^Recommended/ })).toHaveProperty("indeterminate", true);
    await user.click(within(dialog).getByRole("checkbox", { name: /^SSH/ }));
    await user.click(within(dialog).getByRole("checkbox", { name: /^USB storage/ }));
    await user.selectOptions(within(dialog).getByLabelText("Wait for the device"), "4");
    await user.click(within(dialog).getByRole("button", { name: "Run check" }));

    await waitFor(() => expect(server.callsTo("POST /jobs/hardening")).toHaveLength(1));
    expect(server.call("POST /jobs/hardening").body).toEqual({ deviceIds: ["d1"], mode: "check", modules: [...RECOMMENDED, "usb-storage"], options: {}, waitHours: 4 });
    expect(await screen.findByText(/Checking hardening on DB-01/)).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Check hardening" })).not.toBeInTheDocument());
    // The tab stays, says the check is under way, and lists the run.
    expect(await screen.findByText("Checking hardening")).toBeInTheDocument();
    expect(within(screen.getByRole("heading", { name: "Checks" }).closest("section") as HTMLElement).getByText("Queued")).toBeInTheDocument();
    expect(location()).toBe("/devices/d1?tab=hardening");

    // The run ends; its findings were recorded with its result, and are read again.
    state.runs = [hardeningRun("r3", "j3", "succeeded")];
    state.hardening = { ...FOUND, jobId: "j3", modules: FOUND.modules.map((m) => ({ ...m, jobId: "j3", checkedAt: LATEST })) };
    const reads = server.callsTo("GET /devices/:id/hardening").length;
    await act(() => client.invalidateQueries({ queryKey: ["job-runs"] }));
    expect(await screen.findByText("1 of 3 in place")).toBeInTheDocument();
    expect(server.callsTo("GET /devices/:id/hardening").length).toBeGreaterThan(reads);
    expect(screen.queryByText(/From an earlier check/)).not.toBeInTheDocument();
  });

  it("shows the server's refusal in the dialog", async () => {
    const user = userEvent.setup();
    installFakeApi(
      routes(TECHNICIAN, {
        "GET /devices/:id/hardening": ok(NONE),
        "GET /job-runs": ok({ items: [] }),
        "POST /jobs/hardening": fail(422, "validation_failed", "The request is invalid.", {
          deviceIds: "You cannot check hardening on DB-01.",
          modules: 'There is no hardening module "ssh2".',
        }),
      }),
    );
    renderApp("/devices/d1?tab=hardening");
    await user.click(await screen.findByRole("button", { name: "Run check…" }));
    const dialog = await screen.findByRole("dialog", { name: "Check hardening" });
    await user.click(within(dialog).getByRole("button", { name: "Run check" }));
    expect(await within(dialog).findByText("You cannot check hardening on DB-01.")).toBeInTheDocument();
    expect(within(dialog).getByText('There is no hardening module "ssh2".')).toBeInTheDocument();
  });

  it("shows the findings to those who may only view, with no way to check", async () => {
    installFakeApi(routes(READ_ONLY, { "GET /devices/:id": ok({ ...SERVER, canRunScripts: false, canCheckHardening: false }) }));
    renderApp("/devices/d1?tab=hardening");
    expect(await screen.findByText("1 of 3 in place")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run check…" })).not.toBeInTheDocument();
  });

  it("says who can check a device never checked, and lists no checks to those who cannot see jobs", async () => {
    const session = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });
    const server = installFakeApi(routes(session, { "GET /devices/:id": ok({ ...SERVER, canRunScripts: false, canCheckHardening: false }), "GET /devices/:id/hardening": ok(NONE) }));
    renderApp("/devices/d1?tab=hardening");
    expect(await screen.findByText("Not checked yet")).toBeInTheDocument();
    expect(screen.getByText(/Someone who runs scripts on this device can start one/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run check…" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Checks" })).not.toBeInTheDocument();
    expect(server.callsTo("GET /job-runs")).toHaveLength(0);
  });

  it("names the job only to those who can see jobs", async () => {
    const session = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });
    installFakeApi(routes(session));
    renderApp("/devices/d1?tab=hardening");
    const last = (await screen.findByRole("heading", { name: "Last check" })).closest("section") as HTMLElement;
    expect(within(last).getByText("Not visible to your role")).toBeInTheDocument();
    expect(within(last).queryByRole("link")).not.toBeInTheDocument();
    expect(within(moduleItem("Kernel parameters")).queryByRole("link")).not.toBeInTheDocument();
  });

  it("has a Hardening tab only on Linux devices with the agent", async () => {
    installFakeApi(routes(TECHNICIAN, { "GET /devices/:id": ok({ ...SERVER, platform: "windows", osDescription: "Windows Server 2025" }) }));
    const { unmount } = renderApp("/devices/d1?tab=hardening");
    expect(await screen.findByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByRole("tab", { name: "Hardening" })).not.toBeInTheDocument();
    unmount();
  });
});

describe("hardening across the fleet", () => {
  const LINUX = { platform: "linux" as const, osDescription: "Debian GNU/Linux 13 (trixie)", agent: AGENT };
  const DEVICES = [
    device("d1", "DB-01", { ...LINUX, hardening: { checkedAt: LATEST, states: { in_place: 9, partly: 1, not_applicable: 2 } } }),
    device("d2", "WEB-01", { ...LINUX, hardening: { checkedAt: LATEST, states: { in_place: 10 } } }),
    device("d3", "VPN-01", { ...LINUX, hardening: { checkedAt: EARLIER, states: { in_place: 7, half_applied: 1 } } }),
    device("d4", "BUILD-01", LINUX),
    device("d5", "FRONT-DESK", { agent: AGENT }),
  ];
  const lists = {
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
  };

  it("shows each Linux device's hardening and filters by it on the server", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      ...lists,
      "GET /devices": (r) => {
        const f = r.query.get("hardening");
        const items = DEVICES.filter((d) => !f || (f === "attention" ? ["d1", "d3"] : f === "in_place" ? ["d2"] : ["d4"]).includes(d.id));
        return ok({ items });
      },
    });
    renderApp("/devices");
    await screen.findByRole("link", { name: "DB-01" });
    expect(screen.getByRole("columnheader", { name: "Hardening" })).toBeInTheDocument();
    const cell = (name: string) => within(screen.getByRole("row", { name: new RegExp(name) })).getAllByRole("cell").at(-1) as HTMLElement;
    expect(within(cell("DB-01")).getByText("9 of 10 in place")).toHaveAttribute("title", "9 in place, 1 partly in place, 2 not applicable");
    expect(within(cell("WEB-01")).getByText("10 of 10 in place")).toBeInTheDocument();
    expect(within(cell("VPN-01")).getByText("Half applied")).toBeInTheDocument();
    expect(cell("BUILD-01")).toHaveTextContent("Not checked");
    expect(cell("FRONT-DESK")).toHaveTextContent("—");

    await user.selectOptions(screen.getByLabelText("Hardening"), "attention");
    await waitFor(() => expect(screen.queryByRole("link", { name: "WEB-01" })).not.toBeInTheDocument());
    expect(screen.getByRole("link", { name: "VPN-01" })).toBeInTheDocument();
    expect(server.callsTo("GET /devices").at(-1)?.query.get("hardening")).toBe("attention");
    expect(location()).toBe("/devices?hardening=attention");

    await user.selectOptions(screen.getByLabelText("Hardening"), "unchecked");
    await waitFor(() => expect(screen.queryByRole("link", { name: "DB-01" })).not.toBeInTheDocument());
    expect(screen.getByRole("link", { name: "BUILD-01" })).toBeInTheDocument();
  });

  it("has no hardening column when the list has no Linux device", async () => {
    installFakeApi({ ...baseRoutes(TECHNICIAN), ...lists, "GET /devices": ok({ items: [device("d5", "FRONT-DESK", { agent: AGENT })] }) });
    renderApp("/devices");
    await screen.findByRole("link", { name: "FRONT-DESK" });
    expect(screen.queryByRole("columnheader", { name: "Hardening" })).not.toBeInTheDocument();
    // The filter stays: it narrows the list to Linux devices.
    expect(screen.getByLabelText("Hardening")).toBeInTheDocument();
  });
});
