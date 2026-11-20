import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { baseRoutes, unreportedRoutes, fail, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { counts, device, job, jobRun, script } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const location = () => screen.getByTestId("location").textContent;

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null };

const TECHNICIAN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "script.view", "script.run", "job.view", "job.manage"],
});

const RUNNING_JOB = job("j1", "Disk usage", {
  args: ["-h", "two words"],
  counts: counts({ succeeded: 1, failed: 1, running: 1 }),
  total: 3,
  finished: false,
  body: "df \"$@\"\n",
  runs: [
    jobRun("r1", "d1", "PRINT-01", "succeeded"),
    jobRun("r2", "d2", "PRINT-02", "failed"),
    jobRun("r3", "d3", "PRINT-03", "running", { cancelRequested: true, canCancel: false }),
  ],
});

describe("jobs", () => {
  it("lists jobs with their progress and filters by status", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /jobs": (r) =>
        ok({
          items: [RUNNING_JOB, job("j2", "Restart print spooler", { counts: counts({ succeeded: 2 }), total: 2 })].filter(
            (j) => r.query.get("status") !== "open" || !j.finished,
          ),
        }),
    });
    renderApp("/jobs");
    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row");
    expect(within(rows[1]!).getByRole("link", { name: "Disk usage" })).toHaveAttribute("href", "/jobs/j1");
    expect(within(rows[1]!).getByText("Running")).toBeInTheDocument();
    expect(within(rows[1]!).getByText("failed")).toBeInTheDocument();
    expect(within(rows[2]!).getByText("Succeeded")).toBeInTheDocument();
    expect(screen.getByText("2 jobs")).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Status"), "Running or waiting");
    await waitFor(() => expect(screen.getByText("1 job")).toBeInTheDocument());
    expect(server.callsTo("GET /jobs").at(-1)?.query.get("status")).toBe("open");
    expect(location()).toBe("/jobs?status=open");
  });

  it("says when there are no jobs", async () => {
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /jobs": ok({ items: [] }) });
    renderApp("/jobs");
    expect(await screen.findByText(/No jobs yet/)).toBeInTheDocument();
  });

  it("shows a job's devices, arguments and script, and stops it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /jobs/:id": ok(RUNNING_JOB),
      "GET /scripts/:id": fail(404, "not_found", "Not found."),
      "POST /jobs/:id/cancel": ok({ ...RUNNING_JOB }),
    });
    renderApp("/jobs/j1");
    expect(await screen.findByRole("heading", { name: "Disk usage" })).toBeInTheDocument();
    const devices = screen.getByRole("table");
    expect(within(devices).getByRole("link", { name: "PRINT-01" })).toHaveAttribute("href", "/jobs/j1/runs/r1");
    expect(within(devices).getByText("Canceling")).toBeInTheDocument();
    expect(within(devices).getAllByText("1 min 5 s")).toHaveLength(2);
    expect(screen.getByText("two words")).toBeInTheDocument();
    expect(screen.getByLabelText("Script as run")).toHaveTextContent('df "$@"');
    // The script is gone from the library (or out of reach): no "Run again".
    await waitFor(() => expect(server.callsTo("GET /scripts/:id")).toHaveLength(1));
    expect(screen.queryByRole("button", { name: "Run again" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Stop job" }));
    const dialog = await screen.findByRole("dialog", { name: "Stop this job?" });
    await user.click(within(dialog).getByRole("button", { name: "Stop job" }));
    await waitFor(() => expect(server.callsTo("POST /jobs/:id/cancel")).toHaveLength(1));
    expect(await screen.findByText(/Stopping the job/)).toBeInTheDocument();
  });

  it("runs a job again with the same devices and arguments", async () => {
    const user = userEvent.setup();
    const linux = { platform: "linux" as const, agent: AGENT, canRunScripts: true };
    const done = { ...RUNNING_JOB, finished: true, counts: counts({ succeeded: 2, failed: 1 }), runs: RUNNING_JOB.runs?.map((r) => ({ ...r, status: "succeeded" as const })) };
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /jobs/:id": ok(done),
      "GET /scripts/:id": ok(script("sc1", "Disk usage", { body: "df\n", sha256: "b".repeat(64), canEdit: false })),
      "GET /devices": ok({ items: [device("d1", "PRINT-01", linux), device("d2", "PRINT-02", linux), device("d3", "PRINT-03", linux)] }),
      "POST /jobs": { status: 201, body: job("j2", "Disk usage") },
    });
    renderApp("/jobs/j1");
    expect(await screen.findByText("Some failed")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Stop job" })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Run again" }));
    const dialog = await screen.findByRole("dialog", { name: "Run Disk usage" });
    expect(within(dialog).getByText("The script has changed since that job")).toBeInTheDocument();
    expect(await within(dialog).findByText("3 devices selected")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Arguments")).toHaveValue("-h\ntwo words");
    await user.click(within(dialog).getByRole("button", { name: "Run on 3 devices" }));
    await waitFor(() => expect(location()).toBe("/jobs/j2"));
    expect(server.call("POST /jobs").body).toEqual({ scriptId: "sc1", deviceIds: ["d1", "d2", "d3"], args: ["-h", "two words"], timeoutSeconds: 300, waitHours: 24 });
  });

  it("shows a run's output and why it failed", async () => {
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /job-runs/:id": ok(
        jobRun("r2", "d2", "PRINT-02", "failed", {
          stdout: "Filesystem  Size\n/dev/sda1   20G\n",
          stderr: "",
          stdoutTruncated: true,
          error: "The script exited with code 2.",
          deliveries: 2,
          job: job("j1", "Disk usage"),
        }),
      ),
    });
    renderApp("/jobs/j1/runs/r2");
    expect(await screen.findByRole("heading", { name: "PRINT-02" })).toBeInTheDocument();
    expect(screen.getByText("The script exited with code 2.")).toBeInTheDocument();
    // Output keeps its spacing and line breaks.
    expect(screen.getByText(/\/dev\/sda1/).textContent).toBe("Filesystem  Size\n/dev/sda1   20G\n");
    expect(screen.getByText(/its middle was left out/)).toBeInTheDocument();
    expect(screen.getByText("Nothing was written to standard error.")).toBeInTheDocument();
    expect(screen.getByText(/\(2 times\)/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "PRINT-02" })).toHaveAttribute("href", "/devices/d2");
    expect(screen.getByRole("link", { name: "Disk usage" })).toHaveAttribute("href", "/jobs/j1");
    expect(screen.queryByRole("button", { name: "Stop run" })).not.toBeInTheDocument();
  });

  it("says what a waiting run is waiting for, and stops it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /job-runs/:id": ok(jobRun("r4", "d4", "PRINT-04", "queued", { job: job("j1", "Disk usage") })),
      "POST /job-runs/:id/cancel": ok(jobRun("r4", "d4", "PRINT-04", "canceled")),
    });
    renderApp("/jobs/j1/runs/r4");
    expect(await screen.findByText(/Waiting for PRINT-04 to pick it up/)).toBeInTheDocument();
    expect(screen.getByText("The device sends the script’s output when it ends.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Stop run" }));
    const dialog = await screen.findByRole("dialog", { name: "Stop the run on PRINT-04?" });
    expect(within(dialog).getByText(/canceled at once and never runs/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Stop run" }));
    expect(await screen.findByText("Canceled before it started.")).toBeInTheDocument();
    expect(server.callsTo("POST /job-runs/:id/cancel")).toHaveLength(1);
  });
});

describe("scripts on the device page", () => {
  const linux = device("d1", "PRINT-01", { platform: "linux", osDescription: "Debian GNU/Linux 13", agent: AGENT, canRunScripts: true });

  it("lists the device's runs and runs a script on it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      ...unreportedRoutes(),
      "GET /devices/:id": ok(linux),
      "GET /job-runs": ok({ items: [jobRun("r1", "d1", "PRINT-01", "failed"), jobRun("r2", "d1", "PRINT-01", "running", { scriptName: "Update packages" })] }),
      "GET /scripts": ok({ items: [script("sc1", "Disk usage", { description: "Free space.", timeoutSeconds: 120 }), script("sc2", "Hidden", { canRun: false })] }),
      "POST /jobs": { status: 201, body: job("j5", "Disk usage") },
      "GET /jobs/:id": ok(job("j5", "Disk usage", { runs: [] })),
      "GET /scripts/:id": ok(script("sc1", "Disk usage")),
    });
    renderApp("/devices/d1");
    const card = (await screen.findByRole("heading", { name: "Scripts" })).closest("section") as HTMLElement;
    expect(await within(card).findByRole("link", { name: /Update packages/ })).toHaveAttribute("href", "/jobs/j1/runs/r2");
    expect(within(card).getByText(/exit code 2/)).toBeInTheDocument();
    expect(server.call("GET /job-runs").query.get("deviceId")).toBe("d1");

    await user.click(screen.getByRole("button", { name: "Run script" }));
    const dialog = await screen.findByRole("dialog", { name: "Run a script" });
    expect(within(dialog).getByText("On PRINT-01.")).toBeInTheDocument();
    const select = await within(dialog).findByLabelText(/^Script/);
    expect(within(select).getAllByRole("option").map((o) => o.textContent)).toEqual(["Choose…", "Disk usage"]);
    expect(server.call("GET /scripts").query.get("deviceId")).toBe("d1");
    await user.click(within(dialog).getByRole("button", { name: "Run" }));
    await user.selectOptions(select, "Disk usage");
    expect(within(dialog).getByText(/Free space\. Bash, stops after 2 minutes\./)).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Timeout")).toHaveValue(2);
    await user.click(within(dialog).getByRole("button", { name: "Run" }));
    await waitFor(() => expect(location()).toBe("/jobs/j5"));
    expect(server.call("POST /jobs").body).toEqual({ scriptId: "sc1", deviceIds: ["d1"], args: [], timeoutSeconds: 120, waitHours: 24 });
  });

  it("warns before running a script that installs system updates where EasyPatch patches", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: [...TECHNICIAN.permissions, "patch.view"] })),
      ...unreportedRoutes(),
      "GET /devices/:id": ok(linux),
      "GET /job-runs": ok({ items: [] }),
      "GET /patching": ok({ configured: true }),
      "GET /scripts": ok({ items: [script("sc1", "Disk usage"), script("sc3", "Patch everything")] }),
      "GET /scripts/:id": (r) => ok(r.params.id === "sc3" ? script("sc3", "Patch everything", { body: "apt-get update\napt-get -y upgrade\n" }) : script("sc1", "Disk usage", { body: "df -h\n" })),
    });
    renderApp("/devices/d1");
    await user.click(await screen.findByRole("button", { name: "Run script" }));
    const dialog = await screen.findByRole("dialog", { name: "Run a script" });
    const select = await within(dialog).findByLabelText(/^Script/);
    await user.selectOptions(select, "Disk usage");
    await waitFor(() => expect(server.callsTo("GET /scripts/:id")).toHaveLength(1));
    expect(within(dialog).queryByText("This script installs system updates itself")).not.toBeInTheDocument();
    // The list leaves bodies out; the warning reads the chosen script.
    await user.selectOptions(select, "Patch everything");
    expect(await within(dialog).findByText("This script installs system updates itself")).toBeInTheDocument();
    expect(within(dialog).getByText(/Line 2 upgrades every package/)).toBeInTheDocument();
  });

  it("explains why a device cannot run scripts, and hides scripts from roles without them", async () => {
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      ...unreportedRoutes(),
      "GET /devices/:id": ok({ ...linux, platform: "macos" }),
      "GET /job-runs": ok({ items: [] }),
    });
    const { unmount } = renderApp("/devices/d1");
    expect(await screen.findByText("No scripts have run here")).toBeInTheDocument();
    const run = screen.getByRole("button", { name: "Run script" });
    expect(run).toBeDisabled();
    expect(run).toHaveAttribute("title", "Scripts run on Windows and Linux devices.");
    unmount();

    installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["device.view"] })),
      ...unreportedRoutes(),
      "GET /devices/:id": ok({ ...linux, canRunScripts: false }),
    });
    renderApp("/devices/d1");
    expect(await screen.findByRole("heading", { name: "PRINT-01" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run script" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Scripts" })).not.toBeInTheDocument();
  });
});
