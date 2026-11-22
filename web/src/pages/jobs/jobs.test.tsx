import { describe, expect, it } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { focusManager } from "@tanstack/react-query";
import { baseRoutes, unreportedRoutes, fail, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { auditEntry, counts, device, job, jobRun, script } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const location = () => screen.getByTestId("location").textContent;

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null };

const TECHNICIAN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "script.view", "script.run", "job.view", "job.manage", "job.view_sensitive"],
});

/** Read-Only sees jobs and runs, but not what they printed or the arguments they were given (ADR-0063). */
const READ_ONLY = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "script.view", "job.view"] });

/** A secret a script was given and printed; it must never reach a caller without job.view_sensitive. */
const MARKER = "marker-5e1f";

const RUNNING_JOB = job("j1", "Disk usage", {
  argCount: 2,
  canViewArguments: true,
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
      "GET /jobs/:id/arguments": ok({ args: ["-h", "two words"] }),
      "GET /scripts/:id": fail(404, "not_found", "Not found."),
      "POST /jobs/:id/cancel": ok({ ...RUNNING_JOB }),
    });
    renderApp("/jobs/j1");
    expect(await screen.findByRole("heading", { name: "Disk usage" })).toBeInTheDocument();
    const devices = screen.getByRole("table");
    expect(within(devices).getByRole("link", { name: "PRINT-01" })).toHaveAttribute("href", "/jobs/j1/runs/r1");
    expect(within(devices).getByText("Canceling")).toBeInTheDocument();
    expect(within(devices).getAllByText("1 min 5 s")).toHaveLength(2);
    expect(await screen.findByText("two words")).toBeInTheDocument();
    expect(screen.getByLabelText("Script as run")).toHaveTextContent('df "$@"');
    // The script is gone from the library (or out of reach): no "Run again".
    await waitFor(() => expect(server.callsTo("GET /scripts/:id")).toHaveLength(1));
    expect(screen.queryByRole("button", { name: "Run again" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Stop job" }));
    const dialog = await screen.findByRole("dialog", { name: "Stop this job?" });
    await user.click(within(dialog).getByRole("button", { name: "Stop job" }));
    await waitFor(() => expect(server.callsTo("POST /jobs/:id/cancel")).toHaveLength(1));
    expect(await screen.findByText(/Stopping the job/)).toBeInTheDocument();
    // Each read is audited: refreshing the job does not read the arguments again.
    await waitFor(() => expect(server.callsTo("GET /jobs/:id").length).toBeGreaterThan(1));
    expect(server.callsTo("GET /jobs/:id/arguments")).toHaveLength(1);
  });

  it("hides a job's arguments and output from Read-Only, and never asks for them", async () => {
    const user = userEvent.setup();
    const done = { ...RUNNING_JOB, finished: true, canCancel: false, canViewArguments: false, runs: [jobRun("r1", "d1", "PRINT-01", "succeeded")] };
    const run = jobRun("r1", "d1", "PRINT-01", "succeeded", { canViewOutput: false, canCancel: false, job: done });
    const server = installFakeApi({
      ...baseRoutes(READ_ONLY),
      "GET /jobs/:id": ok(done),
      "GET /job-runs/:id": ok(run),
    });
    renderApp("/jobs/j1");
    expect(await screen.findByText(/2 arguments\. Hidden: needs permission to see job arguments/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run again" })).not.toBeInTheDocument();
    // Hovering a run reads the run, not its output.
    await user.hover(screen.getByRole("link", { name: "PRINT-01" }));
    await waitFor(() => expect(server.callsTo("GET /job-runs/:id")).toHaveLength(1));
    await user.click(screen.getByRole("link", { name: "PRINT-01" }));
    expect(await screen.findByText(/Hidden: needs permission to see job output/)).toBeInTheDocument();
    expect(screen.getByText("job.view_sensitive")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove output" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain(MARKER);
    expect(server.calls.filter((c) => c.path.endsWith("/output") || c.path.endsWith("/arguments"))).toEqual([]);
  });

  it("does not run a job again without the arguments it had", async () => {
    const done = { ...RUNNING_JOB, finished: true, canCancel: false, canViewArguments: false, runs: [jobRun("r1", "d1", "PRINT-01", "succeeded")] };
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /jobs/:id": ok(done),
      "GET /scripts/:id": ok(script("sc1", "Disk usage")),
    });
    renderApp("/jobs/j1");
    expect(await screen.findByText(/2 arguments\. Hidden/)).toBeInTheDocument();
    await waitFor(() => expect(server.callsTo("GET /scripts/:id")).toHaveLength(1));
    // The script may be run, but running it without its arguments would run something else.
    expect(screen.queryByRole("button", { name: "Run again" })).not.toBeInTheDocument();
    expect(server.callsTo("GET /jobs/:id/arguments")).toEqual([]);
  });

  it("shows what a hardening check asked for, with no Run again yet", async () => {
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /jobs/:id": ok(
        job("j7", "Check hardening: ssh, firewall", {
          kind: "hardening",
          scriptId: null,
          shell: "sh",
          argCount: 3,
          canViewArguments: true,
          hardening: { mode: "check", modules: ["ssh", "firewall"], options: { allowTcp: ["8443", "9000-9100"], passwordOff: true } },
          body: "#!/bin/sh\n",
          runs: [jobRun("r1", "d1", "SRV-01", "succeeded")],
        }),
      ),
    });
    renderApp("/jobs/j7");
    expect(await screen.findByRole("heading", { name: "Check hardening: ssh, firewall" })).toBeInTheDocument();
    expect(screen.getByText(/own hardening script/)).toBeInTheDocument();
    expect(screen.getByText("Check")).toBeInTheDocument();
    expect(screen.getByText("ssh")).toBeInTheDocument();
    expect(screen.getByText("firewall")).toBeInTheDocument();
    expect(screen.getByText("8443, 9000-9100")).toBeInTheDocument();
    expect(screen.getByText("Password sign-in to SSH off")).toBeInTheDocument();
    // Not a library script, and not offered again until the console has its dialog.
    expect(screen.queryByText(/deleted from the library/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Run again" })).not.toBeInTheDocument();
  });

  it("runs a job again with the same devices and arguments", async () => {
    const user = userEvent.setup();
    const linux = { platform: "linux" as const, agent: AGENT, canRunScripts: true };
    const done = { ...RUNNING_JOB, finished: true, counts: counts({ succeeded: 2, failed: 1 }), runs: RUNNING_JOB.runs?.map((r) => ({ ...r, status: "succeeded" as const })) };
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /jobs/:id": ok(done),
      "GET /jobs/:id/arguments": ok({ args: ["-h", "two words"] }),
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
    // The details and Run again share the one audited read.
    expect(server.callsTo("GET /jobs/:id/arguments")).toHaveLength(1);
  });

  it("shows a run's output and why it failed, reading the output once", async () => {
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /job-runs/:id": ok(
        jobRun("r2", "d2", "PRINT-02", "failed", {
          canViewOutput: true,
          stdoutBytes: 31,
          stderrBytes: 0,
          outputRemovedAt: null,
          error: "The script exited with code 2.",
          deliveries: 2,
          job: job("j1", "Disk usage"),
        }),
      ),
      "GET /job-runs/:id/output": ok({ stdout: "Filesystem  Size\n/dev/sda1   20G\n", stderr: "", stdoutTruncated: true, stderrTruncated: false }),
    });
    renderApp("/jobs/j1/runs/r2");
    expect(await screen.findByRole("heading", { name: "PRINT-02" })).toBeInTheDocument();
    expect(screen.getByText("The script exited with code 2.")).toBeInTheDocument();
    // Output keeps its spacing and line breaks.
    expect((await screen.findByText(/\/dev\/sda1/)).textContent).toBe("Filesystem  Size\n/dev/sda1   20G\n");
    expect(screen.getByText("Opening or downloading a run’s output is recorded in the audit log, each time.")).toBeInTheDocument();
    expect(screen.getByText(/its middle was left out/)).toBeInTheDocument();
    expect(screen.getByText("Nothing was written to standard error.")).toBeInTheDocument();
    expect(screen.getByText(/\(2 times\)/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "PRINT-02" })).toHaveAttribute("href", "/devices/d2");
    expect(screen.getByRole("link", { name: "Disk usage" })).toHaveAttribute("href", "/jobs/j1");
    expect(screen.queryByRole("button", { name: "Stop run" })).not.toBeInTheDocument();
    // Coming back to the window reads the run again, but not its output: each read is audited.
    act(() => {
      focusManager.setFocused(false);
      focusManager.setFocused(true);
    });
    await waitFor(() => expect(server.callsTo("GET /job-runs/:id")).toHaveLength(2));
    expect(server.callsTo("GET /job-runs/:id/output")).toHaveLength(1);
    act(() => focusManager.setFocused(undefined));
  });

  it("offers each stream and the run as files, through the audited downloads", async () => {
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /job-runs/:id": ok(
        jobRun("r2", "d2", "PRINT-02", "failed", { canViewOutput: true, stdoutBytes: 9, stderrBytes: 0, outputRemovedAt: null, job: job("j1", "Disk usage") }),
      ),
      "GET /job-runs/:id/output": ok({ stdout: `${MARKER}\n`, stderr: "", stdoutTruncated: false, stderrTruncated: false }),
    });
    renderApp("/jobs/j1/runs/r2");
    expect(await screen.findByText(MARKER)).toBeInTheDocument();
    // Beside Copy on a stream that has something; the empty stream offers neither.
    expect(screen.getByRole("link", { name: "Download standard output" })).toHaveAttribute("href", "/api/v1/job-runs/r2/output?download=stdout");
    expect(screen.queryByRole("link", { name: "Download standard error" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download run" })).toHaveAttribute("href", "/api/v1/job-runs/r2/output?download=json");
    for (const name of ["Download standard output", "Download run"]) expect(screen.getByRole("link", { name })).toHaveAttribute("download");
    // The links are the downloads: the page itself read the output once.
    expect(server.callsTo("GET /job-runs/:id/output")).toHaveLength(1);
  });

  it("offers a run that printed nothing as a file, and no download where it cannot work", async () => {
    const quiet = jobRun("r1", "d1", "PRINT-01", "succeeded", { canViewOutput: true, stdoutBytes: 0, stderrBytes: 0, outputRemovedAt: null, job: job("j1", "Disk usage") });
    const runs: Record<string, ReturnType<typeof jobRun>> = {
      r1: quiet,
      r2: { ...quiet, id: "r2", outputRemovedAt: "2026-11-01T10:05:00Z" },
      r3: { ...quiet, id: "r3", canViewOutput: false },
      r4: jobRun("r4", "d1", "PRINT-01", "running", { canViewOutput: true, job: job("j1", "Disk usage") }),
    };
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /job-runs/:id": (r) => ok(runs[r.params.id!]) });
    const { unmount } = renderApp("/jobs/j1/runs/r1");
    expect(await screen.findByText("Nothing was written to standard output.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download run" })).toHaveAttribute("href", "/api/v1/job-runs/r1/output?download=json");
    expect(screen.queryByRole("link", { name: /Download standard/ })).not.toBeInTheDocument();
    unmount();
    for (const [id, says] of [
      ["r2", /The output was removed/],
      ["r3", /Hidden: needs permission to see job output/],
      ["r4", /sends the script’s output when it ends/],
    ] as const) {
      const view = renderApp(`/jobs/j1/runs/${id}`);
      expect(await screen.findByText(says)).toBeInTheDocument();
      expect(screen.queryByRole("link", { name: /^Download/ })).not.toBeInTheDocument();
      view.unmount();
    }
  });

  it("offers a job's results to everyone who sees it, and its output only where it can be read", async () => {
    const done = { ...RUNNING_JOB, finished: true, canCancel: false, canViewArguments: false, runs: [jobRun("r1", "d1", "PRINT-01", "succeeded")] };
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /jobs/:id": (r) => ok({ ...done, id: r.params.id!, canDownloadOutput: r.params.id === "j1" }),
      "GET /scripts/:id": fail(404, "not_found", "Not found."),
    });
    const { unmount } = renderApp("/jobs/j1");
    expect(await screen.findByRole("link", { name: "Download output (ZIP)" })).toHaveAttribute("href", "/api/v1/jobs/j1/output.zip");
    expect(screen.getByRole("link", { name: "Download results (CSV)" })).toHaveAttribute("href", "/api/v1/jobs/j1/runs.csv");
    unmount();
    renderApp("/jobs/j9");
    expect(await screen.findByRole("link", { name: "Download results (CSV)" })).toHaveAttribute("href", "/api/v1/jobs/j9/runs.csv");
    expect(screen.queryByRole("link", { name: "Download output (ZIP)" })).not.toBeInTheDocument();
  });

  it("says when a run printed nothing, without reading its output", async () => {
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /job-runs/:id": ok(jobRun("r1", "d1", "PRINT-01", "succeeded", { canViewOutput: true, stdoutBytes: 0, stderrBytes: 0, outputRemovedAt: null, job: job("j1", "Disk usage") })),
    });
    renderApp("/jobs/j1/runs/r1");
    expect(await screen.findByText("Nothing was written to standard output.")).toBeInTheDocument();
    expect(screen.getByText("Nothing was written to standard error.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove output" })).not.toBeInTheDocument();
    expect(server.callsTo("GET /job-runs/:id/output")).toEqual([]);
  });

  it("removes a run's output for everyone", async () => {
    const user = userEvent.setup();
    let removedAt: string | null = null;
    const run = () =>
      jobRun("r2", "d2", "PRINT-02", "succeeded", {
        canViewOutput: true,
        canRemoveOutput: true,
        stdoutBytes: removedAt ? 0 : 18,
        stderrBytes: 0,
        outputRemovedAt: removedAt,
        job: job("j1", "Disk usage"),
      });
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /job-runs/:id": () => ok(run()),
      "GET /job-runs/:id/output": ok({ stdout: `password=${MARKER}\n`, stderr: "", stdoutTruncated: false, stderrTruncated: false }),
      "DELETE /job-runs/:id/output": () => {
        removedAt = "2026-11-01T10:05:00Z";
        return ok(run());
      },
    });
    renderApp("/jobs/j1/runs/r2");
    expect(await screen.findByText(new RegExp(MARKER))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Remove output" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove this run's output?" });
    expect(within(dialog).getByText(/emptied for everyone.*Backups made before keep it/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Remove output" }));
    expect(await screen.findByText("The run's output was removed.")).toBeInTheDocument();
    expect(screen.getByText(/The output was removed .*by retention or by someone who could read it/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(MARKER);
    expect(screen.queryByRole("button", { name: "Remove output" })).not.toBeInTheDocument();
    expect(server.callsTo("DELETE /job-runs/:id/output")).toHaveLength(1);
    expect(server.callsTo("GET /job-runs/:id/output")).toHaveLength(1);
  });

  it("offers removal only when the run says the caller may remove its output", async () => {
    // The session holds job.manage somewhere; the run says whether it holds it at this run's site.
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /job-runs/:id": ok(
        jobRun("r2", "d2", "PRINT-02", "succeeded", { canViewOutput: true, canRemoveOutput: false, stdoutBytes: 3, stderrBytes: 0, outputRemovedAt: null, canCancel: false, job: job("j1", "Disk usage") }),
      ),
      "GET /job-runs/:id/output": ok({ stdout: "ok\n", stderr: "", stdoutTruncated: false, stderrTruncated: false }),
    });
    renderApp("/jobs/j1/runs/r2");
    expect(await screen.findByText("ok")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove output" })).not.toBeInTheDocument();
  });

  it("names reads and removals of output in the audit log", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /organizations": ok({ items: [] }),
      "GET /audit": ok({
        items: [
          auditEntry(5, "job.results_export", { targetType: "job", targetId: "j1", details: { script: "Backup check", rows: 3 } }),
          auditEntry(4, "job_run.output_view", { targetType: "job_run", targetId: "r3", details: { device: "PRINT-03", script: "Disk usage", download: "zip" } }),
          auditEntry(3, "job_run.output_remove", { targetType: "job_run", targetId: "r2", details: { device: "PRINT-02", script: "Disk usage" } }),
          auditEntry(2, "job.arguments_view", { targetType: "job", targetId: "j1", details: { script: "Disk usage", argCount: 2 } }),
          auditEntry(1, "job_run.output_view", { targetType: "job_run", targetId: "r2", outcome: "denied", details: { device: "PRINT-02", script: "Disk usage" } }),
        ],
      }),
    });
    renderApp("/settings?tab=audit");
    expect(await screen.findByText("Removed job output")).toBeInTheDocument();
    expect(screen.getByText("Viewed job arguments")).toBeInTheDocument();
    expect(screen.getByText("Viewed job output")).toBeInTheDocument();
    expect(screen.getByText("Downloaded job output")).toBeInTheDocument();
    expect(screen.getByText("Disk usage on PRINT-03")).toBeInTheDocument();
    expect(screen.getByText("Downloaded job results")).toBeInTheDocument();
    expect(screen.getByText("Backup check")).toBeInTheDocument();
    expect(screen.getAllByText("Disk usage on PRINT-02")).toHaveLength(2);
    expect(screen.getByText("Disk usage")).toBeInTheDocument();
    // job_run is an area of its own: the server matches action prefixes at the dot.
    await user.selectOptions(screen.getByLabelText("Area"), "Job output");
    await waitFor(() => expect(server.callsTo("GET /audit").at(-1)?.query.get("action")).toBe("job_run"));
  });

  it("says what a waiting run is waiting for, and stops it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /job-runs/:id": ok(jobRun("r4", "d4", "PRINT-04", "queued", { canViewOutput: true, stdoutBytes: 0, stderrBytes: 0, outputRemovedAt: null, job: job("j1", "Disk usage") })),
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
    // A run that has not ended has no output to read.
    expect(server.callsTo("GET /job-runs/:id/output")).toEqual([]);
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
