import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { leaveFor } from "../../lib/leave";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { renderApp } from "../../test/render";
import { canRetry, easyPatchHref } from "./patchText";

vi.mock("../../lib/leave", () => ({ leaveFor: vi.fn() }));

describe("links into EasyPatch", () => {
  it("go through EasyRMM's redirect, naming one object", () => {
    expect(easyPatchHref({ device: "d1", tab: "policy" })).toBe("/go/to-easypatch?device=d1&tab=policy");
    expect(easyPatchHref({ device: "d1" })).toBe("/go/to-easypatch?device=d1");
    expect(easyPatchHref({ organization: "o1" })).toBe("/go/to-easypatch?organization=o1");
    expect(easyPatchHref({ job: "j1" })).toBe("/go/to-easypatch?job=j1");
    expect(easyPatchHref({ update: "a b&c" })).toBe("/go/to-easypatch?update=a+b%26c");
    expect(easyPatchHref({})).toBe("/go/to-easypatch");
    // A tab belongs to a device; with anything else it is dropped, and the device wins over the rest.
    expect(easyPatchHref({ job: "j1", tab: "jobs" })).toBe("/go/to-easypatch?job=j1");
    expect(easyPatchHref({ device: "d1", job: "j1" })).toBe("/go/to-easypatch?device=d1");
  });

  it("are handed back to the server when a sign-in interrupted them", async () => {
    installFakeApi(baseRoutes(sessionView()));
    renderApp("/go/to-easypatch?device=d1&tab=jobs");
    await waitFor(() => expect(leaveFor).toHaveBeenCalledWith("/go/to-easypatch?device=d1&tab=jobs"));
    expect(screen.getByText("Loading EasyRMM…")).toBeInTheDocument();
  });
});

describe("links from EasyPatch", () => {
  it("open the page the server resolves the EasyPatch id to", async () => {
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /patching/from-easypatch/:kind/:id": ok({ path: "/devices/d1?tab=patches" }),
      // The device page itself is not under test.
      "GET /devices/:id": fail(404, "not_found", "Not found."),
    });
    renderApp("/go/from-easypatch/endpoints/0b6f3c1e-1111-4222-8333-444455556666");
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/devices/d1?tab=patches"));
    expect(server.call("GET /patching/from-easypatch/:kind/:id").params).toEqual({ kind: "endpoints", id: "0b6f3c1e-1111-4222-8333-444455556666" });
  });

  it("open Patching with the server's notice when nothing matches", async () => {
    installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /patching/from-easypatch/:kind/:id": ok({
        path: "/patching",
        notice: "That EasyPatch endpoint is not linked to an EasyRMM device you can see.",
      }),
      "GET /patching": ok({ configured: false, canOperate: false }),
    });
    renderApp("/go/from-easypatch/endpoints/0b6f3c1e-1111-4222-8333-444455556666");
    expect(await screen.findByText("Opened from EasyPatch")).toBeInTheDocument();
    expect(screen.getByText("That EasyPatch endpoint is not linked to an EasyRMM device you can see.")).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent(/^\/patching$/);
  });

  it("say what went wrong when the server refuses", async () => {
    installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /patching/from-easypatch/:kind/:id": fail(404, "not_found", "The requested item does not exist or you do not have access to it."),
    });
    renderApp("/go/from-easypatch/updates/x");
    expect(await screen.findByRole("heading", { name: "Link from EasyPatch" })).toBeInTheDocument();
    expect(await screen.findByText(/does not exist or you do not have access/)).toBeInTheDocument();
  });

  it("wait for a sign-in first, keeping the link", async () => {
    installFakeApi(baseRoutes(null));
    renderApp("/go/from-easypatch/jobs/j1");
    await waitFor(() =>
      expect(screen.getByTestId("location")).toHaveTextContent(`/login?returnTo=${encodeURIComponent("/go/from-easypatch/jobs/j1")}`),
    );
  });
});

describe("retrying a patch job", () => {
  it("is offered for jobs that finished without doing everything", () => {
    const j = (status: string, extra: { type?: string; failedCount?: number } = {}) => ({ status, type: "InstallUpdates", failedCount: 0, ...extra });
    expect(canRetry(j("Failed"))).toBe(true);
    expect(canRetry(j("Cancelled"))).toBe(true);
    expect(canRetry(j("Expired"))).toBe(true);
    expect(canRetry(j("Completed", { failedCount: 1 }))).toBe(true);
    expect(canRetry(j("Completed"))).toBe(false);
    // Running jobs are cancelled, not retried; downloads are not retried at all.
    expect(canRetry(j("Running", { failedCount: 1 }))).toBe(false);
    expect(canRetry(j("WaitingForReboot"))).toBe(false);
    expect(canRetry(j("Failed", { type: "DownloadUpdates" }))).toBe(false);
  });
});
