import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { leaveFor } from "../../lib/leave";
import { baseRoutes, installFakeApi, sessionView } from "../../test/fakeApi";
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
