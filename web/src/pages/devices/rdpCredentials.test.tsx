import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { RdpCredential } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { device } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const TECHNICIAN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "device.remote_desktop", "device.rdp_credentials.save", "device.terminal", "device.files"],
});
const D1 = device("d1", "FRONT-DESK");
const SAVED: RdpCredential = {
  id: "0d3b8a52-6f0e-4a7e-9c0a-0b5f3a1d2e44", deviceId: "d1", scope: "user", label: "Server admin", domain: "CORP", username: "svc-admin",
  createdAt: "2026-11-01T09:00:00Z", lastUsedAt: null,
};

const launch = (r: FakeRequest) => ({
  status: 201,
  body: { grantId: "g-rdp", url: "https://mesh.rmm.example.com/.easyrmm/launch?t=rdp-token", expiresAt: "2030-01-01T00:00:00Z", kind: "rdp", deviceId: r.params.id },
});

describe("saved RDP credentials in the remote desktop", () => {
  it("opens as before when nothing is saved, with no choice to make", async () => {
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(D1), "GET /devices/:id/rdp-credentials": ok({ credentials: [] }), "POST /devices/:id/remote-sessions": launch,
    });
    renderApp("/devices/d1/remote/rdp");
    const frame = await screen.findByTitle("RDP on FRONT-DESK");
    expect(frame).toHaveAttribute("src", "https://mesh.rmm.example.com/.easyrmm/launch?t=rdp-token");
    expect(server.callsTo("POST /devices/:id/remote-sessions").map((c) => c.body)).toEqual([{ kind: "rdp" }]);
  });

  it("opens as before when the saved credentials cannot be read", async () => {
    installFakeApi({
      ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(D1), "GET /devices/:id/rdp-credentials": fail(500, "internal", "Something went wrong."), "POST /devices/:id/remote-sessions": launch,
    });
    renderApp("/devices/d1/remote/rdp");
    expect(await screen.findByTitle("RDP on FRONT-DESK")).toBeInTheDocument();
  });

  it("offers a saved credential first, and opens with its id, never a password", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(D1), "GET /devices/:id/rdp-credentials": ok({ credentials: [SAVED] }), "POST /devices/:id/remote-sessions": launch,
    });
    renderApp("/devices/d1/remote/rdp");
    const form = await screen.findByRole("form", { name: "How to sign in" });
    expect(server.callsTo("POST /devices/:id/remote-sessions")).toHaveLength(0);
    expect(within(form).getByText("CORP\\svc-admin")).toBeInTheDocument();
    expect(within(form).getByRole("radio", { name: /Use the saved credential “Server admin”/ })).toBeChecked();
    expect(form).not.toHaveTextContent(/password/i);
    await user.click(within(form).getByRole("button", { name: "Connect" }));
    const frame = await screen.findByTitle("RDP on FRONT-DESK");
    expect(server.callsTo("POST /devices/:id/remote-sessions").map((c) => c.body)).toEqual([{ kind: "rdp", savedCredential: true }]);
    expect(new URL(frame.getAttribute("src")!).searchParams.get("rdpcred")).toBe(SAVED.id);
    // A reconnect uses the same choice.
    await user.click(screen.getByRole("button", { name: /Reconnect/ }));
    await waitFor(() => expect(server.callsTo("POST /devices/:id/remote-sessions")).toHaveLength(2));
  });

  it("lets the person type credentials in the session instead", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(D1), "GET /devices/:id/rdp-credentials": ok({ credentials: [SAVED] }), "POST /devices/:id/remote-sessions": launch,
    });
    renderApp("/devices/d1/remote/rdp");
    const form = await screen.findByRole("form", { name: "How to sign in" });
    await user.click(within(form).getByRole("radio", { name: "Type credentials in the session" }));
    await user.click(within(form).getByRole("button", { name: "Connect" }));
    const frame = await screen.findByTitle("RDP on FRONT-DESK");
    expect(server.callsTo("POST /devices/:id/remote-sessions").map((c) => c.body)).toEqual([{ kind: "rdp" }]);
    expect(frame).toHaveAttribute("src", "https://mesh.rmm.example.com/.easyrmm/launch?t=rdp-token");
  });

  it("saves a credential on request, empties the password field and connects with it", async () => {
    const user = userEvent.setup();
    const saved: { current: RdpCredential[] } = { current: [] };
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /devices/:id": ok(D1),
      "GET /devices/:id/rdp-credentials": () => ok({ credentials: saved.current }),
      "PUT /devices/:id/rdp-credentials": (r) => {
        const body = r.body as { label: string; domain: string; username: string };
        saved.current = [{ ...SAVED, label: body.label || body.username, domain: body.domain, username: body.username }];
        return ok(saved.current[0]);
      },
      "POST /devices/:id/remote-sessions": launch,
    });
    renderApp("/devices/d1/remote/rdp");
    await screen.findByTitle("RDP on FRONT-DESK");
    await user.click(screen.getByRole("button", { name: /Saved credential/ }));
    const dialog = await screen.findByRole("dialog", { name: "Saved RDP credential" });
    expect(within(dialog).queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Domain"), "CORP");
    await user.type(within(dialog).getByLabelText(/User name/), "svc-admin");
    const password = within(dialog).getByLabelText(/^Password/);
    expect(password).toHaveAttribute("type", "password");
    await user.type(password, "s3cret!");
    await user.click(within(dialog).getByRole("button", { name: "Save and connect" }));
    await waitFor(() => expect(server.callsTo("PUT /devices/:id/rdp-credentials")).toHaveLength(1));
    expect(server.callsTo("PUT /devices/:id/rdp-credentials")[0]!.body).toEqual({ label: "", domain: "CORP", username: "svc-admin", password: "s3cret!" });
    await waitFor(() => expect(server.callsTo("POST /devices/:id/remote-sessions").map((c) => c.body)).toContainEqual({ kind: "rdp", savedCredential: true }));
    // The page keeps no password and never displays one.
    expect(document.body).not.toHaveTextContent("s3cret!");
    expect(Array.from(document.querySelectorAll("input")).every((i) => i.value !== "s3cret!")).toBe(true);
  });

  it("replaces and deletes the saved credential", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /devices/:id": ok(D1),
      "GET /devices/:id/rdp-credentials": ok({ credentials: [SAVED] }),
      "PUT /devices/:id/rdp-credentials": ok(SAVED),
      "DELETE /devices/:id/rdp-credentials/:cid": () => ({ status: 204, body: null }),
      "POST /devices/:id/remote-sessions": launch,
    });
    renderApp("/devices/d1/remote/rdp");
    const chooser = await screen.findByRole("form", { name: "How to sign in" });
    await user.click(within(chooser).getByRole("button", { name: "Manage saved credentials" }));
    const dialog = await screen.findByRole("dialog", { name: "Saved RDP credential" });
    expect(within(dialog).getByText("CORP\\svc-admin")).toBeInTheDocument();
    // The form starts from the account, never the password.
    expect(within(dialog).getByLabelText(/User name/)).toHaveValue("svc-admin");
    expect(within(dialog).getByLabelText(/New password/)).toHaveValue("");
    await user.type(within(dialog).getByLabelText(/New password/), "n3w");
    await user.click(within(dialog).getByRole("button", { name: "Replace and connect" }));
    await waitFor(() => expect(server.callsTo("PUT /devices/:id/rdp-credentials")).toHaveLength(1));
    await screen.findByTitle("RDP on FRONT-DESK");
    await user.click(screen.getByRole("button", { name: /Saved credential/ }));
    await user.click(await screen.findByRole("button", { name: "Delete" }));
    await waitFor(() => expect(server.callsTo("DELETE /devices/:id/rdp-credentials/:cid")).toHaveLength(1));
    expect(server.callsTo("DELETE /devices/:id/rdp-credentials/:cid")[0]!.params.cid).toBe(SAVED.id);
  });

  it("shows why a save was refused", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /devices/:id": ok(D1),
      "GET /devices/:id/rdp-credentials": ok({ credentials: [] }),
      "PUT /devices/:id/rdp-credentials": fail(403, "forbidden", "You do not have permission to do that."),
      "POST /devices/:id/remote-sessions": launch,
    });
    renderApp("/devices/d1/remote/rdp");
    await screen.findByTitle("RDP on FRONT-DESK");
    await user.click(screen.getByRole("button", { name: /Saved credential/ }));
    const dialog = await screen.findByRole("dialog", { name: "Saved RDP credential" });
    await user.type(within(dialog).getByLabelText(/User name/), "svc-admin");
    await user.type(within(dialog).getByLabelText(/^Password/), "x");
    await user.click(within(dialog).getByRole("button", { name: "Save and connect" }));
    expect(await within(dialog).findByText("You do not have permission to do that.")).toBeInTheDocument();
  });

  it("offers nothing to save on other session types", async () => {
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(D1), "POST /devices/:id/remote-sessions": launch });
    renderApp("/devices/d1/remote/terminal");
    await screen.findByTitle("Terminal on FRONT-DESK");
    expect(screen.queryByRole("button", { name: /Saved credential/ })).not.toBeInTheDocument();
  });
});
