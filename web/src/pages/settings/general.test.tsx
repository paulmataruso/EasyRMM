import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { baseRoutes, installFakeApi, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { org } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// Settings > General (ADR-0080): the app-wide default life of a new Quick Assist link.

function routes() {
  return {
    ...baseRoutes(sessionView()),
    ...unreportedRoutes(),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /quickassist/settings": ok({
      mode: "own_test", defaultLifeMinutes: 1440,
      idleMinutes: 30, maxSessionHours: 8, retentionDays: 30, bucketBurst: 5, bucketRefillMinutes: 3, waitingCap: 20, permanentLinkCap: 5,
    }),
    "PUT /quickassist/settings": ok({ mode: "own_test" }),
    "PUT /quickassist/settings/default-life": ok({ minutes: 60 }),
  };
}

describe("Settings > General", () => {
  it("shows the default and saves a new one within the bounds only", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/settings?tab=general");
    const input = await screen.findByLabelText("New link expires after (minutes)");
    await waitFor(() => expect(input).toHaveValue(1440));
    const save = screen.getByRole("button", { name: "Save" });
    await user.clear(input);
    await user.type(input, "10081");
    expect(save).toBeDisabled();
    await user.clear(input);
    await user.type(input, "60");
    expect(save).toBeEnabled();
    await user.click(save);
    await waitFor(() => expect(server.callsTo("PUT /quickassist/settings/default-life").map((c) => c.body)).toEqual([{ minutes: 60 }]));
  });

  it("shows the limits and sends only what changed, within the bounds", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/settings?tab=general");
    const idle = await screen.findByLabelText("End an idle session after (minutes)");
    await waitFor(() => expect(idle).toHaveValue(30));
    expect(screen.getByLabelText("Longest session (hours)")).toHaveValue(8);
    const save = screen.getByRole("button", { name: "Save limits" });
    await user.clear(idle);
    await user.type(idle, "4");
    expect(save).toBeDisabled();
    await user.clear(idle);
    await user.type(idle, "45");
    expect(save).toBeEnabled();
    await user.click(save);
    await waitFor(() => expect(server.callsTo("PUT /quickassist/settings").map((c) => c.body)).toEqual([{ idleMinutes: 45 }]));
  });
});
