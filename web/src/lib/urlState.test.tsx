import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Link, MemoryRouter, useLocation } from "react-router";
import { useUrlState } from "./urlState";

function Filters() {
  const url = useUrlState();
  const { pathname, search } = useLocation();
  return (
    <>
      <button
        type="button"
        onClick={() => {
          url.set({ active: "false", status: null });
          url.set({ type: "InstallUpdates" });
        }}
      >
        Both
      </button>
      <button type="button" onClick={() => url.set({ type: null })}>
        Clear type
      </button>
      <Link to="/other">Other page</Link>
      <output>{pathname + search}</output>
    </>
  );
}

function Other() {
  const url = useUrlState();
  const { pathname, search } = useLocation();
  return (
    <>
      <button type="button" onClick={() => url.set({ view: "tags" })}>
        Tags
      </button>
      <output>{pathname + search}</output>
    </>
  );
}

function Pages() {
  return useLocation().pathname === "/other" ? <Other /> : <Filters />;
}

describe("useUrlState", () => {
  it("keeps both of two changes made before the page renders again", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/patching?tab=jobs&status=Failed"]}>
        <Pages />
      </MemoryRouter>,
    );
    await user.click(screen.getByRole("button", { name: "Both" }));
    expect(screen.getByRole("status")).toHaveTextContent("/patching?tab=jobs&active=false&type=InstallUpdates");
    await user.click(screen.getByRole("button", { name: "Clear type" }));
    expect(screen.getByRole("status")).toHaveTextContent("/patching?tab=jobs&active=false");
  });

  it("starts from the page's own parameters on another page", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/patching"]}>
        <Pages />
      </MemoryRouter>,
    );
    await user.click(screen.getByRole("button", { name: "Both" }));
    await user.click(screen.getByRole("link", { name: "Other page" }));
    await user.click(screen.getByRole("button", { name: "Tags" }));
    expect(screen.getByRole("status")).toHaveTextContent("/other?view=tags");
  });
});
