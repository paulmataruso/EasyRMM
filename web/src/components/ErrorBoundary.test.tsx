import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { AppErrorBoundary } from "./ErrorBoundary";

/** What a page left open across an upgrade does when a field it reads is gone. */
function OldJobPage({ job }: { job: { args?: string[] } }): ReactNode {
  return <p>{job.args!.length} arguments</p>;
}

describe("AppErrorBoundary", () => {
  it("shows the page while it works", () => {
    render(
      <AppErrorBoundary>
        <OldJobPage job={{ args: ["-h"] }} />
      </AppErrorBoundary>,
    );
    expect(screen.getByText("1 arguments")).toBeInTheDocument();
  });

  it("offers a reload when a page fails to render", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const reload = vi.fn();
    render(
      <AppErrorBoundary reload={reload}>
        <OldJobPage job={{}} />
      </AppErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("This page stopped working");
    await userEvent.setup().click(screen.getByRole("button", { name: "Reload" }));
    expect(reload).toHaveBeenCalledOnce();
  });
});
