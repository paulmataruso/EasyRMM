import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CopyButton } from "./Copy";
import { ToastProvider, useToast } from "./Toast";

// A timer a component leaves running after it unmounts still fires. At the end of a test file that is after jsdom
// has gone, and the React state update it makes throws "window is not defined" outside any test.
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
});

afterEach(() => {
  vi.useRealTimers();
});

function Pusher() {
  const toast = useToast();
  return (
    <>
      <button type="button" onClick={() => toast.success("Saved")}>
        Save
      </button>
      <button type="button" onClick={() => toast.error("Failed")}>
        Fail
      </button>
    </>
  );
}

describe("toasts", () => {
  it("close themselves after a while, errors later than the rest", () => {
    render(
      <ToastProvider>
        <Pusher />
      </ToastProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    fireEvent.click(screen.getByRole("button", { name: "Fail" }));
    expect(screen.getByRole("status")).toHaveTextContent("Saved");
    expect(screen.getByRole("alert")).toHaveTextContent("Failed");

    act(() => vi.advanceTimersByTime(5_000));
    expect(screen.queryByRole("status")).toBeNull();
    expect(screen.getByRole("alert")).toHaveTextContent("Failed");

    act(() => vi.advanceTimersByTime(4_000));
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("leave no timer behind once closed or unmounted", () => {
    const { unmount } = render(
      <ToastProvider>
        <Pusher />
      </ToastProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(vi.getTimerCount()).toBe(2);

    fireEvent.click(screen.getAllByRole("button", { name: "Dismiss" })[0]!);
    expect(vi.getTimerCount()).toBe(1);

    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("copy buttons", () => {
  it("say they copied, go back to their label, and leave no timer behind when unmounted", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const { unmount } = render(<CopyButton text="secret" />);

    await act(async () => fireEvent.click(screen.getByRole("button", { name: "Copy" })));
    expect(writeText).toHaveBeenCalledWith("secret");
    expect(screen.getByRole("button")).toHaveTextContent("Copied");

    act(() => vi.advanceTimersByTime(1_800));
    expect(screen.getByRole("button")).toHaveTextContent("Copy");

    await act(async () => fireEvent.click(screen.getByRole("button", { name: "Copy" })));
    expect(screen.getByRole("button")).toHaveTextContent("Copied");
    expect(vi.getTimerCount()).toBe(1);

    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
