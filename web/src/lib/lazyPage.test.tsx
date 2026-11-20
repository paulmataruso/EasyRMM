import { Component, type ReactNode } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Link, MemoryRouter, Route, Routes } from "react-router";
import { lazyPage, PageFrame, reloadOnce } from "./lazyPage";

afterEach(() => {
  window.sessionStorage.clear();
  vi.restoreAllMocks();
});

describe("reloadOnce", () => {
  it("reloads once, then not again within a minute", () => {
    const reload = vi.fn();
    expect(reloadOnce(reload, 1_000_000)).toBe(true);
    expect(reloadOnce(reload, 1_030_000)).toBe(false);
    expect(reload).toHaveBeenCalledTimes(1);
    expect(reloadOnce(reload, 1_061_000)).toBe(true);
    expect(reload).toHaveBeenCalledTimes(2);
  });

  it("does not reload when it cannot remember doing so", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const reload = vi.fn();
    expect(reloadOnce(reload)).toBe(false);
    expect(reload).not.toHaveBeenCalled();
  });
});

function Hello() {
  return <p>Hello page</p>;
}

function renderAt(element: ReactNode) {
  return render(
    <MemoryRouter initialEntries={["/a"]}>
      <Link to="/b">Elsewhere</Link>
      <PageFrame>
        <Routes>
          <Route path="/a" element={element} />
          <Route path="/b" element={<p>Other page</p>} />
        </Routes>
      </PageFrame>
    </MemoryRouter>,
  );
}

describe("lazyPage", () => {
  it("shows that the page is loading, then the page", async () => {
    let resolve: (page: typeof Hello) => void = () => {};
    const Page = lazyPage(() => new Promise((r) => (resolve = r)));
    renderAt(<Page />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading page…");
    resolve(Hello);
    expect(await screen.findByText("Hello page")).toBeInTheDocument();
  });

  it("renders at once when fetched beforehand", async () => {
    const load = vi.fn(() => Promise.resolve(Hello));
    const Page = lazyPage(load);
    await Page.preload();
    await Page.preload();
    renderAt(<Page />);
    expect(screen.getByText("Hello page")).toBeInTheDocument();
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("keeps showing that it is loading while the console reloads", async () => {
    const onFailure = vi.fn(() => true);
    const Page = lazyPage(() => Promise.reject(new TypeError("Failed to fetch dynamically imported module")), onFailure);
    renderAt(<Page />);
    await vi.waitFor(() => expect(onFailure).toHaveBeenCalled());
    expect(screen.getByRole("status")).toHaveTextContent("Loading page…");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says the page could not be loaded, and clears it on another page", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    const Page = lazyPage(() => Promise.reject(new TypeError("Failed to fetch dynamically imported module")), () => false);
    renderAt(<Page />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("This page could not be loaded");
    expect(alert).toHaveTextContent("If EasyRMM was just upgraded, reloading loads the new console");
    expect(screen.getByRole("button", { name: "Reload" })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("link", { name: "Elsewhere" }));
    expect(await screen.findByText("Other page")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("fetches again after a failure", async () => {
    const load = vi.fn().mockRejectedValueOnce(new TypeError("offline")).mockResolvedValue(Hello);
    const Page = lazyPage(load);
    await expect(Page.preload()).rejects.toThrow("offline");
    await Page.preload();
    expect(load).toHaveBeenCalledTimes(2);
  });
});

class Outer extends Component<{ children: ReactNode }, { error: unknown }> {
  override state = { error: null as unknown };
  static getDerivedStateFromError(error: unknown) {
    return { error };
  }
  override render() {
    return this.state.error ? <p>Outer caught: {String(this.state.error)}</p> : this.props.children;
  }
}

function Broken(): ReactNode {
  throw new Error("a bug in the page");
}

describe("PageFrame", () => {
  it("leaves other errors to whatever handled them before", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    render(
      <MemoryRouter>
        <Outer>
          <PageFrame>
            <Broken />
          </PageFrame>
        </Outer>
      </MemoryRouter>,
    );
    expect(screen.getByText("Outer caught: Error: a bug in the page")).toBeInTheDocument();
    expect(screen.queryByText("This page could not be loaded")).not.toBeInTheDocument();
  });
});
