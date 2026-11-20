import { Component, lazy, Suspense, type ComponentType, type ReactNode } from "react";
import { useLocation } from "react-router";
import { RefreshCw } from "lucide-react";
import { Button, Spinner } from "../components/ui";

/** A page whose code is fetched the first time it is shown, so the console starts with less to load. */
export type LazyPage = ComponentType & {
  /** Fetches the page's code now. Tests call it so pages render at once. */
  preload: () => Promise<unknown>;
};

/** Thrown when a page's code could not be fetched. */
export class PageLoadError extends Error {
  constructor(cause: unknown) {
    super("This page could not be loaded.", { cause });
    this.name = "PageLoadError";
  }
}

const RELOADED_AT = "easyrmm.reloadedForPage";
/** A second failure within this time of the reload is shown instead of reloading again. */
const RELOAD_GUARD_MS = 60_000;

/**
 * Called when a page's code could not be fetched, and reports whether the console is reloading. After an upgrade the
 * server no longer has the files this console was built with, so the first failure loads the new console. A second
 * one within a minute is shown instead, so a server that cannot be reached does not reload the page over and over.
 */
export function reloadOnce(reload: () => void = () => window.location.reload(), now = Date.now()): boolean {
  try {
    const last = Number(window.sessionStorage.getItem(RELOADED_AT));
    if (last && now - last < RELOAD_GUARD_MS) return false;
    window.sessionStorage.setItem(RELOADED_AT, String(now));
  } catch {
    // Without storage the guard cannot hold: show the failure rather than risk reloading forever.
    return false;
  }
  reload();
  return true;
}

/** A page fetched when first shown: `lazyPage(() => import("./pages/X").then((m) => m.XPage))`. */
export function lazyPage(load: () => Promise<ComponentType>, onFailure: () => boolean = reloadOnce): LazyPage {
  let loaded: ComponentType | undefined;
  let pending: Promise<ComponentType> | undefined;
  const preload = () =>
    (pending ??= load().then(
      (page) => (loaded = page),
      (err: unknown) => {
        pending = undefined;
        throw err;
      },
    ));
  const Lazy = lazy(async () => {
    try {
      return { default: await preload() };
    } catch (err) {
      // While the console reloads, keep showing that the page is loading.
      if (onFailure()) return new Promise<never>(() => {});
      throw new PageLoadError(err);
    }
  });
  // Once fetched, the page renders directly, without suspending.
  const Page = () => {
    const Loaded = loaded ?? Lazy;
    return <Loaded />;
  };
  return Object.assign(Page, { preload });
}

class PageLoadBoundary extends Component<{ resetKey: string; children: ReactNode }, { failed: boolean; error: unknown }> {
  override state = { failed: false, error: null as unknown };

  static getDerivedStateFromError(error: unknown) {
    return { failed: true, error };
  }

  override componentDidUpdate(prev: { resetKey: string }) {
    if (this.state.failed && prev.resetKey !== this.props.resetKey) this.setState({ failed: false, error: null });
  }

  override render() {
    if (!this.state.failed) return this.props.children;
    // Only a page that could not be fetched is handled here; any other error goes on as before.
    if (!(this.state.error instanceof PageLoadError)) throw this.state.error;
    return <PageLoadFailed />;
  }
}

function PageLoadFailed() {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center" role="alert">
      <p className="font-medium text-fg">This page could not be loaded</p>
      <p className="max-w-md text-sm text-muted">
        The console could not fetch this page from the EasyRMM server. If EasyRMM was just upgraded, reloading loads
        the new console; otherwise check that the server can be reached.
      </p>
      <Button size="sm" onClick={() => window.location.reload()} icon={<RefreshCw className="size-3.5" aria-hidden />}>
        Reload
      </Button>
    </div>
  );
}

/** Where lazy pages render: a spinner while one is fetched, and a way to reload if it cannot be. */
export function PageFrame({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return (
    <PageLoadBoundary resetKey={pathname}>
      <Suspense fallback={<Spinner label="Loading page…" className="py-16" />}>{children}</Suspense>
    </PageLoadBoundary>
  );
}
