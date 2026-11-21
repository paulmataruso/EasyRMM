import { Component, type ReactNode } from "react";
import { RefreshCw } from "lucide-react";
import { Button } from "./ui";

/**
 * The console's last catch: a page that fails to render offers a reload instead of leaving a blank window. A page left
 * open across an upgrade can be sent answers its code does not expect (ADR-0063 took output and arguments out of
 * jobs and runs); reloading loads the console that matches the server.
 */
export class AppErrorBoundary extends Component<{ children: ReactNode; reload?: () => void }, { failed: boolean }> {
  override state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  override render() {
    if (!this.state.failed) return this.props.children;
    const reload = this.props.reload ?? (() => window.location.reload());
    return (
      <div role="alert" className="flex min-h-dvh flex-col items-center justify-center gap-2 px-4 text-center">
        <p className="font-medium text-fg">This page stopped working</p>
        <p className="max-w-md text-sm text-muted">
          Something on the page failed. If EasyRMM was just upgraded, reloading loads the new console. What you already saved is kept.
        </p>
        <Button size="sm" onClick={reload} icon={<RefreshCw className="size-3.5" aria-hidden />}>
          Reload
        </Button>
      </div>
    );
  }
}
