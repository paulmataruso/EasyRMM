import { useCallback, useEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import { Link, NavLink, useParams } from "react-router";
import { ArrowLeft, Maximize, Minimize, MonitorOff, RotateCw, ShieldOff, ShieldQuestionMark, Unplug } from "lucide-react";
import { api, ApiError, errorMessage } from "../../api/client";
import { useApi } from "../../api/hooks";
import type { Device, RemoteKind, RemoteLaunch } from "../../api/types";
import { REMOTE_KIND_NAMES } from "../../components/StatusBadges";
import { Button, buttonClasses, cx, Dot, Spinner } from "../../components/ui";
import { allowedKinds } from "./DeviceDetailPage";
import { isRemoteKind } from "./platform";

/** What the frame area shows for one launch attempt. */
type Attempt = { key: string; launch?: RemoteLaunch; error?: unknown };

/**
 * A remote session in MeshCentral, embedded full-window. Every visit (and every reconnect or switch between
 * desktop, terminal and files) asks the server for a fresh one-time link, so each session is authorized and
 * audited on its own. The console's own session check (every five minutes while the page is visible) keeps the
 * EasyRMM session, and with it the remote session, alive.
 */
export function RemoteSessionPage() {
  const { id = "", kind: kindParam } = useParams();
  const kind = isRemoteKind(kindParam) ? kindParam : null;
  const device = useApi<Device>(`/devices/${id}`);
  const [nonce, setNonce] = useState(0);
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [certificateHelp, setCertificateHelp] = useState(false);
  const started = useRef<string | null>(null);
  const frame = useRef<HTMLDivElement>(null);
  const fullscreen = useFullscreen(frame);
  const key = `${id}/${kind}/${nonce}`;

  useEffect(() => {
    // Guarded by key so a re-run of the effect (React's development double-invoke) does not launch twice.
    if (!kind || started.current === key) return;
    started.current = key;
    setLoaded(false);
    api.post<RemoteLaunch>(`/devices/${id}/remote-sessions`, { kind }).then(
      (launch) => setAttempt({ key, launch }),
      (error: unknown) => setAttempt({ key, error }),
    );
  }, [id, kind, key]);

  const reconnect = useCallback(() => setNonce((n) => n + 1), []);
  const current = attempt?.key === key ? attempt : null;
  // A session on an address with the server's own certificate (ADR-0016) loads only once the browser trusts that
  // certificate for the session's origin, and a browser cannot ask inside a frame: it shows its error page instead.
  const untrustedOrigin = current?.launch?.internalCa ? new URL(current.launch.url).origin : null;
  const d = device.data;
  const label = kind ? REMOTE_KIND_NAMES[kind] : "Remote session";

  useEffect(() => {
    const previous = document.title;
    document.title = d ? `${label} · ${d.name} · EasyRMM` : `${label} · EasyRMM`;
    return () => {
      document.title = previous;
    };
  }, [d, label]);

  return (
    <div className="flex h-full flex-col bg-canvas">
      {/* One row from sm up; on phones the session-type switcher takes a second row so the name stays readable. */}
      <header className="flex shrink-0 flex-wrap items-center gap-x-2 gap-y-1.5 border-b border-line bg-surface px-2 py-1.5 sm:h-12 sm:flex-nowrap sm:px-3 sm:py-0">
        <Link
          to={`/devices/${id}`}
          aria-label="Device details"
          title="Device details"
          className="inline-flex size-8 shrink-0 items-center justify-center rounded-md text-muted hover:bg-hover hover:text-fg"
        >
          <ArrowLeft className="size-4" aria-hidden />
        </Link>
        <div className="min-w-0 flex-1 sm:max-w-xs sm:flex-initial">
          <h1 className="flex items-center gap-1.5 truncate text-sm font-medium">
            {d && <Dot tone={d.remoteOnline ? "ok" : "neutral"} />}
            <span className="truncate">{d?.name ?? "Device"}</span>
            <span className="sr-only">, {label}</span>
          </h1>
          {d && (
            <p className="hidden truncate text-xs text-muted sm:block">
              {d.organizationName} / {d.siteName}
            </p>
          )}
        </div>
        {d && kind && <KindSwitcher device={d} active={kind} />}
        <div className="hidden flex-1 sm:block" />
        {untrustedOrigin && (
          <Button
            size="sm"
            variant="ghost"
            icon={<ShieldQuestionMark className="size-3.5" aria-hidden />}
            onClick={() => setCertificateHelp((open) => !open)}
            aria-expanded={certificateHelp}
            aria-controls="certificate-help"
            title="Help if the session does not load"
          >
            <span className="hidden md:inline">Not loading?</span>
          </Button>
        )}
        <Button size="sm" variant="ghost" icon={<RotateCw className="size-3.5" aria-hidden />} onClick={reconnect} disabled={!kind} title="Start this session again">
          <span className="hidden md:inline">Reconnect</span>
        </Button>
        <Button
          size="sm"
          variant="ghost"
          icon={fullscreen.active ? <Minimize className="size-3.5" aria-hidden /> : <Maximize className="size-3.5" aria-hidden />}
          onClick={fullscreen.toggle}
          disabled={!fullscreen.supported || !current?.launch}
          title={fullscreen.active ? "Leave full screen (Esc)" : "Full screen"}
        >
          <span className="hidden md:inline">{fullscreen.active ? "Exit full screen" : "Full screen"}</span>
        </Button>
        <Link to={`/devices/${id}`} className={buttonClasses("secondary", "sm")}>
          End<span className="hidden sm:inline"> session</span>
        </Link>
      </header>

      <div ref={frame} className="relative min-h-0 flex-1 bg-canvas">
        {untrustedOrigin && certificateHelp && (
          <CertificateHelp
            origin={untrustedOrigin}
            onClose={() => setCertificateHelp(false)}
            onReconnect={() => {
              setCertificateHelp(false);
              reconnect();
            }}
          />
        )}
        {!kind ? (
          <Problem icon={<MonitorOff className="size-8" aria-hidden />} title="Unknown session type" deviceId={id}>
            Remote sessions are desktop, terminal or files.
          </Problem>
        ) : !current ? (
          <Centered>
            <Spinner label={d ? `Connecting to ${d.name}…` : "Connecting…"} />
          </Centered>
        ) : current.error !== undefined ? (
          <LaunchError error={current.error} kind={kind} deviceId={id} onRetry={reconnect} />
        ) : current.launch ? (
          <>
            {!loaded && (
              <Centered className="absolute inset-0">
                <Spinner label={`Opening ${label.toLowerCase()}…`} />
              </Centered>
            )}
            <iframe
              key={current.launch.grantId}
              src={current.launch.url}
              title={d ? `${label} on ${d.name}` : label}
              onLoad={() => setLoaded(true)}
              className={cx("absolute inset-0 size-full border-0", !loaded && "invisible")}
              sandbox="allow-scripts allow-same-origin allow-forms allow-downloads allow-popups allow-modals"
              allow="clipboard-read; clipboard-write; fullscreen"
              referrerPolicy="no-referrer"
            />
          </>
        ) : null}
      </div>
    </div>
  );
}

function KindSwitcher({ device, active }: { device: Device; active: RemoteKind }) {
  const kinds = allowedKinds(device);
  if (kinds.length < 2) return null;
  return (
    <nav aria-label="Session type" className="order-last flex w-full rounded-md border border-line bg-canvas p-0.5 sm:order-none sm:w-auto sm:shrink-0">
      {kinds.map((k) => (
        <NavLink
          key={k}
          to={`/devices/${device.id}/remote/${k}`}
          replace
          aria-current={k === active ? "page" : undefined}
          className={cx(
            "flex-1 rounded px-2 py-1 text-center text-xs font-medium whitespace-nowrap transition-colors sm:flex-none",
            k === active ? "bg-accent-soft text-fg ring-1 ring-accent/40" : "text-muted hover:bg-hover hover:text-fg",
          )}
        >
          {k === "desktop" ? "Desktop" : REMOTE_KIND_NAMES[k]}
        </NavLink>
      ))}
    </nav>
  );
}

function LaunchError({ error, kind, deviceId, onRetry }: { error: unknown; kind: RemoteKind; deviceId: string; onRetry: () => void }) {
  const code = error instanceof ApiError ? error.code : "";
  const status = error instanceof ApiError ? error.status : 0;
  if (status === 403) {
    return (
      <Problem icon={<ShieldOff className="size-8" aria-hidden />} title="Not available to your role" deviceId={deviceId}>
        Your role does not allow {REMOTE_KIND_NAMES[kind].toLowerCase()} sessions on this device.
      </Problem>
    );
  }
  if (status === 404) {
    return (
      <Problem icon={<MonitorOff className="size-8" aria-hidden />} title="Device not found" deviceId={deviceId}>
        It may have been removed, or you may no longer have access to its site.
      </Problem>
    );
  }
  const titles: Record<string, string> = {
    device_offline: "The device is offline",
    remote_agent_missing: "No remote-access agent",
    remote_unavailable: "Remote access is unavailable",
  };
  const retry = code !== "remote_agent_missing";
  return (
    <Problem icon={<Unplug className="size-8" aria-hidden />} title={titles[code] ?? "The session could not start"} deviceId={deviceId} onRetry={retry ? onRetry : undefined}>
      {errorMessage(error)}
    </Problem>
  );
}

function CertificateHelp({ origin, onClose, onReconnect }: { origin: string; onClose: () => void; onReconnect: () => void }) {
  return (
    <div className="absolute inset-x-0 top-0 z-10 flex justify-center p-3">
      <section id="certificate-help" aria-labelledby="certificate-help-title" className="w-full max-w-lg rounded-lg border border-line bg-surface p-4 text-sm shadow-lg">
        <h2 id="certificate-help-title" className="font-medium text-fg">
          Your browser may not trust this address yet
        </h2>
        <p className="mt-1 text-muted">
          This server uses its own certificate on IP addresses. The session runs on <span className="font-mono text-[0.9em] text-fg">{origin}</span>, and your
          browser cannot ask you to accept a certificate inside the session frame.
        </p>
        <ol className="mt-3 list-decimal space-y-1 pl-5 text-muted">
          <li>
            <a href={origin} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
              Open {new URL(origin).host} in a new tab
            </a>{" "}
            and accept the certificate warning there.
          </li>
          <li>Close that tab and reconnect.</li>
        </ol>
        <p className="mt-3 text-muted">
          To stop the warnings on this computer,{" "}
          <Link to="/devices/add" className="text-accent hover:underline">
            install the server&rsquo;s certificate authority
          </Link>
          .
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <Button size="sm" variant="secondary" onClick={onClose}>
            Close
          </Button>
          <Button size="sm" variant="primary" icon={<RotateCw className="size-3.5" aria-hidden />} onClick={onReconnect}>
            Reconnect
          </Button>
        </div>
      </section>
    </div>
  );
}

function Problem({ icon, title, children, deviceId, onRetry }: { icon: ReactNode; title: string; children: ReactNode; deviceId: string; onRetry?: () => void }) {
  return (
    <Centered>
      <div role="alert" className="flex max-w-md flex-col items-center gap-2 px-4 text-center">
        <div className="text-subtle">{icon}</div>
        <p className="font-medium text-fg">{title}</p>
        <p className="text-sm text-muted">{children}</p>
        <div className="mt-2 flex gap-2">
          {onRetry && (
            <Button variant="primary" onClick={onRetry} icon={<RotateCw className="size-3.5" aria-hidden />}>
              Try again
            </Button>
          )}
          <Link to={`/devices/${deviceId}`} className={buttonClasses("secondary")}>
            Back to the device
          </Link>
        </div>
      </div>
    </Centered>
  );
}

function Centered({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx("flex h-full items-center justify-center", className)}>{children}</div>;
}

function useFullscreen(ref: RefObject<HTMLElement | null>) {
  const [active, setActive] = useState(false);
  useEffect(() => {
    const onChange = () => setActive(document.fullscreenElement !== null && document.fullscreenElement === ref.current);
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, [ref]);
  const supported = typeof document !== "undefined" && document.fullscreenEnabled === true;
  const toggle = useCallback(() => {
    // Browsers refuse full screen without a user gesture or under a restrictive policy; the button then does nothing.
    const done = document.fullscreenElement ? document.exitFullscreen() : ref.current?.requestFullscreen();
    done?.catch(() => undefined);
  }, [ref]);
  return { active, supported, toggle };
}
