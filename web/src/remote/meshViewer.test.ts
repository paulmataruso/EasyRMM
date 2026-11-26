import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";

/**
 * The session view tuning EasyRMM's server writes as MeshCentral's
 * scripts/custom.js (server/internal/meshcentral/viewer.js, ADR-0025). Each
 * test runs it against a fake MeshCentral device page: a fresh document, a
 * manual clock, and desktop modules that behave like MeshCentral's own.
 */
const SCRIPT = readFileSync(resolve(process.cwd(), "../server/internal/meshcentral/viewer.js"), "utf8");

type Op = [number, number, ...unknown[]];

/** The parts of MeshCentral's CreateAgentRemoteDesktop module the tuning touches. */
function desktopModule(canvas: HTMLCanvasElement) {
  const draw = vi.fn();
  const m = {
    CanvasId: canvas,
    Canvas: { drawImage: draw } as { drawImage: (...args: unknown[]) => void },
    draw,
    State: 3,
    PendingOperations: [] as Op[],
    tilesReceived: 0,
    TilesDrawn: 0,
    KillDraw: 0,
    ImageType: 1,
    CompressionLevel: 40,
    ScalingLevel: 1024 as number | string,
    FrameRateTimer: 50,
    ScreenWidth: 0,
    ScreenHeight: 0,
    /** Every scaling, and every frame timer, sent to the agent. */
    sent: [] as number[],
    timers: [] as number[],
    SendCompressionLevel(_type: number, _level?: number | null, scaling?: number | string | null, frametimer?: number) {
      if (scaling) m.ScalingLevel = scaling;
      if (frametimer) m.FrameRateTimer = frametimer;
      m.sent.push(Number(m.ScalingLevel));
      m.timers.push(m.FrameRateTimer);
    },
    // As MeshCentral's: a new size resends the compression settings.
    ProcessScreenMsg(width: number, height: number) {
      if (m.ScreenWidth === width && m.ScreenHeight === height) return;
      m.ScreenWidth = width;
      m.ScreenHeight = height;
      m.SendCompressionLevel(m.ImageType);
    },
    ProcessPictureMsg: vi.fn(),
    // As MeshCentral's: draws tiles strictly in the order they arrived.
    DoPendingOperations(): boolean {
      for (let i = 0; i < m.PendingOperations.length; i++) {
        const op = m.PendingOperations[i]!;
        if (op[0] === m.TilesDrawn + 1) {
          if (op[1] === 2) m.Canvas.drawImage(op[2], op[3], op[4]);
          m.PendingOperations.splice(i, 1);
          m.TilesDrawn++;
          if (m.TilesDrawn === m.tilesReceived && m.KillDraw < m.TilesDrawn) m.KillDraw = m.TilesDrawn = m.tilesReceived = 0;
          return true;
        }
      }
      return false;
    },
  };
  return m;
}
type Desktop = ReturnType<typeof desktopModule>;

/** MeshCentral's RDP module (CreateRDPDesktop), as far as the tuning sees it. */
interface Rdp {
  contype: 4;
  State: number;
  options: Record<string, unknown>;
  Stop: () => void;
}
type Fn = (...args: unknown[]) => unknown;

class FakeBitmap {
  close = vi.fn();
  constructor(readonly name: string) {}
}

interface PageOptions {
  viewmode?: string;
  /** MeshCentral's functions are missing, as after an update that renamed them. */
  bare?: boolean;
  storageBlocked?: boolean;
  createImageBitmap?: boolean;
  fetch?: boolean;
  /** The console opened an RDP session (rdp=1). */
  rdp?: boolean;
  /** The console chose a saved credential for it (rdpcred=). */
  rdpcred?: string;
}

/** A MeshCentral device page with the tuning loaded. */
class Page {
  doc = document.implementation.createHTMLDocument("MeshCentral");
  now = 0;
  private timers = new Map<number, { fn: () => void; at: number; every?: number }>();
  private nextTimer = 0;
  private listeners = new Map<string, Array<() => void>>();
  storage = new Map<string, string>();
  parent = { width: 945, height: 479 };
  decodes: Array<{ blob: Blob; resolve: (b: FakeBitmap) => void; reject: (e: unknown) => void }> = [];
  clicks: string[] = [];
  /** What EasyRMM's gateway answers about held pictures, and what it was asked. */
  gateway = { status: 200, held: 0, active: true };
  asked: string[] = [];
  /** What MeshCentral offers for the device: MeshAgent's desktop, RDP (Windows only). */
  offers = { agent: true, rdp: false };
  /** The options of each RDP connection started, as the RDP module got them. */
  rdpStarts: Array<Record<string, unknown>> = [];
  warn = vi.fn();
  /** What the page sent on WebSockets, by address. */
  sent: Array<{ url: string; data: unknown }> = [];
  win: Record<string, unknown>;

  constructor(opts: PageOptions = {}) {
    const doc = this.doc;
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const page = this;
    doc.body.innerHTML = `<div id="DeskParent"><canvas id="Desk"></canvas></div>
      <span id="connectbutton1span"><input type="button" id="connectbutton1" disabled></span>
      <span id="connectbutton1rspan"><input type="button" id="connectbutton1r" disabled></span>
      <span id="connectbutton1hspan"><input type="button" id="connectbutton1h" disabled></span>
      <input type="button" id="connectbutton2" disabled><input type="button" id="p13Connect" disabled>`;
    const parent = doc.getElementById("DeskParent")!;
    for (const [prop, dim] of [["clientWidth", "width"], ["offsetWidth", "width"], ["clientHeight", "height"], ["offsetHeight", "height"]] as const) {
      Object.defineProperty(parent, prop, { get: () => this.parent[dim] });
    }
    for (const id of ["connectbutton1", "connectbutton1r", "connectbutton1h", "connectbutton2", "p13Connect"]) {
      const b = doc.getElementById(id)!;
      // jsdom does no layout: a button is shown while it is enabled and its span is not hidden.
      Object.defineProperty(b, "offsetParent", {
        get: () => ((b as HTMLInputElement).disabled || b.parentElement!.style.display === "none" ? null : doc.body),
      });
      b.addEventListener("click", () => this.clicks.push(id));
    }
    const win: Record<string, unknown> = {
      document: doc,
      location: { search: `?gotonode=abc&viewmode=${opts.viewmode ?? "11"}&hide=63${opts.rdp ? "&rdp=1" : ""}${opts.rdpcred ? `&rdpcred=${opts.rdpcred}` : ""}` },
      WebSocket: class {
        constructor(readonly url: string) {}
        send(data: unknown) {
          page.sent.push({ url: this.url, data });
        }
      },
      devicePixelRatio: 1,
      console: { warn: this.warn },
      Blob,
      ImageBitmap: FakeBitmap,
      localStorage: {
        setItem: (k: string, v: string) => {
          if (opts.storageBlocked) throw new Error("SecurityError");
          this.storage.set(k, v);
        },
      },
      setTimeout: (fn: () => void, ms: number) => this.schedule(fn, ms),
      clearTimeout: (id: number) => this.timers.delete(id),
      setInterval: (fn: () => void, ms: number) => this.schedule(fn, ms, ms),
      clearInterval: (id: number) => this.timers.delete(id),
      addEventListener: (type: string, fn: () => void) => this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]),
    };
    if (opts.fetch !== false) {
      win.fetch = (url: string) => {
        this.asked.push(url);
        const { status, held, active } = this.gateway;
        return Promise.resolve({ status, ok: status === 200, json: () => Promise.resolve({ held, active }) });
      };
    }
    if (opts.createImageBitmap !== false) {
      win.createImageBitmap = (blob: Blob) =>
        new Promise<FakeBitmap>((resolve, reject) => this.decodes.push({ blob, resolve, reject }));
    }
    if (!opts.bare) {
      win.desktopsettings = { framerate: 50, scaling: 1024, quality: 40 };
      win.deskAspectRatio = 0;
      win.applyDesktopSettings = vi.fn();
      win.deskAdjust = vi.fn();
      // As MeshCentral's: starts a session when there is none and ends the current one otherwise; does
      // nothing while a dialog is open.
      win.desktop = null;
      win.xxdialogMode = null;
      win.connectDesktop = (_e: unknown, contype: number, options?: Record<string, unknown>) => {
        if (win.xxdialogMode) return;
        const current = win.desktop as Rdp | null;
        if (current == null) {
          if (contype === 4 && options) win.desktop = this.rdpModule(options);
        } else {
          current.Stop();
          win.desktop = null;
        }
      };
      // As MeshCentral's: a module that closes stops whichever module is current, and clears it.
      win.onDesktopStateChange = (_m: unknown, state: number) => {
        if (state === 0) {
          (win.desktop as Rdp | null)?.Stop();
          win.desktop = null;
        }
        (win.updateDesktopButtons as Fn)();
      };
      win.updateDesktopButtons = () => {
        const idle = win.desktop == null;
        const show = (id: string, on: boolean) => (doc.getElementById(id)!.style.display = on ? "" : "none");
        show("connectbutton1span", idle && this.offers.agent);
        show("connectbutton1rspan", idle && this.offers.rdp);
        show("connectbutton1hspan", false);
      };
      win.currentNode = { _id: "node//abc$@9" };
      win.CreateAgentRemoteDesktop = (canvas: string) => desktopModule(doc.getElementById(canvas) as HTMLCanvasElement ?? doc.createElement("canvas"));
    }
    this.win = win;
    new Function("window", SCRIPT)(win);
    doc.dispatchEvent(new Event("DOMContentLoaded"));
    this.fire("load");
  }

  private schedule(fn: () => void, ms: number, every?: number) {
    this.timers.set(++this.nextTimer, { fn, at: this.now + ms, every });
    return this.nextTimer;
  }

  /** Runs the clock forward, firing timers in order. */
  advance(ms: number) {
    const end = this.now + ms;
    for (;;) {
      let next: [number, { fn: () => void; at: number; every?: number }] | undefined;
      for (const t of this.timers) if (t[1].at <= end && (!next || t[1].at < next[1].at)) next = t;
      if (!next) break;
      const [id, t] = next;
      this.now = t.at;
      if (t.every) t.at += t.every;
      else this.timers.delete(id);
      t.fn();
    }
    this.now = end;
  }

  fire(type: string) {
    for (const fn of this.listeners.get(type) ?? []) fn();
  }

  button(id: string) {
    return this.doc.getElementById(id) as HTMLInputElement;
  }

  /** A desktop module as the page creates one, for the session view or another canvas. */
  desktop(canvas = "Desk"): Desktop {
    return (this.win.CreateAgentRemoteDesktop as (c: string) => Desktop)(canvas);
  }

  private rdpModule(options: Record<string, unknown>): Rdp {
    const m: Rdp = {
      contype: 4,
      State: 1,
      options: { ...options },
      // The socket closes a little later.
      Stop: () =>
        this.schedule(() => {
          if (m.State === 0) return;
          m.State = 0;
          (this.win.onDesktopStateChange as Fn)(m, 0);
        }, 50),
    };
    this.rdpStarts.push(m.options);
    // As MeshCentral's Start: the size is taken out of the options it was given.
    delete options.width;
    delete options.height;
    return m;
  }

  /** The user submits MeshCentral's RDP credentials dialog, sized as MeshCentral sizes it. */
  submitRdp(size?: { width: number; height: number }) {
    const { width, height } = size ?? this.parent;
    (this.win.connectDesktop as Fn)(null, 4, { domain: "", username: "admin", password: "pw", savecred: false, width, height, flags: 0x2f });
  }

  /** The RDP connection is up. */
  rdpConnected() {
    const m = this.win.desktop as Rdp;
    m.State = 3;
    (this.win.onDesktopStateChange as Fn)(m, 3);
    return m;
  }

  shown(id: string) {
    return this.doc.getElementById(id)!.style.display !== "none";
  }

  /** MeshCentral laying the desktop out again, as on a window resize. */
  relayout(width: number, height: number) {
    this.parent = { width, height };
    (this.win.deskAdjust as () => void)();
  }
}

const tile = (...payload: number[]) => new Uint8Array([0, 3, 0, 8, ...payload]);
const settle = () => new Promise((r) => setTimeout(r, 0));

describe("MeshCentral session view tuning", () => {
  describe("connecting", () => {
    it("clicks Connect once the page enables it, and only once", () => {
      const page = new Page();
      page.advance(1500);
      expect(page.clicks).toEqual([]);
      page.button("connectbutton1").disabled = false;
      page.advance(100);
      expect(page.clicks).toEqual(["connectbutton1"]);
      page.advance(5000);
      expect(page.clicks).toEqual(["connectbutton1"]);
    });

    it.each([
      ["12", "connectbutton2"],
      ["13", "p13Connect"],
    ])("connects view %s with its own button", (viewmode, id) => {
      const page = new Page({ viewmode });
      for (const b of ["connectbutton1", "connectbutton2", "p13Connect"]) page.button(b).disabled = false;
      page.advance(100);
      expect(page.clicks).toEqual([id]);
    });

    it("gives up after 20 seconds, and leaves other views alone", () => {
      const page = new Page();
      page.advance(20_000);
      page.button("connectbutton1").disabled = false;
      page.advance(1000);
      expect(page.clicks).toEqual([]);

      const other = new Page({ viewmode: "1" });
      other.button("connectbutton1").disabled = false;
      other.advance(1000);
      expect(other.clicks).toEqual([]);
    });
  });

  describe("RDP sessions with a saved credential (ADR-0079)", () => {
    const ID = "0d3b8a52-6f0e-4a7e-9c0a-0b5f3a1d2e44";
    const infos = JSON.stringify(["infos", { ip: "node//abc", port: 3389, screen: { width: 945, height: 479 }, domain: "D", username: "typed", password: "typed-pw", options: { savepass: true, flags: 47 }, locale: "en-US" }]);
    const socket = (page: Page, url: string) => new (page.win.WebSocket as new (u: string) => { send(d: unknown): void })(url);

    it("connects at once, without the credentials dialog and without credentials in the options", () => {
      const page = new Page({ rdp: true, rdpcred: ID });
      page.button("connectbutton1r").disabled = false;
      page.advance(100);
      expect(page.clicks).toEqual([]);
      expect(page.rdpStarts).toEqual([{ domain: "", username: "", password: "", savecred: false, width: 944, height: 479, flags: 0x2f, altshell: "", workdir: "" }]);
      page.advance(5000);
      expect(page.rdpStarts).toHaveLength(1);
    });

    it("sizes the session by the desktop settings, as the dialog does", () => {
      const page = new Page({ rdp: true, rdpcred: ID });
      (page.win.desktopsettings as { rdpsize: string }).rdpsize = "1280x720";
      page.button("connectbutton1r").disabled = false;
      page.advance(100);
      expect(page.rdpStarts[0]).toMatchObject({ width: 1280, height: 720 });
    });

    it("names the credential in the connection request, which then carries no credentials", () => {
      const page = new Page({ rdp: true, rdpcred: ID.toUpperCase() });
      socket(page, "wss://mesh.example.com/mstscrelay.ashx").send(infos);
      const sent = JSON.parse(page.sent[0]!.data as string) as [string, Record<string, unknown>];
      expect(sent[0]).toBe("infos");
      expect(sent[1]).toMatchObject({ ip: "node//abc", domain: "", username: "", password: "", options: { savepass: true, flags: 47, useSavedCredential: ID.toUpperCase() } });
      expect(page.sent[0]!.data).not.toContain("typed-pw");
    });

    it("leaves other sockets and other messages alone", () => {
      const page = new Page({ rdp: true, rdpcred: ID });
      socket(page, "wss://mesh.example.com/control.ashx").send(infos);
      socket(page, "wss://mesh.example.com/mstscrelay.ashx").send(JSON.stringify(["mouse", 1, 2, 0, false]));
      socket(page, "wss://mesh.example.com/mstscrelay.ashx").send(new Uint8Array([1, 2]));
      socket(page, "wss://mesh.example.com/mstscrelay.ashx").send("not json");
      expect(page.sent.map((s) => s.data)).toEqual([infos, '["mouse",1,2,0,false]', new Uint8Array([1, 2]), "not json"]);
      expect(page.warn).toHaveBeenCalled();
    });

    it("does nothing in a session without one, or with an id that is not one", () => {
      for (const rdpcred of [undefined, "abc", `${ID}x`, "'; alert(1)"]) {
        const page = new Page({ rdp: true, rdpcred });
        socket(page, "wss://mesh.example.com/mstscrelay.ashx").send(infos);
        expect(page.sent[0]!.data).toBe(infos);
        page.button("connectbutton1r").disabled = false;
        page.advance(100);
        expect(page.clicks).toEqual(["connectbutton1r"]);
      }
      const desktop = new Page({ rdpcred: ID }); // not an RDP session
      socket(desktop, "wss://mesh.example.com/mstscrelay.ashx").send(infos);
      expect(desktop.sent[0]!.data).toBe(infos);
    });

    it("names it again when the view is resized and the session connects again", () => {
      const page = new Page({ rdp: true, rdpcred: ID });
      page.button("connectbutton1r").disabled = false;
      page.advance(100);
      page.rdpConnected();
      page.relayout(1920, 1005);
      page.advance(1000 + 100);
      page.advance(1000);
      expect(page.rdpStarts.map((o) => [o.width, o.height, o.password])).toEqual([[944, 479, ""], [1920, 1005, ""]]);
    });
  });

  describe("RDP sessions", () => {
    it("offer only the RDP Connect button, also where MeshCentral would not, and press it", () => {
      const page = new Page({ rdp: true });
      (page.win.updateDesktopButtons as Fn)();
      expect([page.shown("connectbutton1span"), page.shown("connectbutton1rspan"), page.shown("connectbutton1hspan")]).toEqual([false, true, false]);
      for (const b of ["connectbutton1", "connectbutton1r"]) page.button(b).disabled = false;
      page.advance(100);
      expect(page.clicks).toEqual(["connectbutton1r"]);

      // A desktop session offers only MeshAgent's, even on Windows.
      const desktop = new Page();
      desktop.offers.rdp = true;
      (desktop.win.updateDesktopButtons as Fn)();
      expect([desktop.shown("connectbutton1span"), desktop.shown("connectbutton1rspan")]).toEqual([true, false]);
    });

    it("connect again at the new size with the same credentials when the view is resized", () => {
      const page = new Page({ rdp: true });
      page.relayout(1003, 700);
      page.submitRdp();
      // Widths are a multiple of 4.
      expect(page.rdpStarts).toEqual([expect.objectContaining({ width: 1000, height: 700, username: "admin", password: "pw" })]);
      page.rdpConnected();

      // A small change is left to scaling.
      page.relayout(1020, 690);
      page.advance(2000);
      expect(page.rdpStarts).toHaveLength(1);

      // Maximised: once the window is still for a second.
      page.relayout(1900, 990);
      page.advance(500);
      page.relayout(1921, 1005);
      page.advance(999);
      expect(page.rdpStarts).toHaveLength(1);
      page.advance(200);
      expect(page.rdpStarts).toHaveLength(2);
      expect(page.rdpStarts[1]).toEqual({ domain: "", username: "admin", password: "pw", savecred: false, width: 1920, height: 1005, flags: 0x2f });
      // The old connection's close does not stop the new one.
      const again = page.win.desktop as Rdp;
      page.advance(1000);
      expect(page.win.desktop).toBe(again);
      expect(again.State).toBe(1);

      page.rdpConnected();
      page.relayout(1280, 720);
      page.advance(1200);
      expect(page.rdpStarts.map((o) => [o.width, o.height])).toEqual([[1000, 700], [1920, 1005], [1280, 720]]);
    });

    it("forget the credentials when the session ends, and wait for an open dialog", () => {
      const page = new Page({ rdp: true });
      page.submitRdp();
      page.rdpConnected();
      page.win.xxdialogMode = 2;
      page.relayout(1600, 900);
      page.advance(1200);
      expect(page.rdpStarts).toHaveLength(1);
      page.win.xxdialogMode = null;

      // The user disconnects with MeshCentral's button.
      (page.win.connectDesktop as Fn)(null, 4);
      page.advance(100);
      expect(page.win.desktop).toBeNull();
      page.relayout(1200, 800);
      page.advance(2000);
      expect(page.rdpStarts).toHaveLength(1);

      // A connection that fails or is closed by the device.
      const failed = new Page({ rdp: true });
      failed.submitRdp();
      failed.rdpConnected().Stop();
      failed.advance(100);
      failed.relayout(1200, 800);
      failed.advance(2000);
      expect(failed.rdpStarts).toHaveLength(1);
    });

    it("give up connecting again if the old connection does not close", () => {
      const page = new Page({ rdp: true });
      page.submitRdp();
      const m = page.rdpConnected();
      m.Stop = () => undefined;
      page.relayout(1600, 900);
      page.advance(1000 + 6000);
      expect(page.rdpStarts).toHaveLength(1);
      // And forgets the credentials.
      m.State = 0;
      (page.win.onDesktopStateChange as Fn)(m, 0);
      page.relayout(1200, 700);
      page.advance(2000);
      expect(page.rdpStarts).toHaveLength(1);
    });

    it("keep a fixed size from the desktop settings", () => {
      const page = new Page({ rdp: true });
      (page.win.desktopsettings as { rdpsize: string }).rdpsize = "1280x720";
      page.submitRdp({ width: 1280, height: 720 });
      expect(page.rdpStarts[0]).toMatchObject({ width: 1280, height: 720 });
      page.rdpConnected();
      page.relayout(1600, 900);
      page.advance(2000);
      expect(page.rdpStarts).toHaveLength(1);
    });
  });

  describe("settings", () => {
    it("asks for frames every 20 ms once, and keeps a later choice", () => {
      const page = new Page();
      const apply = () => (page.win.applyDesktopSettings as () => void)();
      apply();
      expect(page.win.desktopsettings).toMatchObject({ framerate: 20, easyrmm: 1, quality: 40 });
      expect(JSON.parse(page.storage.get("desktopsettings")!)).toMatchObject({ framerate: 20, easyrmm: 1 });

      // The user picks "Medium" in MeshCentral's dialog, which saves the whole object.
      (page.win.desktopsettings as { framerate: number }).framerate = 100;
      apply();
      expect(page.win.desktopsettings).toMatchObject({ framerate: 100 });
    });

    it("still applies when the browser blocks storage", () => {
      const page = new Page({ storageBlocked: true });
      (page.win.applyDesktopSettings as () => void)();
      expect(page.win.desktopsettings).toMatchObject({ framerate: 20 });
      expect(page.warn).not.toHaveBeenCalled();
    });
  });

  describe("scaling to the view", () => {
    it("asks the agent for the size the desktop is shown at, rounded up", () => {
      const page = new Page();
      const m = page.desktop();
      m.ProcessScreenMsg(1920, 1080);
      // 1024 × min(945/1920, 479/1080) = 454.2, rounded up to a step of 32.
      expect(m.sent).toEqual([480]);
      // The agent applies it and reports floor(1920 × 480/1024) × floor(1080 × 480/1024).
      m.ProcessScreenMsg(900, 506);
      expect(m.sent).toEqual([480, 480]);

      // The window grows: the agent is asked for more, after the resize settles.
      page.relayout(1890, 958);
      page.advance(299);
      expect(m.sent).toHaveLength(2);
      page.advance(1);
      expect(m.sent.at(-1)).toBe(928);
      m.ProcessScreenMsg(1740, 978);
      expect(m.sent.at(-1)).toBe(928);
    });

    it("on high-density screens, asks for device pixels, up to the settings' most", () => {
      const page = new Page();
      page.win.devicePixelRatio = 2;
      const m = page.desktop();
      m.ProcessScreenMsg(1920, 1080);
      // 1024 × min(1890/1920, 958/1080) = 908.3 → 928.
      expect(m.sent).toEqual([928]);
      page.relayout(1890, 958);
      page.advance(300);
      expect(m.sent.at(-1)).toBe(1024);

      (page.win.desktopsettings as { scaling: string }).scaling = "512";
      page.relayout(1880, 958);
      page.advance(300);
      expect(m.sent.at(-1)).toBe(512);
    });

    it("keeps working with agents that ignore scaling", () => {
      const page = new Page();
      const m = page.desktop();
      m.ProcessScreenMsg(1920, 1080);
      // MeshAgent on Linux keeps sending the full size.
      m.ProcessScreenMsg(1920, 1080);
      page.relayout(946, 480);
      page.advance(300);
      expect(m.sent).toEqual([480]);
    });

    it("follows a new remote screen size", () => {
      const page = new Page();
      const m = page.desktop();
      m.ProcessScreenMsg(1920, 1080);
      // The remote screen changes to 1280×1024 while the agent scales at 480.
      m.ProcessScreenMsg(600, 480);
      // 1024 × min(945/1280, 479/1024) = 479.0 → 480: nothing new to ask.
      expect(m.sent.at(-1)).toBe(480);
      page.relayout(1890, 958);
      page.advance(300);
      expect(m.sent.at(-1)).toBe(960);
    });

    it("sends the full size in MeshCentral's 1:1 zoom mode", () => {
      const page = new Page();
      page.win.deskAspectRatio = 1;
      const m = page.desktop();
      m.ProcessScreenMsg(1920, 1080);
      expect(m.sent).toEqual([1024]);
    });

    it("rescales only a connected session view", () => {
      const page = new Page();
      const m = page.desktop();
      m.ProcessScreenMsg(1920, 1080);
      m.State = 0;
      page.relayout(1890, 958);
      page.advance(300);
      expect(m.sent).toEqual([480]);

      // MeshCentral's multi-device grid keeps its own scaling.
      const grid = page.desktop("kvmid_1");
      grid.ProcessScreenMsg(1920, 1080);
      expect(grid.sent).toEqual([1024]);
    });
  });

  describe("pace on a slow connection", () => {
    /** One poll: the gateway reports `held` more milliseconds than before. */
    async function poll(page: Page, held: number) {
      page.gateway.held += held;
      page.advance(500);
      await settle();
      await settle();
    }

    it("asks for frames less often while the gateway holds the pictures, and more often once clear", async () => {
      const page = new Page();
      (page.win.desktopsettings as { framerate: number }).framerate = 20;
      const m = page.desktop();
      m.FrameRateTimer = 20;
      await poll(page, 0);
      expect(page.asked).toEqual(["/.easyrmm/pressure?node=node%2F%2Fabc%24%409"]);
      // Held 400 of every 500 ms.
      for (let i = 0; i < 6; i++) await poll(page, 400);
      expect(m.timers).toEqual([100, 200, 400, 800, 1000]);
      // Some holding, but under a fifth: stays.
      await poll(page, 50);
      expect(m.timers.at(-1)).toBe(1000);
      // Clear: halves every second poll, down to the settings' timer.
      for (let i = 0; i < 12; i++) await poll(page, 0);
      expect(m.timers.slice(5)).toEqual([500, 250, 125, 62, 31, 20]);
      for (let i = 0; i < 4; i++) await poll(page, 0);
      expect(m.timers).toHaveLength(11);
    });

    it("asks only during a session, and starts over after a reconnect or a restarted count", async () => {
      const page = new Page();
      const m = page.desktop();
      m.State = 0;
      await poll(page, 0);
      expect(page.asked).toEqual([]);
      m.State = 3;
      await poll(page, 0);
      // The gateway's count restarts (a new agent relay): no comparison.
      page.gateway.held = 0;
      await poll(page, 0);
      await poll(page, 0);
      expect(m.timers).toEqual([]);

      // A reconnect creates a new module; the page still asks once a poll.
      const again = page.desktop();
      again.FrameRateTimer = 20;
      const before = page.asked.length;
      await poll(page, 0);
      await poll(page, 450);
      expect(page.asked).toHaveLength(before + 2);
      expect(again.timers).toEqual([100]);
      expect(m.timers).toEqual([]);
    });

    it("stops asking a page outside EasyRMM, or without a desktop grant", async () => {
      for (const status of [404, 403]) {
        const page = new Page();
        page.desktop();
        page.gateway.status = status;
        await poll(page, 0);
        await poll(page, 0);
        expect(page.asked).toHaveLength(1);
      }
      const offline = new Page({ fetch: false });
      offline.desktop();
      await poll(offline, 0);
      expect(offline.asked).toEqual([]);
    });
  });

  describe("decoding", () => {
    it("decodes off the main thread and draws in arrival order", async () => {
      const page = new Page();
      const m = page.desktop();
      m.ProcessPictureMsg(tile(1, 2, 3), 0, 0);
      m.ProcessPictureMsg(tile(4, 5), 64, 0);
      expect(page.decodes.map((d) => d.blob.size)).toEqual([3, 2]);

      const [first, second] = [new FakeBitmap("first"), new FakeBitmap("second")];
      page.decodes[1]!.resolve(second);
      await settle();
      expect(m.draw).not.toHaveBeenCalled();
      page.decodes[0]!.resolve(first);
      await settle();
      expect(m.draw.mock.calls).toEqual([
        [first, 0, 0],
        [second, 64, 0],
      ]);
      expect(first.close).toHaveBeenCalled();
      expect(second.close).toHaveBeenCalled();
    });

    it("skips a tile that fails to decode or arrives after a reset", async () => {
      const page = new Page();
      const m = page.desktop();
      m.ProcessPictureMsg(tile(1), 0, 0);
      m.ProcessPictureMsg(tile(2), 64, 0);
      page.decodes[0]!.reject(new Error("corrupt"));
      const late = new FakeBitmap("late");
      m.KillDraw = 5; // a new screen size discarded the tiles in flight
      page.decodes[1]!.resolve(late);
      await settle();
      expect(m.draw).not.toHaveBeenCalled();
      expect(late.close).toHaveBeenCalled();
    });

    it("keeps MeshCentral's decoding where createImageBitmap is missing", () => {
      const page = new Page({ createImageBitmap: false });
      const m = page.desktop();
      const own = m.ProcessPictureMsg;
      m.ProcessPictureMsg(tile(1), 0, 0);
      expect(own).toHaveBeenCalled();
    });
  });

  it("leaves a page without MeshCentral's functions alone", () => {
    const page = new Page({ bare: true });
    page.advance(25_000);
    expect(page.win.CreateAgentRemoteDesktop).toBeUndefined();
    expect(page.clicks).toEqual([]);
    expect(page.warn).not.toHaveBeenCalled();
  });
});
