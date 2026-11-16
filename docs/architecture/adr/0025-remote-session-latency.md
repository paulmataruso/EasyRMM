# ADR-0025: Remote session latency

* Status: Accepted (2026-11-16).
* Refines: ADR-0005 (MeshCentral integration), ADR-0014 (edge gateway).

## Context
Remote desktop through EasyRMM felt slow. We measured where the time goes
before changing anything, on a Linux test device with a 1920×1080 virtual
desktop, MeshAgent from the EasyRMM server, Chromium driving the console,
and the session embedded as the console embeds it:

* **Our path is not the delay.** The gateway (ADR-0014) and MeshCentral's
  relay add about 4 ms between the agent's socket and the browser's.
  Key-to-screen latency on a LAN, about 150–170 ms at the median, is
  MeshAgent's capture loop on Linux: it re-opens the display, captures the
  whole screen and then sleeps for the frame timer, and reads input once
  per loop. On Windows, input has its own thread and capture is
  incremental.
* **MeshCentral's defaults are conservative.** The session view asks the
  agent to wait 50 ms between captures ("Fast"; agents accept 20 to 5000),
  at 100 % scale whatever the size the session is shown at, and the user
  clicks **Connect** after the page loads.
* **Decoding blocks the page.** Each picture arrives as JPEG, is turned
  into a base64 `data:` URL and decoded by an `<img>` on the main thread.
  `createImageBitmap` on the same tiles is 2.5–4× faster for bursts and
  runs off the main thread.
* **MeshCentral's pages are not compressed.** The device page and its
  scripts are 4.6 MB; MeshCentral can gzip them (1.1 MB) but does not by
  default. Desktop pictures are JPEG and the WebSockets are not touched.
* **On a slow connection, buffers decide latency.** With the viewer on an
  emulated 2 Mbit/s link and the remote screen changing everywhere, key
  presses took tens of seconds to show. MeshCentral's desktop multiplexer
  keeps only the newest picture of each part of the screen and stops
  reading the agent when the viewer falls behind, which is right; but
  everything already written to a socket is sent in order. Kernel socket
  buffers on loopback grow to megabytes (MeshCentral's send buffer toward
  the viewer, its receive buffer from the agent, and ours), so the viewer
  was shown what happened seconds ago.

## Decision
* **Session view tuning.** The server writes MeshCentral's
  `scripts/custom.js` (served from `domains[""].webPublicPath`, under the
  configuration folder it already writes; MeshCentral reads it on each
  request, no restart). Every MeshCentral page loads it after its own
  scripts. It:
  * connects as soon as the device page is ready (the view the console
    opened: desktop, terminal or files);
  * sets the agent's frame timer to 20 ms ("Very fast") once; a later
    choice in MeshCentral's desktop settings is kept;
  * asks the agent for no more pixels than the session view shows (device
    pixels, rounded up to 1/32), and again when the window or the view is
    resized, so maximising the window raises the resolution and shrinking
    it lowers what the agent encodes and sends. The scaling chosen in the
    desktop settings is the most it asks for; 1:1 zoom asks for 100 %.
    Agents that ignore scaling (MeshAgent on Linux) are recognised by the
    size they report;
  * decodes pictures with `createImageBitmap`, keeping MeshCentral's
    drawing order, and releases each bitmap once drawn.

  Each change checks that what it changes exists, so a MeshCentral update
  that renames something turns that change off instead of breaking the
  page. The script is tested against a fake MeshCentral page in the web
  test suite.
* **Compression.** `settings.compression` is on: MeshCentral's pages and
  scripts are gzipped (desktop pictures are JPEG and WebSockets are
  unchanged).
* **Small socket queues on relays** (Linux; elsewhere the kernel's
  defaults apply):
  * the gateway's socket to the browser for a desktop relay keeps at most
    16 KB unsent (`TCP_NOTSENT_LOWAT`); bytes in flight are not limited,
    so neither is throughput;
  * the gateway's connections to MeshCentral for relays use an 8 KB
    receive buffer and 1400-byte segments, which keeps MeshCentral's send
    buffer toward the viewer to about four times that, and keep at most
    32 KB unsent;
  * the agent's side of a desktop relay (MeshCentral asks the agent to
    join it with `p=2`) has a fixed 128 KB receive buffer (`SO_RCVBUF`;
    the kernel doubles it), which bounds the window it advertises and so
    the agent's own send queue. 256 KB carries 2.5 MB/s at a 100 ms round
    trip, more than a scaled desktop needs. (`TCP_WINDOW_CLAMP` does not
    hold: the kernel raises it again while tuning the buffer.);
  * before writing the agent's pictures into MeshCentral, the gateway
    reads how much MeshCentral has received but not read on its side of
    the connection (`sock_diag`, the interface `ss` uses; MeshCentral runs
    on the same host, ADR-0004) and waits while that is over 32 KB,
    checking every 1 ms, then every 4 ms. When MeshCentral stops reading
    the agent, the agent stops sending soon after, and its next pictures
    are current. If the queue cannot be read, writes are not held.
* **The frame timer follows the viewer.** The gateway adds up, per
  device, how long it held the agent's pictures, and answers
  `GET /.easyrmm/pressure?node=…` with that total for a session holding a
  desktop grant on the device (403 otherwise; MeshCentral has no route
  under `/.easyrmm/`). The session view asks twice a second. When pictures
  were held for a fifth of the time or more, it asks the agent to look for
  changes half as often (from 100 ms, at most once a second); after two
  answers under 2 %, twice as often again, down to the desktop settings'
  frame timer. On a slow connection the agent then sends the screen as it
  is now, at the rate the connection carries, instead of a backlog.

## Consequences
* Measured on a LAN, at 1920×1080, stock MeshCentral against the tuned
  view: the first picture arrives in 2.4 s instead of 3.9 s; under a
  scrolling load the browser draws 76 tiles/s instead of 27 (376 KB/s
  instead of 127), with the 95th percentile from arrival to drawing at
  40 ms instead of 68. Key-to-screen latency on the Linux test device is
  unchanged (MeshAgent's capture loop); the frame timer and scaling gains
  have not yet been measured on a Windows device.
* On a slow link: see **Measurements** below.
* A session shown in a small window costs the agent and the network less,
  and a maximised one is sharp, without opening MeshCentral's settings.
* The tuning is a script against MeshCentral 1.3.1's page internals. Each
  MeshCentral update has to be checked against it; the web tests describe
  what it relies on.
* Polling the queue costs a netlink request per write while MeshCentral is
  reading, and every 4 ms per session while it is not. The pressure check
  is a small request twice a second per open desktop session; its grant
  lookup is cached for the grant cache lifetime.

## Measurements
The Linux test device at 1920×1080, the session in Chromium as the console
embeds it, the browser's link emulated (DevTools) at 2 Mbit/s with 40 ms
latency, and the browser leg's segments clamped to 1448 bytes as on a real
network (on loopback they are 64 KB, which inflates send buffers). The load
is an xterm filling the screen with new text continuously; a probe window
changes colour on a key press, and each probe measures how long until the
new colour is drawn in the browser (10 probes, 30 s limit each).

| Build | Key press shown under load | Queued between agent and browser |
|---|---|---|
| Before (stock MeshCentral session view, gateway without queue limits) | 0 of 10 within 30 s | about 15 MB |
| Small socket queues and pacing | 10 of 10; median 14.9 s, 95th percentile 16.2 s | about 2 MB |
| And the frame timer following the viewer | median 3.8 s, 95th percentile 5.4 s | about 0.6 MB |
| And the smaller relay queues above (this record) | median 3.5 s, 95th percentile 4.7 s | about 0.17 MB, in the test browser's own receive buffer |

What is left on that link is mostly the time to send one screen's worth of
changes; a lower quality or scale in the desktop settings shortens it.

The same load on the LAN: the key press shows at a median of 231 ms (95th
percentile 325 ms) and the browser draws 574 KB/s; with the earlier,
larger relay queues (64 KB and 16 KB) it was 235 ms (289 ms) and 480 KB/s,
so the smaller queues cost nothing measurable there. Without load, key to
screen is a median of 167 ms on this device, MeshAgent's capture loop on
Linux.
