/*
 * EasyRMM remote session tuning for MeshCentral's device page (ADR-0025).
 *
 * EasyRMM writes this file as MeshCentral's scripts/custom.js, which every
 * MeshCentral page loads after its own scripts and before its inline ones.
 * It changes only how the embedded session view behaves:
 *
 *  - Sessions connect as soon as the page has opened the device, instead of
 *    waiting for a click on MeshCentral's Connect button.
 *  - The agent looks for screen changes every 20 ms instead of 50 ms
 *    (MeshCentral's "Very fast"), once; a later choice in the desktop
 *    settings is kept.
 *  - The agent scales the desktop down to the size it is shown at, so it
 *    encodes and sends no more pixels than the browser can show, and scales
 *    again when the window is resized. The scaling chosen in the desktop
 *    settings is the most it sends.
 *  - Pictures are decoded off the page's main thread (createImageBitmap)
 *    instead of through a base64 data: URL.
 *  - When the viewer falls behind (a slow connection), the agent is asked
 *    to look for changes less often, so the view shows the screen as it is
 *    now rather than seconds ago, and more often again once it keeps up.
 *  - An RDP session (ADR-0026) asks for the credentials straight away, shows
 *    only the RDP Connect button, and when the view is resized, connects
 *    again at the new size with the credentials typed for this session.
 *
 * Each change first checks that what it changes is there, so a MeshCentral
 * update that renames something turns that change off rather than breaking
 * the page.
 */
(function (w) {
  'use strict';

  var SETTINGS_VERSION = 1;
  // MeshCentral's "Very fast"; agents accept 20 to 5000 ms.
  var FRAME_TIMER = 20;
  // Agents accept scaling from 64 to 4096, in 1/1024ths.
  var MIN_SCALING = 128;
  var SCALING_STEP = 32;
  var RESIZE_DELAY = 300;
  // The Connect button of each session view (MeshCentral's viewmode).
  var CONNECT_BUTTONS = { '11': 'connectbutton1', '12': 'connectbutton2', '13': 'p13Connect' };
  // RDP sessions open the desktop view with rdp=1.
  var RDP = /[?&]rdp=1(?:&|$)/.test(w.location.search);
  var RDP_CONNECT = 'connectbutton1r';
  // Windows accepts session sizes from 200 to 8192 pixels; widths are kept to
  // a multiple of 4, which older RDP servers need. A resize by less than
  // RDP_TOLERANCE is left to scaling; a larger one connects again once the
  // window has been still for RDP_RESIZE_DELAY.
  var RDP_MIN = 200;
  var RDP_MAX = 8192;
  var RDP_TOLERANCE = 32;
  var RDP_RESIZE_DELAY = 1000;
  var RDP_STOP_WAIT = 5000;
  var CONNECT_POLL = 100;
  var CONNECT_WAIT = 20000;
  // How long the EasyRMM gateway held this device's pictures because
  // MeshCentral had stopped reading the agent, which it does while a viewer
  // is behind. Asked twice a second during a session.
  var PRESSURE_PATH = '/.easyrmm/pressure';
  var PRESSURE_POLL = 500;
  // Held for a fifth of the time or more: ask for frames half as often
  // (from 100 ms, up to once a second). Held for under 2 % twice in a row:
  // twice as often, down to the desktop settings' frame timer.
  var PRESSURE_HIGH = 0.2;
  var PRESSURE_CLEAR = 0.02;
  var SLOW_FRAME_TIMER = 100;
  var MAX_FRAME_TIMER = 1000;

  var doc = w.document;
  var main = null; // the desktop module drawing the session view
  var resizeTimer = null;
  // The RDP connection's options, credentials included, kept to connect again
  // at another size; forgotten when the session ends any other way. The RDP
  // module keeps the same credentials for as long as it is connected.
  var rdpOptions = null;
  var rdpSize = null; // the size last asked for
  var rdpTimer = null;
  var rdpRestarting = null; // the module being stopped to connect again

  function wrap(name, after) {
    var original = w[name];
    if (typeof original !== 'function') { return; }
    w[name] = function () {
      var out = original.apply(this, arguments);
      try { after(out); } catch (e) { report(e); }
      return out;
    };
  }

  function report(e) {
    if (w.console && w.console.warn) { w.console.warn('EasyRMM viewer tuning:', e); }
  }

  // Decode pictures with createImageBitmap, keeping MeshCentral's ordering:
  // each tile takes its number on arrival and is drawn in that order.
  function fastDecode(m) {
    if (typeof w.createImageBitmap !== 'function' || typeof w.Blob !== 'function' || typeof m.ProcessPictureMsg !== 'function' ||
      typeof m.DoPendingOperations !== 'function' || !m.Canvas || typeof m.Canvas.drawImage !== 'function') { return; }
    m.ProcessPictureMsg = function (data, X, Y) {
      var r = ++m.tilesReceived;
      var bytes = data.subarray ? data.subarray(4) : data.slice(4);
      w.createImageBitmap(new w.Blob([bytes])).then(function (img) {
        if ((m.Canvas != null) && (m.KillDraw < r) && (m.State != 0)) {
          m.PendingOperations.push([r, 2, img, X, Y]);
          while (m.DoPendingOperations()) { /* draw what is ready */ }
        } else {
          if (img.close) { img.close(); }
          m.PendingOperations.push([r, 0]);
        }
      }, function () {
        m.PendingOperations.push([r, 0]);
        if (m.State != 0) { while (m.DoPendingOperations()) { /* draw what is ready */ } }
      });
    };
    // A drawn bitmap is not drawn again; release it now rather than at the
    // next garbage collection.
    var ctx = m.Canvas, draw = ctx.drawImage;
    ctx.drawImage = function (img) {
      var out = draw.apply(this, arguments);
      if (w.ImageBitmap && img instanceof w.ImageBitmap && img.close) { img.close(); }
      return out;
    };
  }

  // Ask the agent for no more pixels than the view shows. Every scaling
  // MeshCentral sends passes through here; what it asks for (the desktop
  // settings) is the most the agent is asked to send.
  function autoScale(m) {
    if (typeof m.SendCompressionLevel !== 'function' || typeof m.ProcessScreenMsg !== 'function') { return; }
    var send = m.SendCompressionLevel, screen = m.ProcessScreenMsg;
    var sent = 0; // the scaling last sent to the agent
    var recent = [1024]; // scalings the agent may still be sending at
    var remote = null; // the remote screen's size at 100%

    m.easyrmmFit = function () {
      var settings = w.desktopsettings;
      var most = Number(settings && settings.scaling) || 1024;
      var parent = doc.getElementById('DeskParent');
      if (!remote || !parent || w.deskAspectRatio === 1) { return most; }
      var width = parent.clientWidth, height = parent.clientHeight;
      if (width < 64 || height < 64) { return most; }
      var ratio = w.devicePixelRatio || 1;
      var fit = 1024 * Math.min(width * ratio / remote[0], height * ratio / remote[1]);
      // Round up, so the picture is never smaller than the space it fills.
      fit = Math.ceil(fit / SCALING_STEP) * SCALING_STEP;
      return Math.max(MIN_SCALING, Math.min(most, fit));
    };
    m.SendCompressionLevel = function (type, level, scaling, frametimer) {
      var fit = m.easyrmmFit();
      if (fit !== sent) { recent = [1024, sent, fit]; }
      sent = fit;
      return send.call(m, type, level, sent, frametimer);
    };
    m.ProcessScreenMsg = function (width, height) {
      // Agents that scale report floor(size * scaling / 1024); some
      // (MeshAgent on Linux) ignore scaling and report the full size. A
      // size that fits neither is a new remote screen size, reported at
      // the scaling last sent (100% before anything was sent).
      var known = remote && recent.some(function (s) {
        return s && width === Math.floor(remote[0] * s / 1024) && height === Math.floor(remote[1] * s / 1024);
      });
      if (!known) {
        var scale = sent || 1024;
        remote = [Math.round(width * 1024 / scale), Math.round(height * 1024 / scale)];
      }
      return screen.apply(m, arguments);
    };
    m.easyrmmRescale = function () {
      if (m.State != 0 && remote && m.easyrmmFit() !== sent) { m.SendCompressionLevel(m.ImageType); }
    };
  }

  // Follow the pressure the gateway reports, once per page, for whichever
  // module draws the session view. A page not served through EasyRMM's
  // gateway (no such path) or without a desktop grant stops asking.
  var pressure = null;
  function adaptRate() {
    if (pressure !== null || typeof w.fetch !== 'function') { return; }
    var tick = 0, last = null, clear = 0, busy = false;
    pressure = w.setInterval(function () {
      tick++;
      var m = main, node = w.currentNode && w.currentNode._id;
      if (!m || m.State != 3 || typeof node !== 'string') { last = null; return; }
      if (busy) { return; }
      busy = true;
      w.fetch(PRESSURE_PATH + '?node=' + encodeURIComponent(node), { credentials: 'same-origin', cache: 'no-store' }).then(function (r) {
        if (r.status === 403 || r.status === 404) { w.clearInterval(pressure); }
        return r.ok ? r.json() : null;
      }).then(function (p) {
        busy = false;
        if (!p || typeof p.held !== 'number' || !p.active || main !== m) { last = null; return; }
        if (last && last.m === m && p.held >= last.held) { adjust(m, (p.held - last.held) / ((tick - last.tick) * PRESSURE_POLL)); }
        last = { m: m, held: p.held, tick: tick };
      }).catch(function () { busy = false; last = null; });
    }, PRESSURE_POLL);

    function adjust(m, held) {
      var settings = w.desktopsettings;
      var base = Number(settings && settings.framerate) || FRAME_TIMER;
      var current = Number(m.FrameRateTimer) || base;
      var next = current;
      if (held >= PRESSURE_HIGH) {
        clear = 0;
        next = Math.min(MAX_FRAME_TIMER, Math.max(current * 2, SLOW_FRAME_TIMER));
      } else if (held < PRESSURE_CLEAR) {
        if (++clear >= 2) {
          clear = 0;
          next = Math.max(base, Math.floor(current / 2));
        }
      } else {
        clear = 0;
      }
      if (next !== current) { m.SendCompressionLevel(m.ImageType, null, null, next); }
    }
  }

  function onResize() {
    if (resizeTimer) { w.clearTimeout(resizeTimer); }
    resizeTimer = w.setTimeout(function () {
      resizeTimer = null;
      try { if (main && main.easyrmmRescale) { main.easyrmmRescale(); } } catch (e) { report(e); }
    }, RESIZE_DELAY);
    if (rdpOptions) {
      if (rdpTimer) { w.clearTimeout(rdpTimer); }
      rdpTimer = w.setTimeout(function () {
        rdpTimer = null;
        try { rdpResize(); } catch (e) { report(e); }
      }, RDP_RESIZE_DELAY);
    }
  }

  // The size an RDP session fills, as MeshCentral computes it: the session
  // view (the default, or "canvas") or the browser window. A fixed size in
  // the desktop settings is not followed (null).
  function rdpView() {
    var settings = w.desktopsettings;
    var mode = settings && settings.rdpsize;
    var width, height;
    if (!mode || mode === 'canvas') {
      var parent = doc.getElementById('DeskParent');
      if (!parent) { return null; }
      width = parent.offsetWidth;
      height = parent.offsetHeight;
    } else if (mode === 'browser') {
      width = w.innerWidth;
      height = w.innerHeight;
    } else {
      return null;
    }
    if (!(width >= RDP_MIN && height >= RDP_MIN)) { return null; }
    width = Math.min(RDP_MAX, width);
    return [width - width % 4, Math.min(RDP_MAX, height)];
  }

  // Connect again at the size the view has now, once the current connection
  // has closed: MeshCentral clears its session state when a module closes,
  // so a new one started before then would be stopped too.
  function rdpResize() {
    var d = w.desktop;
    // MeshCentral's connectDesktop does nothing while a dialog is open.
    if (!rdpOptions || !d || d.contype != 4 || d.State != 3 || rdpRestarting || w.xxdialogMode) { return; }
    var size = rdpView();
    if (!size || !rdpSize || (Math.abs(size[0] - rdpSize[0]) < RDP_TOLERANCE && Math.abs(size[1] - rdpSize[1]) < RDP_TOLERANCE)) { return; }
    var options = {};
    for (var k in rdpOptions) { if (Object.prototype.hasOwnProperty.call(rdpOptions, k)) { options[k] = rdpOptions[k]; } }
    options.width = size[0];
    options.height = size[1];
    rdpRestarting = d;
    w.connectDesktop(null, 4); // MeshCentral's own disconnect
    var waited = 0;
    var timer = w.setInterval(function () {
      waited += CONNECT_POLL;
      if (d.State != 0 && waited < RDP_STOP_WAIT) { return; }
      w.clearInterval(timer);
      rdpRestarting = null;
      if (d.State == 0 && w.desktop == null) { w.connectDesktop(null, 4, options); }
      else { rdpOptions = null; }
    }, CONNECT_POLL);
  }

  // Keep what an RDP connection was started with, sized to the view.
  function trackRdp(connect) {
    return function (e, contype, options) {
      if (contype == 4 && options && typeof options === 'object' && w.desktop == null) {
        var size = rdpView();
        if (size && options.width && options.height) {
          options.width = size[0];
          options.height = size[1];
        }
        rdpOptions = null;
        rdpSize = null;
        if (!options.servercred && size) {
          rdpOptions = {};
          for (var k in options) { if (Object.prototype.hasOwnProperty.call(options, k)) { rdpOptions[k] = options[k]; } }
          rdpSize = size;
        }
      }
      return connect.apply(this, arguments);
    };
  }

  // A session that ends other than to connect again forgets the credentials.
  function trackRdpState(change) {
    return function (module, state) {
      if (state == 0 && module && module.contype == 4 && module !== rdpRestarting) {
        rdpOptions = null;
        rdpSize = null;
      }
      return change.apply(this, arguments);
    };
  }

  // Each view shows only its own way of connecting: an RDP session the RDP
  // Connect button (also for a device MeshCentral would not offer it for),
  // a desktop session MeshAgent's.
  function onlyOwnConnect() {
    var agent = doc.getElementById('connectbutton1span');
    var hardware = doc.getElementById('connectbutton1hspan');
    var rdp = doc.getElementById('connectbutton1rspan');
    if (!agent || !rdp) { return; }
    if (RDP) {
      var offered = agent.style.display !== 'none' || rdp.style.display !== 'none';
      rdp.style.display = offered ? '' : 'none';
      agent.style.display = 'none';
      if (hardware) { hardware.style.display = 'none'; }
    } else {
      rdp.style.display = 'none';
    }
  }

  function tuneDesktop(m) {
    if (!m || typeof m !== 'object') { return; }
    fastDecode(m);
    // Only the session view; MeshCentral's multi-device grid has settings
    // of its own.
    var canvas = m.CanvasId;
    if (canvas && canvas.id === 'Desk') {
      autoScale(m);
      main = m;
      adaptRate();
    }
  }

  // Once per settings version: the faster frame timer. MeshCentral saves the
  // whole settings object, so a later choice in its dialog is kept.
  function tuneSettings() {
    var s = w.desktopsettings;
    if (!s || typeof s !== 'object' || s.easyrmm >= SETTINGS_VERSION) { return; }
    s.framerate = FRAME_TIMER;
    s.easyrmm = SETTINGS_VERSION;
    try { w.localStorage.setItem('desktopsettings', JSON.stringify(s)); } catch (e) { /* storage blocked: this page only */ }
  }

  function autoConnect() {
    var mode = /[?&]viewmode=(\d+)/.exec(w.location.search);
    var id = mode && CONNECT_BUTTONS[mode[1]];
    if (RDP && id === CONNECT_BUTTONS['11']) { id = RDP_CONNECT; }
    if (!id) { return; }
    var polls = 0;
    var timer = w.setInterval(function () {
      var button = doc.getElementById(id);
      if (button && !button.disabled && button.offsetParent !== null) {
        w.clearInterval(timer);
        button.click();
      } else if (++polls * CONNECT_POLL >= CONNECT_WAIT) {
        w.clearInterval(timer);
      }
    }, CONNECT_POLL);
  }

  // The desktop modules are created by the page's own scripts, which are
  // loaded before this one.
  if (typeof w.CreateAgentRemoteDesktop === 'function') {
    wrap('CreateAgentRemoteDesktop', tuneDesktop);
  }
  // The settings and the page start-up are defined by inline scripts after
  // this one; the page starts on load, after DOMContentLoaded.
  doc.addEventListener('DOMContentLoaded', function () {
    try {
      if (typeof w.applyDesktopSettings === 'function') {
        var apply = w.applyDesktopSettings;
        w.applyDesktopSettings = function () {
          try { tuneSettings(); } catch (e) { report(e); }
          return apply.apply(this, arguments);
        };
      }
      if (typeof w.connectDesktop === 'function') {
        w.connectDesktop = trackRdp(w.connectDesktop);
        if (typeof w.onDesktopStateChange === 'function') { w.onDesktopStateChange = trackRdpState(w.onDesktopStateChange); }
        wrap('updateDesktopButtons', onlyOwnConnect);
        // MeshCentral lays the desktop out again whenever the window, the
        // view or the zoom mode changes.
        wrap('deskAdjust', onResize);
        w.addEventListener('resize', onResize);
        w.addEventListener('load', autoConnect);
      }
    } catch (e) { report(e); }
  });
})(window);
