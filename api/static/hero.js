/* Home hero: a 3D ASCII network drawn into a character grid on a canvas.
   Own projection, own z-buffer, no libraries. Story loop runs ~12s. */
(function () {
  var canvas = document.getElementById("hero-canvas");
  if (!canvas || !canvas.getContext) { return; }
  var ctx = canvas.getContext("2d");
  var captionEl = document.getElementById("hero-caption");

  var RAMP = " .:-=+*#%@";
  var INK = 1, BLUE = 2, RED = 3;
  var PEN = { 1: "#161513", 2: "#1D3BD1", 3: "#C4332B" };

  var CENTER = { label: "your site", r: 0.95, p: [0, 0, 0], tip: "your site · what every visitor loads" };
  var NODES = [
    { id: "cdn", label: "CDN", r: 0.44, p: [-0.3, 2.9, 0.3], tip: "CDN · a script on every page" },
    { id: "bucket", label: "bucket", r: 0.40, p: [2.7, 1.5, -0.7], tip: "bucket · the deploy pulls files from it" },
    { id: "github", label: "GitHub", r: 0.40, p: [3.0, -1.1, 0.6], tip: "GitHub · the build installs from it" },
    { id: "api", label: "API", r: 0.38, p: [1.3, -2.8, -0.4], tip: "API · live requests go here" },
    { id: "analytics", label: "analytics", r: 0.38, p: [-1.6, -2.7, 0.5], tip: "analytics · runs in the browser" },
    { id: "payments", label: "payments", r: 0.40, p: [-3.0, -0.8, -0.6], tip: "payments · checkout loads it" },
    { id: "fonts", label: "fonts", r: 0.38, p: [-2.7, 1.5, 0.7], tip: "fonts · loaded on every page" }
  ];
  var STRANGER = { id: "stranger", label: "stranger", r: 0.42, p: [2.3, 2.5, -0.9], tip: "stranger · whoever bought the domain" };
  var LINKS = [["bucket", "github"], ["analytics", "payments"], ["cdn", "fonts"]];
  var BY_ID = {};
  NODES.forEach(function (n) { BY_ID[n.id] = n; });

  /* story: start time of each beat, then the loop length */
  var BEATS = [
    { t: 0, cap: "" },
    { t: 2.0, cap: "2019 · trusted by 100,000 sites" },
    { t: 4.2, cap: "domain sold" },
    { t: 6.0, cap: "malware reaches every visitor" },
    { t: 8.6, cap: "" },
    { t: 10.4, cap: "know what your code is tethered to" }
  ];
  var LOOP = 12.4;

  /* a fixed scatter cloud, so "dust" looks the same every loop */
  var DUST = [];
  (function () {
    var seed = 7;
    function rnd() { seed = (seed * 1103515 + 12345) & 0x7fffffff; return seed / 0x7fffffff; }
    for (var i = 0; i < 44; i++) {
      var a = rnd() * Math.PI * 2, u = rnd() * 2 - 1, s = Math.sqrt(1 - u * u);
      DUST.push([s * Math.cos(a), u, s * Math.sin(a), 0.5 + rnd()]);
    }
  })();

  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  var cols = 0, rows = 0, cellW = 0, cellH = 0, aspect = 1, k = 1, tight = false;
  var chars = [], pen = null, depth = null;
  var yaw = -0.35, pitch = 0.22, spin = 0, drag = null, hover = null;
  var hits = [];
  var start = 0, paused = false, last = 0, visible = true, stats = { frames: 0, total: 0 };

  function layout() {
    var w = canvas.parentNode.clientWidth || 360;
    tight = w < 420;
    cols = tight ? 56 : Math.min(112, Math.max(72, Math.round(w / 4.6)));
    rows = tight ? 36 : 54;
    cellW = w / cols;
    cellH = cellW * 1.8;
    aspect = cellW / cellH;
    k = cols / (tight ? 3.6 : 3.05);  /* a coarse grid needs more room for labels */
    var h = Math.round(rows * cellH);
    canvas.style.width = "100%";
    canvas.style.height = h + "px";
    var dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.font = "500 " + (cellW / 0.6).toFixed(2) + 'px "IBM Plex Mono", ui-monospace, monospace';
    ctx.textBaseline = "middle";
    chars = new Array(cols * rows);
    pen = new Uint8Array(cols * rows);
    depth = new Float32Array(cols * rows);
  }

  function clear() {
    for (var i = 0; i < pen.length; i++) { pen[i] = 0; depth[i] = -1e9; }
  }

  function put(c, r, ch, color, z) {
    c = Math.round(c); r = Math.round(r);
    if (c < 0 || r < 0 || c >= cols || r >= rows || ch === " ") { return; }
    var i = r * cols + c;
    if (z <= depth[i]) { return; }
    depth[i] = z; chars[i] = ch; pen[i] = color;
  }

  function text(c, r, str, color) {
    c = Math.round(Math.max(0, Math.min(cols - str.length, c)));
    r = Math.round(r);
    if (r < 0 || r >= rows) { return; }
    for (var i = 0; i < str.length; i++) { put(c + i, r, str.charAt(i), color, 1e8); }
  }

  function rotate(p) {
    var cy = Math.cos(yaw), sy = Math.sin(yaw), cp = Math.cos(pitch), sp = Math.sin(pitch);
    var x = p[0] * cy + p[2] * sy, z1 = -p[0] * sy + p[2] * cy;
    return [x, p[1] * cp - z1 * sp, p[1] * sp + z1 * cp];
  }

  var DIST = 7.5, FOCAL = 2.6;
  function project(p) {
    var v = rotate(p);
    var s = FOCAL / Math.max(0.6, DIST - v[2]);
    return { c: cols / 2 + v[0] * s * k, r: rows / 2 - v[1] * s * k * aspect, z: v[2], s: s };
  }

  function fade(z) { return 0.55 + 0.45 * Math.max(0, Math.min(1, (z + 4) / 8)); }

  function shadeChar(v) {
    var i = Math.round(Math.max(0, Math.min(1, v)) * (RAMP.length - 1));
    return RAMP.charAt(i);
  }

  /* Lambert light from the upper left, towards the viewer */
  var LX = -0.52, LY = 0.6, LZ = 0.61;

  /* offsets of a 3x3 sample grid inside one cell */
  var SUB = [-1 / 3, 0, 1 / 3];

  function sphere(p, r, color, strength) {
    var v = project(p);
    var rc = r * v.s * k, rr = rc * aspect;
    if (rc < 0.6) { rc = 0.6; rr = 0.6 * aspect; }
    var f = fade(v.z) * (strength === undefined ? 1 : strength);
    for (var r0 = Math.floor(v.r - rr - 1); r0 <= Math.ceil(v.r + rr + 1); r0++) {
      for (var c0 = Math.floor(v.c - rc - 1); c0 <= Math.ceil(v.c + rc + 1); c0++) {
        /* average the light over the part of the cell the sphere actually covers,
           so edge cells come out faint instead of full strength or nothing */
        var lit = 0, hits9 = 0, near = -1e9;
        for (var a = 0; a < 3; a++) {
          for (var b = 0; b < 3; b++) {
            var dx = (c0 + SUB[b] - v.c) / rc, dy = -(r0 + SUB[a] - v.r) / rr;
            var q = dx * dx + dy * dy;
            if (q > 1) { continue; }
            var nz = Math.sqrt(1 - q);
            lit += Math.max(0, dx * LX + dy * LY + nz * LZ);
            hits9++;
            if (v.z + r * nz > near) { near = v.z + r * nz; }
          }
        }
        if (!hits9) { continue; }
        var cover = hits9 / 9;
        var val = (0.18 + 0.82 * (lit / hits9)) * f * (0.4 + 0.6 * cover);
        /* the unlit side still has to read as part of the ball, not a bite out of it */
        if (cover >= 0.5) { val = Math.max(val, 0.085); }
        put(c0, r0, shadeChar(val), color, near);
      }
    }
    return { c: v.c, r: v.r, rc: rc, rr: rr, z: v.z };
  }

  function trailChar(dc, dr) {
    var a = Math.atan2(-dr / aspect, dc);
    var d = Math.abs(a) > Math.PI / 2 ? a - Math.sign(a) * Math.PI : a;
    if (d > 1.18) { return "|"; }
    if (d > 0.39) { return "/"; }
    if (d > -0.39) { return "-"; }
    if (d > -1.18) { return "\\"; }
    return "|";
  }

  function tether(a, b, color, from, to) {
    var ea = project(a), eb = project(b);
    var span = Math.max(Math.abs(eb.c - ea.c), Math.abs(eb.r - ea.r));
    var steps = Math.max(8, Math.round(span * 2.2));
    var prev = null;
    for (var i = 0; i <= steps; i++) {
      var u = i / steps;
      if (u < (from || 0) || u > (to === undefined ? 1 : to)) { prev = null; continue; }
      var v = project([a[0] + (b[0] - a[0]) * u, a[1] + (b[1] - a[1]) * u, a[2] + (b[2] - a[2]) * u]);
      if (prev) {
        var ch = fade(v.z) < 0.72 ? "·" : trailChar(v.c - prev.c, v.r - prev.r);
        put(v.c, v.r, ch, color, v.z - 0.02);
      }
      prev = v;
    }
  }

  function particles(a, b, color, t, count, speed) {
    for (var i = 0; i < count; i++) {
      var u = 1 - (((t * speed + i / count) % 1));
      var v = project([a[0] + (b[0] - a[0]) * u, a[1] + (b[1] - a[1]) * u, a[2] + (b[2] - a[2]) * u]);
      put(v.c, v.r, "·", color, v.z + 0.2);
    }
  }

  function dust(p, spread, color, strength) {
    for (var i = 0; i < DUST.length; i++) {
      var d = DUST[i];
      var g = spread * d[3];
      var v = project([p[0] + d[0] * g, p[1] + d[1] * g, p[2] + d[2] * g]);
      if (strength > 0.45 || i % 2 === 0) { put(v.c, v.r, strength > 0.7 ? "·" : ".", color, v.z); }
    }
  }

  function ring(center, radius, color) {
    var n = Math.max(32, Math.round(radius * 6.5));  /* enough samples to keep the ring unbroken */
    for (var i = 0; i < n; i++) {
      var a = (i / n) * Math.PI * 2;
      put(center.c + Math.cos(a) * radius, center.r - Math.sin(a) * radius * aspect, i % 3 ? "·" : "-", color, 1e7);
    }
  }

  function label(hit, str, color, below) {
    var gap = hit.rr + (tight ? 2 : 1.6);   /* clear of the sphere's faint rim */
    var r = below ? hit.r + gap : hit.r - gap;
    text(hit.c - str.length / 2, r, str, color);
  }

  function beat(t) {
    var i = BEATS.length - 1;
    while (i > 0 && t < BEATS[i].t) { i--; }
    var next = i + 1 < BEATS.length ? BEATS[i + 1].t : LOOP;
    return { i: i, p: Math.max(0, Math.min(1, (t - BEATS[i].t) / (next - BEATS[i].t))), cap: BEATS[i].cap };
  }

  function draw(now) {
    var t0 = performance.now();
    var t = reduce.matches ? 9.4 : ((now - start) / 1000) % LOOP;
    var b = beat(t);
    clear();
    hits = [];

    var hub = sphere(CENTER.p, CENTER.r * (hover === "center" ? 1.35 : 1), INK);
    hits.push({ id: "center", node: CENTER, hit: hub });
    label(hub, CENTER.label, INK, true);

    LINKS.forEach(function (pair) {
      tether(BY_ID[pair[0]].p, BY_ID[pair[1]].p, INK, 0.12, 0.88);
    });

    NODES.forEach(function (n) {
      var cdn = n.id === "cdn";
      var color = INK, strength = 1, spread = 0;
      var name = cdn && b.i >= 1 ? "polyfill.io" : n.label;
      var r = n.r * (hover === n.id ? 1.35 : 1);

      if (cdn) {
        if (b.i === 1) { r *= 1 + 0.18 * Math.sin(b.p * Math.PI * 6); }
        if (b.i === 2) { spread = 0.25 + 1.8 * b.p; strength = 1 - b.p; }
        if (b.i === 3) { spread = 2.05 * (1 - b.p); strength = b.p; color = RED; }
        if (b.i === 4) { color = RED; }
        if (b.i === 5) { color = BLUE; }
      }

      var tcolor = cdn && b.i >= 3 ? (b.i >= 5 ? BLUE : RED) : INK;
      tether(CENTER.p, n.p, tcolor, 0.3, 0.3 + 0.6 * strength);  /* starts outside the hub */

      if (spread > 0.25) { dust(n.p, spread, color === RED ? RED : INK, 1 - strength); }
      if (strength > 0.08) {
        var hit = sphere(n.p, r, color, strength);
        hits.push({ id: n.id, node: n, hit: hit });
        label(hit, name, color, n.p[1] < 0);
      }

      if (b.i === 3 && cdn) { particles(n.p, CENTER.p, RED, t, 9, 1.6); }
      if (b.i !== 3 && !cdn && !reduce.matches) { particles(n.p, CENTER.p, INK, t, 2, 0.35); }
    });

    if (b.i === 3 || b.i === 4) {
      var sr = sphere(STRANGER.p, STRANGER.r * (b.i === 3 ? b.p : 1) * (hover === "stranger" ? 1.35 : 1), RED);
      hits.push({ id: "stranger", node: STRANGER, hit: sr });
      label(sr, "stranger", RED, false);
      tether(STRANGER.p, BY_ID.cdn.p, RED, 0.2, 0.8);
    }

    if (b.i === 4) {
      ring(hub, (0.3 + 3.2 * b.p) * k * 0.42, BLUE);
      var tag = tight ? "Proven · Fix it" : "Tether · Proven · Fix it";
      var mid = project([BY_ID.cdn.p[0] / 2, BY_ID.cdn.p[1] / 2, BY_ID.cdn.p[2] / 2]);
      text(mid.c + 2, mid.r + 2, tag, BLUE);
    }

    var tip = hover && hits.filter(function (h) { return h.id === hover; })[0];
    if (tip) {
      text(tip.hit.c - tip.node.tip.length / 2, tip.hit.r + tip.hit.rr + 2, tip.node.tip, BLUE);
    }
    if (captionEl) {
      captionEl.textContent = b.cap || "\u00a0";
    }

    paint();
    stats.frames++;
    stats.total += performance.now() - t0;
    window.heroStats = { frames: stats.frames, avgMs: stats.total / stats.frames, cols: cols, rows: rows };
  }

  /* one fillText per run of same-coloured cells in a row */
  function paint() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (var r = 0; r < rows; r++) {
      var run = "", runCol = 0, start0 = 0;
      for (var c = 0; c <= cols; c++) {
        var i = r * cols + c;
        var p = c < cols ? pen[i] : 0;
        if (p !== runCol || c === cols) {
          if (run && runCol) {
            ctx.fillStyle = PEN[runCol];
            ctx.fillText(run, start0 * cellW, (r + 0.5) * cellH);
          }
          run = ""; runCol = p; start0 = c;
        }
        if (p) { run += chars[i]; }
      }
    }
  }

  function frame(now) {
    if (paused) { return; }
    if (now - last < 15.5) { requestAnimationFrame(frame); return; }
    last = now;
    if (!drag && !reduce.matches) {
      spin *= 0.95;
      if (Math.abs(spin) < 0.0012) { spin = 0.0012; }  /* settles into a slow idle spin */
      yaw += spin;
    }
    draw(now);
    requestAnimationFrame(frame);
  }

  function pick(ev) {
    var box = canvas.getBoundingClientRect();
    var c = (ev.clientX - box.left) / cellW, r = (ev.clientY - box.top) / cellH;
    var found = null;
    hits.forEach(function (h) {
      var dx = (c - h.hit.c) / h.hit.rc, dy = (r - h.hit.r) / h.hit.rr;
      if (dx * dx + dy * dy <= 1.25 && (!found || h.hit.z > found.hit.z)) { found = h; }
    });
    return found ? found.id : null;
  }

  canvas.addEventListener("pointerdown", function (ev) {
    drag = { x: ev.clientX, y: ev.clientY };
    canvas.classList.add("is-drag");
    canvas.setPointerCapture(ev.pointerId);
  });
  canvas.addEventListener("pointermove", function (ev) {
    if (drag) {
      var dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
      yaw += dx * 0.006; pitch = Math.max(-0.8, Math.min(0.8, pitch + dy * 0.004));
      spin = dx * 0.0015;
      drag.x = ev.clientX; drag.y = ev.clientY;
      if (paused) { draw(performance.now()); }
      ev.preventDefault();
      return;
    }
    var id = pick(ev);
    if (id !== hover) { hover = id; if (paused) { draw(performance.now()); } }
  });
  function endDrag() { drag = null; canvas.classList.remove("is-drag"); }
  canvas.addEventListener("pointerup", endDrag);
  canvas.addEventListener("pointercancel", endDrag);
  canvas.addEventListener("pointerleave", function () { endDrag(); hover = null; });
  canvas.addEventListener("touchmove", function (ev) { if (drag) { ev.preventDefault(); } }, { passive: false });

  function run(on) {
    if (on === !paused) { return; }
    paused = !on;
    if (on) { last = 0; requestAnimationFrame(frame); }
  }

  function resize() {
    layout();
    start = start || performance.now();
    draw(performance.now());
  }

  /* test hook: jump to a point in the story loop */
  window.heroSeek = function (sec) { start = performance.now() - sec * 1000; draw(performance.now()); };

  layout();
  start = performance.now();
  if (reduce.matches) {
    draw(performance.now());
    paused = true;
  } else {
    requestAnimationFrame(frame);
  }

  window.addEventListener("resize", resize);
  document.addEventListener("visibilitychange", function () {
    run(!document.hidden && !reduce.matches && visible);
  });

  if (window.IntersectionObserver) {
    new IntersectionObserver(function (entries) {
      visible = entries[0].isIntersecting;
      run(visible && !document.hidden && !reduce.matches);
    }, { threshold: 0.01 }).observe(canvas);
  }
})();
