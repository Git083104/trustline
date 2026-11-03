/* Tether frontend. Every number and label comes from the API; nothing is mocked.
   Report text is attacker-controlled, so it only ever reaches the DOM as textContent. */
(function () {
  "use strict";

  var STAGES = ["Find", "Check", "Investigate", "Rank", "Report"];
  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  var SEV_KEY = { critical: "critical", high: "high", medium: "medium", low: "low", info: "safe" };
  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Safe" };
  var KIND_LABEL = { repo: "GitHub repo", website: "Website", path: "Local path" };
  var PLAN_QUESTION = {
    rdap: "Who owns this domain now?",
    dns: "Does this host still resolve?",
    bucket_probe: "Does this bucket still exist?",
    github_owner: "Is this GitHub account still there?",
    github_repo: "Does this repository still exist?",
    live_fetch: "What does this URL serve now?",
    tranco: "How widely used is this host?"
  };
  var POLL_EVERY_MS = 1500;
  var POLL_LIMIT = 240;   // ~6 minutes of waiting before offering a retry
  var FOUND_BUCKETS = [
    { key: "claimable", label: "Claimable now", sev: "critical" },
    { key: "compromised", label: "Known compromised", sev: "high" },
    { key: "checking", label: "Checking", sev: "checking" },
    { key: "safe", label: "Looks safe", sev: "safe" }
  ];

  var $ = function (id) { return document.getElementById(id); };
  var el = {
    home: $("page-home"),
    app: $("page-app"),
    scanning: $("screen-scanning"),
    results: $("screen-results"),
    homeError: $("home-error"),
    appError: $("app-error"),
    nav: $("top-nav"),
    hero: $("hero"),
    heroInner: document.querySelector(".hero-inner"),
    glow: $("hero-glow"),
    haze: $("hero-haze"),
    form: $("scan-form"),
    target: $("target"),
    chip: $("kind-chip"),
    scanBtn: $("scan-btn"),
    scanTarget: $("scan-target"),
    scanKind: $("scan-kind"),
    scanRecorded: $("scan-recorded"),
    clock: $("scan-clock"),
    feed: $("feed"),
    callsUsed: $("calls-used"),
    skip: $("skip-report"),
    resTarget: $("res-target"),
    resKind: $("res-kind"),
    resRecorded: $("res-recorded"),
    headline: $("res-headline"),
    resChips: $("res-chips"),
    resMeta: $("res-meta"),
    partial: $("partial-banner"),
    workToggle: $("work-toggle"),
    workPanel: $("work-panel"),
    tabFix: $("tab-fix"),
    tabAll: $("tab-all"),
    tabTrace: $("tab-trace"),
    tabRaw: $("tab-raw"),
    tabNFix: $("tab-n-fix"),
    tabNAll: $("tab-n-all"),
    tabNTrace: $("tab-n-trace")
  };

  var state = {
    screen: "home",
    kind: "",
    target: "",
    scanId: "",
    demo: false,
    source: null,
    timer: null,
    startedAt: 0,
    elapsedMs: 0,
    report: null,
    finished: false,
    streamed: false,
    pollTimer: null,
    stage: 0,
    calls: 0,
    turns: [],
    rows: {},
    buckets: {},
    targetsSeen: 0,
    counts: { find: 0, check: 0, rank: 0, report: 0 }
  };

  /* ---------- small DOM helpers (textContent only) ---------- */

  function make(tag, className, textValue) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (textValue != null) { node.textContent = String(textValue); }
    return node;
  }

  function svgIcon(paths, size, strokeWidth) {
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("width", String(size));
    svg.setAttribute("height", String(size));
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", String(strokeWidth));
    svg.setAttribute("aria-hidden", "true");
    paths.forEach(function (spec) {
      var node = document.createElementNS(ns, spec.tag);
      Object.keys(spec.attrs).forEach(function (key) {
        node.setAttribute(key, spec.attrs[key]);
      });
      svg.appendChild(node);
    });
    return svg;
  }

  function caretIcon() {
    var svg = svgIcon([{ tag: "polyline", attrs: { points: "6 9 12 15 18 9" } }], 14, 2.2);
    svg.classList.add("caret");
    return svg;
  }

  function copyIcon() {
    return svgIcon([
      { tag: "rect", attrs: { x: "8", y: "8", width: "12", height: "12", rx: "2" } },
      { tag: "path", attrs: { d: "M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" } }
    ], 14, 2);
  }

  /* ---------- errors ---------- */

  function errorNode() {
    return state.screen === "home" ? el.homeError : el.appError;
  }

  function clearErrors() {
    [el.homeError, el.appError].forEach(function (node) {
      node.hidden = true;
      node.replaceChildren();
    });
  }

  function showError(message, retry) {
    clearErrors();
    if (!message) { return; }
    var node = errorNode();
    node.hidden = false;
    node.replaceChildren(make("span", null, message));
    if (retry) {
      var btn = make("button", "btn btn-secondary", "Retry");
      btn.type = "button";
      btn.addEventListener("click", function () {
        clearErrors();
        retry();
      });
      node.appendChild(btn);
    }
  }

  /* ---------- navigation between screens ---------- */

  function show(screen) {
    state.screen = screen;
    el.home.hidden = screen !== "home";
    el.app.hidden = screen === "home";
    el.scanning.hidden = screen !== "scanning";
    el.results.hidden = screen !== "results";
    window.scrollTo(0, 0);
    if (screen === "home") { onScroll(); }
  }

  function closeSource() {
    if (state.source) {
      state.source.close();
      state.source = null;
    }
    if (state.timer) {
      clearInterval(state.timer);
      state.timer = null;
    }
    if (state.pollTimer) {
      clearTimeout(state.pollTimer);
      state.pollTimer = null;
    }
  }

  function goHome() {
    closeSource();
    clearErrors();
    history.replaceState({}, "", window.location.pathname);
    state.report = null;
    show("home");
  }

  /* ---------- target detection ---------- */

  function normalize(raw) {
    var value = (raw || "").trim();
    if (!value) { return ""; }
    if (/^[\w.-]+\/[\w.-]+$/.test(value) && value.indexOf(".") === -1) {
      return "https://github.com/" + value;
    }
    if (!/^https?:\/\//i.test(value) && /^[\w-]+(\.[\w-]+)+(\/|$)/.test(value)) {
      return "https://" + value;
    }
    return value;
  }

  function detectKind(raw) {
    var value = normalize(raw);
    if (/^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/#?]+/i.test(value)) { return "repo"; }
    if (/^https?:\/\/[\w-]+(\.[\w-]+)+/i.test(value)) { return "website"; }
    return "";
  }

  function syncInput() {
    var kind = detectKind(el.target.value);
    el.chip.hidden = !kind;
    if (kind) { el.chip.textContent = KIND_LABEL[kind]; }
    el.scanBtn.disabled = !kind;
  }

  /* ---------- clock ---------- */

  function clock(ms) {
    var total = Math.max(0, Math.floor(ms / 1000));
    return Math.floor(total / 60) + ":" + String(total % 60).padStart(2, "0");
  }

  function longClock(ms) {
    var total = Math.max(0, Math.floor(ms / 1000));
    var minutes = Math.floor(total / 60);
    var seconds = total % 60;
    if (!minutes) { return seconds + "s"; }
    return minutes + "m " + String(seconds).padStart(2, "0") + "s";
  }

  function tick() {
    state.elapsedMs = Date.now() - state.startedAt;
    el.clock.textContent = clock(state.elapsedMs);
  }

  /* ---------- scanning screen ---------- */

  function renderLayers() {
    Array.prototype.forEach.call(document.querySelectorAll(".slab, #stack-list li"), function (node) {
      var index = Number(node.getAttribute("data-layer")) - 1;
      var status = "pending";
      if (index < state.stage) { status = "done"; }
      else if (index === state.stage) { status = "running"; }
      node.setAttribute("data-state", status);
    });
    var stackCell = document.querySelector(".stack-cell");
    if (stackCell) { stackCell.setAttribute("data-scan", state.finished ? "done" : "running"); }
    var counts = {
      find: state.counts.find,
      check: state.counts.check,
      investigate: state.calls,
      rank: state.counts.rank,
      report: state.counts.report
    };
    Object.keys(counts).forEach(function (key) {
      var node = document.querySelector('[data-count="' + key + '"]');
      if (node) { node.textContent = String(counts[key]); }
    });
    if (el.callsUsed) { el.callsUsed.textContent = "Agent calls " + state.calls; }
  }

  function setProgress() {}

  function renderPips() {
    renderLayers();
  }

  function renderFound() {
    renderLayers();
  }

  function parseSummary(raw) {
    if (raw == null) { return null; }
    try {
      var parsed = JSON.parse(String(raw));
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch (err) {
      return null;
    }
  }

  // Turns a tool's raw result into a short line and a severity key, from the
  // facts in the result itself — no model text, no guessing.
  function readResult(tool, raw) {
    var data = parseSummary(raw);
    var text = "";
    var sev = "checking";
    if (data && data.done === true) {
      // The agent ended this target's turn: the precomputed lookups were enough.
      return { text: String(data.summary || "no further checks needed"), sev: "neutral" };
    }
    if (data) {
      if (typeof data.status === "string" && data.status) {
        text = data.status;
      } else if (typeof data.exists === "boolean") {
        text = data.exists ? "exists" : "not found";
      } else if (typeof data.http_status === "number") {
        text = "HTTP " + data.http_status;
      }
      if (data.vulnerable === true) { text = text ? text + " · unclaimed" : "unclaimed"; }
      if (data.http_status === 404 && text.toLowerCase() !== "nosuchbucket") {
        text = text ? text + " (404)" : "404";
      }
    }
    if (!text) { text = String(raw == null ? "" : raw).slice(0, 80); }
    var probe = text.toLowerCase();
    if (/unregistered|nxdomain|nosuchbucket|not found|missing|404|unclaimed/.test(probe)) {
      sev = "critical";
    } else if (/registered|resolves|exists|\bok\b/.test(probe)) {
      sev = "safe";
    }
    return { text: text, sev: sev };
  }

  function callText(tool, args) {
    var value = "";
    if (args && typeof args === "object") {
      var keys = Object.keys(args);
      if (keys.length) { value = String(args[keys[0]]); }
    }
    return { tool: String(tool || ""), arg: value };
  }

  function setRowResult(row, sev, text) {
    row.resultBadge.className = "sev-badge sev-" + sev;
    row.resultBadge.replaceChildren();
    if (sev === "checking") { row.resultBadge.appendChild(make("span", "spinner")); }
    row.resultBadge.appendChild(make("span", null, sev === "checking" ? "Checking" : sevLabelFor(sev)));
    row.resultText.className = "feed-result sev-fg-" + sev;
    row.resultText.textContent = text;
  }

  function sevLabelFor(key) {
    if (key === "safe") { return "Safe"; }
    if (key === "neutral") { return "Checked"; }
    return key.charAt(0).toUpperCase() + key.slice(1);
  }

  function newTurn(event) {
    var call = callText(event.tool, event.args);
    var turn = {
      target: String(event.target || ""),
      tool: call.tool,
      arg: call.arg,
      plan: call.tool === "done"
        ? "The precomputed lookups already answer " + String(event.target || "this reference") + "."
        : PLAN_QUESTION[call.tool] || "Checking what this reference points to now.",
      result: "running…",
      sev: "checking"
    };
    state.turns.push(turn);

    var row = make("div", "feed-row");
    row.appendChild(make("span", "feed-n", String(state.turns.length).padStart(2, "0")));
    var body = make("div", "feed-body");

    var planLine = make("div", "feed-line");
    planLine.appendChild(make("span", "feed-k", "Plan"));
    planLine.appendChild(make("span", "feed-plan", turn.plan));
    body.appendChild(planLine);

    var callLine = make("div", "feed-line");
    callLine.appendChild(make("span", "feed-k", "Call"));
    var code = make("code", "feed-call");
    code.appendChild(make("span", "accent", turn.tool));
    code.appendChild(document.createTextNode('("' + turn.arg + '")'));
    callLine.appendChild(code);
    body.appendChild(callLine);

    var resultLine = make("div", "feed-line feed-line-result");
    resultLine.appendChild(make("span", "feed-k", "Result"));
    var badge = make("span", "sev-badge sev-checking");
    var resultText = make("span", "feed-result sev-fg-checking");
    resultLine.appendChild(badge);
    resultLine.appendChild(resultText);
    body.appendChild(resultLine);

    row.appendChild(body);
    el.feed.appendChild(row);

    turn.node = { resultBadge: badge, resultText: resultText };
    setRowResult(turn.node, "checking", "running…");
    state.rows[turn.target] = state.rows[turn.target] || [];
    state.rows[turn.target].push(turn);
    return turn;
  }

  function handleAgentEvent(event) {
    if (event.type === "plan") {
      // "done" ends a target's turn without an outside lookup, so it is shown
      // in the feed but never counted as an agent call.
      if (event.tool !== "done") { state.calls += 1; }
      newTurn(event);
      renderPips();
      return;
    }
    var turn = state.turns[state.turns.length - 1];
    if (!turn) { return; }
    if (event.type === "observe") {
      var read = readResult(event.tool, event.result_summary);
      turn.result = read.text;
      turn.sev = read.sev;
      setRowResult(turn.node, read.sev, read.text);
    }
  }

  function applyRanked(event) {
    var key = SEV_KEY[String(event.severity || "")] || "checking";
    var turns = state.rows[String(event.target || "")] || [];
    turns.forEach(function (turn) {
      turn.sev = key;
      setRowResult(turn.node, key, turn.result);
    });
  }

  function bucketFor(event) {
    var line = String(event.evidence_line || event.risk || "");
    if (/compromis/i.test(line)) { return "compromised"; }
    if (event.severity === "info") { return "safe"; }
    if (event.severity === "critical" || event.severity === "high") { return "claimable"; }
    return "checking";
  }

  function stageFor(type) {
    if (type === "extracted") { return 0; }
    if (type === "precheck") { return 1; }
    if (type === "plan" || type === "act" || type === "observe") { return 2; }
    if (type === "ranked") { return 3; }
    if (type === "done") { return 4; }
    return state.stage;
  }

  function resetScan(meta) {
    closeSource();
    clearErrors();
    state.kind = meta.kind;
    state.target = meta.target;
    state.scanId = meta.scanId;
    state.demo = meta.demo;
    state.report = null;
    state.finished = false;
    state.streamed = false;
    state.stage = 0;
    state.calls = 0;
    state.turns = [];
    state.rows = {};
    state.buckets = {};
    state.targetsSeen = 0;
    state.counts = { find: 0, check: 0, rank: 0, report: 0 };
    state.startedAt = Date.now();
    state.elapsedMs = 0;
    el.feed.replaceChildren();
    setTargetLabels();
    setRecordedLabel(el.scanRecorded, null);
    renderLayers();
    renderPips();
    renderFound();
    el.skip.disabled = true;
    tick();
    state.timer = setInterval(tick, 250);
    show("scanning");
  }

  function setTargetLabels() {
    el.scanTarget.textContent = state.target;
    el.scanKind.hidden = !state.kind;
    if (state.kind) { el.scanKind.textContent = KIND_LABEL[state.kind] || state.kind; }
  }

  function beginStream(url, meta) {
    resetScan(meta);
    var source;
    try {
      source = new EventSource(url);
    } catch (err) {
      // No EventSource here (older webview, blocked by an extension). The scan
      // is already running on the server, so wait it out instead of losing it.
      waitWithoutStream();
      return;
    }
    if (!source) {
      waitWithoutStream();
      return;
    }
    state.source = source;
    source.onmessage = function (message) {
      var event;
      try {
        event = JSON.parse(message.data);
      } catch (err) {
        return;
      }
      state.streamed = true;
      consume(event);
    };
    source.onerror = function () {
      source.close();
      state.source = null;
      if (state.finished) { return; }
      if (!state.streamed) {
        // Never received a frame: the stream itself is the problem, not the
        // scan. A buffering proxy looks exactly like this.
        waitWithoutStream();
        return;
      }
      if (state.demo && state.report) {
        showResults(state.report);
        return;
      }
      showError("The live scan connection dropped.", function () {
        if (state.demo) { startDemo(); }
        else if (state.scanId) { reattach(state.scanId); }
      });
    };
  }

  // Fallback when live events can't reach us: poll for the finished report.
  function waitWithoutStream() {
    if (state.demo) {
      showError("Live updates aren't available in this browser, so the demo can't play.");
      return;
    }
    showError("Live updates aren't available in this browser. Waiting for the report…");
    el.clock.textContent = "Scanning";
    var attempts = 0;
    function poll() {
      if (state.finished) { return; }
      attempts += 1;
      if (attempts > POLL_LIMIT) {
        showError("The scan is taking longer than expected.", function () {
          attempts = 0;
          poll();
        });
        return;
      }
      fetch("/api/scan/" + encodeURIComponent(state.scanId))
        .then(function (res) {
          if (res.status === 409) { return null; }
          if (!res.ok) { throw new Error("scan " + res.status); }
          return res.json();
        })
        .then(function (report) {
          if (report) {
            clearErrors();
            state.stage = STAGES.length - 1;
            showResults(report);
            return;
          }
          state.pollTimer = setTimeout(poll, POLL_EVERY_MS);
        })
        .catch(function () {
          showError("The scan failed.", function () { startScan(state.target); });
        });
    }
    state.pollTimer = setTimeout(poll, POLL_EVERY_MS);
  }

  function consume(event) {
    var next = stageFor(event.type);
    if (next > state.stage) {
      state.stage = next;
      renderLayers();
      setProgress((state.stage + 1) / STAGES.length * 100);
    }
    if (event.type === "started") {
      state.kind = event.kind || state.kind;
      state.target = event.target || state.target;
      setTargetLabels();
    }
    if (event.type === "extracted") {
      var extracted = event.actionable != null ? event.actionable : event.count;
      if (extracted != null) { state.counts.find = Number(extracted) || 0; }
      renderLayers();
    }
    if (event.type === "precheck" && event.target) {
      if (!state.buckets[event.target]) { state.targetsSeen += 1; }
      state.buckets[event.target] = event.hard_signal ? "claimable" : "checking";
      state.counts.check += 1;
      if (state.counts.find < state.targetsSeen) { state.counts.find = state.targetsSeen; }
      renderFound();
      renderPips();
    }
    if (event.type === "plan" || event.type === "act" || event.type === "observe") {
      handleAgentEvent(event);
    }
    if (event.type === "ranked" && event.target) {
      state.buckets[event.target] = bucketFor(event);
      state.counts.rank += 1;
      applyRanked(event);
      renderFound();
    }
    if (event.type === "error") {
      closeSource();
      showError(event.message || "The scan failed.", function () {
        if (state.demo) { startDemo(); } else { startScan(state.target); }
      });
    }
    if (event.type === "done") {
      closeSource();
      state.elapsedMs = Date.now() - state.startedAt;
      state.counts.report = 1;
      renderLayers();
      loadReport();
    }
  }

  function loadReport() {
    var url = state.demo ? "/api/scan/demo" : "/api/scan/" + encodeURIComponent(state.scanId);
    fetch(url)
      .then(function (res) {
        if (!res.ok) { throw new Error("report " + res.status); }
        return res.json();
      })
      .then(function (report) {
        state.report = report;
        el.skip.disabled = false;
        showResults(report);
      })
      .catch(function () {
        showError("The scan finished but the report could not be loaded.", loadReport);
      });
  }

  /* ---------- starting scans ---------- */

  function httpMessage(status, body) {
    var message = (body && (body.error || body.message || body.detail)) || "";
    if (status === 503) { return message || "Live scans aren't configured; try the demo"; }
    if (status === 429) {
      if (/daily/i.test(message)) { return message; }
      return message || "Too many scans right now; try the demo";
    }
    if (status === 400) {
      if (/can't be scanned|cannot be scanned/i.test(message)) {
        return message || "This address can't be scanned";
      }
      return message || "Paste a GitHub repository or website URL.";
    }
    return message || "The scan could not be started.";
  }

  function startScan(raw) {
    var target = normalize(raw);
    if (!detectKind(target)) {
      showError("Paste a GitHub repository or website URL.");
      return;
    }
    clearErrors();
    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: target })
    })
      .then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (body) {
          return { status: res.status, ok: res.ok, body: body };
        });
      })
      .then(function (out) {
        if (!out.ok) {
          showError(httpMessage(out.status, out.body), function () { startScan(raw); });
          return;
        }
        var id = String(out.body.scan_id);
        history.replaceState({}, "", "?scan=" + encodeURIComponent(id));
        beginStream("/api/scan/" + encodeURIComponent(id) + "/events", {
          kind: out.body.kind,
          target: out.body.target,
          scanId: id,
          demo: false
        });
      })
      .catch(function () {
        showError("The scan could not be started.", function () { startScan(raw); });
      });
  }

  function startDemo() {
    history.replaceState({}, "", "?demo=1");
    beginStream("/api/scan/demo/events", {
      kind: "",
      target: "",
      scanId: "demo",
      demo: true
    });
    // The demo report is a checked-in fixture, so "Skip to report" can work at once.
    fetch("/api/scan/demo")
      .then(function (res) { return res.json(); })
      .then(function (report) {
        state.report = report;
        el.skip.disabled = false;
        if (report.recorded_at) {
          window.__tetherRecordedAt = report.recorded_at;
          setRecordedLabel(el.scanRecorded, report);
        }
      })
      .catch(function () {});
  }

  function reattach(id) {
    beginStream("/api/scan/" + encodeURIComponent(id) + "/events", {
      kind: state.kind,
      target: state.target,
      scanId: id,
      demo: false
    });
  }

  function openScanId(id) {
    fetch("/api/scan/" + encodeURIComponent(id))
      .then(function (res) {
        if (res.status === 409) {
          reattach(id);
          return null;
        }
        if (!res.ok) { throw new Error("scan " + res.status); }
        return res.json();
      })
      .then(function (report) {
        if (!report) { return; }
        state.scanId = id;
        state.demo = false;
        state.elapsedMs = 0;
        state.report = report;
        showResults(report);
      })
      .catch(function () {
        show("home");
        showError("That scan is no longer available. Run it again.");
      });
  }

  /* ---------- report helpers (all code-derived) ---------- */

  function whereUsed(item) {
    var refs = item.references || [];
    return refs.map(function (ref) {
      if (typeof ref === "string") { return ref; }
      if (!ref || typeof ref !== "object") { return ""; }
      if (ref.page_url) { return ref.page_url + (ref.line ? ":" + ref.line : ""); }
      if (ref.file_line) { return ref.file_line; }
      if (ref.file) { return ref.file + (ref.line ? ":" + ref.line : ""); }
      return "";
    }).filter(Boolean).join(", ");
  }

  function evidenceText(item) {
    return String(item.evidence_line || "").replace(/^Evidence:\s*/, "");
  }

  function ownerStatus(item) {
    var evidence = item.evidence || {};
    var rdap = evidence.rdap || {};
    var dns = evidence.dns || {};
    var bucket = evidence.bucket_probe || {};
    var owner = evidence.github_owner || {};
    var repo = evidence.github_repo || {};
    if (bucket.status) { return String(bucket.status); }
    if (String(owner.status || "") === "missing" || owner.exists === false) { return "owner 404"; }
    if (String(repo.status || "") === "missing" || repo.exists === false) { return "repo 404"; }
    if (rdap.status) { return String(rdap.status); }
    if (dns.status) { return String(dns.status); }
    if (owner.exists === true) { return "owner exists"; }
    return "—";
  }

  function sortFindings(list) {
    return list.slice().sort(function (a, b) {
      var left = SEV_ORDER[a.severity];
      var right = SEV_ORDER[b.severity];
      left = left == null ? 9 : left;
      right = right == null ? 9 : right;
      if (left !== right) { return left - right; }
      return String(a.target).localeCompare(String(b.target));
    });
  }

  /* ---------- results rendering ---------- */

  function findingCard(item) {
    var key = SEV_KEY[item.severity] || "low";
    var article = make("article", "finding ring-" + key);
    var main = make("div", "finding-main");

    var top = make("div", "finding-top");
    var sev = make("span", "finding-sev sev-" + key);
    sev.appendChild(make("span", "sev-dot"));
    sev.appendChild(make("span", null, SEV_LABEL[item.severity] || item.severity));
    top.appendChild(sev);
    top.appendChild(make("span", "finding-target", item.target));
    if (item.kind) { top.appendChild(make("span", "finding-type", item.kind)); }
    if (item.evidence_level === "proven") {
      top.appendChild(make("span", "finding-where", "Proven"));
    } else if (item.evidence_level === "likely") {
      top.appendChild(make("span", "finding-where", "Likely"));
    }
    var where = whereUsed(item);
    main.appendChild(top);

    if (item.risk) { main.appendChild(make("p", "finding-risk", item.risk)); }

    var fixRow = make("div", "fix-row");
    fixRow.appendChild(make("span", "fix-k", "Fix"));
    fixRow.appendChild(make("span", "fix-text", item.fix || ""));
    var copy = make("button", "btn btn-secondary copy-btn");
    copy.type = "button";
    var copyLabel = make("span", null, "Copy");
    copy.appendChild(copyIcon());
    copy.appendChild(copyLabel);
    copy.addEventListener("click", function () {
      var value = item.fix || "";
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value).catch(function () {});
      }
      copyLabel.textContent = "Copied";
      setTimeout(function () { copyLabel.textContent = "Copy"; }, 1500);
    });
    fixRow.appendChild(copy);
    main.appendChild(fixRow);

    var details = make("div", "finding-details");
    details.hidden = true;
    addDetail(details, "Evidence", evidenceText(item), false);
    addDetail(details, "Found in", where, false);
    evidenceDates(item).forEach(function (line) {
      addDetail(details, "Date", line, false);
    });
    if (item.floor_reason) { addDetail(details, "Rule note", item.floor_reason, true); }
    if (item.tranco_rank != null) { addDetail(details, "Tranco", "rank " + item.tranco_rank, false); }
    if (item.for_sale || item.parked) {
      addDetail(details, "Live fetch", item.for_sale ? "listed for sale" : "parked", false);
    }
    if (item.action_ref) {
      addDetail(details, "Action ref",
        item.action_ref + (item.action_sha_pinned ? " (SHA-pinned)" : " (not SHA-pinned)"), false);
    }

    var toggle = make("button", "details-btn");
    toggle.type = "button";
    toggle.setAttribute("aria-expanded", "false");
    toggle.appendChild(caretIcon());
    toggle.appendChild(make("span", null, "Details"));
    toggle.addEventListener("click", function () {
      var open = toggle.getAttribute("aria-expanded") === "true";
      toggle.setAttribute("aria-expanded", open ? "false" : "true");
      details.hidden = open;
    });
    main.appendChild(toggle);

    article.appendChild(main);
    article.appendChild(details);
    return article;
  }

  function evidenceDates(item) {
    var evidence = item.evidence || {};
    var rdap = evidence.rdap || {};
    var lines = [];
    ["expiration", "expiry", "expires", "updated", "created", "event_date"].forEach(function (key) {
      if (rdap[key]) { lines.push(key + ": " + rdap[key]); }
    });
    return lines;
  }

  function addDetail(grid, label, value, isRule) {
    if (!value) { return; }
    grid.appendChild(make("span", "detail-k" + (isRule ? " is-rule" : ""), label));
    grid.appendChild(make("span", "detail-v" + (isRule ? " is-prose" : ""), value));
  }

  function collapsedGroup(tag, sevKey, title, items) {
    var wrap = make("div", "group");
    var btn = make("button", "group-btn");
    btn.type = "button";
    btn.setAttribute("aria-expanded", "false");
    btn.appendChild(caretIcon());
    btn.appendChild(make("span", "group-tag sev-" + sevKey, tag));
    btn.appendChild(make("span", null, title));

    var rows = make("div", "group-rows");
    rows.hidden = true;
    items.forEach(function (item) {
      var row = make("div", "group-row");
      row.appendChild(make("span", "group-row-target", item.target));
      row.appendChild(make("span", "group-row-note", evidenceText(item) || whereUsed(item)));
      rows.appendChild(row);
    });

    btn.addEventListener("click", function () {
      var open = btn.getAttribute("aria-expanded") === "true";
      btn.setAttribute("aria-expanded", open ? "false" : "true");
      rows.hidden = open;
    });
    wrap.appendChild(btn);
    wrap.appendChild(rows);
    return wrap;
  }

  function renderChips(findings) {
    el.resChips.replaceChildren();
    ["critical", "high", "medium", "low", "info"].forEach(function (severity) {
      var n = findings.filter(function (f) { return f.severity === severity; }).length;
      if (!n) { return; }
      var chip = make("span", "res-chip res-chip-" + SEV_KEY[severity]);
      chip.appendChild(make("span", "res-chip-n", String(n)));
      chip.appendChild(make("span", null, SEV_LABEL[severity]));
      el.resChips.appendChild(chip);
    });
  }

  function metaItem(label, value, mono) {
    var span = make("span", null, label + " ");
    span.appendChild(make("b", mono ? "mono" : null, value));
    return span;
  }

  function renderMeta(report) {
    var coverage = report.coverage || {};
    el.resMeta.replaceChildren();
    if (state.elapsedMs > 0) {
      el.resMeta.appendChild(metaItem("Scan time", longClock(state.elapsedMs), true));
    }
    if (state.calls > 0) {
      el.resMeta.appendChild(metaItem("Agent calls", String(state.calls), true));
    }
    var coverageText = coverage.truncated
      ? coverage.files_scanned + " of " + coverage.files_total + " files scanned"
      : "all files scanned";
    el.resMeta.appendChild(metaItem("Coverage:", coverageText, false));
    if (report.partial) {
      el.resMeta.appendChild(metaItem("Scan", "partial", false));
    }
    var skipped = report.skipped_targets || [];
    if (skipped.length) {
      el.resMeta.appendChild(metaItem("Skipped", skipped.join(", "), true));
    }
  }

  function renderAllTargets(findings) {
    var wrap = make("div", "table-wrap");
    var table = make("table", "table");
    var thead = make("thead");
    var headRow = make("tr");
    ["Target", "Type", "Owner status", "Severity", "Where used"].forEach(function (name) {
      headRow.appendChild(make("th", null, name));
    });
    thead.appendChild(headRow);
    var tbody = make("tbody");
    findings.forEach(function (item) {
      var tr = make("tr");
      tr.appendChild(make("td", "col-target", item.target));
      tr.appendChild(make("td", "col-type", item.kind || ""));
      tr.appendChild(make("td", "col-owner", ownerStatus(item)));
      var sevCell = make("td");
      sevCell.appendChild(make("span", "sev-badge sev-" + (SEV_KEY[item.severity] || "low"),
        SEV_LABEL[item.severity] || item.severity));
      tr.appendChild(sevCell);
      tr.appendChild(make("td", "col-where", whereUsed(item)));
      tbody.appendChild(tr);
    });
    table.appendChild(thead);
    table.appendChild(tbody);
    wrap.appendChild(table);
    el.tabAll.replaceChildren(wrap);
  }

  function renderTrace() {
    el.tabTrace.replaceChildren();
    if (!state.turns.length) {
      el.tabTrace.appendChild(make("div", "empty-note",
        "The agent trace is only available while a scan is streaming."));
      return;
    }
    var card = make("div", "trace-card");
    state.turns.forEach(function (turn, index) {
      var row = make("div", "trace-row");
      row.appendChild(make("span", "feed-n", String(index + 1).padStart(2, "0")));
      var body = make("div", "trace-body");
      body.appendChild(make("span", "trace-plan", turn.plan));
      var line = make("div", "trace-call-line");
      var call = make("span", "trace-call");
      call.appendChild(make("span", "accent", turn.tool));
      call.appendChild(document.createTextNode('("' + turn.arg + '")'));
      line.appendChild(call);
      line.appendChild(make("span", "dim", "→"));
      line.appendChild(make("span", "sev-fg-" + turn.sev, turn.result));
      body.appendChild(line);
      row.appendChild(body);
      card.appendChild(row);
    });
    el.tabTrace.appendChild(card);
  }

  function showResults(report) {
    closeSource();
    state.report = report;
    state.finished = true;
    show("results");

    el.resTarget.textContent = report.target || state.target;
    var kind = report.kind || state.kind;
    el.resKind.hidden = !kind;
    if (kind) { el.resKind.textContent = KIND_LABEL[kind] || kind; }

    var findings = sortFindings(report.findings || []);
    var fix = findings.filter(function (f) { return f.severity === "critical" || f.severity === "high"; });
    var later = findings.filter(function (f) { return f.severity === "medium" || f.severity === "low"; });
    var safe = findings.filter(function (f) { return f.severity === "info"; });

    el.headline.textContent = fix.length === 0
      ? "Nothing to fix today"
      : fix.length + (fix.length === 1 ? " thing to fix today" : " things to fix today");
    renderChips(findings);
    renderMeta(report);
    setRecordedLabel(el.resRecorded, report);
    if (el.partial) {
      var skipped = report.skipped_targets || [];
      if (report.partial && skipped.length) {
        el.partial.hidden = false;
        el.partial.textContent = "Partial scan. Skipped: " + skipped.join(", ");
      } else if (report.partial) {
        el.partial.hidden = false;
        el.partial.textContent = "Partial scan. Some targets were skipped.";
      } else {
        el.partial.hidden = true;
        el.partial.textContent = "";
      }
    }
    if (el.workPanel) { el.workPanel.hidden = true; }
    if (el.workToggle) {
      el.workToggle.setAttribute("aria-expanded", "false");
      el.workToggle.textContent = "Show the work";
    }

    el.tabNFix.textContent = String(fix.length);
    el.tabNAll.textContent = String(findings.length);
    el.tabNTrace.textContent = String(state.turns.length);

    el.tabFix.replaceChildren();
    fix.forEach(function (item) { el.tabFix.appendChild(findingCard(item)); });
    if (!fix.length) {
      el.tabFix.appendChild(make("div", "empty-note", "No critical or high findings in this scan."));
    }
    if (later.length) {
      el.tabFix.appendChild(collapsedGroup("Later", "low",
        "Review later (" + later.length + ")", later));
    }
    if (safe.length) {
      el.tabFix.appendChild(collapsedGroup("Safe", "safe",
        "Checked and safe (" + safe.length + ")", safe));
    }

    renderAllTargets(findings);
    renderTrace();
    el.tabRaw.replaceChildren();
    var pre = make("pre", "raw-json", JSON.stringify(report, null, 2));
    el.tabRaw.appendChild(pre);
    selectTab("fix");
  }

  function selectTab(name) {
    var panels = { fix: el.tabFix, all: el.tabAll, trace: el.tabTrace, raw: el.tabRaw };
    Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (btn) {
      btn.setAttribute("aria-selected", btn.getAttribute("data-tab") === name ? "true" : "false");
    });
    Object.keys(panels).forEach(function (key) {
      if (key === "fix") {
        panels[key].hidden = false;
        return;
      }
      panels[key].hidden = key !== name;
    });
  }

  function setRecordedLabel(node, report) {
    if (!node) { return; }
    var stamp = (report && (report.recorded_at || report.recorded_live)) || "";
    if (!stamp && state.demo) { stamp = demoRecordedAt(); }
    if (!stamp) { node.hidden = true; node.textContent = ""; return; }
    node.hidden = false;
    node.textContent = "Recorded live scan · " + stamp;
  }

  function demoRecordedAt() {
    return window.__tetherRecordedAt || "";
  }

  /* ---------- home: nav tint, hero clearance, layer picker ---------- */

  function onScroll() {}
  function syncHeroClearance() {}

  function loadRepos() {
    var list = $("repos-list");
    if (!list) { return; }
    fetch("/static/targets.json")
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(function (data) {
        if (!data || !data.groups) { return; }
        list.replaceChildren();
        data.groups.forEach(function (group) {
          var wrap = make("div", "dr-group");
          wrap.appendChild(make("h3", null, group.title || "Repos"));
          (group.repos || []).forEach(function (repo) {
            var btn = make("button", "dr-item dr-scan");
            btn.type = "button";
            btn.appendChild(make("span", "dr-repo", repo.repo));
            if (repo.finding) { btn.appendChild(make("span", "dr-finding", repo.finding)); }
            btn.addEventListener("click", function () {
              el.target.value = "https://github.com/" + repo.repo;
              syncInput();
              el.target.focus();
            });
            wrap.appendChild(btn);
          });
          list.appendChild(wrap);
        });
      })
      .catch(function () {});
  }

  /* ---------- wiring ---------- */

  el.target.addEventListener("input", syncInput);
  el.form.addEventListener("submit", function (event) {
    event.preventDefault();
    startScan(el.target.value);
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-demo]"), function (btn) {
    btn.addEventListener("click", startDemo);
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-home]"), function (btn) {
    btn.addEventListener("click", goHome);
  });
  Array.prototype.forEach.call(document.querySelectorAll(".tab"), function (btn) {
    btn.addEventListener("click", function () { selectTab(btn.getAttribute("data-tab")); });
  });
  Array.prototype.forEach.call(document.querySelectorAll("[data-try]"), function (btn) {
    btn.addEventListener("click", function () {
      el.target.value = btn.getAttribute("data-try") || "";
      syncInput();
      el.target.focus();
    });
  });
  if (el.workToggle) {
    el.workToggle.addEventListener("click", function () {
      var open = el.workToggle.getAttribute("aria-expanded") === "true";
      el.workToggle.setAttribute("aria-expanded", open ? "false" : "true");
      el.workToggle.textContent = open ? "Show the work" : "Hide the work";
      el.workPanel.hidden = open;
    });
  }
  el.skip.addEventListener("click", function () {
    if (state.report) { showResults(state.report); }
  });

  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", syncHeroClearance);

  syncInput();
  loadRepos();

  var params = new URLSearchParams(window.location.search);
  var scanParam = params.get("scan");
  if (params.get("demo") === "1") {
    startDemo();
  } else if (scanParam && /^[A-Za-z0-9_-]+$/.test(scanParam)) {
    openScanId(scanParam);
  }
})();
