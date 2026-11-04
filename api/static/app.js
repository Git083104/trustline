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
    platform_takeover: "Is this hosting platform still claimed?",
    tranco: "How widely used is this host?"
  };
  var CHECK_LABEL = {
    dns: "DNS",
    rdap: "registry",
    bucket_probe: "bucket",
    github_owner: "GitHub",
    github_repo: "GitHub",
    live_fetch: "live fetch",
    platform_takeover: "GitHub",
    wayback: "archive",
    cert_history: "certificates",
    done: "done"
  };
  var STATUS_WORDS = {
    blocked: "doesn't resolve",
    nxdomain: "doesn't resolve",
    nosuchbucket: "doesn't exist",
    unregistered: "not registered",
    registered: "registered",
    resolves: "resolves",
    missing: "not found",
    ok: "ok",
    unavailable: "unavailable",
    error: "failed"
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
    resume: $("scan-resume"),
    resumeText: $("scan-resume-text"),
    resumeView: $("scan-resume-view"),
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
    tabNTrace: $("tab-n-trace"),
    fixIt: $("fix-it"),
    fixPanel: $("fix-panel"),
    fixItems: $("fix-items"),
    fixAdvanced: $("fix-advanced"),
    fixEditN: $("fix-edit-n"),
    fixDownload: $("fix-download"),
    skippedToggle: $("skipped-toggle"),
    skippedList: $("skipped-list"),
    ignoredSummary: $("ignored-summary"),
    ignoredToggle: $("ignored-toggle"),
    ignoredList: $("ignored-list"),
    codeOnlySummary: $("code-only-summary"),
    codeOnlyToggle: $("code-only-toggle"),
    codeOnlyList: $("code-only-list"),
    badgeSnippet: $("badge-snippet"),
    badgeBox: $("badge-box"),
    badgeCopy: $("badge-copy"),
    nowTarget: $("now-target"),
    nowCheckName: $("now-check-name"),
    nowResult: $("now-check-result"),
    nowCounts: $("now-counts")
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
    if (screen === "home") { onScroll(); renderResumeBar(); }
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

  function scanQuery() {
    var path = window.location.pathname || "/";
    if (state.demo) { return path + "?demo=1"; }
    if (state.scanId) { return path + "?scan=" + encodeURIComponent(state.scanId); }
    return path;
  }

  function pushView(view, replace) {
    var data = { view: view, scanId: state.scanId || "", demo: !!state.demo };
    if (replace) { history.replaceState(data, "", scanQuery()); }
    else { history.pushState(data, "", scanQuery()); }
  }

  function stageName() {
    return STAGES[state.stage] || "Scan";
  }

  function renderResumeBar() {
    if (!el.resume) { return; }
    var live = (state.scanId || state.demo) && !state.finished;
    if (!live) {
      el.resume.hidden = true;
      return;
    }
    el.resume.hidden = false;
    if (el.resumeText) {
      el.resumeText.textContent = "Scan in progress: " + (state.target || "scan") + " · " + stageName() + " · ";
    }
  }

  function viewRunningScan() {
    if (state.finished && state.report) {
      showResults(state.report);
      return;
    }
    if (!state.source && !state.demo && state.scanId) {
      connectStream("/api/scan/" + encodeURIComponent(state.scanId) + "/events", {
        kind: state.kind,
        target: state.target,
        scanId: state.scanId,
        demo: false
      }, false);
    }
    pushView("scanning");
    show("scanning");
  }

  function goHome() {
    clearErrors();
    pushView("home");
    show("home");
  }

  function applyHistory(data) {
    var view = (data && data.view) || "home";
    if (view === "scanning") {
      if (!state.source && !state.demo && state.scanId && !state.finished) {
        connectStream("/api/scan/" + encodeURIComponent(state.scanId) + "/events", {
          kind: state.kind,
          target: state.target,
          scanId: state.scanId,
          demo: false
        }, false);
      }
      show("scanning");
      return;
    }
    if (view === "results") {
      if (state.report) { showResults(state.report, true); }
      else if (state.scanId && !state.demo) { loadReport(); }
      else { show("home"); }
      return;
    }
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
        var mapped = STATUS_WORDS[String(data.status).toLowerCase()];
        text = mapped || data.status;
      } else if (typeof data.exists === "boolean") {
        text = data.exists ? "exists" : "not found";
      } else if (typeof data.http_status === "number") {
        text = "HTTP " + data.http_status;
      }
      if (data.vulnerable === true) { text = text ? text + " · unclaimed" : "unclaimed"; }
      if (data.http_status === 404 && text !== "doesn't exist") {
        text = text && text !== "ok" ? text + " (404)" : "not found";
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
    planLine.appendChild(make("span", "feed-k", "Question"));
    planLine.appendChild(make("span", "feed-plan", turn.plan));
    body.appendChild(planLine);

    var callLine = make("div", "feed-line");
    callLine.appendChild(make("span", "feed-k", "Check"));
    var check = make("span", "feed-call");
    check.textContent = call.tool === "done" ? "lookups already in" : (CHECK_LABEL[call.tool] || call.tool);
    callLine.appendChild(check);
    body.appendChild(callLine);

    var resultLine = make("div", "feed-line feed-line-result");
    resultLine.appendChild(make("span", "feed-k", "Result"));
    var resultWrap = make("div", "feed-result-wrap");
    var badge = make("span", "sev-badge sev-checking");
    var resultText = make("span", "feed-result sev-fg-checking");
    resultWrap.appendChild(badge);
    resultWrap.appendChild(resultText);
    resultLine.appendChild(resultWrap);
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
      nowCheck(event.target, CHECK_LABEL[event.tool] || event.tool, "");
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
      nowCheck(turn.target, CHECK_LABEL[event.tool] || event.tool, read.text);
    }
  }

  function nowCheck(target, check, result) {
    if (el.nowTarget && target) { el.nowTarget.textContent = target; }
    if (el.nowCheckName && check) { el.nowCheckName.textContent = check; }
    if (el.nowResult && result) { el.nowResult.textContent = result; }
    nowCounts();
  }

  function nowCounts() {
    if (!el.nowCounts) { return; }
    var risky = 0;
    var safe = 0;
    Object.keys(state.buckets).forEach(function (name) {
      var bucket = state.buckets[name];
      if (bucket === "claimable" || bucket === "compromised") { risky += 1; }
      else if (bucket === "safe") { safe += 1; }
    });
    el.nowCounts.textContent = "checked " + (state.targetsSeen || 0) + " · risky " + risky + " · safe " + safe;
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
    nowCheck("—", "—", "—");
    setTargetLabels();
    setRecordedLabel(el.scanRecorded, null);
    renderLayers();
    renderPips();
    renderFound();
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
    connectStream(url, meta, true);
  }

  function connectStream(url, meta, reset) {
    if (reset !== false) { resetScan(meta); }
    else {
      state.kind = meta.kind || state.kind;
      state.target = meta.target || state.target;
      state.scanId = meta.scanId;
      state.demo = meta.demo;
    }
    if (state.source) { return; }
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
      nowCheck(event.target, "code checks", event.hard_signal ? "signal found" : "looking up");
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
      nowCheck(event.target, null, SEV_LABEL[event.severity] || String(event.severity || ""));
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
      finishTurns();
      renderLayers();
      loadReport();
    }
    if (state.screen === "home") { renderResumeBar(); }
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
        if (state.screen === "home") {
          renderResumeBar();
          return;
        }
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
        beginStream("/api/scan/" + encodeURIComponent(id) + "/events", {
          kind: out.body.kind,
          target: out.body.target,
          scanId: id,
          demo: false
        });
        history.pushState({ view: "scanning", scanId: id, demo: false }, "", "?scan=" + encodeURIComponent(id));
      })
      .catch(function () {
        showError("The scan could not be started.", function () { startScan(raw); });
      });
  }

  function startDemo() {
    beginStream("/api/scan/demo/events", {
      kind: "",
      target: "",
      scanId: "demo",
      demo: true
    });
    history.pushState({ view: "scanning", scanId: "demo", demo: true }, "", "?demo=1");
    fetch("/api/scan/demo")
      .then(function (res) { return res.json(); })
      .then(function (report) {
        state.report = report;
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
        showError("This scan is no longer available. Scan again.");
      });
  }

  /* ---------- report helpers (all code-derived) ---------- */

  function locRank(ref) {
    var file = "";
    var runs = "";
    if (typeof ref === "string") { file = ref.split(":")[0]; }
    else if (ref && typeof ref === "object") {
      file = String(ref.file || "");
      runs = String(ref.runs_in || "");
    }
    var lower = file.toLowerCase();
    if (runs === "test" || runs === "docs_only" || /\.md$/.test(lower) || /\.json$/.test(lower)
        || /(^|\/)(tests|test|docs|design|examples|fixtures)\//.test(lower)) {
      return 2;
    }
    if (/package\.json$|manifest\.json$|\.config\.|docker-compose|\.github\/workflows\//.test(lower)) {
      return 1;
    }
    return 0;
  }

  function locLine(ref) {
    if (typeof ref === "string") { return ref; }
    if (!ref || typeof ref !== "object") { return ""; }
    if (ref.file) { return ref.file + (ref.line ? ":" + ref.line : ""); }
    if (ref.page_url) { return ref.page_url + (ref.line ? ":" + ref.line : ""); }
    if (ref.file_line) { return ref.file_line; }
    return "";
  }

  function sortedRefs(item) {
    var refs = (item.locations && item.locations.length ? item.locations : item.references) || [];
    return refs.slice().sort(function (a, b) { return locRank(a) - locRank(b); });
  }

  function locationLines(item) {
    var lines = sortedRefs(item).map(locLine).filter(Boolean);
    return { shown: lines.slice(0, 3).join(", "), more: Math.max(0, lines.length - 3) };
  }

  function whereUsed(item) {
    var lines = sortedRefs(item).map(locLine).filter(Boolean);
    if (lines.length <= 3) { return lines.join(", "); }
    return lines.slice(0, 3).join(", ") + " +" + (lines.length - 3) + " more";
  }

  function isInertItem(item) {
    var refs = sortedRefs(item);
    if (!refs.length) { return false; }
    return refs.every(function (ref) { return locRank(ref) === 2; });
  }

  function fileBucket(ref) {
    var file = typeof ref === "string" ? ref.split(":")[0] : String((ref && ref.file) || "");
    var lower = file.toLowerCase();
    if (/(^|\/)(tests|test|__tests__|spec|fixtures)\//.test(lower) || /(^|\/)test_/.test(lower)) {
      return "tests";
    }
    return "docs";
  }

  function inertPlace(item) {
    var tests = {};
    var docs = {};
    sortedRefs(item).forEach(function (ref) {
      var file = typeof ref === "string" ? ref.split(":")[0] : String((ref && ref.file) || "");
      if (!file) { return; }
      if (fileBucket(ref) === "tests") { tests[file] = true; }
      else { docs[file] = true; }
    });
    var t = Object.keys(tests).length;
    var d = Object.keys(docs).length;
    var bits = [];
    if (t) { bits.push("in tests (" + t + (t === 1 ? " file)" : " files)")); }
    if (d) { bits.push("in docs (" + d + (d === 1 ? " file)" : " files)")); }
    return bits.join(" · ");
  }

  function evidenceText(item) {
    return String(item.evidence_line || "").replace(/^Evidence:\s*/, "");
  }

  function ownerStatus(item) {
    var evidence = item.evidence || {};
    if (/compromis/i.test(String(item.evidence_line || item.risk || ""))) {
      return "compromised";
    }
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
    var sevcol = make("div", "sevcol");
    var sev = make("span", "finding-sev sev-" + key);
    sev.appendChild(make("span", "sev-dot"));
    sev.appendChild(make("span", null, SEV_LABEL[item.severity] || item.severity));
    sevcol.appendChild(sev);
    var main = make("div", "finding-main");

    main.appendChild(make("p", "finding-headline", item.headline || item.risk || item.target));
    var badge = make("span", "finding-where");
    if (item.evidence_level === "proven") {
      badge.textContent = "Proven";
      badge.title = "Proven: checked directly, e.g. the registry says no one owns this domain";
      main.appendChild(badge);
    } else if (item.evidence_level === "likely") {
      badge.textContent = "Likely";
      badge.title = "Likely: the lookups point to a problem, but a human should confirm the dates";
      main.appendChild(badge);
    }
    var why = item.why || item.risk || "";
    if (why) {
      var whyP = make("p", "finding-why");
      whyP.appendChild(make("span", "why-k", "Why it matters"));
      whyP.appendChild(document.createTextNode(" " + why));
      main.appendChild(whyP);
    }
    var steps = item.steps || [];
    if (steps.length) {
      var ol = make("ol", "finding-steps");
      var cap = make("p", "steps-k", "What to do");
      main.appendChild(cap);
      steps.slice(0, 3).forEach(function (step) {
        ol.appendChild(make("li", null, step));
      });
      main.appendChild(ol);
    }
    var where = whereUsed(item);

    var details = make("div", "finding-details");
    details.hidden = true;
    addDetail(details, "Target", item.target, false);
    addDetail(details, "Evidence", evidenceText(item), false);
    var locs = locationLines(item);
    addDetail(details, "Found in", locs.shown, false);
    if (locs.more) { addDetail(details, "More", "and " + locs.more + " more", false); }
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
    if (item.evidence && item.evidence.csp_blocks_external_scripts) {
      addDetail(
        details,
        "CSP",
        "Blocked on this page by its CSP; any other page loading this URL is exposed",
        true
      );
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
    main.appendChild(details);

    article.appendChild(sevcol);
    article.appendChild(main);
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
      row.appendChild(make("span", "group-row-sep", "·"));
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

  function recordedScanSeconds(report) {
    var stages = (report && report.stage_seconds) || {};
    var total = 0;
    Object.keys(stages).forEach(function (key) {
      total += Number(stages[key]) || 0;
    });
    if (total > 0) { return Math.round(total); }
    if (state.elapsedMs > 0 && !state.demo) { return Math.round(state.elapsedMs / 1000); }
    return 0;
  }

  function renderMeta(report) {
    var coverage = report.coverage || {};
    var findings = report.findings || [];
    var secs = recordedScanSeconds(report);
    var files = Number(coverage.files_scanned || 0);
    var outside = findings.length;
    var fixN = findings.filter(function (f) {
      return f.severity === "critical" || f.severity === "high";
    }).length;
    var fileBit = files === 1 ? "1 file" : files.toLocaleString() + " files";
    var timeBit = secs > 0 ? " in " + secs + "s" : (state.demo ? " (replayed)" : "");
    var svc = outside === 1 ? "1 outside service" : outside.toLocaleString() + " outside services";
    var need = fixN === 1 ? "1 needs fixing today" : fixN + " need fixing today";
    el.resMeta.textContent = "Scanned " + fileBit + timeBit + " · found " + svc + " · " + need;
  }

  function bindCollapsible(toggle, list, names, showLabel) {
    if (!toggle || !list) { return; }
    list.replaceChildren();
    if (!names.length) {
      toggle.hidden = true;
      list.hidden = true;
      return;
    }
    toggle.hidden = false;
    toggle.textContent = showLabel || "Show list";
    names.slice(0, 40).forEach(function (name) {
      list.appendChild(make("li", null, name));
    });
    list.hidden = true;
    toggle.onclick = function () {
      var open = !list.hidden;
      list.hidden = open;
      toggle.textContent = open ? (showLabel || "Show list") : "Hide list";
    };
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

  function finishTurns() {
    state.turns.forEach(function (turn) {
      if (turn.tool === "done" && (turn.sev === "checking" || turn.result === "running…")) {
        turn.sev = "neutral";
        turn.result = turn.plan || "lookups already answered this";
      } else if (turn.sev === "checking" || turn.result === "running…") {
        turn.sev = "neutral";
        turn.result = "no answer in time";
      }
      if (turn.node) { setRowResult(turn.node, turn.sev, turn.result); }
    });
  }

  function renderTrace() {
    el.tabTrace.replaceChildren();
    if (state.finished) { finishTurns(); }
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
      body.appendChild(make("div", "feed-line")).appendChild(make("span", "feed-k", "Question"));
      body.lastChild.appendChild(make("span", "feed-plan", turn.plan));
      if (turn.tool !== "done") {
        var checkLine = make("div", "feed-line");
        checkLine.appendChild(make("span", "feed-k", "Check"));
        checkLine.appendChild(make("span", "feed-call", CHECK_LABEL[turn.tool] || turn.tool));
        body.appendChild(checkLine);
      }
      var resultLine = make("div", "feed-line");
      resultLine.appendChild(make("span", "feed-k", "Result"));
      resultLine.appendChild(make("span", "sev-fg-" + turn.sev, turn.result));
      body.appendChild(resultLine);
      row.appendChild(body);
      card.appendChild(row);
    });
    el.tabTrace.appendChild(card);
  }

  function showResults(report, fromHistory) {
    closeSource();
    state.report = report;
    state.finished = true;
    if (!fromHistory) { pushView("results"); }
    try {
      sessionStorage.setItem("tether-view", "results");
      sessionStorage.setItem("tether-scan", state.demo ? "demo" : (state.scanId || ""));
    } catch (err) {}
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
    if (el.badgeSnippet) {
      var target = report.target || state.target || "";
      if ((report.kind || state.kind) === "repo" && target) {
        var badgeUrl = location.origin + "/api/badge?repo=" + encodeURIComponent(target);
        el.badgeSnippet.textContent = "[![Tether](" + badgeUrl + ")](" + location.origin + ")";
        if (el.badgeBox) { el.badgeBox.hidden = false; }
      } else {
        el.badgeSnippet.textContent = "";
        if (el.badgeBox) { el.badgeBox.hidden = true; }
      }
    }
    setRecordedLabel(el.resRecorded, report);
    var ignored = ((report.coverage || {}).ignored_files) || [];
    if (el.ignoredSummary) {
      if (ignored.length) {
        el.ignoredSummary.hidden = false;
        el.ignoredSummary.textContent = ignored.length + " files ignored by .tether.yml";
      } else {
        el.ignoredSummary.hidden = true;
        el.ignoredSummary.textContent = "";
      }
    }
    bindCollapsible(el.ignoredToggle, el.ignoredList, ignored, "Show list");
    var codeOnly = report.code_only_targets || [];
    if (el.codeOnlySummary) {
      if (codeOnly.length) {
        el.codeOnlySummary.hidden = false;
        el.codeOnlySummary.textContent = "Checked by code only (" + codeOnly.length + ")";
      } else {
        el.codeOnlySummary.hidden = true;
        el.codeOnlySummary.textContent = "";
      }
    }
    bindCollapsible(el.codeOnlyToggle, el.codeOnlyList, codeOnly, "Show list");
    if (el.partial) {
      var skipped = report.skipped_targets || [];
      if (report.code_only) {
        el.partial.hidden = false;
        el.partial.textContent = report.code_only_banner
          || "Daily AI budget reached: this scan used code rules only.";
        if (el.skippedToggle) { el.skippedToggle.hidden = true; }
        if (el.skippedList) { el.skippedList.hidden = true; }
      } else if (skipped.length) {
        el.partial.hidden = false;
        el.partial.textContent = "Partial scan: " + skipped.length + " targets not checked (time limit).";
        bindCollapsible(el.skippedToggle, el.skippedList, skipped, "Show list");
      } else {
        el.partial.hidden = true;
        el.partial.textContent = "";
        if (el.skippedToggle) { el.skippedToggle.hidden = true; }
        if (el.skippedList) { el.skippedList.hidden = true; }
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
    var inertLater = later.filter(isInertItem);
    var restLater = later.filter(function (item) { return !isInertItem(item); });
    if (inertLater.length) {
      var n = inertLater.length;
      var inertWrap = collapsedGroup(
        "Review",
        "low",
        n + " names in tests and docs no longer exist. They never run, so there's nothing to fix.",
        []
      );
      var inertRows = inertWrap.querySelector(".group-rows");
      inertLater.forEach(function (item) {
        var row = make("div", "group-row");
        row.appendChild(make("span", "group-row-target", item.target));
        row.appendChild(make("span", "group-row-sep", "·"));
        row.appendChild(make("span", "group-row-note", ownerStatus(item)));
        row.appendChild(make("span", "group-row-sep", "·"));
        row.appendChild(make("span", "group-row-note", inertPlace(item)));
        inertRows.appendChild(row);
      });
      el.tabFix.appendChild(inertWrap);
    }
    if (restLater.length) {
      el.tabFix.appendChild(collapsedGroup("Review", "low",
        restLater.length + " to look at later", restLater));
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
    setupFixIt(report);
  }

  function setupFixIt(report) {
    if (!el.fixIt || !el.fixPanel) { return; }
    el.fixPanel.hidden = true;
    if (el.fixItems) { el.fixItems.replaceChildren(); }
    var id = state.demo ? "demo" : state.scanId;
    if (!id) {
      el.fixIt.hidden = true;
      return;
    }
    el.fixIt.hidden = false;
    el.fixDownload.href = "/api/scan/" + encodeURIComponent(id) + "/fix.patch";
    el.fixIt.onclick = function () {
      fetch("/api/scan/" + encodeURIComponent(id) + "/fix")
        .then(function (res) { return res.ok ? res.json() : {}; })
        .then(function (data) {
          el.fixPanel.hidden = false;
          renderFixPlan(data);
        })
        .catch(function () {
          el.fixPanel.hidden = false;
          if (el.fixItems) {
            el.fixItems.textContent = "The fix plan could not be built.";
          }
        });
    };
  }

  function copyBtn(label, value) {
    var btn = make("button", "btn btn-secondary copy-btn");
    btn.type = "button";
    btn.appendChild(copyIcon());
    btn.appendChild(make("span", null, label));
    btn.addEventListener("click", function () {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value || "").catch(function () {});
      }
      btn.lastChild.textContent = "Copied";
      setTimeout(function () { btn.lastChild.textContent = label; }, 1500);
    });
    return btn;
  }

  function renderFixPlan(data) {
    if (!el.fixItems) { return; }
    el.fixItems.replaceChildren();
    (data.items || []).forEach(function (item) {
      var card = make("div", "fix-item");
      card.appendChild(make("p", "finding-headline", item.headline || item.target));
      var ol = make("ol", "finding-steps");
      (item.steps || []).forEach(function (step) { ol.appendChild(make("li", null, step)); });
      card.appendChild(ol);
      card.appendChild(copyBtn("Copy as GitHub issue", (item.issue_title || "") + "\n\n" + (item.issue_body || "")));
      card.appendChild(copyBtn("Copy prompt for your coding assistant", item.prompt || ""));
      el.fixItems.appendChild(card);
    });
    var n = data.edit_count || (data.edits || []).length || 0;
    if (el.fixAdvanced) {
      el.fixAdvanced.hidden = false;
      if (el.fixEditN) { el.fixEditN.textContent = String(n); }
    }
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
    var more = $("repos-more");
    var sites = $("sites-list");
    fetch("/static/targets.json")
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(function (data) {
        if (!data) { return; }
        if (list && data.groups) {
          list.replaceChildren();
          data.groups.forEach(function (group) {
            (group.repos || []).forEach(function (repo) {
              var btn = make("button", "repo-chip");
              btn.type = "button";
              btn.appendChild(make("span", "repo-chip-name", repo.repo));
              if (repo.about) {
                btn.appendChild(make("span", "repo-chip-about", repo.about));
              }
              btn.appendChild(make("span", "repo-chip-expect", repo.expect || ""));
              btn.addEventListener("click", function () {
                el.target.value = "https://github.com/" + repo.repo;
                syncInput();
                el.target.focus();
              });
              list.appendChild(btn);
            });
          });
          if (more) {
            more.hidden = list.children.length <= 6;
            more.textContent = "Show all";
            more.addEventListener("click", function () {
              var open = !list.classList.contains("is-collapsed");
              list.classList.toggle("is-collapsed", open);
              more.textContent = open ? "Show all" : "Show fewer";
            });
          }
        }
        if (sites && data.websites) {
          sites.replaceChildren();
          data.websites.forEach(function (site) {
            var btn = make("button", "repo-chip");
            btn.type = "button";
            btn.appendChild(make("span", "repo-chip-name", site.name || site.url));
            if (site.about) {
              btn.appendChild(make("span", "repo-chip-about", site.about));
            }
            btn.appendChild(make("span", "repo-chip-expect", site.expect || ""));
            btn.addEventListener("click", function () {
              el.target.value = site.url;
              syncInput();
              el.target.focus();
            });
            sites.appendChild(btn);
          });
        }
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
  if (el.resumeView) {
    el.resumeView.addEventListener("click", viewRunningScan);
  }
  window.addEventListener("popstate", function (event) {
    applyHistory(event.state || {});
  });
  if (el.badgeCopy) {
    el.badgeCopy.addEventListener("click", function () {
      var value = el.badgeSnippet ? el.badgeSnippet.textContent : "";
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value || "").catch(function () {});
      }
      el.badgeCopy.textContent = "Copied";
      setTimeout(function () { el.badgeCopy.textContent = "Copy badge"; }, 1500);
    });
  }

  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", syncHeroClearance);

  syncInput();
  loadRepos();

  var params = new URLSearchParams(window.location.search);
  var scanParam = params.get("scan");
  var savedView = "";
  var savedScan = "";
  try {
    savedView = sessionStorage.getItem("tether-view") || "";
    savedScan = sessionStorage.getItem("tether-scan") || "";
  } catch (err) {}
  if (scanParam && /^[A-Za-z0-9_-]+$/.test(scanParam)) {
    openScanId(scanParam);
  } else if (params.get("demo") === "1") {
    if (savedView === "results" && savedScan === "demo") {
      fetch("/api/scan/demo")
        .then(function (res) { return res.json(); })
        .then(function (report) {
          state.demo = true;
          state.scanId = "demo";
          showResults(report, true);
        })
        .catch(function () { startDemo(); });
    } else {
      startDemo();
    }
  } else {
    history.replaceState({ view: "home", scanId: "", demo: false }, "", window.location.pathname);
  }
})();
