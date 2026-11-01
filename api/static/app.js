(function () {
  var MAX_CALLS = 6;
  var STAGES = ["Find", "Check", "Investigate", "Rank", "Report"];
  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  var LEGEND = [
    { key: "claimable", label: "Claimable now", color: "oklch(0.62 0.18 25)" },
    { key: "compromised", label: "Known compromised", color: "oklch(0.70 0.14 55)" },
    { key: "checking", label: "Checking", color: "#968ae0" },
    { key: "safe", label: "Looks safe", color: "oklch(0.62 0.12 160)" }
  ];

  var state = {
    kind: "",
    target: "",
    scanId: "",
    demo: false,
    source: null,
    events: [],
    report: null,
    calls: 0,
    found: 0,
    stage: 0,
    startedAt: 0,
    timer: null,
    buckets: {},
    ready: false
  };

  var el = {
    error: document.getElementById("error"),
    home: document.getElementById("page-home"),
    scan: document.getElementById("page-scan"),
    results: document.getElementById("page-results"),
    target: document.getElementById("target"),
    chip: document.getElementById("kind-chip"),
    form: document.getElementById("scan-form"),
    demo: document.getElementById("demo"),
    stepper: document.getElementById("stepper"),
    feed: document.getElementById("feed"),
    bar: document.getElementById("progress-bar"),
    foundCount: document.getElementById("found-count"),
    legendBar: document.getElementById("legend-bar"),
    legend: document.getElementById("legend"),
    callsUsed: document.getElementById("calls-used"),
    callsMax: document.getElementById("calls-max"),
    pips: document.getElementById("calls-pips"),
    scanLabel: document.getElementById("scan-target-label"),
    scanChip: document.getElementById("scan-kind-chip"),
    scanStatus: document.getElementById("scan-status"),
    skip: document.getElementById("skip-report"),
    resTarget: document.getElementById("res-target"),
    resChip: document.getElementById("res-kind-chip"),
    headline: document.getElementById("res-headline"),
    chips: document.getElementById("res-chips"),
    resMeta: document.getElementById("res-meta"),
    tabFix: document.getElementById("tab-fix"),
    tabAll: document.getElementById("tab-all"),
    tabTrace: document.getElementById("tab-trace"),
    tabRaw: document.getElementById("tab-raw"),
    tabNFix: document.getElementById("tab-n-fix"),
    tabNAll: document.getElementById("tab-n-all"),
    tabNTrace: document.getElementById("tab-n-trace")
  };

  el.callsMax.textContent = String(MAX_CALLS);

  function text(node, value) {
    node.textContent = value == null ? "" : String(value);
  }

  function showError(message, retry) {
    el.error.hidden = !message;
    el.error.replaceChildren();
    if (!message) {
      return;
    }
    var span = document.createElement("span");
    text(span, message);
    el.error.appendChild(span);
    if (retry) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-secondary";
      text(btn, "Retry");
      btn.addEventListener("click", retry);
      el.error.appendChild(btn);
    }
  }

  function detectKind(value) {
    var v = (value || "").trim();
    if (/^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/]+/i.test(v)) {
      return "GitHub repo";
    }
    if (/^https?:\/\//i.test(v)) {
      return "Website";
    }
    return "";
  }

  function setChip(node, kind) {
    if (!kind) {
      node.hidden = true;
      return;
    }
    node.hidden = false;
    text(node, kind);
  }

  function page(name) {
    el.home.hidden = name !== "home";
    el.scan.hidden = name !== "scan";
    el.results.hidden = name !== "results";
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
  }

  function formatClock(ms) {
    var sec = Math.max(0, Math.floor(ms / 1000));
    var m = Math.floor(sec / 60);
    var s = sec % 60;
    return m + ":" + String(s).padStart(2, "0");
  }

  function tickTimer() {
    text(el.scanStatus, "Scanning · " + formatClock(Date.now() - state.startedAt));
  }

  function mapHttpError(status, body) {
    var err = (body && (body.error || body.message)) || "";
    if (status === 503) {
      return err || "Live scans aren't configured; try the demo";
    }
    if (status === 429) {
      if (/daily/i.test(err)) {
        return "Daily limit reached, try the demo";
      }
      return "5 scans per hour per IP; try again later";
    }
    if (/can't be scanned|blocked/i.test(err)) {
      return "This address can't be scanned";
    }
    if (status === 400) {
      return err || "That URL isn't supported";
    }
    return err || "Scan failed";
  }

  function startScan(target) {
    showError("");
    closeSource();
    page("home");
    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: target })
    })
      .then(function (res) {
        return res.json().then(function (body) {
          return { res: res, body: body };
        });
      })
      .then(function (out) {
        if (!out.res.ok) {
          showError(mapHttpError(out.res.status, out.body), function () {
            startScan(target);
          });
          return;
        }
        var id = out.body.scan_id;
        history.replaceState({}, "", "?scan=" + encodeURIComponent(id));
        beginStream("/api/scan/" + encodeURIComponent(id) + "/events", {
          kind: out.body.kind === "website" ? "Website" : "GitHub repo",
          target: out.body.target,
          scanId: id,
          demo: false
        });
      })
      .catch(function () {
        showError("Scan failed or the connection dropped", function () {
          startScan(target);
        });
      });
  }

  function startDemo() {
    showError("");
    history.replaceState({}, "", "?demo=1");
    beginStream("/api/scan/demo/events", {
      kind: "GitHub repo",
      target: "tests/fixtures/demo_repo",
      scanId: "demo",
      demo: true
    });
  }

  function setSkipEnabled(on) {
    state.ready = !!on;
    el.skip.disabled = !on;
  }

  function resetScanUi(meta) {
    state.events = [];
    state.report = null;
    state.calls = 0;
    state.found = 0;
    state.stage = 0;
    state.kind = meta.kind;
    state.target = meta.target;
    state.scanId = meta.scanId;
    state.demo = meta.demo;
    state.buckets = {};
    state.startedAt = Date.now();
    text(el.scanLabel, meta.target);
    setChip(el.scanChip, meta.kind);
    tickTimer();
    el.feed.replaceChildren();
    text(el.foundCount, "0");
    renderStepper(0);
    setProgress(8);
    renderPips(0);
    renderLegend();
    setSkipEnabled(false);
    if (meta.demo) {
      setSkipEnabled(true);
      fetch("/api/scan/demo")
        .then(function (res) { return res.json(); })
        .then(function (report) {
          state.report = report;
          setSkipEnabled(true);
        })
        .catch(function () {});
    }
    page("scan");
    if (state.timer) {
      clearInterval(state.timer);
    }
    state.timer = setInterval(tickTimer, 250);
  }

  function renderStepper(stage) {
    el.stepper.replaceChildren();
    STAGES.forEach(function (name, index) {
      var li = document.createElement("li");
      if (index < stage) {
        li.className = "done";
      }
      if (index === stage) {
        li.className = "active";
      }
      var mark = document.createElement("span");
      text(mark, index < stage ? "✓" : String(index + 1));
      var label = document.createElement("b");
      label.style.fontWeight = "500";
      text(label, name);
      li.appendChild(mark);
      li.appendChild(label);
      el.stepper.appendChild(li);
    });
  }

  function setProgress(pct) {
    el.bar.style.width = Math.max(0, Math.min(100, pct)) + "%";
    el.bar.parentNode.setAttribute("aria-valuenow", String(Math.round(pct)));
  }

  function renderPips(used) {
    text(el.callsUsed, String(used));
    el.pips.replaceChildren();
    for (var i = 0; i < MAX_CALLS; i += 1) {
      var pip = document.createElement("i");
      if (i < used) {
        pip.className = "on";
      }
      el.pips.appendChild(pip);
    }
  }

  function countBuckets() {
    var counts = { claimable: 0, compromised: 0, checking: 0, safe: 0 };
    Object.keys(state.buckets).forEach(function (k) {
      var b = state.buckets[k];
      if (counts[b] != null) {
        counts[b] += 1;
      }
    });
    return counts;
  }

  function renderLegend() {
    var counts = countBuckets();
    var total = state.found || Object.keys(state.buckets).length;
    text(el.foundCount, String(total));
    el.legendBar.replaceChildren();
    el.legend.replaceChildren();
    LEGEND.forEach(function (item) {
      var n = counts[item.key] || 0;
      var seg = document.createElement("i");
      seg.style.background = item.color;
      seg.style.flex = String(Math.max(n, 0));
      el.legendBar.appendChild(seg);
      var row = document.createElement("div");
      var left = document.createElement("span");
      var sw = document.createElement("span");
      sw.className = "sw";
      sw.style.background = item.color;
      left.appendChild(sw);
      left.appendChild(document.createTextNode(item.label));
      var right = document.createElement("span");
      text(right, String(n));
      row.appendChild(left);
      row.appendChild(right);
      el.legend.appendChild(row);
    });
  }

  function stageFrom(type) {
    if (type === "extracted") {
      return 0;
    }
    if (type === "precheck") {
      return 1;
    }
    if (type === "plan" || type === "act" || type === "observe") {
      return 2;
    }
    if (type === "ranked") {
      return 3;
    }
    if (type === "done") {
      return 4;
    }
    return state.stage;
  }

  function resultPill(summary) {
    var s = String(summary || "");
    var pill = document.createElement("span");
    var label = "Checking";
    var cls = "sev-checking";
    if (/NoSuchBucket|unregistered|nxdomain|not found|404|claimable/i.test(s)) {
      label = "Critical";
      cls = "sev-critical";
    } else if (/compromised/i.test(s)) {
      label = "High";
      cls = "sev-high";
    } else if (/ok|exists|registered|safe|tranco/i.test(s)) {
      label = "Safe";
      cls = "sev-info";
    }
    pill.className = "sev " + cls;
    text(pill, label);
    return pill;
  }

  function appendFeed(event) {
    if (event.type !== "plan" && event.type !== "act" && event.type !== "observe") {
      return;
    }
    if (event.tool === "done") {
      return;
    }
    var row = el.feed.lastElementChild;
    if (!row || row.getAttribute("data-target") !== String(event.target || "")) {
      row = document.createElement("div");
      row.className = "feed-item";
      row.setAttribute("data-target", event.target || "");
      var n = document.createElement("span");
      n.className = "feed-n";
      text(n, String(el.feed.children.length + 1).padStart(2, "0"));
      var body = document.createElement("div");
      row.appendChild(n);
      row.appendChild(body);
      el.feed.appendChild(row);
    }
    var body = row.lastElementChild;
    var line = document.createElement("div");
    line.className = "feed-line";
    var label = document.createElement("span");
    label.className = "feed-k";
    if (event.type === "plan") {
      text(label, "Plan");
      var value = document.createElement("span");
      text(value, event.tool ? "pick " + event.tool : "plan");
      line.appendChild(label);
      line.appendChild(value);
    } else if (event.type === "act") {
      text(label, "Call");
      var code = document.createElement("code");
      var args = event.args ? JSON.stringify(event.args) : "";
      text(code, (event.tool || "") + "(" + args.replace(/^\{|\}$/g, "") + ")");
      line.appendChild(label);
      line.appendChild(code);
    } else {
      text(label, "Result");
      var wrap = document.createElement("span");
      wrap.appendChild(resultPill(event.result_summary));
      wrap.appendChild(document.createTextNode(" "));
      var rest = document.createElement("span");
      text(rest, event.result_summary || "");
      wrap.appendChild(rest);
      line.appendChild(label);
      line.appendChild(wrap);
    }
    body.appendChild(line);
  }

  function bumpFound(event) {
    if (event.type === "extracted" && typeof event.actionable === "number") {
      state.found = event.actionable;
    }
    if (event.type === "precheck" && event.target) {
      state.buckets[event.target] = event.hard_signal ? "claimable" : "checking";
      state.found = Math.max(state.found, Object.keys(state.buckets).length);
    }
    if (event.type === "ranked" && event.target) {
      var sev = String(event.severity || "");
      var line = String(event.evidence_line || event.risk || "");
      if (/compromised/i.test(line) || event.target === "polyfill.io") {
        state.buckets[event.target] = "compromised";
      } else if (sev === "info") {
        state.buckets[event.target] = "safe";
      } else if (sev === "critical" || sev === "high") {
        if (state.buckets[event.target] !== "compromised") {
          state.buckets[event.target] = "claimable";
        }
      }
    }
    renderLegend();
  }

  function beginStream(url, meta) {
    closeSource();
    resetScanUi(meta);
    var source = new EventSource(url);
    state.source = source;
    source.onmessage = function (msg) {
      var event;
      try {
        event = JSON.parse(msg.data);
      } catch (err) {
        return;
      }
      state.events.push(event);
      var next = stageFrom(event.type);
      if (next > state.stage) {
        state.stage = next;
        renderStepper(state.stage);
        setProgress((state.stage + 1) / STAGES.length * 100);
      }
      if (event.type === "plan" && event.tool !== "done") {
        state.calls = Math.min(MAX_CALLS, state.calls + 1);
        renderPips(state.calls);
      }
      appendFeed(event);
      bumpFound(event);
      if (event.type === "error") {
        source.close();
        showError(event.message || "Scan failed", function () {
          if (state.demo) {
            startDemo();
          } else {
            startScan(state.target);
          }
        });
      }
      if (event.type === "done") {
        source.close();
        finish();
      }
    };
    source.onerror = function () {
      source.close();
      if (!state.report) {
        showError("Scan failed or the connection dropped", function () {
          if (state.demo) {
            startDemo();
          } else if (state.scanId && state.scanId !== "demo") {
            loadFinished(state.scanId);
          } else {
            startScan(state.target);
          }
        });
      }
    };
  }

  function finish() {
    renderStepper(4);
    setProgress(100);
    var url = state.demo ? "/api/scan/demo" : "/api/scan/" + encodeURIComponent(state.scanId);
    fetch(url)
      .then(function (res) {
        if (res.status === 409) {
          throw new Error("running");
        }
        return res.json();
      })
      .then(function (report) {
        state.report = report;
        setSkipEnabled(true);
        showResults(report);
      })
      .catch(function () {
        showError("Scan finished but the report could not be loaded", function () {
          if (state.demo) {
            startDemo();
          } else {
            loadFinished(state.scanId);
          }
        });
      });
  }

  function loadFinished(id) {
    fetch("/api/scan/" + encodeURIComponent(id))
      .then(function (res) {
        if (res.status === 404) {
          throw new Error("missing");
        }
        if (res.status === 409) {
          beginStream("/api/scan/" + encodeURIComponent(id) + "/events", {
            kind: "GitHub repo",
            target: id,
            scanId: id,
            demo: false
          });
          return null;
        }
        return res.json();
      })
      .then(function (report) {
        if (report) {
          showResults(report);
        }
      })
      .catch(function () {
        showError("That scan is no longer in memory. Run it again.");
        page("home");
      });
  }

  function ownerStatus(item) {
    var ev = item.evidence || {};
    var owner = ev.github_owner || {};
    var repo = ev.github_repo || {};
    var rdap = ev.rdap || {};
    var bucket = ev.bucket_probe || {};
    if (String(owner.status || "").toLowerCase() === "missing") {
      return "owner missing";
    }
    if (String(repo.status || "").toLowerCase() === "missing") {
      return "repo missing";
    }
    if (String(rdap.status || "").toLowerCase() === "unregistered") {
      return "unregistered";
    }
    if (bucket.status === "NoSuchBucket") {
      return "bucket missing";
    }
    if (String(rdap.status || "").toLowerCase() === "registered") {
      return "registered";
    }
    if (owner.exists) {
      return "owner exists";
    }
    return "—";
  }

  function whereUsed(item) {
    var refs = item.references || [];
    if (!refs.length) {
      return "";
    }
    if (typeof refs[0] === "string") {
      return refs.join(", ");
    }
    return refs
      .map(function (ref) {
        if (ref.page_url) {
          return ref.page_url + " <" + (ref.tag || "") + ">:" + ref.line;
        }
        if (ref.file_line) {
          return ref.file_line;
        }
        if (ref.file) {
          return ref.file + ":" + ref.line;
        }
        return "";
      })
      .filter(Boolean)
      .join(", ");
  }

  function sortFindings(list) {
    return list.slice().sort(function (a, b) {
      var da = SEV_ORDER[a.severity] || 9;
      var db = SEV_ORDER[b.severity] || 9;
      if (da !== db) {
        return da - db;
      }
      return String(a.target).localeCompare(String(b.target));
    });
  }

  function addDetail(grid, label, value) {
    if (!value) {
      return;
    }
    var k = document.createElement("span");
    k.className = "k";
    text(k, label);
    var v = document.createElement("code");
    text(v, value);
    grid.appendChild(k);
    grid.appendChild(v);
  }

  function findingCard(item) {
    var art = document.createElement("article");
    art.className = "finding is-" + (item.severity || "info");
    var top = document.createElement("div");
    top.className = "finding-top";
    var sev = document.createElement("span");
    sev.className = "sev sev-" + (item.severity || "info");
    text(sev, item.severity || "info");
    var tgt = document.createElement("span");
    tgt.className = "mono";
    text(tgt, item.target);
    var typ = document.createElement("span");
    typ.className = "tag tag-neutral";
    text(typ, item.kind || "");
    var where = document.createElement("span");
    where.className = "where";
    text(where, whereUsed(item));
    top.appendChild(sev);
    top.appendChild(tgt);
    top.appendChild(typ);
    top.appendChild(where);
    var risk = document.createElement("p");
    risk.className = "risk";
    text(risk, item.risk || "");
    var fixRow = document.createElement("div");
    fixRow.className = "fix-row";
    var fixK = document.createElement("span");
    fixK.className = "fix-k";
    text(fixK, "Fix");
    var fixT = document.createElement("span");
    fixT.className = "fix-t";
    text(fixT, item.fix || "");
    var copy = document.createElement("button");
    copy.type = "button";
    copy.className = "btn btn-secondary";
    text(copy, "Copy");
    copy.addEventListener("click", function () {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(item.fix || "").then(function () {
          text(copy, "Copied");
        });
      }
    });
    fixRow.appendChild(fixK);
    fixRow.appendChild(fixT);
    fixRow.appendChild(copy);
    var detailsBtn = document.createElement("button");
    detailsBtn.type = "button";
    detailsBtn.className = "details-btn";
    text(detailsBtn, "▾ Details");
    var details = document.createElement("div");
    details.className = "details";
    addDetail(details, "Evidence", item.evidence_line);
    addDetail(details, "Found in", whereUsed(item));
    addDetail(details, "Rule note", item.floor_reason);
    if (item.tranco_rank != null) {
      addDetail(details, "Tranco", "rank " + item.tranco_rank);
    }
    if (item.parked || item.for_sale) {
      addDetail(
        details,
        "Live fetch",
        (item.for_sale ? "for sale" : "parked") +
          (item.live_signal ? " · " + item.live_signal : "")
      );
    }
    if (item.action_ref) {
      addDetail(
        details,
        "Action ref",
        item.action_ref +
          (item.action_sha_pinned ? " (SHA-pinned)" : " (not SHA-pinned)")
      );
    }
    detailsBtn.addEventListener("click", function () {
      art.classList.toggle("open");
    });
    art.appendChild(top);
    art.appendChild(risk);
    art.appendChild(fixRow);
    art.appendChild(detailsBtn);
    art.appendChild(details);
    return art;
  }

  function collapsedGroup(title, tag, items, cls) {
    var wrap = document.createElement("div");
    wrap.className = "group";
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "group-btn";
    var label = document.createElement("span");
    label.className = "sev " + cls;
    text(label, tag);
    var rest = document.createElement("span");
    text(rest, title);
    btn.appendChild(label);
    btn.appendChild(rest);
    var inner = document.createElement("div");
    inner.className = "group-inner";
    inner.hidden = true;
    items.forEach(function (item) {
      inner.appendChild(findingCard(item));
    });
    btn.addEventListener("click", function () {
      inner.hidden = !inner.hidden;
    });
    wrap.appendChild(btn);
    wrap.appendChild(inner);
    return wrap;
  }

  function metaPair(label, value) {
    var span = document.createElement("span");
    span.appendChild(document.createTextNode(label + " "));
    var b = document.createElement("b");
    text(b, value);
    span.appendChild(b);
    return span;
  }

  function showResults(report) {
    state.report = report;
    setSkipEnabled(true);
    closeSource();
    page("results");
    text(el.resTarget, report.target || state.target);
    setChip(el.resChip, state.kind || (report.kind === "website" ? "Website" : "GitHub repo"));
    var findings = sortFindings(report.findings || []);
    findings.sort(function (a, b) {
      return (SEV_ORDER[a.severity] || 9) - (SEV_ORDER[b.severity] || 9);
    });
    var fix = findings.filter(function (f) {
      return f.severity === "critical" || f.severity === "high";
    });
    var later = findings.filter(function (f) {
      return f.severity === "low" || f.severity === "medium";
    });
    var safe = findings.filter(function (f) {
      return f.severity === "info";
    });
    text(el.headline, fix.length + " things to fix today");
    el.chips.replaceChildren();
    [
      ["critical", "Critical"],
      ["high", "High"],
      ["medium", "Medium"],
      ["low", "Low"],
      ["info", "Safe"]
    ].forEach(function (pair) {
      var sev = pair[0];
      var n = findings.filter(function (f) { return f.severity === sev; }).length;
      if (!n) {
        return;
      }
      var chip = document.createElement("span");
      chip.className = "chip sev-" + (sev === "info" ? "info" : sev);
      var count = document.createElement("span");
      count.className = "n";
      text(count, String(n));
      chip.appendChild(count);
      chip.appendChild(document.createTextNode(" " + pair[1]));
      el.chips.appendChild(chip);
    });
    var cov = report.coverage || {};
    var elapsed = formatClock(Date.now() - (state.startedAt || Date.now()));
    el.resMeta.replaceChildren();
    el.resMeta.appendChild(metaPair("Scan time", elapsed));
    el.resMeta.appendChild(metaPair("Agent calls", String(state.calls || "—")));
    el.resMeta.appendChild(
      metaPair(
        "Coverage:",
        cov.truncated
          ? "partial (" + (cov.reason || "truncated") + ")"
          : "all files scanned"
      )
    );
    text(el.tabNFix, String(fix.length));
    text(el.tabNAll, String(findings.length));
    var traceN = state.events.filter(function (e) {
      return e.type === "plan" || e.type === "act" || e.type === "observe";
    }).length;
    text(el.tabNTrace, String(Math.min(state.calls, MAX_CALLS) || traceN));
    el.tabFix.replaceChildren();
    fix.forEach(function (item) {
      el.tabFix.appendChild(findingCard(item));
    });
    if (later.length) {
      el.tabFix.appendChild(
        collapsedGroup(later.length + " to review later", "Low", later, "sev-low")
      );
    }
    if (safe.length) {
      el.tabFix.appendChild(
        collapsedGroup(safe.length + " references checked and safe", "Safe", safe, "sev-info")
      );
    }
    var table = document.createElement("table");
    table.className = "table";
    var head = document.createElement("thead");
    var hr = document.createElement("tr");
    ["Target", "Type", "Owner status", "Severity", "Where used"].forEach(function (h) {
      var th = document.createElement("th");
      text(th, h);
      hr.appendChild(th);
    });
    head.appendChild(hr);
    var body = document.createElement("tbody");
    findings.forEach(function (item) {
      var tr = document.createElement("tr");
      [item.target, item.kind, ownerStatus(item), item.severity, whereUsed(item)].forEach(function (val) {
        var td = document.createElement("td");
        text(td, val);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    table.appendChild(head);
    table.appendChild(body);
    var wrap = document.createElement("div");
    wrap.className = "table-wrap";
    wrap.appendChild(table);
    el.tabAll.replaceChildren(wrap);
    el.tabTrace.replaceChildren();
    state.events
      .filter(function (e) {
        return e.type === "plan" || e.type === "act" || e.type === "observe";
      })
      .forEach(function (event, index) {
        var row = document.createElement("div");
        row.className = "feed-item";
        var n = document.createElement("span");
        n.className = "feed-n";
        text(n, String(index + 1).padStart(2, "0"));
        var col = document.createElement("div");
        var p = document.createElement("div");
        text(p, (event.type || "") + " " + (event.tool || "") + " " + (event.target || ""));
        var r = document.createElement("code");
        text(r, event.result_summary || JSON.stringify(event.args || {}));
        col.appendChild(p);
        col.appendChild(r);
        row.appendChild(n);
        row.appendChild(col);
        el.tabTrace.appendChild(row);
      });
    text(el.tabRaw, JSON.stringify(report, null, 2));
    selectTab("fix");
  }

  function selectTab(name) {
    document.querySelectorAll(".tab").forEach(function (btn) {
      btn.setAttribute("aria-selected", btn.getAttribute("data-tab") === name ? "true" : "false");
    });
    el.tabFix.hidden = name !== "fix";
    el.tabAll.hidden = name !== "all";
    el.tabTrace.hidden = name !== "trace";
    el.tabRaw.hidden = name !== "raw";
  }

  el.target.addEventListener("input", function () {
    setChip(el.chip, detectKind(el.target.value));
  });
  el.form.addEventListener("submit", function (event) {
    event.preventDefault();
    var value = el.target.value.trim();
    if (!value) {
      showError("Paste a GitHub repo or website URL");
      return;
    }
    startScan(value);
  });
  function bindDemo(node) {
    if (node) {
      node.addEventListener("click", startDemo);
    }
  }
  bindDemo(el.demo);
  bindDemo(document.getElementById("demo-report"));
  document.querySelectorAll("[data-demo]").forEach(bindDemo);
  document.querySelectorAll("[data-home]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      closeSource();
      history.replaceState({}, "", "/");
      showError("");
      page("home");
    });
  });
  document.querySelectorAll(".tab").forEach(function (btn) {
    btn.addEventListener("click", function () {
      selectTab(btn.getAttribute("data-tab"));
    });
  });
  el.skip.addEventListener("click", function () {
    if (state.report) {
      showResults(state.report);
    }
  });
  document.querySelectorAll(".layer-label").forEach(function (btn) {
    btn.addEventListener("click", function () {
      document.querySelectorAll(".layer-label").forEach(function (other) {
        other.classList.toggle("on", other === btn);
      });
    });
  });

  var params = new URLSearchParams(window.location.search);
  if (params.get("demo") === "1") {
    startDemo();
  } else if (params.get("scan")) {
    var id = params.get("scan");
    if (/^[a-zA-Z0-9]+$/.test(id)) {
      loadFinished(id);
    }
  }
})();
