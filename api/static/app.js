(function () {
  var MAX_CALLS = 6;
  var STAGES = ["Find", "Check", "Investigate", "Rank", "Report"];
  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  var SEV_STYLE = {
    critical: { fg: "var(--crit-fg)", bg: "var(--crit-bg)" },
    high: { fg: "var(--high-fg)", bg: "var(--high-bg)" },
    medium: { fg: "var(--med-fg)", bg: "var(--med-bg)" },
    low: { fg: "var(--low-fg)", bg: "var(--low-bg)" },
    info: { fg: "var(--info-fg)", bg: "var(--info-bg)" }
  };

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
    stage: 0
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
    foundList: document.getElementById("found-list"),
    callsUsed: document.getElementById("calls-used"),
    callsMax: document.getElementById("calls-max"),
    pips: document.getElementById("calls-pips"),
    scanLabel: document.getElementById("scan-target-label"),
    scanChip: document.getElementById("scan-kind-chip"),
    scanStatus: document.getElementById("scan-status"),
    resTarget: document.getElementById("res-target"),
    resChip: document.getElementById("res-kind-chip"),
    headline: document.getElementById("res-headline"),
    chips: document.getElementById("res-chips"),
    coverage: document.getElementById("res-coverage"),
    tabFix: document.getElementById("tab-fix"),
    tabAll: document.getElementById("tab-all"),
    tabTrace: document.getElementById("tab-trace"),
    tabRaw: document.getElementById("tab-raw")
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
      btn.style.marginLeft = "12px";
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
  }

  function mapHttpError(status, body) {
    var err = (body && body.error) || (body && body.message) || "";
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
    text(el.scanLabel, meta.target);
    setChip(el.scanChip, meta.kind);
    text(el.scanStatus, "Scanning");
    el.feed.replaceChildren();
    el.foundList.replaceChildren();
    text(el.foundCount, "0");
    renderStepper(0);
    setProgress(8);
    renderPips(0);
    page("scan");
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
      li.appendChild(mark);
      li.appendChild(document.createTextNode(name));
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
      var pip = document.createElement("span");
      if (i < used) {
        pip.className = "on";
      }
      el.pips.appendChild(pip);
    }
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

  function appendFeed(event) {
    if (event.type !== "plan" && event.type !== "act" && event.type !== "observe") {
      return;
    }
    var row = el.feed.lastElementChild;
    if (!row || row.getAttribute("data-target") !== String(event.target || "")) {
      row = document.createElement("div");
      row.className = "feed-row";
      row.setAttribute("data-target", event.target || "");
      var n = document.createElement("span");
      n.className = "mono muted";
      text(n, String(el.feed.children.length + 1));
      var body = document.createElement("div");
      body.className = "feed-body";
      row.appendChild(n);
      row.appendChild(body);
      el.feed.appendChild(row);
    }
    var body = row.lastElementChild;
    var line = document.createElement("div");
    var label = document.createElement("span");
    label.className = "kicker";
    var value = document.createElement("span");
    if (event.type === "plan") {
      text(label, "Plan");
      text(value, event.tool ? "pick " + event.tool : "plan");
    } else if (event.type === "act") {
      text(label, "Call");
      var args = event.args ? JSON.stringify(event.args) : "";
      text(value, (event.tool || "") + " " + args);
    } else {
      text(label, "Result");
      text(value, event.result_summary || "");
    }
    line.appendChild(label);
    line.appendChild(value);
    body.appendChild(line);
  }

  function bumpFound(event) {
    if (event.type === "extracted" && typeof event.actionable === "number") {
      state.found = event.actionable;
    } else if (event.type === "precheck") {
      state.found = Math.max(state.found, el.foundList.children.length + 1);
    }
    text(el.foundCount, String(state.found));
    if (event.type === "precheck" && event.target) {
      var row = document.createElement("div");
      var name = document.createElement("span");
      text(name, event.target);
      var kind = document.createElement("span");
      kind.className = "muted";
      text(kind, event.kind || "");
      row.appendChild(name);
      row.appendChild(kind);
      el.foundList.appendChild(row);
    }
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
      if (event.type === "plan") {
        state.calls += 1;
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
    text(el.scanStatus, "Done");
    renderStepper(4);
    setProgress(100);
    if (state.demo) {
      fetch("/api/scan/demo")
        .then(function (res) { return res.json(); })
        .then(showResults)
        .catch(function () {
          showError("Could not load the demo report");
        });
      return;
    }
    fetch("/api/scan/" + encodeURIComponent(state.scanId))
      .then(function (res) {
        if (res.status === 409) {
          throw new Error("running");
        }
        return res.json();
      })
      .then(showResults)
      .catch(function () {
        showError("Scan finished but the report could not be loaded", function () {
          loadFinished(state.scanId);
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

  function sevStyle(sev) {
    return SEV_STYLE[sev] || SEV_STYLE.info;
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
    k.className = "kicker";
    text(k, label);
    var v = document.createElement("code");
    text(v, value);
    grid.appendChild(k);
    grid.appendChild(v);
  }

  function findingCard(item) {
    var art = document.createElement("article");
    art.className = "finding";
    var body = document.createElement("div");
    body.className = "finding-body";
    var top = document.createElement("div");
    var style = sevStyle(item.severity);
    var sev = document.createElement("span");
    sev.className = "sev";
    sev.style.color = style.fg;
    sev.style.background = style.bg;
    text(sev, item.severity || "info");
    var tgt = document.createElement("span");
    tgt.className = "mono";
    text(tgt, item.target);
    var typ = document.createElement("span");
    typ.className = "tag";
    typ.style.background = "var(--color-neutral-200)";
    typ.style.color = "var(--color-neutral-800)";
    text(typ, item.kind || "");
    top.appendChild(sev);
    top.appendChild(tgt);
    top.appendChild(typ);
    var risk = document.createElement("p");
    text(risk, item.risk || "");
    var fixRow = document.createElement("div");
    fixRow.className = "fix-row";
    var fixK = document.createElement("span");
    fixK.className = "kicker";
    text(fixK, "Fix");
    var fixT = document.createElement("span");
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
    detailsBtn.className = "btn btn-ghost";
    text(detailsBtn, "Details");
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
    body.appendChild(top);
    body.appendChild(risk);
    body.appendChild(fixRow);
    body.appendChild(detailsBtn);
    art.appendChild(body);
    art.appendChild(details);
    return art;
  }

  function collapsedGroup(title, tag, items) {
    var wrap = document.createElement("div");
    wrap.className = "group";
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "group-btn";
    var label = document.createElement("span");
    label.className = "sev";
    text(label, tag);
    btn.appendChild(label);
    btn.appendChild(document.createTextNode(" " + title + " (" + items.length + ")"));
    var inner = document.createElement("div");
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

  function showResults(report) {
    state.report = report;
    page("results");
    text(el.resTarget, report.target || state.target);
    setChip(el.resChip, state.kind || (report.kind === "website" ? "Website" : "GitHub repo"));
    var findings = sortFindings(report.findings || []);
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
    ["critical", "high", "medium", "low", "info"].forEach(function (sev) {
      var n = findings.filter(function (f) { return f.severity === sev; }).length;
      if (!n) {
        return;
      }
      var chip = document.createElement("span");
      chip.className = "chip";
      var st = sevStyle(sev);
      chip.style.color = st.fg;
      chip.style.background = st.bg;
      var count = document.createElement("span");
      count.className = "mono";
      text(count, String(n));
      chip.appendChild(count);
      chip.appendChild(document.createTextNode(" " + sev));
      el.chips.appendChild(chip);
    });
    var cov = report.coverage || {};
    var covText = cov.truncated
      ? "Partial scan (" + (cov.reason || "truncated") + ")"
      : "Coverage: files scanned " + (cov.files_scanned || "—");
    text(el.coverage, covText);
    el.tabFix.replaceChildren();
    fix.forEach(function (item) {
      el.tabFix.appendChild(findingCard(item));
    });
    if (later.length) {
      el.tabFix.appendChild(collapsedGroup("Review later", "later", later));
    }
    if (safe.length) {
      el.tabFix.appendChild(collapsedGroup("Checked and safe", "safe", safe));
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
        row.className = "feed-row";
        var n = document.createElement("span");
        n.className = "mono muted";
        text(n, String(index + 1));
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
  el.demo.addEventListener("click", startDemo);
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
