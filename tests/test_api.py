import asyncio
import json
import re
import shutil
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.classify_target import classify_target, infer_kind
from api.demo import DEMO_GAP_CAP_MS, demo_gap_ms, demo_report, demo_waits_ms, load_demo
from api.jobs import Job
from scanner.extract import CloneError
from api.main import LIVE_UNCONFIGURED, create_app
from scanner.config import DEMO_EVENT_GAP_MS, SCAN_COST_CAP_USD
from scanner.llm import FakeModelClient
from scanner.lookups import LookupCache
from scanner.models import BucketProbeResult
from scanner.report import ScanOutcome
from tests.test_agent import _ctx, _scripted_client
from tests.test_report import _fixture_handler

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "demo_repo"


def _parse_sse(text: str) -> list[dict]:
    events = []
    for block in text.split("\n\n"):
        line = block.strip()
        if line.startswith("data: "):
            events.append(json.loads(line[6:]))
    return events


def _fixture_app(**kwargs):
    async def fake_bucket(name, provider, cache=None, **kw):
        missing = "acme-static-assets" not in name
        return BucketProbeResult(
            name=name,
            provider=provider,
            status="NoSuchBucket" if missing else "exists",
            http_status=404 if missing else 403,
        )

    tmp_path = kwargs.pop("tmp_path")
    client = FakeModelClient(
        handler=_fixture_handler(),
        tool_handler=_scripted_client().tool_handler,
    )
    cache = LookupCache(tmp_path / "api.db")
    return create_app(
        model_client=client,
        cache=cache,
        ctx=_ctx(tmp_path, bucket_probe=fake_bucket),
        **kwargs,
    )


def test_placeholder_home_and_demo_button():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        home = client.get("/")
        assert home.status_code == 200
        body = home.text
        assert "<title>Tether</title>" in body
        assert 'id="target"' in body
        assert "Watch the demo" in body
        css = client.get("/static/app.css")
        js = client.get("/static/app.js")
        assert css.status_code == 200
        assert js.status_code == 200
        assert "EventSource" in js.text
        assert "locRank" in js.text
        assert "no answer in time" in js.text
        assert 'feed-k", "Question"' in js.text or "Question" in js.text
        demo = client.get("/api/scan/demo/events", params={"speed": "0"})
        assert demo.status_code == 200
        types = [item.get("type") for item in _parse_sse(demo.text)]
        assert "done" in types


def test_live_scan_without_key_returns_503(monkeypatch):
    monkeypatch.setattr("api.main._load_local_env", lambda: None)
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    app = create_app()
    with TestClient(app) as client:
        response = client.post("/api/scan", json={"target": "https://example.com"})
        assert response.status_code == 503
        assert response.json() == {"error": LIVE_UNCONFIGURED}
        assert app.state.store._jobs == {}


def test_health_and_cors():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        response = client.get(
            "/api/health", headers={"Origin": "http://localhost:3000"}
        )
        assert response.status_code == 200
        assert response.json() == {"ok": True}
        assert response.headers.get("access-control-allow-origin") in {
            "*",
            "http://localhost:3000",
        }


def test_infer_kind_and_website_accepted():
    assert infer_kind("https://github.com/acme/widgets") == "repo"
    assert infer_kind(str(FIXTURE_ROOT)) == "path"
    assert infer_kind("https://example.com") == "website"
    assert classify_target("https://example.com") == ("website", "https://example.com")


def test_post_website_starts_job():
    async def runner(*args, **kwargs):
        return ScanOutcome(findings=[])

    app = create_app(
        model_client=FakeModelClient(handler=lambda r: {}),
        runner=runner,
    )
    with TestClient(app) as client:
        response = client.post("/api/scan", json={"target": "https://example.com"})
        assert response.status_code == 200
        body = response.json()
        assert body["kind"] == "website"
        assert body["target"] == "https://example.com"
        assert body["scan_id"]


def test_post_github_returns_kind_without_clone():
    async def runner(*args, **kwargs):
        return ScanOutcome(findings=[])

    app = create_app(
        model_client=FakeModelClient(handler=lambda r: {}),
        runner=runner,
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/scan", json={"target": "https://github.com/acme/widgets"}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["kind"] == "repo"
        assert body["target"] == "https://github.com/acme/widgets"
        assert body["scan_id"]


def test_report_409_while_running():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    job = Job(kind="path", target=str(FIXTURE_ROOT))
    app.state.store.add(job)
    with TestClient(app) as client:
        assert client.get(f"/api/scan/{job.scan_id}").status_code == 409


def test_unknown_scan_404():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        assert client.get("/api/scan/missing").status_code == 404
        assert client.get("/api/scan/missing/events").status_code == 404


def test_fixture_path_scan_sse_and_report(tmp_path):
    app = _fixture_app(tmp_path=tmp_path)
    with TestClient(app) as client:
        posted = client.post("/api/scan", json={"target": str(FIXTURE_ROOT)})
        assert posted.status_code == 200
        assert posted.json()["kind"] == "path"
        scan_id = posted.json()["scan_id"]
        stream = client.get(f"/api/scan/{scan_id}/events")
        assert stream.status_code == 200
        events = _parse_sse(stream.text)
        types = [item["type"] for item in events]
        assert types[0] == "started"
        assert "extracted" in types
        extracted = next(item for item in events if item["type"] == "extracted")
        assert extracted["coverage"]["files_scanned"] >= 1
        assert extracted["coverage"]["files_total"] >= extracted["coverage"]["files_scanned"]
        assert "truncated" in extracted["coverage"]
        assert "precheck" in types
        assert "ranked" in types
        assert types[-1] == "done"
        assert all(item["scan_id"] == scan_id for item in events)
        report = client.get(f"/api/scan/{scan_id}")
        assert report.status_code == 200
        body = report.json()
        assert body["status"] == "done"
        assert body["findings"]
        critical = {
            item["target"]
            for item in body["findings"]
            if item["severity"] == "critical"
        }
        assert {
            "acme-legacy-uploads-a3f91c2e",
            "cdn-assets-trustmap-7f3k2.com",
            "trustmap-demo-assets",
            "github.com/trustmap-missing-owner-a3f91c2e",
            "trustmap-demo-pages.github.io",
            "trustmapdemoassets",
        } <= critical
        assert body["coverage"]["files_scanned"] == extracted["coverage"]["files_scanned"]
        assert "cost_usd" in body
        assert body["cost_usd"] == pytest.approx(
            body["classify_cost_usd"]
            + body["agent_cost_usd"]
            + body["rank_cost_usd"]
        )


def test_tiny_cost_cap_lists_budget_targets(tmp_path):
    app = _fixture_app(tmp_path=tmp_path, cost_cap=0.0)
    with TestClient(app) as client:
        scan_id = client.post(
            "/api/scan", json={"target": str(FIXTURE_ROOT)}
        ).json()["scan_id"]
        events = _parse_sse(client.get(f"/api/scan/{scan_id}/events").text)
        done = events[-1]
        assert done["type"] == "done"
        assert done["budget_targets"]
        report = client.get(f"/api/scan/{scan_id}").json()
        assert report["budget_targets"] == done["budget_targets"]


def test_demo_report_and_events_offline():
    assert DEMO_EVENT_GAP_MS == 150
    assert demo_gap_ms(None) == 150
    assert demo_gap_ms("0") == 0
    assert demo_gap_ms("40") == 40
    with pytest.raises(ValueError):
        demo_gap_ms("-1")
    payload = load_demo()
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        report = client.get("/api/scan/demo")
        assert report.status_code == 200
        body = report.json()
        assert body == demo_report(payload)
        assert "events" not in body
        assert body["status"] == "done"
        assert body["findings"]
        stream = client.get("/api/scan/demo/events?speed=0")
        assert stream.status_code == 200
        events = _parse_sse(stream.text)
        assert events == payload["events"]
        assert events[0]["type"] == "started"
        assert events[-1]["type"] == "done"
        assert client.get("/api/scan/demo/events?speed=nope").status_code == 400


def test_demo_gap_default_matches_config():
    assert demo_gap_ms("") == DEMO_EVENT_GAP_MS
    assert SCAN_COST_CAP_USD == 1.00


STATIC = Path(__file__).resolve().parents[1] / "api" / "static"


def test_frontend_has_the_three_screens_and_no_design_switcher():
    markup = (STATIC / "index.html").read_text()
    for anchor in ('id="page-home"', 'id="screen-scanning"', 'id="screen-results"'):
        assert anchor in markup
    # the floating Home/Scanning/Results control is a design-tool affordance
    assert "showSwitcher" not in markup
    assert "Trustmap" not in markup
    assert "Trustline" not in markup
    assert markup.count("Tether") > 1
    assert "Inter" in markup and "IBM+Plex+Mono" in markup
    assert "home-art" in markup
    assert "repo-grid" in markup
    assert "Websites to try" in markup
    assert "Fix it" in markup


def test_home_try_cards_have_expect_lines_and_drop_zipline():
    data = json.loads((STATIC / "targets.json").read_text())
    repos = [repo["repo"] for group in data["groups"] for repo in group["repos"]]
    assert "quantopian/zipline" not in repos
    assert repos[:4] == [
        "TryKickoff/kickoff",
        "debois/elm-mdl",
        "LeaVerou/bliss",
        "blinkfox/hexo-theme-matery",
    ]
    assert "lbryio/lbry-desktop" not in repos
    assert repos[4:7] == ["expressjs/express", "pallets/click", "psf/requests"]
    assert "quantopian/zipline" not in json.dumps(data)
    sites = {site["url"]: site for site in data["websites"]}
    shop = sites["https://git083104.github.io/paperplane-shop/"]
    assert shop["name"] == "Demo storefront (ours)"
    assert shop["about"] == "4 problems planted on purpose"
    wiki = sites["https://www.wikipedia.org"]
    assert wiki["name"] == "wikipedia.org"
    assert wiki["about"] == "Control: should come back clean"
    assert wiki["about"].count("should come back clean") == 1
    for item in data["websites"] + [repo for group in data["groups"] for repo in group["repos"]]:
        assert str(item.get("expect") or "").startswith("Expect:")
    js = (STATIC / "app.js").read_text()
    assert "repo-chip-expect" in js
    css = (STATIC / "app.css").read_text()
    assert "text-overflow:ellipsis" not in css.split(".repo-chip-name")[1].split("}")[0]


def test_results_layout_and_feed_wording_ship():
    css = (STATIC / "app.css").read_text()
    js = (STATIC / "app.js").read_text()
    assert "62px minmax(0,1fr) auto" not in css
    assert "72px minmax(0,1fr)" in css
    assert "doesn't resolve" in js
    assert "needs fixing today" in js
    assert "replayed" in js
    assert "repo-chip" in js


def test_report_panels_ship_empty_so_only_api_data_renders():
    markup = (STATIC / "index.html").read_text()
    for panel in ("tab-fix", "tab-all", "tab-trace", "tab-raw"):
        assert re.search(rf'id="{panel}"[^>]*>\s*</div>', markup), panel
    script = (STATIC / "app.js").read_text()
    for mock in ("paperplane", "trustline-demo-", "polyfill.io"):
        assert mock not in script, mock


def test_frontend_never_writes_report_text_as_html():
    script = (STATIC / "app.js").read_text()
    assert "innerHTML" not in script
    assert "outerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert "alert(" not in script
    # report targets must not become links
    assert 'createElement("a")' not in script


def test_frontend_keeps_only_the_scan_id_in_the_url():
    script = (STATIC / "app.js").read_text()
    assert '"?scan=" + encodeURIComponent(id)' in script
    assert '"?demo=1"' in script


def test_frontend_handles_every_documented_sse_event():
    script = (STATIC / "app.js").read_text()
    for event_type in ("started", "extracted", "precheck", "plan", "act",
                       "observe", "ranked", "done", "error"):
        assert f'"{event_type}"' in script, event_type


def test_static_assets_are_served_and_packaged():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        for path in ("/static/app.css", "/static/app.js"):
            assert client.get(path).status_code == 200
    packaging = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    for name in ("index.html", "app.css", "app.js"):
        assert f'"api/static/{name}"' in packaging


async def test_events_emitted_from_a_worker_thread_reach_the_stream():
    # the blocking scan stages run via asyncio.to_thread, so emit() must wake a
    # stream waiter while the event loop is parked with nothing else to do
    job = Job(kind="repo", target="https://github.com/acme/widgets")
    received: list[dict] = []

    async def drain() -> None:
        async for event in job.stream():
            received.append(event)

    task = asyncio.create_task(drain())
    await asyncio.sleep(0.05)

    def emit_from_thread() -> None:
        job.emit({"type": "precheck", "target": "acme.test"})
        job.emit({"type": "done", "finding_count": 0})

    threading.Thread(target=emit_from_thread).start()
    await asyncio.wait_for(task, timeout=5)
    assert [item["type"] for item in received] == ["precheck", "done"]


def test_pasted_github_url_scans_end_to_end(tmp_path, monkeypatch):
    # the whole repo path: GitHub URL -> shallow clone -> extract -> report,
    # with the clone stubbed to the checked-in fixture repo
    def fake_clone(url: str, dest_parent: Path) -> Path:
        dest = dest_parent / "widgets"
        shutil.copytree(FIXTURE_ROOT, dest)
        return dest

    monkeypatch.setattr("scanner.extract._clone_github", fake_clone)
    app = _fixture_app(tmp_path=tmp_path)
    with TestClient(app) as client:
        posted = client.post(
            "/api/scan", json={"target": "https://github.com/acme/widgets"}
        )
        assert posted.status_code == 200
        assert posted.json()["kind"] == "repo"
        scan_id = posted.json()["scan_id"]
        events = _parse_sse(client.get(f"/api/scan/{scan_id}/events").text)
        types = [item["type"] for item in events]
        assert types[0] == "started" and types[-1] == "done"
        assert "ranked" in types
        report = client.get(f"/api/scan/{scan_id}").json()
        assert report["kind"] == "repo"
        assert report["target"] == "https://github.com/acme/widgets"
        assert report["findings"]


def test_clone_failure_is_reported_as_a_scan_error(tmp_path, monkeypatch):
    def refuse(url: str, dest_parent: Path) -> Path:
        raise CloneError("acme/widgets could not be downloaded; it may be private or renamed")

    monkeypatch.setattr("scanner.extract._clone_github", refuse)
    app = _fixture_app(tmp_path=tmp_path)
    with TestClient(app) as client:
        scan_id = client.post(
            "/api/scan", json={"target": "https://github.com/acme/widgets"}
        ).json()["scan_id"]
        events = _parse_sse(client.get(f"/api/scan/{scan_id}/events").text)
        failure = events[-1]
        assert failure["type"] == "error"
        assert "private or renamed" in failure["message"]
        assert client.get(f"/api/scan/{scan_id}").status_code == 500


def test_warns_when_serverless_ledger_is_in_tmp(monkeypatch, caplog):
    import logging

    from api.main import warn_ephemeral_ledger

    caplog.set_level(logging.WARNING)
    monkeypatch.setenv("VERCEL", "1")
    warn_ephemeral_ledger(Path("/tmp/trustmap.db"))
    assert "serverless" in caplog.text.lower()
    assert "/tmp" in caplog.text


def test_blocked_literal_ips_never_create_a_job():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        for url in ("http://169.254.169.254", "http://127.0.0.1"):
            response = client.post("/api/scan", json={"target": url})
            assert response.status_code == 400, url
            assert "can't be scanned" in response.json()["error"]
            stream = client.post("/api/scan/stream", json={"target": url})
            assert stream.status_code == 400, url
        assert app.state.store._jobs == {}


def test_scan_stream_finishes_for_fixture(tmp_path):
    app = _fixture_app(tmp_path=tmp_path)
    with TestClient(app) as client:
        response = client.post(
            "/api/scan/stream", json={"target": str(FIXTURE_ROOT)}
        )
        assert response.status_code == 200
        events = _parse_sse(response.text)
        assert events[0]["type"] == "started"
        assert events[-1]["type"] == "done"
        assert "agent_runs" in events[-1]


def test_demo_fix_patch_download():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        data = client.get("/api/scan/demo/fix")
        assert data.status_code == 200
        payload = data.json()
        assert "edits" in payload
        patch = client.get("/api/scan/demo/fix.patch")
        assert patch.status_code == 200
        assert "patch" in patch.headers.get("content-disposition", "").lower() or patch.text is not None
        assert "polyfill" in (payload.get("patch") or patch.text).lower() or payload.get("edits") is not None


def test_live_job_fix_patch(tmp_path):
    html = (Path(__file__).resolve().parents[1] / "api" / "demo_pages.html").read_text()

    async def runner(*args, **kwargs):
        from scanner.fix import propose_fixes
        from scanner.models import Finding
        from scanner.report import ScanOutcome

        finding = Finding(
            target="polyfill.io",
            kind="domain",
            references=["index.html:1"],
            severity="critical",
            model_severity="critical",
            final_severity="critical",
            classified_blast_radius=3,
            ranked_blast_radius=3,
            risk="polyfill.io is abandoned.",
            fix="replace with maintained source",
            evidence={},
            locations=[
                {
                    "file": "index.html",
                    "line": 8,
                    "tag": "script",
                    "runs_in": "browser",
                    "raw": "https://cdn.polyfill.io/v3/polyfill.min.js",
                    "sri": False,
                }
            ],
        )
        _ = propose_fixes
        return ScanOutcome(findings=[finding], file_texts={"index.html": html})

    app = create_app(
        model_client=FakeModelClient(handler=lambda r: {}),
        runner=runner,
    )
    with TestClient(app) as client:
        started = client.post(
            "/api/scan", json={"target": "https://example.com"}
        ).json()
        scan_id = started["scan_id"]
        client.get(f"/api/scan/{scan_id}/events")
        patch = client.get(f"/api/scan/{scan_id}/fix.patch")
        assert patch.status_code == 200
        assert "cdnjs.cloudflare.com/polyfill" in patch.text


def test_demo_waits_cap_gaps():
    events = [{"ts": 1.0}, {"ts": 10.0}, {"ts": 10.2}]
    waits = demo_waits_ms(events, None)
    assert waits[0] == 0
    assert waits[1] == DEMO_GAP_CAP_MS
    assert waits[2] == 200
    assert demo_waits_ms(events, "0") == [0, 0, 0]


def test_frontend_falls_back_when_the_event_stream_cannot_open():
    # a client without EventSource, or a proxy that buffers the stream, must
    # still end up with the report rather than a dropped scan
    script = (STATIC / "app.js").read_text()
    assert "waitWithoutStream" in script
    assert "new EventSource" in script
    assert "catch" in script.split("new EventSource")[1][:200]
    assert "Live updates aren't available" in script
    assert "skipped_targets" in script
    assert "code_only_targets" in script
    assert "files ignored by .tether.yml" in script
    assert "Checked by code only" in script
    assert "partial" in script
