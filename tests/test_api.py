import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.classify_target import classify_target, infer_kind
from api.demo import demo_gap_ms, demo_report, load_demo
from api.jobs import Job
from api.main import create_app
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
        assert "<title>Trustmap</title>" in body
        assert 'id="target"' in body
        assert "Watch the demo scan" in body
        css = client.get("/static/app.css")
        js = client.get("/static/app.js")
        assert css.status_code == 200
        assert js.status_code == 200
        assert "EventSource" in js.text
        demo = client.get("/api/scan/demo/events", params={"speed": "0"})
        assert demo.status_code == 200
        types = [item.get("type") for item in _parse_sse(demo.text)]
        assert "done" in types


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
