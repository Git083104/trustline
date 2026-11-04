import pytest
from fastapi.testclient import TestClient

from scanner.llm import OVERLOAD_BACKOFF_S, FakeModelClient, OverloadError, reset_overload_for_tests
from scanner.lookups import LookupCache
from scanner.report import ScanOutcome, run_scan
from tests.test_agent import _ctx, _scripted_client
from tests.test_website import PAGES_ROOT, _PagesHandler
from http.server import ThreadingHTTPServer
import threading


@pytest.fixture(autouse=True)
def _reset_overload(monkeypatch):
    reset_overload_for_tests()
    monkeypatch.setattr("scanner.llm.OVERLOAD_BACKOFF_S", (0, 0))
    monkeypatch.setattr("scanner.agent.OVERLOAD_BACKOFF_S", (0, 0))


class _Boom(Exception):
    status_code = 503

    def __str__(self) -> str:
        return "Error code: 503 - backend is temporarily overloaded"


def _pages(monkeypatch):
    monkeypatch.setenv("TRUSTMAP_ALLOW_LOCAL_SCAN", "1")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PagesHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    yield f"http://{host}:{port}/"
    server.shutdown()
    thread.join(timeout=2)


@pytest.fixture
def pages_server(monkeypatch):
    yield from _pages(monkeypatch)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["classify", "rank", "agent"])
async def test_503_still_returns_a_report(pages_server, tmp_path, stage):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if stage == "classify" and request.get("schema_name") == "classification_batch":
            raise _Boom()
        if stage == "rank" and request.get("schema_name") == "rank_finding":
            raise _Boom()
        if request.get("schema_name") == "classification_batch":
            payload = __import__("json").loads(request["user"].split("\n", 1)[-1])
            return {
                "items": [
                    {
                        "id": item["id"],
                        "type": "script",
                        "runs_in": "browser",
                        "blast_radius": 3,
                        "confidence": 0.9,
                        "reason": "ok",
                    }
                    for item in payload["references"]
                ]
            }
        return {
            "severity": "info",
            "risk": "Checked and safe.",
            "fix": "remove dead reference",
            "uncertain_about": "",
            "blast_radius": 2,
            "blast_override_reason": "",
        }

    def tools(*args, **kwargs):
        if stage == "agent":
            raise _Boom()
        return _scripted_client().tool_handler(*args, **kwargs)

    outcome = await run_scan(
        pages_server,
        client=FakeModelClient(handler=handler, tool_handler=tools),
        cache=LookupCache(tmp_path / f"{stage}.db"),
        ctx=_ctx(tmp_path),
        hydrate_only=False,
    )
    assert isinstance(outcome, ScanOutcome)
    assert outcome.findings
    assert any(item.target == "polyfill.io" for item in outcome.findings)


def test_backoff_tuple_has_two_steps():
    assert len(OVERLOAD_BACKOFF_S) == 2
