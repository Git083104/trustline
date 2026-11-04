import json
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest

from scanner.compromised import POLYFILL_FIX, SRI_FIX
from scanner.llm import FakeModelClient
from scanner.lookups import LookupCache
from scanner.report import run_scan, scan
from scanner.ssrf import SCAN_BLOCKED, ScanBlockedError
from scanner.website import csp_blocks_external_scripts, extract_website, extract_website_scan, safe_get
from tests.test_agent import _ctx, _scripted_client
from tests.test_report import _rank_ok

SITE_ROOT = Path(__file__).parent / "fixtures" / "demo_site"
PAGES_ROOT = Path(__file__).parent / "fixtures" / "demo_pages"
EXPECTED = json.loads((SITE_ROOT / "expected.json").read_text())


class _QuietHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SITE_ROOT), **kwargs)

    def log_message(self, *_args):
        return


@pytest.fixture
def site_server(monkeypatch):
    monkeypatch.setenv("TRUSTMAP_ALLOW_LOCAL_SCAN", "1")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    yield f"http://{host}:{port}/"
    server.shutdown()
    thread.join(timeout=2)


def _by_host(refs):
    return {ref.host_or_bucket: ref for ref in refs}


@pytest.mark.asyncio
async def test_extract_website_fixture(site_server):
    refs = await extract_website(site_server)
    got = [
        {
            "tag": ref.tag,
            "attribute": ref.attribute,
            "raw_host": ref.host_or_bucket,
            "sri": ref.sri,
            "loaded_by": ref.loaded_by,
            "filter_reason": ref.filter_reason,
        }
        for ref in refs
        if ref.host_or_bucket != "127.0.0.1"
    ]
    from scanner.extract import JUNK_REASONS

    expected = [
        item for item in EXPECTED["references"] if item.get("filter_reason") not in JUNK_REASONS
    ]
    assert got == expected
    polyfill = _by_host(refs)["cdn.polyfill.io"]
    assert polyfill.page_url.startswith(site_server)
    assert polyfill.sri is False
    js = _by_host(refs)["first-party-js-trustmap-7f3k2.com"]
    assert js.loaded_by == "first_party_js"
    assert js.file.endswith("/app.js")


@pytest.mark.asyncio
async def test_website_scan_floors_and_fixes(site_server, tmp_path):
    expected_hosts = {
        item["raw_host"]: item for item in EXPECTED["references"]
    }

    def handler(request):
        payload = json.loads(request["user"].split("\n", 1)[-1])
        if request.get("schema_name") == "classification_batch":
            items = []
            for item in payload["references"]:
                host = item["host_or_bucket"]
                exp = expected_hosts.get(host, {})
                tag = exp.get("tag", "")
                items.append(
                    {
                        "id": item["id"],
                        "type": "script" if tag == "script" else "asset",
                        "runs_in": "browser",
                        "blast_radius": 2 if exp.get("filter_reason") is None else 0,
                        "confidence": 0.9,
                        "reason": "fixture",
                    }
                )
            return {"items": items}
        return _rank_ok(
            severity="low",
            risk="A stranger could take this over.",
            blast_radius=2,
            override="",
        )

    findings = await scan(
        site_server,
        client=FakeModelClient(
            handler=handler,
            tool_handler=_scripted_client().tool_handler,
        ),
        cache=LookupCache(tmp_path / "web.db"),
        ctx=_ctx(tmp_path),
        hydrate_only=False,
    )
    by_target = {item.target: item for item in findings}
    polyfill = by_target["polyfill.io"]
    assert polyfill.severity == "critical"
    assert polyfill.fix == POLYFILL_FIX
    assert polyfill.locations
    assert polyfill.locations[0]["page_url"].startswith(site_server)
    assert polyfill.locations[0]["sri"] is False
    unreg = by_target["cdn-assets-trustmap-7f3k2.com"]
    assert unreg.severity == "critical"
    assert unreg.fix == SRI_FIX
    pages = by_target["trustmap-missing-owner-a3f91c2e.github.io"]
    assert pages.severity == "critical"
    jquery = by_target["jsdelivr.net"]
    assert jquery.severity in {"low", "info", "medium"}
    assert jquery.fix != POLYFILL_FIX
    assert "assets.brand-cdn.example.net" not in by_target
    assert "brand-cdn.example.net" not in by_target


class _PagesHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PAGES_ROOT), **kwargs)

    def log_message(self, *_args):
        return


@pytest.fixture
def pages_server(monkeypatch):
    monkeypatch.setenv("TRUSTMAP_ALLOW_LOCAL_SCAN", "1")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PagesHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    yield f"http://{host}:{port}/"
    server.shutdown()
    thread.join(timeout=2)


@pytest.mark.asyncio
async def test_demo_pages_fixture_records_csp_and_keeps_severity(pages_server, tmp_path):
    extracted = await extract_website_scan(pages_server)
    assert extracted.csp_blocks_external_scripts is True
    assert csp_blocks_external_scripts(
        "default-src 'self'; script-src 'self'; style-src 'self' https://cdnjs.cloudflare.com"
    )
    by_host = {ref.host_or_bucket: ref for ref in extracted.references}
    assert by_host["cdn.polyfill.io"].sri is False
    assert by_host["cdn.polyfill.io"].csp_blocks_external_scripts is True
    assert by_host["trustline-demo-cartkit.com"].csp_blocks_external_scripts is True
    assert by_host["trustline-demo-chat.github.io"].csp_blocks_external_scripts is True
    assert by_host["cdnjs.cloudflare.com"].sri is True
    assert "trustlinedemoassets" in by_host or "trustlinedemoassets.blob.core.windows.net" in by_host

    def handler(request):
        payload = json.loads(request["user"].split("\n", 1)[-1])
        if request.get("schema_name") == "classification_batch":
            items = []
            for item in payload["references"]:
                items.append(
                    {
                        "id": item["id"],
                        "type": "script",
                        "runs_in": "browser",
                        "blast_radius": 3,
                        "confidence": 0.9,
                        "reason": "fixture",
                    }
                )
            return {"items": items}
        return _rank_ok(
            severity="low",
            risk="A stranger could take this over.",
            blast_radius=3,
            override="",
        )

    findings = await scan(
        pages_server,
        client=FakeModelClient(
            handler=handler,
            tool_handler=_scripted_client().tool_handler,
        ),
        cache=LookupCache(tmp_path / "pages.db"),
        ctx=_ctx(tmp_path),
        hydrate_only=False,
    )
    by_target = {item.target: item for item in findings}
    assert by_target["polyfill.io"].severity == "critical"
    assert by_target["polyfill.io"].evidence.get("csp_blocks_external_scripts") is True
    assert "trustline-demo-cartkit.com" in by_target
    assert "trustline-demo-chat.github.io" in by_target
    cdnjs = by_target.get("cdnjs.cloudflare.com") or by_target.get("cloudflare.com")
    assert cdnjs is not None
    assert cdnjs.severity in {"low", "info", "medium"}


@pytest.mark.asyncio
async def test_code_only_scan_skips_model_and_keeps_floors(pages_server, tmp_path):
    def boom(_request):
        raise AssertionError("model should not be called")

    outcome = await run_scan(
        pages_server,
        client=FakeModelClient(
            handler=boom,
            tool_handler=_scripted_client().tool_handler,
        ),
        cache=LookupCache(tmp_path / "code_only.db"),
        ctx=_ctx(tmp_path),
        hydrate_only=False,
        code_only=True,
    )
    assert outcome.code_only is True
    assert outcome.cost_usd == 0
    by_target = {item.target: item for item in outcome.findings}
    assert by_target["polyfill.io"].severity == "critical"


@pytest.mark.asyncio
async def test_local_scan_flag_required_for_fixture_port(site_server, monkeypatch):
    monkeypatch.delenv("TRUSTMAP_ALLOW_LOCAL_SCAN", raising=False)
    parsed = urlparse(site_server)
    with pytest.raises(ScanBlockedError) as caught:
        await safe_get(site_server)
    assert str(caught.value) == SCAN_BLOCKED
    assert parsed.port not in {80, 443}
