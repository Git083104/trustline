import pytest

from scanner.lookups import LookupCache
from scanner.models import Reference
from scanner.report import floor_decision
from scanner.ssrf import SCAN_BLOCKED
from scanner.tools import ToolContext, run
from scanner.website import FetchResult
from tests.test_report import _cl, _inv


async def _run(tmp_path, url, *, body="", status=200, chain=None, ns=None, fetch=None):
    async def fake_fetch(target, **_kwargs):
        if fetch:
            return await fetch(target, **_kwargs)
        return FetchResult(
            url=chain[-1] if chain else target,
            status_code=status,
            body=body,
            content_type="text/html",
            redirect_chain=list(chain[:-1] if chain else []),
        )

    async def fake_ns(host, cache=None, **kwargs):
        return list(ns or [])

    ctx = ToolContext(
        cache=LookupCache(tmp_path / "live.db"),
        nameservers=fake_ns,
        fetch=fake_fetch,
    )
    return await run("live_fetch", {"url": url}, ctx)


@pytest.mark.asyncio
async def test_parked_page_and_nameserver(tmp_path):
    result = await _run(
        tmp_path,
        "https://idle.example/",
        body="<html><title>Parked</title><p>This domain is parked at Sedo.</p></html>",
        ns=["ns1.sedoparking.com"],
    )
    assert result["parked"] is True
    assert result["for_sale"] is False
    assert result["title"] == "Parked"
    assert result["signal"]


@pytest.mark.asyncio
async def test_for_sale_redirect(tmp_path):
    result = await _run(
        tmp_path,
        "https://forsale.example/",
        body="<html><title>Buy</title></html>",
        chain=["https://forsale.example/", "https://dan.com/forsale.example"],
    )
    assert result["for_sale"] is True
    assert result["final_url"] == "https://dan.com/forsale.example"
    assert result["redirect_chain"] == ["https://forsale.example/"]
    assert result["signal"] == "dan.com"


@pytest.mark.asyncio
async def test_normal_page(tmp_path):
    result = await _run(
        tmp_path,
        "https://docs.example/",
        body="<html><title>Docs</title><p>Hello</p></html>",
    )
    assert result["parked"] is False
    assert result["for_sale"] is False
    assert result["title"] == "Docs"
    assert result["status"] == "ok"


@pytest.mark.asyncio
async def test_sale_text_without_redirect(tmp_path):
    result = await _run(
        tmp_path,
        "https://buyme.example/",
        body="<html>This domain is for sale at HugeDomains</html>",
    )
    assert result["for_sale"] is True


def test_parked_and_for_sale_floors():
    parked_ref = Reference(
        file="src/config.js",
        line=2,
        raw="https://idle.example/api",
        host_or_bucket="idle.example",
        domain="idle.example",
    )
    parked = {
        "target": "idle.example",
        "rows": [
            (
                parked_ref,
                _cl(parked_ref, type="api", runs_in="server"),
                _inv(parked_ref, {}),
            )
        ],
        "evidence": {"live_fetch": {"parked": True, "for_sale": False, "signal": "ns1.sedoparking.com"}},
    }
    level, reason = floor_decision(parked)
    assert level == "high"
    assert "parked" in reason.lower()
    sale_ref = Reference(
        file="https://shop.example/",
        line=4,
        raw="https://cdn.sale.example/app.js",
        host_or_bucket="cdn.sale.example",
        domain="sale.example",
        page_url="https://shop.example/",
        tag="script",
        sri=False,
    )
    sale = {
        "target": "sale.example",
        "rows": [
            (sale_ref, _cl(sale_ref, type="script", runs_in="browser"), _inv(sale_ref, {}))
        ],
        "evidence": {"live_fetch": {"parked": False, "for_sale": True, "signal": "dan.com"}},
    }
    level, reason = floor_decision(sale)
    assert level == "critical"
    assert "for sale" in reason.lower()


@pytest.mark.asyncio
async def test_live_fetch_refuses_private_and_metadata(tmp_path, monkeypatch):
    monkeypatch.delenv("TRUSTMAP_ALLOW_LOCAL_SCAN", raising=False)

    async def send(*_args, **_kwargs):
        raise AssertionError("must not connect")

    from scanner.website import safe_get

    async def wrapped(url, **kwargs):
        kwargs.setdefault("send", send)
        return await safe_get(url, **kwargs)

    ctx = ToolContext(
        cache=LookupCache(tmp_path / "ssrf.db"),
        nameservers=lambda host, cache=None, **kw: [],
        fetch=wrapped,
    )
    for url in ("http://127.0.0.1/", "http://169.254.169.254/"):
        result = await run("live_fetch", {"url": url}, ctx)
        assert result["status"] == "blocked"
        assert SCAN_BLOCKED in (result.get("error") or "")
        assert "127" not in (result.get("error") or "")
        assert "169.254" not in (result.get("error") or "")


@pytest.mark.asyncio
async def test_live_fetch_refuses_redirect_to_private(tmp_path, monkeypatch):
    monkeypatch.delenv("TRUSTMAP_ALLOW_LOCAL_SCAN", raising=False)

    async def resolve(host):
        if host in {"10.0.0.1", "127.0.0.1"}:
            return [host]
        return ["93.184.216.34"]

    async def send(_method, connect_url, _headers, **_kwargs):
        if "93.184.216.34" in connect_url:
            return 302, {"location": "http://10.0.0.1/secret"}, b""
        raise AssertionError(f"must not fetch {connect_url}")

    from scanner.website import safe_get

    async def wrapped(url, **kwargs):
        kwargs["resolve"] = resolve
        kwargs["send"] = send
        return await safe_get(url, **kwargs)

    ctx = ToolContext(
        cache=LookupCache(tmp_path / "redir.db"),
        nameservers=lambda host, cache=None, **kw: [],
        fetch=wrapped,
    )
    result = await run("live_fetch", {"url": "https://public.example/"}, ctx)
    assert result["status"] == "blocked"
    assert SCAN_BLOCKED in (result.get("error") or "")
