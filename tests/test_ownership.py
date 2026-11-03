import json
from pathlib import Path

import httpx
import pytest

from scanner.lookups import LookupCache, line_first_seen, rdap
from scanner.models import Classification, Investigation, Reference
from scanner.ownership import (
    attach_changed_hands,
    likely_risk,
    ownership_claim_without_fact,
    supporting_facts,
)
from scanner.report import finding_evidence_level, floor_severity, rank
from scanner.llm import FakeModelClient
from scanner.tools import ToolContext
from tests.test_report import _cl, _inv, _rank_ok

FIXTURES = Path(__file__).parent / "fixtures" / "ownership"


def _ref(**kwargs) -> Reference:
    return Reference(
        file=kwargs.get("file", "index.html"),
        line=kwargs.get("line", 7),
        raw=kwargs.get("raw", "https://cdn.old-brand.example/app.js"),
        host_or_bucket=kwargs.get("host", "cdn.old-brand.example"),
        domain=kwargs.get("domain", "old-brand.example"),
    )


def test_proven_reregistered_after_reference_floors():
    payload = json.loads((FIXTURES / "proven.json").read_text())
    ref = _ref()
    group = {
        "target": "old-brand.example",
        "kind": "domain",
        "rows": [
            (
                ref,
                _cl(ref, type="script", runs_in="browser", blast_radius=2),
                _inv(ref, {}),
            )
        ],
        "evidence": {
            "dns": {"status": "resolves"},
            "rdap": payload["rdap"],
            "changed_hands": {
                "status": "ok",
                "reference_date": payload["reference_date"],
                "reference_source": payload["reference_source"],
                "registration_date": payload["registration_date"],
                "reregistered_after_reference": True,
            },
        },
    }
    assert finding_evidence_level(group) == "proven"
    assert floor_severity(group) == "critical"


def test_likely_supporting_signals_do_not_floor():
    payload = json.loads((FIXTURES / "likely.json").read_text())
    ref = _ref()
    evidence = {
        "dns": {"status": "resolves"},
        "rdap": {"status": "registered", "registered": "2010-01-01"},
        "changed_hands": {
            "status": "ok",
            "reregistered_after_reference": False,
            "supporting": supporting_facts(payload),
        },
        **{k: v for k, v in payload.items() if k != "reregistered_after_reference"},
    }
    group = {
        "target": "old-brand.example",
        "kind": "domain",
        "rows": [
            (
                ref,
                _cl(ref, type="script", runs_in="browser", blast_radius=2),
                _inv(ref, evidence),
            )
        ],
        "evidence": evidence,
    }
    assert supporting_facts(evidence)
    assert finding_evidence_level(group) == "likely"
    assert floor_severity(group) is None
    assert likely_risk(group).startswith("Likely changed hands")


def test_likely_rank_uses_template(tmp_path):
    payload = json.loads((FIXTURES / "likely.json").read_text())
    ref = _ref()
    evidence = {
        "dns": {"status": "resolves"},
        "rdap": {"status": "registered"},
        **{k: v for k, v in payload.items() if k != "reregistered_after_reference"},
        "changed_hands": {"reregistered_after_reference": False},
    }
    client = FakeModelClient(handler=lambda request: _rank_ok(severity="low"))
    findings = rank(
        [
            (
                ref,
                _cl(ref, type="script", runs_in="browser", blast_radius=2),
                _inv(ref, evidence),
            )
        ],
        client=client,
        cache=LookupCache(tmp_path / "c.db"),
    )
    assert client.calls == []
    assert findings[0].evidence_level == "likely"
    assert findings[0].risk.startswith("Likely changed hands")
    assert findings[0].severity == "medium"
    assert findings[0].floor_applied == ""


def test_proven_rank_skips_model(tmp_path):
    ref = _ref()
    evidence = {
        "dns": {"status": "resolves"},
        "rdap": {"status": "registered", "registered": "2024-02-10"},
        "changed_hands": {
            "status": "ok",
            "reference_date": "2018-04-01",
            "reference_source": "blame",
            "registration_date": "2024-02-10",
            "reregistered_after_reference": True,
        },
    }
    client = FakeModelClient(handler=lambda request: _rank_ok(severity="low"))
    findings = rank(
        [
            (
                ref,
                _cl(ref, type="script", runs_in="browser", blast_radius=2),
                _inv(ref, evidence),
            )
        ],
        client=client,
        cache=LookupCache(tmp_path / "c.db"),
    )
    assert client.calls == []
    assert findings[0].evidence_level == "proven"
    assert "2024-02-10" in findings[0].risk
    assert findings[0].severity == "critical"


def test_model_cannot_claim_ownership_change_without_fact(tmp_path):
    ref = _ref()
    client = FakeModelClient(
        handler=lambda request: _rank_ok(
            severity="high",
            risk="This domain changed hands in 2020.",
            blast_radius=2,
            override="",
        )
    )
    findings = rank(
        [
            (
                ref,
                _cl(ref, type="script", runs_in="browser", blast_radius=2),
                _inv(
                    ref,
                    {
                        "dns": {"status": "resolves"},
                        "rdap": {"status": "registered"},
                    },
                ),
            )
        ],
        client=client,
        cache=LookupCache(tmp_path / "c.db"),
    )
    assert findings[0].needs_review is True
    assert ownership_claim_without_fact("this domain changed hands", {})


@pytest.mark.asyncio
async def test_attach_compares_blame_and_rdap_dates(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_testtoken_not_a_secret_value")
    ref = _ref()
    inv = Investigation(
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        status="done",
        evidence={
            "dns": {"status": "resolves"},
            "rdap": {
                "status": "registered",
                "registered": "2024-02-10",
                "transfer": "2024-02-11",
            },
        },
    )
    cl = Classification(
        id="0",
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        type="script",
        runs_in="browser",
        blast_radius=2,
        confidence=1,
        reason="t",
    )

    async def fake_blame(owner, repo, path, line, cache=None, **kwargs):
        return {
            "status": "ok",
            "source": "blame",
            "date": "2018-04-01",
            "path": path,
            "line": line,
        }

    async def fake_certs(domain, cache=None, **kwargs):
        from scanner.models import CertHistoryResult

        return CertHistoryResult(domain=domain, status="unavailable")

    async def fake_wayback(url, cache=None, **kwargs):
        from scanner.models import WaybackResult

        return WaybackResult(url=url, status="unavailable")

    ctx = ToolContext(
        cache=LookupCache(tmp_path / "c.db"),
        line_first_seen=fake_blame,
        cert_history=fake_certs,
        wayback=fake_wayback,
    )
    await attach_changed_hands(
        [(ref, cl, inv)],
        github_owner="acme",
        github_repo="widgets",
        ctx=ctx,
    )
    hands = inv.evidence["changed_hands"]
    assert hands["reregistered_after_reference"] is True
    assert hands["reference_source"] == "blame"
    assert hands["registration_date"] == "2024-02-10"


@pytest.mark.asyncio
async def test_blame_falls_back_to_oldest_commit(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_testtoken_not_a_secret_value")
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        seen.append(url)
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"repository": {"object": None}}})
        if request.method == "GET" and "/commits" in url:
            if "page=2" in url:
                return httpx.Response(
                    200,
                    json=[
                        {
                            "commit": {
                                "committer": {"date": "2016-05-01T00:00:00Z"}
                            }
                        }
                    ],
                )
            return httpx.Response(
                200,
                headers={
                    "Link": '<https://api.github.com/repos/acme/widgets/commits?path=index.html&per_page=1&page=2>; rel="last"'
                },
                json=[
                    {"commit": {"committer": {"date": "2024-01-01T00:00:00Z"}}}
                ],
            )
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        hit = await line_first_seen(
            "acme",
            "widgets",
            "index.html",
            7,
            client=client,
            cache=LookupCache(tmp_path / "b.db"),
        )
    assert hit["source"] == "file existed since"
    assert hit["date"] == "2016-05-01"
    assert any("graphql" in url for url in seen)


@pytest.mark.asyncio
async def test_rdap_keeps_registration_and_transfer(tmp_path):
    bootstrap = {"services": [[["com"], ["https://rdap.example/com/"]]]}

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "data.iana.org/rdap/dns.json" in url:
            return httpx.Response(200, json=bootstrap)
        return httpx.Response(
            200,
            json={
                "status": ["active"],
                "events": [
                    {"eventAction": "registration", "eventDate": "2024-02-10T00:00:00Z"},
                    {"eventAction": "transfer", "eventDate": "2024-02-11T00:00:00Z"},
                    {"eventAction": "last changed", "eventDate": "2024-02-12T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2026-01-01T00:00:00Z"},
                ],
                "nameservers": [{"ldhName": "ns1.takeover.example."}],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await rdap("old-brand.com", client=client, cache=LookupCache(tmp_path / "r.db"))
    assert result.registered.isoformat() == "2024-02-10"
    assert result.transfer.isoformat() == "2024-02-11"
    assert result.last_changed.isoformat() == "2024-02-12"
    assert result.nameservers == ["ns1.takeover.example"]


@pytest.mark.asyncio
async def test_blame_budget_stops(tmp_path):
    ref = _ref()
    inv = Investigation(
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        status="done",
        evidence={"rdap": {"status": "registered", "registered": "2024-02-10"}},
    )
    cl = Classification(
        id="0",
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        type="script",
        runs_in="browser",
        blast_radius=2,
        confidence=1,
        reason="t",
    )
    calls = {"n": 0}

    async def slow_blame(*args, **kwargs):
        calls["n"] += 1
        import asyncio

        await asyncio.sleep(1)
        return {"status": "ok", "source": "blame", "date": "2018-01-01", "path": "x", "line": 1}

    async def fake_certs(domain, cache=None, **kwargs):
        from scanner.models import CertHistoryResult

        return CertHistoryResult(domain=domain, status="unavailable")

    async def fake_wayback(url, cache=None, **kwargs):
        from scanner.models import WaybackResult

        return WaybackResult(url=url, status="unavailable")

    ctx = ToolContext(
        cache=LookupCache(tmp_path / "c.db"),
        line_first_seen=slow_blame,
        cert_history=fake_certs,
        wayback=fake_wayback,
    )
    await attach_changed_hands(
        [(ref, cl, inv)],
        github_owner="acme",
        github_repo="widgets",
        ctx=ctx,
        budget_s=0.05,
    )
    hands = inv.evidence.get("changed_hands") or {}
    assert hands.get("reregistered_after_reference") is not True
    assert calls["n"] <= 1
