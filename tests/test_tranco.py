import pytest

from scanner.agent import investigate, precheck, tranco_checked_safe
from scanner.llm import FakeModelClient
from scanner.models import Reference
from scanner.report import floor_decision, rank
from scanner.tranco import TOP_SAFE_RANK, tranco_rank
from tests.test_agent import _classification, _ctx
from tests.test_report import _cl, _inv, _rank_ok


def test_tranco_rank_looks_up_registrable_domain():
    assert tranco_rank("stripe.com") == 204
    assert tranco_rank("stripe.com") <= TOP_SAFE_RANK
    assert tranco_rank("this-is-not-on-the-tranco-list.invalid") is None
    assert tranco_rank("") is None


@pytest.mark.asyncio
async def test_popular_domain_with_no_signals_skips_agent(tmp_path):
    ref = Reference(
        file="src/pay.js",
        line=3,
        raw="https://js.stripe.com/v3/",
        host_or_bucket="js.stripe.com",
        domain="stripe.com",
    )

    def tool_handler(_request):
        raise AssertionError("agent must not run for a popular resolving domain")

    results = await investigate(
        [(ref, _classification(ref, type="script", blast_radius=2))],
        client=FakeModelClient(tool_handler=tool_handler),
        ctx=_ctx(tmp_path),
    )
    assert len(results) == 1
    assert results[0].summary == "Tranco rank 204"
    assert results[0].evidence["tranco_rank"] == 204
    assert results[0].evidence["dns"]["status"] == "resolves"
    findings = rank(
        [(ref, _cl(ref, type="script", runs_in="browser"), results[0])],
        client=FakeModelClient(handler=lambda request: (_ for _ in ()).throw(
            AssertionError("ranker must not run for tranco-safe")
        )),
    )
    assert findings[0].severity == "info"
    assert "Tranco rank 204" in findings[0].evidence_line
    assert findings[0].fix == "No action needed"


@pytest.mark.asyncio
async def test_popular_compromised_domain_stays_critical(tmp_path, monkeypatch):
    monkeypatch.setattr("scanner.agent.tranco_rank", lambda domain: 50)
    monkeypatch.setattr("scanner.report.tranco_rank", lambda domain: 50)
    ref = Reference(
        file="index.html",
        line=7,
        raw="https://cdn.polyfill.io/v3/polyfill.min.js",
        host_or_bucket="cdn.polyfill.io",
        domain="polyfill.io",
        tag="script",
        sri=False,
    )
    agent_calls = {"n": 0}

    def tool_handler(_request):
        agent_calls["n"] += 1
        return {"name": "done", "arguments": {"summary": "compromised"}}

    results = await investigate(
        [(ref, _classification(ref, type="script", blast_radius=2))],
        client=FakeModelClient(tool_handler=tool_handler),
        ctx=_ctx(tmp_path),
    )
    assert agent_calls["n"] == 0
    evidence = results[0].evidence
    evidence["tranco_rank"] = 50
    group = {
        "target": "polyfill.io",
        "rows": [
            (ref, _cl(ref, type="script", runs_in="browser"), _inv(ref, evidence))
        ],
        "evidence": evidence,
    }
    level, reason = floor_decision(group)
    assert level == "critical"
    assert "compromised" in reason
    assert not tranco_checked_safe(ref, evidence)


@pytest.mark.asyncio
async def test_popular_nxdomain_keeps_floor(tmp_path):
    async def fake_dns(host, cache=None, **kwargs):
        from scanner.models import DnsResult

        return DnsResult(host=host, status="nxdomain", addresses=[])

    ref = Reference(
        file="index.html",
        line=1,
        raw="https://js.stripe.com/v3/",
        host_or_bucket="js.stripe.com",
        domain="stripe.com",
        tag="script",
    )
    evidence = await precheck(
        ref, _classification(ref, type="script"), _ctx(tmp_path, dns=fake_dns)
    )
    assert evidence["tranco_rank"] == 204
    assert evidence["dns"]["status"] == "nxdomain"
    group = {
        "target": "stripe.com",
        "rows": [
            (ref, _cl(ref, type="script", runs_in="browser"), _inv(ref, evidence))
        ],
        "evidence": evidence,
    }
    level, reason = floor_decision(group)
    assert level == "high"
    assert "NXDOMAIN" in reason
    findings = rank(
        [(ref, _cl(ref, type="script", runs_in="browser"), _inv(ref, evidence))],
        client=FakeModelClient(handler=lambda request: _rank_ok(severity="info", risk="DNS does not resolve.")),
    )
    assert findings[0].severity == "high"
    assert findings[0].model_severity == "info"
