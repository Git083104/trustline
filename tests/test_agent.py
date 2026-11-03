import asyncio
import json
import threading
import time
from pathlib import Path

import pytest

from scanner.agent import BUDGET_NOTE, investigate, precheck
from scanner.extract import extract
from scanner.llm import FakeModelClient
from scanner.lookups import LookupCache
from datetime import date

from scanner.models import (
    BucketProbeResult,
    CertHistoryResult,
    Classification,
    DnsResult,
    GithubOwnerResult,
    GithubRepoResult,
    PlatformTakeoverResult,
    RdapResult,
    Reference,
    WaybackResult,
)
from scanner.tools import ToolContext
from scanner.website import FetchResult

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "demo_repo"
EXPECTED_PATH = Path(__file__).parent / "fixtures" / "expected.json"


def _classification(ref: Reference, **kwargs) -> Classification:
    return Classification(
        id="0",
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        type=kwargs.get("type", "script"),
        runs_in=kwargs.get("runs_in", "browser"),
        blast_radius=kwargs.get("blast_radius", 2),
        confidence=0.9,
        reason="test",
    )


def _ctx(tmp_path, **impls) -> ToolContext:
    async def fake_dns(host, cache=None, **kwargs):
        status = "nxdomain" if "7f3k2" in host else "resolves"
        addrs = [] if status == "nxdomain" else ["203.0.113.9"]
        return DnsResult(host=host, status=status, addresses=addrs)

    async def fake_bucket(name, provider, cache=None, **kwargs):
        missing = "live" not in name
        return BucketProbeResult(
            name=name,
            provider=provider,
            status="NoSuchBucket" if missing else "exists",
            http_status=404 if missing else 403,
        )

    async def fake_rdap(domain, cache=None, **kwargs):
        if "7f3k2" in domain:
            return RdapResult(domain=domain, status="unregistered")
        return RdapResult(domain=domain, status="registered", days_to_expiry=400)

    async def fake_platform(host, cnames=None, dns_status=None, cache=None, **kwargs):
        if "github.io" in host:
            return PlatformTakeoverResult(
                host=host,
                status="unclaimed",
                platform="GitHub Pages",
                takeover="vulnerable",
                signal="There isn't a GitHub Pages site here",
                http_status=404,
            )
        return PlatformTakeoverResult(host=host, status="skipped")

    async def fake_github_owner(owner, cache=None, **kwargs):
        missing = "missing" in owner.lower()
        return GithubOwnerResult(
            owner=owner,
            status="missing" if missing else "exists",
            exists=not missing,
            http_status=404 if missing else 200,
        )

    async def fake_nameservers(host, cache=None, **kwargs):
        return []

    async def fake_github_repo(owner, repo, cache=None, **kwargs):
        missing = "missing" in repo.lower()
        return GithubRepoResult(
            owner=owner,
            repo=repo,
            status="missing" if missing else "exists",
            exists=not missing,
            http_status=404 if missing else 200,
        )

    async def fake_certs(domain, cache=None, **kwargs):
        return CertHistoryResult(
            domain=domain,
            status="ok",
            issuers=["Let's Encrypt"],
            first_seen=date(2019, 3, 2),
            last_seen=date(2023, 5, 30),
        )

    async def fake_wayback(url, cache=None, **kwargs):
        return WaybackResult(url=url, status="unavailable")

    async def fake_fetch(url, max_bytes=0, timeout=0.0, **kwargs):
        # a plain home page; tests about parked or for-sale pages pass their own
        return FetchResult(url=url, status_code=200, body="<html><title>Home</title></html>")

    return ToolContext(
        cache=LookupCache(tmp_path / "c.db"),
        dns=impls.get("dns", fake_dns),
        bucket_probe=impls.get("bucket_probe", fake_bucket),
        rdap=impls.get("rdap", fake_rdap),
        platform_takeover=impls.get("platform_takeover", fake_platform),
        github_owner=impls.get("github_owner", fake_github_owner),
        github_repo=impls.get("github_repo", fake_github_repo),
        nameservers=impls.get("nameservers", fake_nameservers),
        cert_history=impls.get("cert_history", fake_certs),
        wayback=impls.get("wayback", fake_wayback),
        fetch=impls.get("fetch", fake_fetch),
    )


def _scripted_client():
    def tool_handler(request):
        first = json.loads(request["messages"][0]["content"])
        n_tools = sum(1 for msg in request["messages"] if msg["role"] == "assistant")
        if first["reference"]["type"] == "bucket":
            return {"name": "done", "arguments": {"summary": "bucket checked"}}
        if first.get("precomputed", {}).get("github_owner") or first.get(
            "precomputed", {}
        ).get("platform_takeover"):
            return {"name": "done", "arguments": {"summary": "precomputed only"}}
        if n_tools == 0:
            domain = first["reference"]["domain"] or first["reference"]["host_or_bucket"]
            return {"name": "rdap", "arguments": {"domain": domain}}
        return {"name": "done", "arguments": {"summary": "domain checked"}}

    return FakeModelClient(tool_handler=tool_handler)


@pytest.mark.asyncio
async def test_prerun_dns_and_bucket_always_in_evidence(tmp_path):
    domain_ref = Reference(
        file="index.html",
        line=7,
        raw="https://cdn-assets-trustmap-7f3k2.com/lib.js",
        host_or_bucket="cdn-assets-trustmap-7f3k2.com",
        domain="cdn-assets-trustmap-7f3k2.com",
    )
    bucket_ref = Reference(
        file="deploy/infra.yaml",
        line=3,
        raw="s3://missing-orphan-bucket",
        host_or_bucket="missing-orphan-bucket",
    )
    client = FakeModelClient(
        tool_handler=lambda request: {
            "name": "done",
            "arguments": {"summary": "precomputed only"},
        }
    )
    results = await investigate(
        [
            (domain_ref, _classification(domain_ref, type="script")),
            (bucket_ref, _classification(bucket_ref, type="bucket", runs_in="deploy")),
        ],
        client=client,
        ctx=_ctx(tmp_path),
    )
    by_host = {item.host_or_bucket: item for item in results}
    assert by_host["cdn-assets-trustmap-7f3k2.com"].evidence["dns"]["status"] == "nxdomain"
    assert by_host["cdn-assets-trustmap-7f3k2.com"].evidence["rdap"]["status"] == (
        "unregistered"
    )
    gone = bucket_ref.host_or_bucket
    assert by_host[gone].evidence["bucket_probe"]["status"] == "NoSuchBucket"
    assert any(
        "precomputed" in json.loads(call["messages"][0]["content"])
        for call in client.calls
    )


@pytest.mark.asyncio
async def test_precheck_probes_s3_url_even_if_classified_ci(tmp_path):
    ref = Reference(
        file=".github/workflows/ci.yaml",
        line=31,
        raw="https://s3.amazonaws.com/quantopian-orchestration/packages/x.tar.gz",
        host_or_bucket="quantopian-orchestration",
        domain="amazonaws.com",
    )
    evidence = await precheck(
        ref, _classification(ref, type="other", runs_in="ci"), _ctx(tmp_path)
    )
    assert evidence["bucket_probe"]["status"] == "NoSuchBucket"
    assert "dns" not in evidence


@pytest.mark.asyncio
async def test_fixture_gone_bucket_and_unregistered_host(tmp_path):
    expected = json.loads(EXPECTED_PATH.read_text())["references"]
    refs = extract(str(FIXTURE_ROOT))
    by_loc = {(row["file"], row["line"]): row for row in expected}
    pairs = []
    for ref in refs:
        exp = by_loc.get((ref.file, ref.line))
        if not exp:
            continue
        blast = 0 if exp["type"] == "bucket" else (2 if ref.filter_reason is None else 0)
        pairs.append(
            (
                ref,
                _classification(
                    ref,
                    type=exp["type"],
                    runs_in=exp["runs_in"],
                    blast_radius=blast,
                ),
            )
        )
    results = await investigate(
        pairs, client=_scripted_client(), ctx=_ctx(tmp_path)
    )
    hosts = {item.host_or_bucket for item in results}
    gone_name = next(
        row["host_or_bucket"]
        for row in expected
        if row["file"] == "deploy/infra.yaml" and row["raw"].startswith("s3://")
    )
    assert "cdn-assets-trustmap-7f3k2.com" in hosts
    assert gone_name in hosts
    gone = next(item for item in results if item.host_or_bucket == gone_name)
    domain = next(
        item for item in results if item.host_or_bucket == "cdn-assets-trustmap-7f3k2.com"
    )
    assert gone.evidence["bucket_probe"]["status"] == "NoSuchBucket"
    assert domain.evidence["dns"]["status"] == "nxdomain"
    assert domain.evidence["rdap"]["status"] == "unregistered"
    assert all(item.status == "done" for item in results)


@pytest.mark.asyncio
async def test_skips_filtered_and_low_blast(tmp_path):
    ref = Reference(
        file="a.py",
        line=1,
        raw="https://cdn-assets-trustmap-7f3k2.com/x",
        host_or_bucket="cdn-assets-trustmap-7f3k2.com",
        filter_reason="reserved_domain",
    )
    low = Reference(
        file="b.py",
        line=1,
        raw="https://api.vendor.example.net/v1",
        host_or_bucket="api.vendor.example.net",
        domain="vendor.example.net",
    )
    results = await investigate(
        [
            (ref, _classification(ref, blast_radius=3)),
            (low, _classification(low, type="api", runs_in="server", blast_radius=0)),
        ],
        client=_scripted_client(),
        ctx=_ctx(tmp_path),
    )
    assert results == []


@pytest.mark.asyncio
async def test_nosuchbucket_blast_zero_is_still_investigated(tmp_path):
    ref = Reference(
        file="deploy/infra.yaml",
        line=3,
        raw="s3://missing-orphan-bucket",
        host_or_bucket="missing-orphan-bucket",
    )
    results = await investigate(
        [(ref, _classification(ref, type="bucket", runs_in="deploy", blast_radius=0))],
        client=_scripted_client(),
        ctx=_ctx(tmp_path),
    )
    assert len(results) == 1
    assert results[0].status == "done"
    assert results[0].evidence["bucket_probe"]["status"] == "NoSuchBucket"


@pytest.mark.asyncio
async def test_concurrency_caps_at_four(tmp_path):
    inflight = 0
    max_seen = 0
    gate = threading.Lock()

    def tool_handler(request):
        nonlocal inflight, max_seen
        with gate:
            inflight += 1
            max_seen = max(max_seen, inflight)
        time.sleep(0.05)
        with gate:
            inflight -= 1
        return {"name": "done", "arguments": {"summary": "ok"}}

    # eight separate targets, each with a red flag (the domain does not resolve)
    refs = [
        Reference(
            file=f"f{i}.py",
            line=1,
            raw=f"https://cdn{i}-7f3k2.net/x",
            host_or_bucket=f"cdn{i}-7f3k2.net",
            domain=f"cdn{i}-7f3k2.net",
        )
        for i in range(8)
    ]
    pairs = [
        (ref, _classification(ref, type="script", blast_radius=2)) for ref in refs
    ]
    await investigate(
        pairs,
        client=FakeModelClient(tool_handler=tool_handler),
        ctx=_ctx(tmp_path),
        max_concurrent=4,
        cost_cap=10.0,
    )
    assert max_seen <= 4
    assert max_seen >= 2


@pytest.mark.asyncio
async def test_cost_cap_finishes_inflight_and_skips_rest(tmp_path):
    usage = {"input_tokens": 320_000, "output_tokens": 0}
    client = FakeModelClient(
        tool_handler=lambda request: {
            "name": "done",
            "arguments": {"summary": "ok"},
            "usage": usage,
        }
    )
    refs = [
        Reference(
            file=f"f{i}.py",
            line=1,
            raw=f"https://cdn{i}-7f3k2.net/x",
            host_or_bucket=f"cdn{i}-7f3k2.net",
            domain=f"cdn{i}-7f3k2.net",
        )
        for i in range(3)
    ]
    pairs = [(ref, _classification(ref, blast_radius=2)) for ref in refs]
    results = await investigate(
        pairs,
        client=client,
        ctx=_ctx(tmp_path),
        max_concurrent=1,
        cost_cap=0.5,
    )
    statuses = [item.status for item in results]
    assert statuses.count("done") == 2
    assert statuses.count("budget") == 1
    assert results[-1].summary == BUDGET_NOTE
    # the free lookups survive a spent budget, so rank's floors still see them
    assert results[-1].evidence["dns"]["status"] == "nxdomain"
    assert results[-1].evidence["rdap"]["status"] == "unregistered"


@pytest.mark.asyncio
async def test_trace_is_plan_act_observe(tmp_path):
    ref = Reference(
        file="index.html",
        line=7,
        raw="https://cdn-assets-trustmap-7f3k2.com/lib.js",
        host_or_bucket="cdn-assets-trustmap-7f3k2.com",
        domain="cdn-assets-trustmap-7f3k2.com",
    )
    results = await investigate(
        [(ref, _classification(ref, type="script"))],
        client=_scripted_client(),
        ctx=_ctx(tmp_path),
    )
    kinds = [event.kind for event in results[0].trace]
    assert kinds[:3] == ["plan", "act", "observe"]
    assert "rdap" in {event.tool for event in results[0].trace}
    assert kinds[-3:] == ["plan", "act", "observe"]
    assert results[0].trace[-1].tool == "done"


@pytest.mark.asyncio
async def test_one_agent_run_per_target_not_per_reference(tmp_path):
    # the same host named from many lines is one takeover question, so the
    # agent should be asked once and the answer shared
    refs = [
        Reference(
            file=f"src/page{index}.html",
            line=index + 1,
            raw="https://cdn-assets-trustmap-7f3k2.com/lib.js",
            host_or_bucket="cdn-assets-trustmap-7f3k2.com",
            domain="cdn-assets-trustmap-7f3k2.com",
        )
        for index in range(12)
    ]
    pairs = [(ref, _classification(ref)) for ref in refs]

    calls: list[str] = []
    scripted = _scripted_client()
    inner = scripted.tool_handler

    def counting(request):
        first = json.loads(request["messages"][0]["content"])
        calls.append(first["reference"]["file"])
        return inner(request)

    client = FakeModelClient(tool_handler=counting)
    found = await investigate(pairs, client=client, ctx=_ctx(tmp_path))

    assert len(found) == len(refs)
    # every reference keeps its own location
    assert {(item.file, item.line) for item in found} == {
        (ref.file, ref.line) for ref in refs
    }
    # but only one of them was actually investigated
    assert len(set(calls)) == 1
    assert sum(1 for item in found if item.cost_usd > 0) == 1
    assert all(item.summary == found[0].summary for item in found)


@pytest.mark.asyncio
async def test_one_agent_run_per_target_even_when_labels_differ(tmp_path):
    # The page shows one row per target. Two runs for one target (one per label
    # or per subdomain) stacked under it and read as more checks than listed.
    low = Reference(
        file="docs/page.html",
        line=9,
        raw="https://cdn-assets-trustmap-7f3k2.com/lib.js",
        host_or_bucket="cdn-assets-trustmap-7f3k2.com",
        domain="cdn-assets-trustmap-7f3k2.com",
    )
    high = low.model_copy(update={"file": "index.html", "line": 1})
    sub = low.model_copy(
        update={
            "file": "app.js",
            "line": 3,
            "raw": "https://img.cdn-assets-trustmap-7f3k2.com/a.png",
            "host_or_bucket": "img.cdn-assets-trustmap-7f3k2.com",
        }
    )
    pairs = [
        (low, _classification(low, blast_radius=1, runs_in="docs_only")),
        (high, _classification(high, blast_radius=3)),
        (sub, _classification(sub, type="asset", blast_radius=1)),
    ]
    client = _scripted_client()
    found = await investigate(pairs, client=client, ctx=_ctx(tmp_path))
    assert len(found) == 3
    assert sum(1 for item in found if item.cost_usd > 0) == 1
    # the agent is asked about the most exposed reference
    first = json.loads(client.calls[0]["messages"][0]["content"])
    assert first["reference"]["file"] == "index.html"
    # every reference keeps its own host and lookups
    by_file = {item.file: item for item in found}
    assert by_file["app.js"].host_or_bucket == "img.cdn-assets-trustmap-7f3k2.com"


@pytest.mark.asyncio
async def test_clean_lookups_skip_the_agent_but_are_still_ranked(tmp_path):
    from scanner.agent import FACTS_NOTE

    ref = Reference(
        file="index.html",
        line=4,
        raw="https://cdn.vendor-assets.net/app.js",
        host_or_bucket="cdn.vendor-assets.net",
        domain="vendor-assets.net",
    )
    client = _scripted_client()
    events: list[dict] = []
    found = await investigate(
        [(ref, _classification(ref, blast_radius=3))],
        client=client,
        ctx=_ctx(tmp_path),
        on_event=events.append,
    )
    assert client.calls == []
    assert len(found) == 1
    assert found[0].summary == FACTS_NOTE
    evidence = found[0].evidence
    assert evidence["dns"]["status"] == "resolves"
    # the checks an agent used to pick for a clean target now run every time
    assert evidence["live_fetch"]["url"] == "https://cdn.vendor-assets.net/"
    assert evidence["cert_history"]["status"] == "ok"
    assert evidence["wayback"]["url"] == "https://cdn.vendor-assets.net/app.js"
    assert [item["next"] for item in events if item["type"] == "precheck"] == ["facts"]
    checked = [item for item in events if item["type"] == "checked"]
    assert checked and checked[0]["evidence"]["cert_history"]["status"] == "ok"


@pytest.mark.asyncio
async def test_a_parked_home_page_is_a_red_flag_found_every_time(tmp_path):
    from scanner.agent import next_step

    async def parked(url, max_bytes=0, timeout=0.0, **kwargs):
        return FetchResult(url=url, status_code=200, body="<html>This domain is for sale! Buy this domain.</html>")

    ref = Reference(
        file="index.html",
        line=4,
        raw="https://cdn.vendor-assets.net/app.js",
        host_or_bucket="cdn.vendor-assets.net",
        domain="vendor-assets.net",
    )
    client = _scripted_client()
    events: list[dict] = []
    found = await investigate(
        [(ref, _classification(ref, blast_radius=3))],
        client=client,
        ctx=_ctx(tmp_path, fetch=parked),
        on_event=events.append,
    )
    assert found[0].evidence["live_fetch"]["for_sale"] is True
    first = next(item for item in events if item["type"] == "precheck")
    assert first["next"] == "agent"
    assert "domain listed for sale" in first["flags"]
    assert client.calls, "a red flag gets the agent"


def test_renewal_alone_is_not_a_red_flag():
    from scanner.agent import needs_agent, next_step, red_flags

    ref = Reference(
        file="index.html",
        line=4,
        raw="https://cdn.vendor-assets.net/app.js",
        host_or_bucket="cdn.vendor-assets.net",
        domain="vendor-assets.net",
    )
    cl = _classification(ref, blast_radius=2)
    renewing = {
        "dns": {"status": "resolves", "host": "cdn.vendor-assets.net"},
        "rdap": {"status": "registered", "days_to_expiry": 30},
    }
    assert red_flags(ref, renewing) == []
    assert not needs_agent(ref, cl, renewing)
    assert next_step(ref, cl, renewing) == "facts"
    dark = {**renewing, "dns": {"status": "nxdomain", "host": "cdn.vendor-assets.net"}}
    assert "domain expires in 30 days" in red_flags(ref, dark)
    assert next_step(ref, cl, dark) == "agent"


@pytest.mark.asyncio
async def test_agent_adds_facts_but_never_replaces_the_lookups(tmp_path):
    ref = Reference(
        file="index.html",
        line=7,
        raw="https://cdn-assets-trustmap-7f3k2.com/lib.js",
        host_or_bucket="cdn-assets-trustmap-7f3k2.com",
        domain="cdn-assets-trustmap-7f3k2.com",
    )
    asked: list[str] = []

    async def counting_dns(host, cache=None, **kwargs):
        asked.append(host)
        status = "nxdomain" if "7f3k2" in host else "resolves"
        return DnsResult(host=host, status=status, addresses=[] if status == "nxdomain" else ["203.0.113.9"])

    offered: list[list[str]] = []
    plan = [
        {"name": "dns", "arguments": {"host": "cdn-assets-trustmap-7f3k2.com"}},  # a repeat
        {"name": "dns", "arguments": {"host": "www.example.org"}},  # a new subject
        {"name": "done", "arguments": {"summary": "checked"}},
    ]

    def tool_handler(request):
        offered.append([tool["function"]["name"] for tool in request["tools"]])
        turn = sum(1 for msg in request["messages"] if msg["role"] == "assistant")
        return plan[turn]

    found = await investigate(
        [(ref, _classification(ref))],
        client=FakeModelClient(tool_handler=tool_handler),
        ctx=_ctx(tmp_path, dns=counting_dns),
    )
    evidence = found[0].evidence
    # the code's NXDOMAIN stays; the other host's answer sits beside it
    assert evidence["dns"]["status"] == "nxdomain"
    assert evidence["agent_findings"] == [
        {
            "tool": "dns",
            "args": {"host": "www.example.org"},
            "result": {"host": "www.example.org", "status": "resolves", "addresses": ["203.0.113.9"], "cnames": []},
        }
    ]
    # the repeat came from what was known: one lookup for the CDN host, by code
    assert asked.count("cdn-assets-trustmap-7f3k2.com") == 1
    # every tool stays on offer, as before
    assert {"dns", "rdap", "wayback", "cert_history", "live_fetch", "done"} <= set(offered[0])


@pytest.mark.asyncio
async def test_every_reference_to_a_target_reports_the_same_next_step(tmp_path):
    quiet = Reference(
        file="docs/links.html",
        line=2,
        raw="https://www.cdn-assets-trustmap-7f3k2.com/",
        host_or_bucket="www.cdn-assets-trustmap-7f3k2.com",
        domain="cdn-assets-trustmap-7f3k2.com",
    )
    loud = Reference(
        file="index.html",
        line=7,
        raw="https://cdn-assets-trustmap-7f3k2.com/lib.js",
        host_or_bucket="cdn-assets-trustmap-7f3k2.com",
        domain="cdn-assets-trustmap-7f3k2.com",
    )
    async def split_dns(host, cache=None, **kwargs):
        # www still answers; the CDN host is gone
        if host.startswith("www."):
            return DnsResult(host=host, status="resolves", addresses=["203.0.113.9"])
        return DnsResult(host=host, status="nxdomain", addresses=[])

    from scanner.agent import next_step

    ctx = _ctx(tmp_path, dns=split_dns)
    quiet_cl = _classification(quiet, blast_radius=0, runs_in="docs_only")
    alone = await precheck(quiet, quiet_cl, ctx)
    # on its own the docs link would not even be ranked
    assert next_step(quiet, quiet_cl, alone) == "low_exposure"
    events: list[dict] = []
    await investigate(
        [
            (quiet, quiet_cl),
            (loud, _classification(loud, blast_radius=2)),
        ],
        client=_scripted_client(),
        ctx=ctx,
        on_event=events.append,
    )
    prechecks = [item for item in events if item["type"] == "precheck"]
    assert [item["next"] for item in prechecks] == ["agent", "agent"]
    first = next(item for item in prechecks if "evidence" in item)
    assert first["max_turns"] >= 1
    assert "DNS does not resolve" in first["flags"]


@pytest.mark.asyncio
async def test_past_deadline_skips_the_agent_but_keeps_the_precheck(tmp_path):
    from scanner.agent import TIME_NOTE

    ref = Reference(
        file="index.html",
        line=7,
        raw="https://cdn-assets-trustmap-7f3k2.com/lib.js",
        host_or_bucket="cdn-assets-trustmap-7f3k2.com",
        domain="cdn-assets-trustmap-7f3k2.com",
    )
    client = FakeModelClient(
        tool_handler=lambda request: {"name": "done", "arguments": {"summary": "never"}}
    )
    results = await investigate(
        [(ref, _classification(ref))],
        client=client,
        ctx=_ctx(tmp_path),
        deadline=time.monotonic() - 1,
    )
    assert client.calls == []
    assert results[0].summary == TIME_NOTE
    assert results[0].status == "done"
    # rank and its severity floors still see what the lookups found
    assert results[0].evidence["rdap"]["status"] == "unregistered"


@pytest.mark.asyncio
async def test_deadline_stops_an_agent_between_turns(tmp_path):
    from scanner.agent import TIME_NOTE, investigate_one

    ref = Reference(
        file="index.html",
        line=7,
        raw="https://cdn-assets-trustmap-7f3k2.com/lib.js",
        host_or_bucket="cdn-assets-trustmap-7f3k2.com",
        domain="cdn-assets-trustmap-7f3k2.com",
    )
    client = FakeModelClient(
        tool_handler=lambda request: {"name": "rdap", "arguments": {"domain": "cdn-assets-trustmap-7f3k2.com"}}
    )
    result = await investigate_one(
        ref,
        _classification(ref),
        client=client,
        ctx=_ctx(tmp_path),
        deadline=time.monotonic() + 0.0,
    )
    assert len(client.calls) == 1
    assert result.summary == TIME_NOTE
