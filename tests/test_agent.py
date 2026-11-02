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
from scanner.models import (
    BucketProbeResult,
    Classification,
    DnsResult,
    GithubOwnerResult,
    GithubRepoResult,
    PlatformTakeoverResult,
    RdapResult,
    Reference,
)
from scanner.tools import ToolContext

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

    return ToolContext(
        cache=LookupCache(tmp_path / "c.db"),
        dns=impls.get("dns", fake_dns),
        bucket_probe=impls.get("bucket_probe", fake_bucket),
        rdap=impls.get("rdap", fake_rdap),
        platform_takeover=impls.get("platform_takeover", fake_platform),
        github_owner=impls.get("github_owner", fake_github_owner),
        github_repo=impls.get("github_repo", fake_github_repo),
        nameservers=impls.get("nameservers", fake_nameservers),
        fetch=impls.get("fetch"),
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

    refs = [
        Reference(
            file=f"f{i}.py",
            line=1,
            raw=f"https://host{i}.example.net/x",
            host_or_bucket=f"host{i}.example.net",
            domain="example.net",
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
            raw="https://cdn-assets-trustmap-7f3k2.com/x",
            host_or_bucket=f"host{i}.example.net",
            domain="example.net",
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
async def test_targets_with_different_context_are_investigated_apart(tmp_path):
    # same host, different blast radius: a genuinely different question
    first = Reference(
        file="index.html",
        line=1,
        raw="https://cdn-assets-trustmap-7f3k2.com/lib.js",
        host_or_bucket="cdn-assets-trustmap-7f3k2.com",
        domain="cdn-assets-trustmap-7f3k2.com",
    )
    second = first.model_copy(update={"file": "docs/page.html", "line": 9})
    pairs = [
        (first, _classification(first, blast_radius=2)),
        (second, _classification(second, blast_radius=1)),
    ]
    found = await investigate(pairs, client=_scripted_client(), ctx=_ctx(tmp_path))
    assert len(found) == 2
    assert sum(1 for item in found if item.cost_usd > 0) == 2


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
