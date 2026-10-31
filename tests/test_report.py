import json
from pathlib import Path

import pytest

from scanner.extract import extract
from scanner.llm import FakeModelClient
from scanner.lookups import LookupCache
from scanner.models import (
    BucketProbeResult,
    Classification,
    Investigation,
    Reference,
)
from scanner.report import (
    CLAIMABLE_FIX,
    apply_floor,
    finding_payload,
    floor_severity,
    format_table,
    group_by_target,
    missing_claims,
    rank,
    scan,
)
from scanner.tools import ToolContext
from tests.test_agent import _ctx, _scripted_client

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "demo_repo"
EXPECTED_PATH = Path(__file__).parent / "fixtures" / "expected.json"


def _cl(ref: Reference, **kwargs) -> Classification:
    return Classification(
        id="0",
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        type=kwargs.get("type", "bucket"),
        runs_in=kwargs.get("runs_in", "deploy"),
        blast_radius=kwargs.get("blast_radius", 0),
        confidence=0.9,
        reason=kwargs.get("reason", "test"),
    )


def _inv(ref: Reference, evidence: dict, **kwargs) -> Investigation:
    return Investigation(
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        status="done",
        evidence=evidence,
        cost_usd=kwargs.get("cost_usd", 0.0),
    )


def _rank_ok(**kwargs) -> dict:
    return {
        "severity": kwargs.get("severity", "medium"),
        "risk": kwargs.get("risk", "bucket_probe status NoSuchBucket http 404"),
        "fix": kwargs.get("fix", "re-register what you abandoned"),
        "uncertain_about": "",
        "blast_radius": kwargs.get("blast_radius", 3),
        "blast_override_reason": kwargs.get("override", "NoSuchBucket in deploy"),
    }


def test_group_by_target_merges_two_bucket_refs():
    gone = "acme-legacy-uploads-a3f91c2e"
    a = Reference(file="deploy/infra.yaml", line=3, raw=f"s3://{gone}", host_or_bucket=gone)
    b = Reference(
        file="deploy/infra.yaml",
        line=5,
        raw=f"https://s3.amazonaws.com/{gone}",
        host_or_bucket=gone,
    )
    evidence = {"bucket_probe": {"status": "NoSuchBucket", "http_status": 404}}
    groups = group_by_target(
        [
            (a, _cl(a), _inv(a, evidence)),
            (b, _cl(b), _inv(b, evidence)),
        ]
    )
    assert len(groups) == 1
    assert groups[0]["target"] == gone
    assert len(groups[0]["rows"]) == 2


def test_missing_claims_requires_evidence_tokens():
    evidence = {"bucket_probe": {"status": "NoSuchBucket", "http_status": 404}}
    assert missing_claims("NoSuchBucket 404", evidence=evidence) == []
    assert missing_claims("does not exist", evidence=evidence) == []
    assert missing_claims("NoSuchBucket 999", evidence=evidence) == ["999"]


def test_self_check_allows_lines_and_region_but_rejects_invented_date():
    gone = "acme-legacy-uploads-a3f91c2e"
    a = Reference(
        file="deploy/infra.yaml",
        line=3,
        raw=f"s3://{gone}",
        host_or_bucket=gone,
    )
    b = Reference(
        file="deploy/infra.yaml",
        line=5,
        raw=f"https://s3.us-east-2.amazonaws.com/{gone}",
        host_or_bucket=gone,
    )
    evidence = {
        "bucket_probe": {
            "name": gone,
            "provider": "s3",
            "status": "NoSuchBucket",
            "http_status": 404,
        }
    }
    group = group_by_target(
        [
            (a, _cl(a, blast_radius=2), _inv(a, evidence)),
            (b, _cl(b, blast_radius=2), _inv(b, evidence)),
        ]
    )[0]
    allowed = finding_payload(group)
    ok = "The bucket does not exist; lines 3 and 5 in us-east-2"
    assert missing_claims(ok, allowed) == []
    bad = ok + " first seen 2020-01-01"
    assert "2020-01-01" in missing_claims(bad, allowed)


def test_floor_claimable_is_critical_other_hard_is_high():
    gone = Reference(
        file="deploy/infra.yaml",
        line=3,
        raw="s3://missing",
        host_or_bucket="missing",
    )
    claim = {
        "target": "missing",
        "rows": [(gone, _cl(gone, runs_in="deploy"), _inv(gone, {}))],
        "evidence": {"bucket_probe": {"status": "NoSuchBucket"}},
    }
    assert floor_severity(claim) == "critical"
    host = Reference(
        file="index.html",
        line=1,
        raw="https://soon.example.net/x",
        host_or_bucket="soon.example.net",
        domain="example.net",
    )
    expiring = {
        "target": "example.net",
        "rows": [(host, _cl(host, type="script", runs_in="browser"), _inv(host, {}))],
        "evidence": {
            "dns": {"status": "resolves"},
            "rdap": {"status": "registered", "days_to_expiry": 12},
        },
    }
    assert floor_severity(expiring) == "high"
    nx = {
        "target": "example.net",
        "rows": [(host, _cl(host, type="script", runs_in="browser"), _inv(host, {}))],
        "evidence": {
            "dns": {"status": "nxdomain"},
            "rdap": {"status": "registered", "days_to_expiry": 400},
        },
    }
    assert floor_severity(nx) == "high"
    unreg = {
        "target": "cdn-assets-trustmap-7f3k2.com",
        "rows": [(host, _cl(host, type="script", runs_in="browser"), _inv(host, {}))],
        "evidence": {
            "dns": {"status": "nxdomain"},
            "rdap": {"status": "unregistered"},
        },
    }
    assert floor_severity(unreg) == "critical"
    docs = {
        "target": "missing",
        "rows": [(gone, _cl(gone, runs_in="docs_only"), _inv(gone, {}))],
        "evidence": {"bucket_probe": {"status": "NoSuchBucket"}},
    }
    assert floor_severity(docs) is None
    severity, note = apply_floor("medium", "critical")
    assert severity == "critical"
    assert note == "critical"


def test_rank_overrides_blast_and_applies_floor(tmp_path):
    ref = Reference(
        file="deploy/infra.yaml",
        line=3,
        raw="s3://missing",
        host_or_bucket="missing",
    )
    client = FakeModelClient(
        handler=lambda request: _rank_ok(
            severity="low",
            blast_radius=3,
            override="claimable bucket in deploy",
        )
    )
    findings = rank(
        [
            (
                ref,
                _cl(ref, blast_radius=0),
                _inv(ref, {"bucket_probe": {"status": "NoSuchBucket", "http_status": 404}}),
            )
        ],
        client=client,
        cache=LookupCache(tmp_path / "c.db"),
    )
    assert findings[0].severity == "critical"
    assert findings[0].model_severity == "low"
    assert findings[0].final_severity == "critical"
    assert findings[0].floor_applied == "critical"
    assert "NoSuchBucket" in findings[0].floor_reason
    assert findings[0].fix == CLAIMABLE_FIX
    assert findings[0].classified_blast_radius == 0
    assert findings[0].ranked_blast_radius == 3
    assert findings[0].blast_override_reason == "claimable bucket in deploy"
    assert findings[0].references == ["deploy/infra.yaml:3"]
    table = format_table(findings)
    assert "model=low" in table
    assert "final=critical" in table


def test_self_check_retries_then_needs_review(tmp_path):
    ref = Reference(
        file="deploy/infra.yaml",
        line=3,
        raw="s3://missing",
        host_or_bucket="missing",
    )
    users: list[str] = []

    def handler(request):
        users.append(request["user"])
        if "Self-check rejected these tokens" in request["user"]:
            assert "777" in request["user"]
            return _rank_ok()
        return _rank_ok(risk="invented 777 status")

    rows = [
        (
            ref,
            _cl(ref),
            _inv(ref, {"bucket_probe": {"status": "NoSuchBucket", "http_status": 404}}),
        )
    ]
    ok = rank(rows, client=FakeModelClient(handler), cache=LookupCache(tmp_path / "a.db"))
    assert ok[0].needs_review is False
    assert len(users) == 2
    assert "777" in users[1]
    assert "Self-check rejected these tokens" in users[1]

    always = FakeModelClient(handler=lambda request: _rank_ok(risk="invented 777 status"))
    bad = rank(rows, client=always, cache=LookupCache(tmp_path / "b.db"))
    assert bad[0].needs_review is True
    assert bad[0].severity == "critical"
    assert bad[0].model_severity == "info"
    assert bad[0].final_severity == "critical"
    assert bad[0].fix == CLAIMABLE_FIX


def _fixture_handler():
    expected = {
        (row["file"], row["line"]): row
        for row in json.loads(EXPECTED_PATH.read_text())["references"]
    }

    def handler(request):
        if request.get("schema_name") == "ranking":
            text = request["user"]
            payload = json.loads(text[text.find("{") : text.rfind("}") + 1])
            blob = json.dumps(payload.get("evidence", {}))
            if "NoSuchBucket" in blob:
                return _rank_ok(
                    severity="critical",
                    risk="NoSuchBucket 404",
                    blast_radius=3,
                    override="claimable now",
                )
            if "unregistered" in blob:
                return _rank_ok(
                    severity="critical",
                    risk="NXDOMAIN unregistered",
                    blast_radius=3,
                    override="claimable now",
                )
            return {
                "severity": "low",
                "risk": "bucket_probe status exists http 403",
                "fix": "remove dead reference",
                "uncertain_about": "",
                "blast_radius": 1,
                "blast_override_reason": "",
            }
        payload = json.loads(request["user"].split("\n", 1)[1])
        items = []
        for ref in payload["references"]:
            exp = expected[(ref["file"], ref["line"])]
            items.append(
                {
                    "id": ref["id"],
                    "type": exp["type"],
                    "runs_in": exp["runs_in"],
                    "blast_radius": 2 if exp["filter_reason"] is None else 0,
                    "confidence": 0.9,
                    "reason": "fixture",
                }
            )
        return {"items": items}

    return handler


@pytest.mark.asyncio
async def test_fixture_scan_groups_and_ranks_claimable_first(tmp_path):
    async def fake_bucket(name, provider, cache=None, **kwargs):
        missing = "acme-static-assets" not in name
        return BucketProbeResult(
            name=name,
            provider=provider,
            status="NoSuchBucket" if missing else "exists",
            http_status=404 if missing else 403,
        )

    client = FakeModelClient(
        handler=_fixture_handler(),
        tool_handler=_scripted_client().tool_handler,
    )
    findings = await scan(
        str(FIXTURE_ROOT),
        client=client,
        cache=LookupCache(tmp_path / "c.db"),
        ctx=_ctx(tmp_path, bucket_probe=fake_bucket),
    )
    targets = [item.target for item in findings]
    assert "cdn.this-host-does-not-resolve-trustmap.invalid" not in targets
    assert not any("README" in loc for item in findings for loc in item.references)
    assert not any("test_client.py" in loc for item in findings for loc in item.references)
    gone = "acme-legacy-uploads-a3f91c2e"
    live = "acme-static-assets-a3f91c2e"
    top = findings[:3]
    top_targets = {item.target for item in top}
    assert top_targets == {
        gone,
        "cdn-assets-trustmap-7f3k2.com",
        "trustmap-demo-assets",
    }
    assert all(item.severity == "critical" for item in top)
    assert all(item.fix == CLAIMABLE_FIX for item in top)
    gone_hit = next(item for item in findings if item.target == gone)
    assert gone_hit.references == ["deploy/infra.yaml:3", "deploy/infra.yaml:5"]
    live_hit = next(item for item in findings if item.target == live)
    assert live_hit.severity in {"low", "info"}
    assert live_hit.fix != CLAIMABLE_FIX
    table = format_table(findings)
    assert gone in table
    assert "critical" in table


def test_filtered_hosts_are_not_extracted_as_ranked_targets():
    refs = extract(str(FIXTURE_ROOT))
    assert any(ref.filter_reason == "reserved_tld" for ref in refs)
