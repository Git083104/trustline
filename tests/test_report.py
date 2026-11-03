import json
from pathlib import Path

import pytest

from scanner.extract import extract
from scanner.llm import FakeModelClient
from scanner.lookups import LookupCache
from scanner.models import (
    BucketProbeResult,
    Classification,
    Finding,
    Investigation,
    Reference,
)
from scanner.compromised import POLYFILL_FIX, SRI_FIX
from scanner.report import (
    ACTION_MISSING_FIX,
    CLAIMABLE_FIX,
    GITHUB_OWNER_NOTE,
    NO_ACTION_FIX,
    apply_floor,
    choose_fix,
    evidence_line,
    floor_decision,
    finding_payload,
    floor_severity,
    format_table,
    human_fix,
    group_by_target,
    missing_claims,
    rank,
    scan,
    usable_evidence,
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
        "risk": kwargs.get(
            "risk",
            "A stranger could create this missing bucket and serve files to deploy/infra.yaml:3.",
        ),
        "fix": kwargs.get("fix", "re-register what you abandoned"),
        "uncertain_about": kwargs.get("uncertain_about", ""),
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


def test_unavailable_lookup_is_unknown_not_evidence(tmp_path):
    gone = "missing"
    ref = Reference(
        file="deploy/infra.yaml",
        line=3,
        raw=f"s3://{gone}",
        host_or_bucket=gone,
    )
    evidence = {
        "bucket_probe": {"status": "NoSuchBucket", "http_status": 404, "provider": "s3"},
        "wayback": {"status": "unavailable", "url": "https://example"},
    }
    usable = usable_evidence(evidence)
    assert "wayback" not in usable
    assert usable["bucket_probe"]["status"] == "NoSuchBucket"
    group = group_by_target([(ref, _cl(ref), _inv(ref, evidence))])[0]
    payload = finding_payload(group)
    assert "wayback" not in payload["evidence"]
    line = evidence_line(group)
    assert "unavailable" not in line.lower()
    assert "wayback" not in line.lower()
    assert "does not exist" in line
    users: list[str] = []

    def handler(request):
        users.append(request["user"])
        if "unknown lookups cited" in request["user"]:
            return _rank_ok()
        return _rank_ok(
            risk="The archive is unavailable so this bucket was abandoned."
        )

    findings = rank(
        [(ref, _cl(ref), _inv(ref, evidence))],
        client=FakeModelClient(handler),
        cache=LookupCache(tmp_path / "c.db"),
    )
    assert any("unknown lookups cited" in user for user in users)
    assert findings[0].needs_review is False
    assert "unavailable" not in findings[0].risk.lower()


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
    assert floor_severity(expiring) is None
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
    owner_ref = Reference(
        file=".github/workflows/ci.yml",
        line=11,
        raw="https://raw.githubusercontent.com/gone-user/tools/main/install.sh",
        host_or_bucket="github.com/gone-user",
    )
    owner_missing = {
        "target": "github.com/gone-user",
        "rows": [
            (
                owner_ref,
                _cl(owner_ref, type="script", runs_in="ci"),
                _inv(owner_ref, {}),
            )
        ],
        "evidence": {"github_owner": {"status": "missing", "exists": False}},
    }
    assert floor_severity(owner_missing) == "critical"
    action_ref = Reference(
        file=".github/workflows/actions.yml",
        line=9,
        raw="actions/trustmap-missing-repo@main",
        host_or_bucket="github.com/actions/trustmap-missing-repo",
        action_owner="actions",
        action_repo="trustmap-missing-repo",
        action_ref="main",
        action_sha_pinned=False,
    )
    repo_missing = {
        "target": "github.com/actions/trustmap-missing-repo",
        "rows": [
            (
                action_ref,
                _cl(action_ref, type="script", runs_in="ci"),
                _inv(action_ref, {}),
            )
        ],
        "evidence": {
            "github_owner": {"status": "exists", "exists": True},
            "github_repo": {"status": "missing", "exists": False},
        },
    }
    assert floor_severity(repo_missing) == "high"
    assert choose_fix(repo_missing["evidence"], "remove dead reference", "high", repo_missing["rows"]) == ACTION_MISSING_FIX
    pages = Reference(
        file="index.html",
        line=8,
        raw="https://gone.github.io/widget.js",
        host_or_bucket="gone.github.io",
        domain="gone.github.io",
    )
    vulnerable = {
        "target": "gone.github.io",
        "rows": [
            (pages, _cl(pages, type="script", runs_in="browser"), _inv(pages, {}))
        ],
        "evidence": {
            "platform_takeover": {
                "status": "unclaimed",
                "platform": "GitHub Pages",
                "takeover": "vulnerable",
                "signal": "There isn't a GitHub Pages site here",
            }
        },
    }
    assert floor_severity(vulnerable) == "critical"
    edge = {
        "target": "gone.herokuapp.com",
        "rows": [
            (pages, _cl(pages, type="script", runs_in="browser"), _inv(pages, {}))
        ],
        "evidence": {
            "platform_takeover": {
                "status": "unclaimed",
                "platform": "Heroku",
                "takeover": "edge case",
                "signal": "No such app",
            }
        },
    }
    level, reason = floor_decision(edge)
    assert level == "high"
    assert "edge case" in reason
    assert "Heroku" in reason
    docs = {
        "target": "missing",
        "rows": [(gone, _cl(gone, runs_in="docs_only"), _inv(gone, {}))],
        "evidence": {"bucket_probe": {"status": "NoSuchBucket"}},
    }
    # only named in docs: never Fix today, but always in Review (matches the
    # eval labels, which call a claimable docs-only target low)
    level, reason = floor_decision(docs)
    assert level == "low"
    assert "docs" in reason
    quiet = {**docs, "evidence": {"bucket_probe": {"status": "exists"}}}
    assert floor_severity(quiet) is None
    severity, note = apply_floor("medium", "critical")
    assert severity == "critical"
    assert note == "critical"


def test_website_compromised_and_sri_floors():
    poly = Reference(
        file="https://shop.example/index.html",
        line=7,
        raw="https://cdn.polyfill.io/v3/polyfill.min.js",
        host_or_bucket="cdn.polyfill.io",
        domain="polyfill.io",
        page_url="https://shop.example/index.html",
        tag="script",
        attribute="src",
        sri=False,
    )
    compromised = {
        "target": "cdn.polyfill.io",
        "rows": [
            (poly, _cl(poly, type="script", runs_in="browser"), _inv(poly, {}))
        ],
        "evidence": {"dns": {"status": "resolves"}, "rdap": {"status": "registered"}},
    }
    level, reason = floor_decision(compromised)
    assert level == "critical"
    assert "compromised" in reason
    associated_ref = poly.model_copy(
        update={"host_or_bucket": "bootcdn.net", "domain": "bootcdn.net", "sri": True}
    )
    associated = {
        "target": "bootcdn.net",
        "rows": [
            (
                associated_ref,
                _cl(associated_ref, type="script", runs_in="browser"),
                _inv(associated_ref, {}),
            )
        ],
        "evidence": {"dns": {"status": "resolves"}},
    }
    level, reason = floor_decision(associated)
    assert level == "high"
    assert "associated" in reason
    unreg = poly.model_copy(
        update={
            "host_or_bucket": "cdn-assets-trustmap-7f3k2.com",
            "domain": "cdn-assets-trustmap-7f3k2.com",
            "sri": True,
        }
    )
    claimable_sri = {
        "target": "cdn-assets-trustmap-7f3k2.com",
        "rows": [
            (unreg, _cl(unreg, type="script", runs_in="browser"), _inv(unreg, {}))
        ],
        "evidence": {
            "dns": {"status": "nxdomain"},
            "rdap": {"status": "unregistered"},
        },
    }
    assert floor_severity(claimable_sri) == "medium"
    assert choose_fix({}, "remove dead reference", "critical", compromised["rows"]) == POLYFILL_FIX
    third = poly.model_copy(
        update={"host_or_bucket": "cdn.example.com", "domain": "example.com", "sri": False}
    )
    assert (
        choose_fix({}, "remove dead reference", "critical", [
            (third, _cl(third, type="script", runs_in="browser"), _inv(third, {}))
        ])
        == SRI_FIX
    )


def test_claimable_static_asset_floor_is_high():
    images = Reference(
        file="src/config.js",
        line=3,
        raw="https://trustlinedemoassets.blob.core.windows.net/catalog",
        host_or_bucket="trustlinedemoassets",
        context='export const PRODUCT_IMAGES = "https://trustlinedemoassets.blob.core.windows.net/catalog"',
    )
    group = {
        "target": "trustlinedemoassets",
        "rows": [
            (
                images,
                _cl(images, type="asset", runs_in="browser"),
                _inv(images, {}),
            )
        ],
        "evidence": {"bucket_probe": {"status": "NoSuchBucket", "provider": "azure"}},
    }
    level, reason = floor_decision(group)
    assert level == "high"
    assert "static asset" in reason
    assert "at least high" in reason
    img = Reference(
        file="index.html",
        line=14,
        raw="https://cdn.example.net/logo.png",
        host_or_bucket="cdn.example.net",
        domain="example.net",
        tag="img",
        attribute="src",
    )
    unreg_img = {
        "target": "example.net",
        "rows": [(img, _cl(img, type="asset", runs_in="browser"), _inv(img, {}))],
        "evidence": {
            "dns": {"status": "nxdomain"},
            "rdap": {"status": "unregistered"},
        },
    }
    assert floor_severity(unreg_img) == "high"


def test_human_fix_maps_enums_to_sentences():
    assert human_fix("remove dead reference").endswith(".")
    assert " " in human_fix("remove dead reference")
    assert human_fix("remove dead reference") != "remove dead reference"
    assert choose_fix(
        {"dns": {"status": "nxdomain"}}, "remove dead reference", "high"
    ) == human_fix("remove dead reference")
    assert "no longer resolves" in human_fix("remove dead reference")


def test_evidence_line_keeps_spaces_in_runs_in_phrases():
    ref = Reference(
        file=".github/workflows/deploy.yml",
        line=11,
        raw="https://raw.githubusercontent.com/gone/tools/main/install.sh",
        host_or_bucket="github.com/gone",
    )
    group = {
        "target": "github.com/gone",
        "rows": [(ref, _cl(ref, type="script", runs_in="ci"), _inv(ref, {}))],
        "evidence": {"github_owner": {"status": "missing"}},
    }
    line = evidence_line(group)
    assert " in CI" in line
    assert "inCI" not in line
    table = format_table(
        [
            Finding(
                target="github.com/gone",
                kind="domain",
                references=[".github/workflows/deploy.yml:11"],
                severity="critical",
                model_severity="high",
                final_severity="critical",
                classified_blast_radius=2,
                ranked_blast_radius=3,
                risk="A stranger could take this over.",
                fix=CLAIMABLE_FIX,
                evidence_line=line,
            )
        ]
    )
    assert "inCI" not in table
    assert " in CI" in table
    assert "becausethe" not in table
    assert "loadsit" not in table
    assert "itis" not in table


def test_s3_path_style_groups_as_bucket_even_if_classified_ci():
    ref = Reference(
        file=".github/workflows/ci.yaml",
        line=31,
        raw="https://s3.amazonaws.com/quantopian-orchestration/packages/ta-lib-0.4.0-src.tar.gz",
        host_or_bucket="quantopian-orchestration",
        domain="amazonaws.com",
    )
    evidence = {
        "bucket_probe": {
            "status": "NoSuchBucket",
            "provider": "s3",
            "name": "quantopian-orchestration",
        }
    }
    groups = group_by_target(
        [(ref, _cl(ref, type="other", runs_in="ci"), _inv(ref, evidence))]
    )
    assert groups[0]["target"] == "quantopian-orchestration"
    assert groups[0]["kind"] == "bucket"
    assert floor_severity(groups[0]) == "critical"


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
    assert "override:" in table
    assert "Evidence:" in table


def test_no_override_line_when_blast_unchanged(tmp_path):
    ref = Reference(
        file="deploy/infra.yaml",
        line=4,
        raw="s3://live",
        host_or_bucket="live",
    )
    client = FakeModelClient(
        handler=lambda request: _rank_ok(
            severity="info",
            risk="Nobody else can take this bucket; it already exists at deploy/infra.yaml:4.",
            blast_radius=2,
            override="should not print because blast did not change",
        )
    )
    findings = rank(
        [
            (
                ref,
                _cl(ref, blast_radius=2),
                _inv(ref, {"bucket_probe": {"status": "exists", "http_status": 403}}),
            )
        ],
        client=client,
        cache=LookupCache(tmp_path / "c.db"),
    )
    assert findings[0].blast_override_reason == ""
    assert findings[0].fix == NO_ACTION_FIX
    assert "override:" not in format_table(findings)


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
                    risk="A stranger could create this missing bucket and serve files to deploy/infra.yaml.",
                    blast_radius=3,
                    override="claimable now",
                )
            evidence = payload.get("evidence") or {}
            repo = evidence.get("github_repo") or {}
            owner = evidence.get("github_owner") or {}
            if (
                str(repo.get("status", "")).lower() == "missing"
                and str(owner.get("status", "")).lower() != "missing"
            ):
                return _rank_ok(
                    severity="high",
                    risk="A stranger could recreate this GitHub action repo and run it in CI.",
                    blast_radius=3,
                    override="repo missing",
                )
            if str(owner.get("status", "")).lower() == "missing" or '"exists": false' in blob:
                return _rank_ok(
                    severity="critical",
                    risk="A stranger could register this GitHub account and ship install.sh into CI.",
                    blast_radius=3,
                    override="claimable now",
                )
            if "unclaimed" in blob and "GitHub Pages" in blob:
                return _rank_ok(
                    severity="medium",
                    risk="A stranger could publish GitHub Pages and run script from index.html:8 in the browser.",
                    blast_radius=3,
                    override="claimable now",
                )
            if "unregistered" in blob:
                return _rank_ok(
                    severity="critical",
                    risk="A stranger could register this domain and run script from index.html:7 in the browser.",
                    blast_radius=3,
                    override="claimable now",
                )
            return {
                "severity": "info",
                "risk": "Nobody else can take this bucket; it already exists at deploy/infra.yaml.",
                "fix": "self-host the asset",
                "uncertain_about": "",
                "blast_radius": 2,
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
    owner = "github.com/trustmap-missing-owner-a3f91c2e"
    pages = "trustmap-demo-pages.github.io"
    azure = "trustmapdemoassets"
    critical = {item.target for item in findings if item.severity == "critical"}
    assert {
        gone,
        "cdn-assets-trustmap-7f3k2.com",
        "trustmap-demo-assets",
        owner,
        pages,
        azure,
    } <= critical
    claimable = [
        item
        for item in findings
        if item.target in {gone, "cdn-assets-trustmap-7f3k2.com", "trustmap-demo-assets", owner, pages, azure}
    ]
    assert all(item.fix == CLAIMABLE_FIX for item in claimable)
    owner_hit = next(item for item in findings if item.target == owner)
    assert owner_hit.uncertain_about == GITHUB_OWNER_NOTE
    pages_hit = next(item for item in findings if item.target == pages)
    assert "GitHub Pages" in pages_hit.floor_reason
    assert "vulnerable" in pages_hit.floor_reason
    gone_hit = next(item for item in findings if item.target == gone)
    assert gone_hit.references == ["deploy/infra.yaml:3", "deploy/infra.yaml:5"]
    live_hit = next(item for item in findings if item.target == live)
    assert live_hit.severity in {"low", "info"}
    assert live_hit.fix == NO_ACTION_FIX
    table = format_table(findings)
    assert gone in table
    assert "critical" in table


def test_filtered_hosts_are_not_extracted_as_ranked_targets():
    refs = extract(str(FIXTURE_ROOT))
    assert any(ref.filter_reason == "reserved_tld" for ref in refs)


def test_rank_runs_targets_in_parallel_and_streams_each_one(tmp_path):
    # rank was a serial loop that emitted only after every target was done:
    # 79% of a real scan's wall time with nothing on screen
    import time
    from scanner.config import RANK_CONCURRENCY

    targets = 8
    rows = []
    for index in range(targets):
        ref = Reference(
            file="deploy/infra.yaml",
            line=index + 1,
            raw=f"s3://missing-bucket-{index}",
            host_or_bucket=f"missing-bucket-{index}",
        )
        rows.append(
            (
                ref,
                _cl(ref),
                _inv(ref, {"bucket_probe": {"status": "NoSuchBucket", "http_status": 404}}),
            )
        )

    delay = 0.2

    def slow(request):
        time.sleep(delay)
        return _rank_ok()

    seen: list[str] = []
    started = time.perf_counter()
    findings = rank(
        rows,
        client=FakeModelClient(handler=slow),
        cache=LookupCache(tmp_path / "rank.db"),
        on_event=lambda event: seen.append(event["type"]),
    )
    elapsed = time.perf_counter() - started

    assert len(findings) == targets
    assert seen == ["ranked"] * targets
    serial = delay * targets
    assert elapsed < serial / 2, f"{elapsed:.2f}s is not faster than serial {serial:.2f}s"
    assert RANK_CONCURRENCY > 1


def test_rank_returns_findings_sorted_whatever_order_they_finish(tmp_path):
    order = ["info", "critical", "low", "high"]
    rows = []
    for index, severity in enumerate(order):
        ref = Reference(
            file="deploy/infra.yaml",
            line=index + 1,
            raw=f"s3://bucket-{severity}",
            host_or_bucket=f"bucket-{severity}",
        )
        rows.append(
            (
                ref,
                _cl(ref),
                _inv(ref, {"bucket_probe": {"status": "exists", "http_status": 403}}),
            )
        )

    def by_target(request):
        for severity in order:
            if f"bucket-{severity}" in request["user"]:
                return _rank_ok(severity=severity, risk="Checked.", override="")
        return _rank_ok()

    findings = rank(
        rows,
        client=FakeModelClient(handler=by_target),
        cache=LookupCache(tmp_path / "sorted.db"),
    )
    severities = [item.severity for item in findings]
    from scanner.report import SEVERITY_ORDER

    assert severities == sorted(severities, key=lambda s: SEVERITY_ORDER[s])


@pytest.mark.asyncio
async def test_scan_never_asks_the_model_about_references_code_set_aside(tmp_path):
    refs = extract(str(FIXTURE_ROOT))
    dropped = {(ref.file, ref.line) for ref in refs if ref.filter_reason is not None}
    kept = {(ref.file, ref.line) for ref in refs if ref.filter_reason is None}
    assert dropped
    asked: set = set()
    inner = _fixture_handler()

    def handler(request):
        if request["schema_name"] == "classification_batch":
            payload = json.loads(request["user"].split("\n", 1)[1])
            asked.update((item["file"], item["line"]) for item in payload["references"])
        return inner(request)

    async def fake_bucket(name, provider, cache=None, **kwargs):
        return BucketProbeResult(name=name, provider=provider, status="exists", http_status=403)

    client = FakeModelClient(handler=handler, tool_handler=_scripted_client().tool_handler)
    await scan(
        str(FIXTURE_ROOT),
        client=client,
        cache=LookupCache(tmp_path / "s.db"),
        ctx=_ctx(tmp_path, bucket_probe=fake_bucket),
    )
    assert asked == kept
    assert not asked & dropped


def test_rank_past_its_deadline_keeps_code_severity_without_a_model_call(tmp_path):
    import time

    from scanner.report import RANK_TIME_NOTE

    ref = Reference(file="deploy/infra.yaml", line=3, raw="s3://missing", host_or_bucket="missing")
    rows = [(ref, _cl(ref), _inv(ref, {"bucket_probe": {"status": "NoSuchBucket", "http_status": 404}}))]
    client = FakeModelClient(handler=lambda request: pytest.fail("rank called the model"))
    found = rank(rows, client=client, cache=LookupCache(tmp_path / "d.db"), deadline=time.monotonic() - 1)
    assert found[0].severity == "critical"
    assert found[0].risk == RANK_TIME_NOTE
    assert found[0].needs_review is False
    assert client.calls == []


def test_rules_cover_what_only_the_model_used_to_catch():
    # Fix today needs a code rule now, so every pattern the model alone used to
    # rank high has a rule of its own.
    ci = Reference(
        file=".github/workflows/build.yml",
        line=12,
        raw="curl -s https://cdn.polyfill.io/install.sh | sh",
        host_or_bucket="cdn.polyfill.io",
        domain="polyfill.io",
    )
    fetched = {
        "target": "polyfill.io",
        "rows": [(ci, _cl(ci, type="script", runs_in="ci"), _inv(ci, {}))],
        "evidence": {"dns": {"status": "resolves"}, "rdap": {"status": "registered"}},
    }
    level, reason = floor_decision(fetched)
    assert level == "high" and "compromised" in reason
    api = ci.model_copy(update={"host_or_bucket": "api.bootcdn.net", "domain": "bootcdn.net"})
    called = {
        "target": "bootcdn.net",
        "rows": [(api, _cl(api, type="api", runs_in="server"), _inv(api, {}))],
        "evidence": {"dns": {"status": "resolves"}},
    }
    level, reason = floor_decision(called)
    assert level == "medium" and "associated" in reason
    doc = Reference(
        file="README.md",
        line=3,
        raw="https://old-demo.example.net/",
        host_or_bucket="old-demo.example.net",
        domain="example.net",
    )
    sold = {
        "target": "example.net",
        "rows": [(doc, _cl(doc, type="docs_link", runs_in="docs_only"), _inv(doc, {}))],
        "evidence": {"dns": {"status": "resolves"}, "live_fetch": {"status": "ok", "for_sale": True}},
    }
    level, reason = floor_decision(sold)
    assert level == "low" and "for sale" in reason


def test_a_disabled_action_repo_is_review_with_its_own_fix():
    action = Reference(
        file=".github/workflows/preview-deploy.yml",
        line=38,
        raw="actions-cool/maintain-one-comment@v1.2.1",
        host_or_bucket="github.com/actions-cool/maintain-one-comment",
        action_owner="actions-cool",
        action_repo="maintain-one-comment",
        action_ref="v1.2.1",
        action_sha_pinned=False,
    )
    group = {
        "target": "github.com/actions-cool/maintain-one-comment",
        "rows": [(action, _cl(action, type="script", runs_in="ci"), _inv(action, {}))],
        "evidence": {
            "github_owner": {"status": "exists", "exists": True},
            "github_repo": {"status": "disabled", "exists": True},
        },
    }
    level, reason = floor_decision(group)
    assert level == "medium" and "disabled" in reason
    fix = choose_fix(group["evidence"], "remove dead reference", "medium", group["rows"])
    assert "disabled" in fix and "commit SHA" in fix
    assert "GitHub repo disabled" in evidence_line(group)
