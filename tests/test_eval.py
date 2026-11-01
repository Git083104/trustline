import asyncio
import json
from io import StringIO
from pathlib import Path

import pytest

from eval.label import (
    auto_severity,
    format_target,
    gather_groups,
    is_docs_test_path,
    label_source,
    load_labeled_keys,
    load_repos,
    select_groups,
    three_line_context,
)
from eval.run_eval import (
    apply_revised_rubric,
    baseline_original,
    baseline_severity,
    debug_gold,
    evaluate,
    flag_stats,
    is_expiry_only,
    precision_at_10,
    run,
)
from scanner.config import EVAL_SCAN_COST_CAP_USD
from scanner.lookups import LookupCache
from scanner.models import BucketProbeResult, DnsResult, Finding, Reference
from scanner.report import ScanOutcome, evidence_line
from tests.test_agent import _ctx

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "demo_repo"


def _group(target: str, hard: bool) -> dict:
    ref = Reference(
        file="a.py",
        line=1,
        raw=f"https://{target}/x",
        host_or_bucket=target,
        domain=target,
    )
    evidence = (
        {"dns": {"status": "nxdomain"}, "rdap": {"status": "unregistered"}}
        if hard
        else {"dns": {"status": "resolves"}, "rdap": {"status": "registered", "days_to_expiry": 400}}
    )
    return {
        "target": target,
        "kind": "domain",
        "rows": [(ref, None, None)],
        "evidence": evidence,
    }


def test_repos_txt_lists_ten_github_urls():
    urls = load_repos()
    assert len(urls) == 10
    assert urls[0] == "https://github.com/quantopian/zipline"
    assert urls[-1] == "https://github.com/psf/requests"


def _auto_group(file: str, evidence: dict, *, kind: str = "domain", target: str = "x.example") -> dict:
    ref = Reference(
        file=file,
        line=1,
        raw=f"https://{target}/x" if kind == "domain" else f"s3://{target}",
        host_or_bucket=target,
        domain=target if kind == "domain" else "",
    )
    return {
        "target": target,
        "kind": kind,
        "rows": [(ref, None, None)],
        "evidence": evidence,
    }


def test_auto_info_when_healthy_even_if_expiring():
    exists = _auto_group(
        "src/app.py",
        {"bucket_probe": {"status": "exists"}},
        kind="bucket",
        target="live-bucket",
    )
    assert auto_severity(exists) == "info"
    registered = _auto_group(
        "src/app.py",
        {
            "dns": {"status": "resolves"},
            "rdap": {"status": "registered", "days_to_expiry": 12},
        },
    )
    assert auto_severity(registered) == "info"
    unknown = _auto_group(
        "backend/settings.py",
        {"dns": {"status": "resolves"}, "rdap": {"status": "unknown"}},
    )
    assert auto_severity(unknown) == "info"


def test_auto_docs_and_tests_low_if_claimable_else_info():
    assert is_docs_test_path("README.md")
    assert is_docs_test_path("docs/guide.html")
    assert is_docs_test_path("doc/index.html")
    assert is_docs_test_path("CHANGELOG")
    assert is_docs_test_path("LICENSE.txt")
    assert is_docs_test_path("tests/test_client.py")
    assert is_docs_test_path("pkg/foo_test.py")
    assert not is_docs_test_path("src/app.py")
    claimable = _auto_group(
        "README.md",
        {"bucket_probe": {"status": "NoSuchBucket"}},
        kind="bucket",
        target="gone-bucket",
    )
    assert auto_severity(claimable) == "low"
    nx = _auto_group(
        "tests/test_client.py",
        {"dns": {"status": "nxdomain"}, "rdap": {"status": "registered"}},
    )
    assert auto_severity(nx) == "low"
    healthy_docs = _auto_group(
        "docs/overview.rst",
        {"dns": {"status": "resolves"}, "rdap": {"status": "registered"}},
    )
    assert auto_severity(healthy_docs) == "info"
    runtime_claimable = _auto_group(
        "deploy/infra.yaml",
        {"bucket_probe": {"status": "NoSuchBucket"}},
        kind="bucket",
        target="gone-bucket",
    )
    assert auto_severity(runtime_claimable) is None
    runtime_nx = _auto_group(
        "index.html",
        {"dns": {"status": "nxdomain"}, "rdap": {"status": "unregistered"}},
    )
    assert auto_severity(runtime_nx) is None


def test_evidence_line_records_dns_timeout():
    line = evidence_line(
        {
            "target": "slow.example",
            "rows": [],
            "evidence": {"dns": {"status": "timeout", "host": "slow.example"}},
        }
    )
    assert "DNS unknown (timeout)" in line


@pytest.mark.asyncio
async def test_gather_groups_progress_and_concurrency(tmp_path):
    inflight = {"n": 0, "peak": 0}

    async def fake_dns(host, cache=None, **kwargs):
        inflight["n"] += 1
        inflight["peak"] = max(inflight["peak"], inflight["n"])
        await asyncio.sleep(0.02)
        inflight["n"] -= 1
        return DnsResult(host=host, status="resolves", addresses=["203.0.113.9"])

    refs = [
        Reference(
            file="a.py",
            line=i,
            raw=f"https://h{i}.example/x",
            host_or_bucket=f"h{i}.example",
            domain=f"h{i}.example",
        )
        for i in range(1, 16)
    ]
    buf = StringIO()
    groups = await gather_groups(
        refs,
        _ctx(tmp_path, dns=fake_dns),
        progress=lambda done, total: print(f"checking {done} of {total}", file=buf),
        concurrency=10,
    )
    text = buf.getvalue()
    assert "checking 1 of 15" in text
    assert "checking 15 of 15" in text
    assert inflight["peak"] <= 10
    assert inflight["peak"] >= 2
    assert len(groups) == 15


def test_select_groups_hard_first_then_seeded_sample():
    hard = [_group(f"hard{i}.com", True) for i in range(5)]
    rest = [_group(f"rest{i}.com", False) for i in range(30)]
    chosen = select_groups(hard + rest, cap=25, seed=42)
    assert len(chosen) == 25
    assert [g["target"] for g in chosen[:5]] == [f"hard{i}.com" for i in range(5)]
    again = select_groups(hard + rest, cap=25, seed=42)
    assert [g["target"] for g in chosen] == [g["target"] for g in again]


def test_three_line_context_is_adjacent_lines():
    ref = Reference(
        file="deploy/infra.yaml",
        line=3,
        raw="s3://acme-legacy-uploads-a3f91c2e",
        host_or_bucket="acme-legacy-uploads-a3f91c2e",
    )
    text = three_line_context(FIXTURE_ROOT, ref)
    assert "2\t" in text
    assert "3\t" in text
    assert "4\t" in text
    assert "7\t" not in text


@pytest.mark.asyncio
async def test_label_resume_and_display(tmp_path):
    labels = tmp_path / "labels.jsonl"
    answers = iter(["c", "first", "s", "", "l", "ok", "i", ""])

    def input_fn(prompt):
        return next(answers)

    buf = StringIO()
    written = await label_source(
        str(FIXTURE_ROOT),
        cache=LookupCache(tmp_path / "c.db"),
        labels_path=labels,
        ctx=_ctx(tmp_path),
        input_fn=input_fn,
        output=buf,
    )
    assert written >= 1
    display = buf.getvalue()
    assert "target:" in display
    assert "Evidence:" in display
    assert "target " in display and " of " in display
    assert "blast_radius" not in display
    assert "runs_in" not in display
    rows = [json.loads(line) for line in labels.read_text().splitlines()]
    assert rows[0]["severity"] == "critical"
    more = await label_source(
        str(FIXTURE_ROOT),
        cache=LookupCache(tmp_path / "c.db"),
        labels_path=labels,
        ctx=_ctx(tmp_path),
        input_fn=lambda prompt: (_ for _ in ()).throw(AssertionError("resume asked again")),
        output=StringIO(),
    )
    assert more == 0
    assert load_labeled_keys(labels) == {
        (str(FIXTURE_ROOT), row["target"]) for row in rows
    }


def test_format_target_has_no_model_fields():
    from scanner.extract import extract

    refs = [
        ref
        for ref in extract(str(FIXTURE_ROOT))
        if ref.file == "index.html" and ref.line == 7
    ]
    assert refs
    group = {
        "target": refs[0].domain,
        "kind": "domain",
        "rows": [(refs[0], None, None)],
        "evidence": {
            "dns": {"status": "nxdomain"},
            "rdap": {"status": "unregistered"},
        },
    }
    text = format_target(group, FIXTURE_ROOT)
    assert "cdn-assets-trustmap-7f3k2.com" in text
    assert "type=" not in text
    assert "blast" not in text
    assert "critical" not in text
    assert "referenced at index.html:7" in text


def test_baseline_severity_rules():
    assert (
        baseline_severity({"bucket_probe": {"status": "NoSuchBucket"}}) == "critical"
    )
    assert (
        baseline_severity({"rdap": {"status": "unregistered"}, "dns": {"status": "nxdomain"}})
        == "critical"
    )
    assert baseline_severity({"dns": {"status": "nxdomain"}}) == "high"
    assert (
        baseline_severity({"rdap": {"status": "registered", "days_to_expiry": 12}})
        == "low"
    )
    assert (
        baseline_original(
            {
                "dns": {"status": "resolves"},
                "rdap": {"status": "registered", "days_to_expiry": 12},
            }
        )
        == "high"
    )


def test_revised_rubric_maps_expiry_only_to_info():
    expiry = {
        "dns": {"status": "resolves"},
        "rdap": {"status": "registered", "days_to_expiry": 80},
    }
    abandoned = {
        "dns": {"status": "nxdomain"},
        "rdap": {"status": "registered", "days_to_expiry": 70},
    }
    assert is_expiry_only(expiry)
    assert not is_expiry_only(abandoned)
    labels = [
        {
            "repo": "https://github.com/quantopian/zipline",
            "target": "quandl.com",
            "severity": "high",
            "evidence": expiry,
        },
        {
            "repo": "https://github.com/lbryio/lbry-desktop",
            "target": "lbry.tech",
            "severity": "high",
            "evidence": abandoned,
        },
    ]
    mapped, changes = apply_revised_rubric(labels)
    assert mapped[0]["severity"] == "info"
    assert mapped[1]["severity"] == "high"
    assert labels[0]["severity"] == "high"
    assert changes == [
        {
            "repo": "https://github.com/quantopian/zipline",
            "target": "quandl.com",
            "from": "high",
            "to": "info",
            "days_to_expiry": 80,
        }
    ]
    text = evaluate(labels, {}, 0.0, [], rubric="revised")
    assert "`quandl.com`: high → info" in text
    assert "## Original rubric" in text
    assert "## Revised rubric" in text
    assert "baseline (original)" in text
    assert "baseline (revised)" in text
    assert (
        baseline_severity({"bucket_probe": {"status": "exists"}, "dns": {"status": "resolves"}})
        == "low"
    )


def _finding(target: str, severity: str) -> Finding:
    return Finding(
        target=target,
        kind="domain",
        references=["a.py:1"],
        severity=severity,
        model_severity=severity,
        final_severity=severity,
        classified_blast_radius=1,
        ranked_blast_radius=1,
        risk="x",
        fix="No action needed",
    )


@pytest.mark.asyncio
async def test_run_eval_labeled_only_metrics(tmp_path):
    labels_path = tmp_path / "labels.jsonl"
    labels = [
        {
            "repo": "repo-a",
            "target": "gone.example",
            "severity": "critical",
            "evidence": {"bucket_probe": {"status": "NoSuchBucket"}},
        },
        {
            "repo": "repo-a",
            "target": "nx.example",
            "severity": "high",
            "evidence": {"dns": {"status": "nxdomain"}},
        },
        {
            "repo": "repo-a",
            "target": "ok.example",
            "severity": "low",
            "evidence": {"bucket_probe": {"status": "exists"}},
        },
    ]
    labels_path.write_text("".join(json.dumps(row) + "\n" for row in labels))

    async def fake_scan(source, **kwargs):
        assert kwargs["hydrate_only"] is True
        assert kwargs["cost_cap"] == EVAL_SCAN_COST_CAP_USD
        return ScanOutcome(
            findings=[
                _finding("gone.example", "critical"),
                _finding("nx.example", "low"),
                _finding("ok.example", "info"),
                _finding("unlabeled.example", "critical"),
            ],
            classify_cost_usd=0.01,
            agent_cost_usd=0.02,
            rank_cost_usd=0.03,
            budget_targets=["paused.example"],
        )

    results_path = tmp_path / "results.md"
    text = await run(
        labels_path=labels_path,
        results_path=results_path,
        cache=LookupCache(tmp_path / "c.db"),
        client=object(),
        scan_fn=fake_scan,
    )
    assert "| baseline (original) |" in text
    assert "| baseline (revised) |" in text
    assert "| trustmap |" in text
    assert "0.06000000" in text
    assert "paused.example: not investigated (budget)" in text
    assert results_path.read_text() == text
    p = precision_at_10(
        labels,
        {"gone.example": "critical", "nx.example": "low", "ok.example": "info"},
    )
    assert p == pytest.approx(2 / 3)


def test_evaluate_precision_ignores_unlabeled():
    labels = [
        {
            "repo": "r",
            "target": "a",
            "severity": "critical",
            "evidence": {"bucket_probe": {"status": "NoSuchBucket"}},
        },
        {
            "repo": "r",
            "target": "b",
            "severity": "low",
            "evidence": {"bucket_probe": {"status": "exists"}},
        },
    ]
    outcome = ScanOutcome(
        findings=[
            _finding("a", "critical"),
            _finding("b", "low"),
            _finding("unlabeled-critical", "critical"),
        ]
    )
    text = evaluate(labels, {"r": outcome}, 0.0, [])
    assert "unlabeled-critical" not in text.split("Budget")[0]
    # top 2 labeled: a critical, b low → 1/2 gold in top 2
    assert "### All labels" in text
    assert "### Human-labeled only" in text
    assert "| trustmap | 0.500 |" in text
    assert "flag_precision" in text
    assert "NO MATCH" not in text
    stats = flag_stats(
        labels,
        {("r", "a"): "critical", ("r", "b"): "low"},
    )
    assert stats["flagged"] == 1
    assert stats["true_pos"] == 1
    assert stats["false_alarms"] == 0


def test_debug_gold_missed_critical_shows_no_match():
    labels = [
        {
            "repo": "r",
            "target": "quantopian-orchestration",
            "severity": "critical",
            "evidence": {"bucket_probe": {"status": "NoSuchBucket"}},
        }
    ]
    miss = ScanOutcome(findings=[_finding("amazonaws.com", "info")])
    text = debug_gold(labels, {"r": miss})
    assert "quantopian-orchestration" in text
    assert "NO MATCH" in text
    assert "amazonaws.com" in text
    hit = ScanOutcome(
        findings=[
            Finding(
                target="quantopian-orchestration",
                kind="bucket",
                references=[".github/workflows/ci.yaml:31"],
                severity="critical",
                model_severity="low",
                final_severity="critical",
                classified_blast_radius=1,
                ranked_blast_radius=1,
                risk="x",
                fix="No action needed",
                floor_reason="NoSuchBucket in executing position (ci) is at least critical",
                evidence={"bucket_probe": {"status": "NoSuchBucket"}},
            )
        ]
    )
    found = debug_gold(labels, {"r": hit})
    assert "NO MATCH" not in found
    assert "final_severity=critical" in found
    assert "model_severity=low" in found


def test_evaluate_reports_human_only_separately():
    labels = [
        {
            "repo": "r",
            "target": "a",
            "severity": "critical",
            "source": "human",
            "evidence": {"bucket_probe": {"status": "NoSuchBucket"}},
        },
        {
            "repo": "r",
            "target": "b",
            "severity": "info",
            "source": "auto",
            "evidence": {"bucket_probe": {"status": "exists"}},
        },
    ]
    outcome = ScanOutcome(
        findings=[_finding("a", "critical"), _finding("b", "info")]
    )
    text = evaluate(labels, {"r": outcome}, 0.01, [])
    all_sec, human_sec = text.split("## Human-labeled only", 1)
    assert "| trustmap | 0.500 |" in all_sec
    assert "| trustmap | 1.000 |" in human_sec


@pytest.mark.asyncio
async def test_label_auto_keeps_human_and_summarizes(tmp_path):
    labels = tmp_path / "labels.jsonl"
    source = str(FIXTURE_ROOT)
    append_existing = {
        "repo": source,
        "target": "keep-me.example",
        "severity": "high",
        "source": "human",
        "evidence": {},
    }
    labels.write_text(json.dumps(append_existing) + "\n")

    async def fake_bucket(name, provider, cache=None, **kwargs):
        missing = "acme-static-assets" not in name
        return BucketProbeResult(
            name=name,
            provider=provider,
            status="NoSuchBucket" if missing else "exists",
            http_status=404 if missing else 403,
        )

    answers = iter(["c", "note", "c", "", "c", "", "c", "", "c", ""])
    buf = StringIO()
    await label_source(
        source,
        cache=LookupCache(tmp_path / "c.db"),
        labels_path=labels,
        ctx=_ctx(tmp_path, bucket_probe=fake_bucket),
        input_fn=lambda prompt: next(answers),
        output=buf,
        auto=True,
    )
    rows = [json.loads(line) for line in labels.read_text().splitlines()]
    by_target = {row["target"]: row for row in rows}
    assert by_target["keep-me.example"]["source"] == "human"
    assert by_target["keep-me.example"]["severity"] == "high"
    live = by_target["acme-static-assets-a3f91c2e"]
    assert live["source"] == "auto"
    assert live["severity"] == "info"
    gone = by_target["acme-legacy-uploads-a3f91c2e"]
    assert gone["source"] == "human"
    summary = buf.getvalue()
    assert "auto-labeled" in summary
    assert "left for you" in summary
