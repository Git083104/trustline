import json
from io import StringIO
from pathlib import Path

import pytest

from eval.label import (
    format_target,
    gather_groups,
    label_source,
    load_labeled_keys,
    load_repos,
    select_groups,
    three_line_context,
)
from eval.run_eval import (
    baseline_severity,
    evaluate,
    precision_at_10,
    run,
)
from scanner.config import EVAL_SCAN_COST_CAP_USD
from scanner.lookups import LookupCache
from scanner.models import Finding, Reference
from scanner.report import ScanOutcome
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
        == "high"
    )
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
        assert kwargs["hydrate_only"] is False
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
    assert "| baseline |" in text
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
    assert "| trustmap | 0.500 |" in text
