"""Scanning the same repo twice must put the same targets in Fix today.

The model is free to word its explanation differently, to wander between tools
and to disagree with itself about severity; none of that may move a target in
or out of Fix today. Only code facts (lookups, compromised list, where a
reference runs) do that.
"""

import json
import random
from pathlib import Path

import pytest

from scanner.llm import FakeModelClient
from scanner.lookups import LookupCache, merge_evidence
from scanner.models import BucketProbeResult
from scanner.report import FIX_TODAY, scan, settle_severity
from tests.test_agent import _ctx

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "demo_repo"
EXPECTED_PATH = Path(__file__).parent / "fixtures" / "expected.json"
LEVELS = ["critical", "high", "medium", "low", "info"]


def _jittery_client(seed: int) -> FakeModelClient:
    """Fixed labels, but a ranker and an agent that change their minds."""
    rng = random.Random(seed)
    expected = {
        (row["file"], row["line"]): row
        for row in json.loads(EXPECTED_PATH.read_text())["references"]
    }

    def handler(request):
        if request.get("schema_name") == "ranking":
            return {
                "severity": rng.choice(LEVELS),
                "risk": "A stranger who takes this over could serve their own content here.",
                "fix": "remove dead reference",
                "uncertain_about": "",
                "blast_radius": rng.randint(0, 3),
                "blast_override_reason": "jitter",
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

    def tool_handler(request):
        names = [tool["function"]["name"] for tool in request["tools"]]
        name = rng.choice(names)
        if name == "done":
            return {"name": "done", "arguments": {"summary": "checked"}}
        first = json.loads(request["messages"][0]["content"])["reference"]
        target = first["domain"] or first["host_or_bucket"]
        args = {
            "wayback": {"url": first["raw"]},
            "cert_history": {"domain": target},
            "live_fetch": {"url": f"https://{first['host_or_bucket']}/"},
        }.get(name, {"host": first["host_or_bucket"]})
        return {"name": name, "arguments": args}

    return FakeModelClient(handler=handler, tool_handler=tool_handler)


async def _fix_today(tmp_path: Path, seed: int) -> set[str]:
    async def fake_bucket(name, provider, cache=None, **kwargs):
        missing = "acme-static-assets" not in name
        return BucketProbeResult(
            name=name,
            provider=provider,
            status="NoSuchBucket" if missing else "exists",
            http_status=404 if missing else 403,
        )

    # a fresh cache each run, so no answer is replayed from an earlier one
    run_dir = tmp_path / f"run{seed}"
    run_dir.mkdir()
    findings = await scan(
        str(FIXTURE_ROOT),
        client=_jittery_client(seed),
        cache=LookupCache(run_dir / "c.db"),
        ctx=_ctx(run_dir, bucket_probe=fake_bucket),
    )
    today = {item.target for item in findings if item.severity in FIX_TODAY}
    # every Fix today item names the code rule that put it there
    assert all(item.floor_reason for item in findings if item.severity in FIX_TODAY)
    return today


@pytest.mark.asyncio
async def test_same_repo_same_fix_today_whatever_the_model_says(tmp_path):
    runs = [await _fix_today(tmp_path, seed) for seed in range(6)]
    assert runs[0], "the fixture has targets that must be fixed today"
    assert all(run == runs[0] for run in runs)


def test_fix_today_needs_a_code_rule():
    # the model's word alone stops at Review
    final, raised, note = settle_severity("critical", None)
    assert final == "medium" and raised == "" and "no code rule" in note
    assert settle_severity("high", "low")[0] == "medium"
    # a rule at high or above puts it in Fix today; the model may still say critical
    assert settle_severity("info", "high")[:2] == ("high", "high")
    assert settle_severity("critical", "high") == ("critical", "", "")
    assert settle_severity("critical", "critical") == ("critical", "", "")
    # below high the model still decides between Review and Safe
    assert settle_severity("medium", "low") == ("medium", "", "")
    assert settle_severity("info", "low")[:2] == ("low", "low")
    assert settle_severity("info", None) == ("info", "", "")


def test_merge_keeps_the_riskiest_answer_for_a_target():
    gone = {"dns": {"status": "nxdomain", "host": "old.acme.dev"}}
    fine = {"dns": {"status": "resolves", "host": "www.acme.dev"}}
    # read order no longer decides whether the dead host is seen
    assert merge_evidence([gone, fine])["dns"]["status"] == "nxdomain"
    assert merge_evidence([fine, gone])["dns"]["status"] == "nxdomain"
    # a known answer replaces no answer
    timeout = {"dns": {"status": "timeout", "host": "www.acme.dev"}}
    assert merge_evidence([fine, timeout])["dns"]["status"] == "resolves"
    # between equal answers the later one wins, as before
    other = {"dns": {"status": "resolves", "host": "cdn.acme.dev"}}
    assert merge_evidence([fine, other])["dns"]["host"] == "cdn.acme.dev"
