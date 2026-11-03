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
from scanner.report import FIX_TODAY, apply_floor, scan
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
        first = json.loads(request["messages"][0]["content"])["reference"]
        turns = sum(1 for msg in request["messages"] if msg["role"] == "assistant")
        if turns:
            return {"name": "done", "arguments": {"summary": "checked"}}
        return {"name": "dns", "arguments": {"host": first["host_or_bucket"]}}

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
    today = {
        item.target
        for item in findings
        if item.severity in FIX_TODAY and item.floor_reason
    }
    return today


@pytest.mark.asyncio
async def test_same_repo_same_fix_today_whatever_the_model_says(tmp_path):
    today = await _fix_today(tmp_path, seed=0)
    assert today, "the fixture has targets that must be fixed today"


def test_fix_today_uses_code_floors():
    assert apply_floor("info", "high") == ("high", "high")
    assert apply_floor("critical", "high") == ("critical", "")
    assert apply_floor("info", None) == ("info", "")


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
