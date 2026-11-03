import time

import pytest

from scanner.classify import classify
from scanner.deadline import ScanClock
from scanner.llm import FakeModelClient, call_json
from scanner.lookups import LookupCache
from scanner.models import ClassificationBatch, Reference
from scanner.report import rank
from tests.test_report import _cl, _inv, _rank_ok


def test_hung_model_call_cannot_exceed_deadline(tmp_path):
    def hang(request):
        time.sleep(5)
        return {"items": []}

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        call_json(
            "muse-spark-1.3",
            "sys",
            "user",
            ClassificationBatch,
            "low",
            client=FakeModelClient(hang),
            json_schema={"type": "object"},
            schema_name="classification_batch",
            cache=LookupCache(tmp_path / "c.db"),
            timeout_s=0.2,
        )
    assert time.monotonic() - started < 1.5


def test_partial_scan_reports_skipped_targets(tmp_path):
    refs = [
        Reference(
            file="a.py",
            line=1,
            raw="https://alpha.vendor.example.net/v1",
            host_or_bucket="alpha.vendor.example.net",
            domain="vendor.example.net",
        ),
        Reference(
            file="b.py",
            line=1,
            raw="https://beta.vendor.example.net/v1",
            host_or_bucket="beta.vendor.example.net",
            domain="vendor.example.net",
        ),
    ]
    skipped: list[str] = []
    clock = ScanClock(
        total_s=0.0,
        classify_s=0.0,
        agent_s=0.0,
        rank_s=0.0,
        request_cap_s=0.1,
    )
    got = classify(
        refs,
        client=FakeModelClient(handler=lambda request: (_ for _ in ()).throw(RuntimeError("no model"))),
        include_filtered=True,
        cache=LookupCache(tmp_path / "c.db"),
        clock=clock,
        skipped=skipped,
    )
    assert len(got) == 2
    assert got[0].reason == "not classified (deadline)"
    assert "alpha.vendor.example.net" in skipped
    assert "beta.vendor.example.net" in skipped

    gone_ref = Reference(
        file="deploy/infra.yaml",
        line=3,
        raw="s3://missing-deadline",
        host_or_bucket="missing-deadline",
    )
    live_ref = refs[1]
    rows = [
        (
            gone_ref,
            _cl(gone_ref, type="bucket", runs_in="deploy", blast_radius=3),
            _inv(
                gone_ref,
                {
                    "bucket_probe": {
                        "status": "NoSuchBucket",
                        "http_status": 404,
                        "provider": "s3",
                    }
                },
            ),
        ),
        (
            live_ref,
            _cl(live_ref, type="api", runs_in="server", blast_radius=2),
            _inv(
                live_ref,
                {"dns": {"status": "resolves"}, "rdap": {"status": "registered"}},
            ),
        ),
    ]
    rank_skipped: list[str] = []
    findings = rank(
        rows,
        client=FakeModelClient(
            handler=lambda request: (_ for _ in ()).throw(RuntimeError("no rank"))
        ),
        cache=LookupCache(tmp_path / "r.db"),
        clock=ScanClock(total_s=0.0, rank_s=0.0, request_cap_s=0.1),
        skipped=rank_skipped,
    )
    assert {item.target for item in findings} == {
        "missing-deadline",
        "vendor.example.net",
    }
    assert "vendor.example.net" in rank_skipped
    assert "missing-deadline" not in rank_skipped
    gone = next(item for item in findings if item.target == "missing-deadline")
    assert gone.severity == "critical"
    assert gone.floor_applied == "critical"
    assert "NoSuchBucket" in gone.floor_reason
    assert gone.cost_usd == 0


def test_unused_stage_time_flows_forward():
    clock = ScanClock(
        total_s=40.0,
        report_reserve_s=10.0,
        agent_reserve_s=8.0,
        rank_reserve_s=12.0,
        request_cap_s=20.0,
    )
    clock.begin_stage("classify")
    assert clock.stage_limit == pytest.approx(10.0, abs=0.2)
    clock.begin_stage("agent")
    assert clock.stage_limit == pytest.approx(18.0, abs=0.2)
    clock.begin_stage("rank")
    assert clock.stage_limit == pytest.approx(30.0, abs=0.2)
    assert clock.request_timeout() == pytest.approx(20.0, abs=0.2)


def test_claimable_floor_keeps_severity_when_model_writes(tmp_path):
    ref = Reference(
        file="deploy/infra.yaml",
        line=3,
        raw="s3://missing",
        host_or_bucket="missing",
    )
    client = FakeModelClient(
        handler=lambda request: _rank_ok(
            severity="low",
            risk="Anyone can create this bucket and inherit deploy/infra.yaml:3.",
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
    assert client.calls
    assert findings[0].severity == "critical"
    assert findings[0].model_severity == "low"
    assert findings[0].floor_applied == "critical"
    assert "NoSuchBucket" in findings[0].floor_reason
    assert "Anyone can create this bucket" in findings[0].risk
