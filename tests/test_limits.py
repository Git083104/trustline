import asyncio
import threading

import pytest
from fastapi.testclient import TestClient

from api.limits import (
    BUSY_MSG,
    DAILY_LIMIT_MSG,
    HOURLY_LIMIT_MSG,
    LimitsStore,
    client_ip,
)
from api.main import create_app
from scanner.llm import FakeModelClient
from scanner.lookups import LookupCache
from scanner.report import ScanOutcome


@pytest.fixture(autouse=True)
def local_paths_allowed(monkeypatch):
    # these tests post a temp dir as the cheapest valid target; path policy is
    # covered in test_api.py
    monkeypatch.setenv("TRUSTMAP_ALLOW_LOCAL_SCAN", "1")


class _Req:
    def __init__(self, host: str, forwarded: str | None = None) -> None:
        self.client = type("C", (), {"host": host})()
        self.headers = {}
        if forwarded is not None:
            self.headers["x-forwarded-for"] = forwarded


def test_client_ip_ignores_xff_when_hops_zero():
    req = _Req("10.0.0.8", "203.0.113.9, 198.51.100.1")
    assert client_ip(req, hops=0) == "10.0.0.8"


def test_client_ip_uses_rightmost_minus_hops():
    req = _Req("10.0.0.8", "spoofed, 203.0.113.9")
    assert client_ip(req, hops=1) == "203.0.113.9"
    assert client_ip(req, hops=2) == "spoofed"


def test_daily_and_hourly_store(tmp_path):
    clock = {"t": 1_700_000_000.0}

    def now():
        return clock["t"]

    store = LimitsStore(
        tmp_path / "limits.db",
        daily_cap=10,
        ip_per_hour=5,
        max_concurrent=10,
        scan_reserve=1,
        now=now,
    )
    assert store.check("1.1.1.1") is None
    store.add_spend(10)
    assert store.spent_today() == 10
    assert store.check("1.1.1.1") == DAILY_LIMIT_MSG
    store.add_spend(0.5)
    assert store.spent_today() == 10.5

    other = LimitsStore(
        tmp_path / "hourly.db",
        daily_cap=10,
        ip_per_hour=2,
        max_concurrent=10,
        now=now,
    )
    assert other.check("9.9.9.9") is None
    other.record_start("9.9.9.9")
    other.record_start("9.9.9.9")
    assert other.check("9.9.9.9") == HOURLY_LIMIT_MSG
    assert other.check("8.8.8.8") is None
    clock["t"] += 3601
    assert other.check("9.9.9.9") is None


def test_daily_cap_429_demo_still_works(tmp_path):
    limits = LimitsStore(
        tmp_path / "cap.db", daily_cap=1, ip_per_hour=50, scan_reserve=1
    )
    limits.add_spend(1)

    async def runner(*args, **kwargs):
        return ScanOutcome(findings=[])

    app = create_app(
        model_client=FakeModelClient(handler=lambda r: {}),
        cache=LookupCache(tmp_path / "c.db"),
        runner=runner,
        limits=limits,
    )
    with TestClient(app) as client:
        blocked = client.post("/api/scan", json={"target": str(tmp_path)})
        assert blocked.status_code == 429
        assert blocked.json() == {"error": DAILY_LIMIT_MSG}
        assert client.get("/api/scan/demo").status_code == 200
        events = client.get("/api/scan/demo/events?speed=0")
        assert events.status_code == 200


def test_ip_limit_429_other_ip_ok(tmp_path):
    limits = LimitsStore(
        tmp_path / "ip.db",
        daily_cap=10,
        ip_per_hour=2,
        trusted_hops=1,
        max_concurrent=10,
    )
    (tmp_path / "ok.txt").write_text("x\n")

    async def runner(*args, **kwargs):
        return ScanOutcome(findings=[])

    app = create_app(
        model_client=FakeModelClient(handler=lambda r: {}),
        cache=LookupCache(tmp_path / "c.db"),
        runner=runner,
        limits=limits,
    )
    with TestClient(app) as client:
        headers = {"X-Forwarded-For": "203.0.113.9"}
        first = client.post(
            "/api/scan", json={"target": str(tmp_path)}, headers=headers
        )
        second = client.post(
            "/api/scan", json={"target": str(tmp_path)}, headers=headers
        )
        third = client.post(
            "/api/scan", json={"target": str(tmp_path)}, headers=headers
        )
        assert first.status_code == 200
        assert second.status_code == 200
        assert third.status_code == 429
        assert third.json() == {"error": HOURLY_LIMIT_MSG}
        other = client.post(
            "/api/scan",
            json={"target": str(tmp_path)},
            headers={"X-Forwarded-For": "198.51.100.2"},
        )
        assert other.status_code == 200
        assert client.get("/api/health").status_code == 200


def test_spoofed_xff_does_not_bypass_ip_limit(tmp_path):
    limits = LimitsStore(
        tmp_path / "spoof.db",
        daily_cap=10,
        ip_per_hour=1,
        trusted_hops=0,
        max_concurrent=10,
    )
    (tmp_path / "ok.txt").write_text("x\n")

    async def runner(*args, **kwargs):
        return ScanOutcome(findings=[])

    app = create_app(
        model_client=FakeModelClient(handler=lambda r: {}),
        cache=LookupCache(tmp_path / "c.db"),
        runner=runner,
        limits=limits,
    )
    with TestClient(app) as client:
        first = client.post("/api/scan", json={"target": str(tmp_path)})
        spoofed = client.post(
            "/api/scan",
            json={"target": str(tmp_path)},
            headers={"X-Forwarded-For": "198.51.100.99"},
        )
        assert first.status_code == 200
        assert spoofed.status_code == 429
        assert spoofed.json() == {"error": HOURLY_LIMIT_MSG}


def test_third_simultaneous_scan_refused_when_daily_reserved(tmp_path):
    limits = LimitsStore(
        tmp_path / "reserve.db",
        daily_cap=2,
        ip_per_hour=50,
        max_concurrent=10,
        scan_reserve=1,
    )
    (tmp_path / "ok.txt").write_text("x\n")
    hold = threading.Event()

    async def runner(*args, **kwargs):
        await asyncio.to_thread(hold.wait)
        return ScanOutcome(findings=[])

    app = create_app(
        model_client=FakeModelClient(handler=lambda r: {}),
        cache=LookupCache(tmp_path / "c.db"),
        runner=runner,
        limits=limits,
        cost_cap=1.0,
    )
    with TestClient(app) as client:
        try:
            first = client.post("/api/scan", json={"target": str(tmp_path)})
            second = client.post("/api/scan", json={"target": str(tmp_path)})
            third = client.post("/api/scan", json={"target": str(tmp_path)})
            assert first.status_code == 200
            assert second.status_code == 200
            assert third.status_code == 429
            assert third.json() == {"error": DAILY_LIMIT_MSG}
            assert limits.spent_today() == 2
        finally:
            hold.set()


def test_busy_when_over_concurrent_limit(tmp_path):
    limits = LimitsStore(
        tmp_path / "busy.db",
        daily_cap=100,
        ip_per_hour=50,
        max_concurrent=3,
        scan_reserve=1,
    )
    (tmp_path / "ok.txt").write_text("x\n")
    hold = threading.Event()

    async def runner(*args, **kwargs):
        await asyncio.to_thread(hold.wait)
        return ScanOutcome(findings=[])

    app = create_app(
        model_client=FakeModelClient(handler=lambda r: {}),
        cache=LookupCache(tmp_path / "c.db"),
        runner=runner,
        limits=limits,
        cost_cap=1.0,
    )
    with TestClient(app) as client:
        try:
            codes = [
                client.post("/api/scan", json={"target": str(tmp_path)}).status_code
                for _ in range(4)
            ]
            assert codes[:3] == [200, 200, 200]
            assert codes[3] == 429
            fourth = client.post("/api/scan", json={"target": str(tmp_path)})
            assert fourth.json() == {"error": BUSY_MSG}
        finally:
            hold.set()


def test_vercel_trusts_one_forwarded_hop(monkeypatch):
    from api.limits import trusted_proxy_hops

    monkeypatch.delenv("TRUSTMAP_TRUSTED_PROXY_HOPS", raising=False)
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.setenv("VERCEL", "1")
    assert trusted_proxy_hops() == 1
    req = _Req("10.0.0.8", "203.0.113.9")
    assert client_ip(req, hops=trusted_proxy_hops()) == "203.0.113.9"
