from fastapi.testclient import TestClient

from api.limits import DAILY_LIMIT_MSG, HOURLY_LIMIT_MSG, LimitsStore
from api.main import create_app
from scanner.llm import FakeModelClient
from scanner.lookups import LookupCache
from scanner.report import ScanOutcome


def test_daily_and_hourly_store(tmp_path):
    clock = {"t": 1_700_000_000.0}

    def now():
        return clock["t"]

    store = LimitsStore(
        tmp_path / "limits.db",
        daily_cap=10,
        ip_per_hour=5,
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
    limits = LimitsStore(tmp_path / "cap.db", daily_cap=1, ip_per_hour=50)
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
    limits = LimitsStore(tmp_path / "ip.db", daily_cap=10, ip_per_hour=2)
    tmp_path.mkdir(parents=True, exist_ok=True)
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
