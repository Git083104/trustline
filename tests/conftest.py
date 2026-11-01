import pytest


@pytest.fixture(autouse=True)
def generous_api_limits(monkeypatch):
    monkeypatch.setenv("TRUSTMAP_DAILY_CAP_USD", "1000")
    monkeypatch.setenv("TRUSTMAP_IP_SCANS_PER_HOUR", "1000")
