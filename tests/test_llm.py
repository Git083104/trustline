import json

from scanner.llm import FakeModelClient, call_json, cost_usd, redact_secrets
from scanner.lookups import LookupCache
from scanner.models import ClassificationBatch


def test_redact_secrets():
    text = "api_key=sk-live-abcdefghijklmnopqrstuvwxyz token=abcd1234secretvalue password=hunter2"
    redacted = redact_secrets(text)
    assert "sk-live" not in redacted
    assert "hunter2" not in redacted
    assert "=[REDACTED]" in redacted


def test_cost_uses_config_prices():
    # 1M in + 1M out = 1.25 + 4.25
    assert cost_usd("muse-spark-1.3", 1_000_000, 1_000_000) == 5.5


def test_call_json_retries_invalid_then_succeeds(tmp_path):
    attempts = {"n": 0}

    def handler(request):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return "not-json"
        return {
            "items": [
                {
                    "id": "0",
                    "type": "script",
                    "runs_in": "browser",
                    "blast_radius": 2,
                    "confidence": 0.9,
                    "reason": "script tag",
                }
            ]
        }

    client = FakeModelClient(handler)
    parsed, log = call_json(
        "muse-spark-1.3",
        "sys",
        "user",
        ClassificationBatch,
        "low",
        client=client,
        json_schema={"type": "object"},
        schema_name="classification_batch",
        cache=LookupCache(tmp_path / "c.db"),
    )
    assert attempts["n"] == 2
    assert parsed.items[0].id == "0"
    assert log.cached is False
    assert log.cost_usd > 0
    assert log.api_usage is not None
    assert "input_tokens" in log.api_usage


def test_cache_hit_skips_client_and_costs_zero(tmp_path):
    client = FakeModelClient(
        lambda request: {
            "items": [
                {
                    "id": "0",
                    "type": "docs",
                    "runs_in": "docs_only",
                    "blast_radius": 0,
                    "confidence": 1,
                    "reason": "readme",
                }
            ]
        }
    )
    cache = LookupCache(tmp_path / "c.db")
    kwargs = dict(
        model="muse-spark-1.3",
        system="sys",
        user="same-input",
        schema=ClassificationBatch,
        reasoning_effort="low",
        client=client,
        json_schema={"type": "object"},
        schema_name="classification_batch",
        cache=cache,
    )
    first, log1 = call_json(**kwargs)
    second, log2 = call_json(**kwargs)
    assert len(client.calls) == 1
    assert first.items[0].type == second.items[0].type
    assert log1.cached is False
    assert log2.cached is True
    assert log2.cost_usd == 0
    assert log2.input_tokens == 0
