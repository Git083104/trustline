import json
import ssl

import certifi
import httpx
import openai
import pytest

from scanner import llm
from scanner.llm import FakeModelClient, _tokens, call_json, cost_usd, failure_message, redact_secrets
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


def test_reasoning_tokens_count_as_output_when_not_already_included():
    in_tok, out_tok, _ = _tokens(
        {
            "input_tokens": 10,
            "output_tokens": 20,
            "output_tokens_details": {"reasoning_tokens": 50},
        }
    )
    assert in_tok == 10
    assert out_tok == 70
    in_tok, out_tok, _ = _tokens(
        {
            "prompt_tokens": 10,
            "completion_tokens": 80,
            "completion_tokens_details": {"reasoning_tokens": 50},
        }
    )
    assert out_tok == 80


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
                    "type": "docs_link",
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


def test_model_client_trusts_certifi_when_the_host_has_no_ca_store(monkeypatch):
    # The SDK's HTTP stack trusts only the OS store; a host image without one made
    # every Muse Spark call fail with a bare "Connection error."
    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", lambda self, purpose=None: None)
    certifi_only = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    certifi_only.load_verify_locations(certifi.where())
    ctx = llm._tls_context()
    assert ctx.cert_store_stats()["x509_ca"] == certifi_only.cert_store_stats()["x509_ca"] > 0
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


def test_live_client_hands_the_sdk_that_trust_store(monkeypatch):
    sentinel = ssl.create_default_context()
    seen = {}
    real = openai.DefaultHttpxClient

    def recording(**kwargs):
        seen.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(llm, "_tls_context", lambda: sentinel)
    monkeypatch.setattr(openai, "DefaultHttpxClient", recording)
    llm.LiveModelClient(api_key="test-key-not-real")
    assert seen["verify"] is sentinel


def _connection_error(root: BaseException, kind=openai.APIConnectionError) -> BaseException:
    request = httpx.Request("POST", "https://api.meta.ai/v1/chat/completions")
    try:
        try:
            raise root
        except BaseException as cause:
            raise kind(request=request) from cause
    except openai.APIConnectionError as exc:
        return exc


def test_failure_message_names_the_cause_behind_connection_error():
    exc = _connection_error(
        ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    )
    assert str(exc) == "Connection error."
    message = failure_message(exc)
    assert message.startswith("Couldn't reach the Meta Model API (SSLCertVerificationError:")
    assert "CERTIFICATE_VERIFY_FAILED" in message


def test_failure_message_for_timeouts_secrets_and_plain_errors():
    late = failure_message(_connection_error(TimeoutError("read timed out"), openai.APITimeoutError))
    assert late.startswith("The Meta Model API did not answer in time")
    leaky = failure_message(_connection_error(OSError("proxy said api_key=sk-live-abcdef123456")))
    assert "sk-live" not in leaky and "[REDACTED]" in leaky
    assert failure_message(ValueError("model did not pick a tool")) == "model did not pick a tool"
    assert len(failure_message(RuntimeError("x" * 1000))) == llm.FAILURE_LIMIT + 3



FAKE_KEY = "LLM_000000000_FAKEkeyFAKEkeyFAKE"


def test_redact_secrets_hides_bearer_tokens_and_our_own_keys(monkeypatch):
    monkeypatch.setenv("MODEL_API_KEY", "\n" + FAKE_KEY)
    # the exact shape the HTTP library used when it refused the header
    leaked = f"Illegal header value b'Bearer \\n{FAKE_KEY}'"
    assert "FAKEkey" not in redact_secrets(leaked)
    assert "FAKEkey" not in redact_secrets(f"found {FAKE_KEY} in a log line")
    assert redact_secrets("Authorization: Bearer abcdef0123456789") == "Authorization: Bearer [REDACTED]"
    monkeypatch.delenv("MODEL_API_KEY")
    assert "FAKEkey" not in redact_secrets(leaked)  # the Bearer pattern alone still catches it


def test_failure_message_never_shows_the_key(monkeypatch):
    monkeypatch.setenv("MODEL_API_KEY", "\n" + FAKE_KEY)
    exc = _connection_error(Exception(f"Illegal header value b'Bearer \\n{FAKE_KEY}'"))
    message = failure_message(exc)
    assert message.startswith("Couldn't reach the Meta Model API (Exception: Illegal header value")
    assert "FAKEkey" not in message and "[REDACTED]" in message


def test_live_client_strips_a_key_pasted_with_line_breaks(monkeypatch):
    monkeypatch.setenv("MODEL_API_KEY", f"\n {FAKE_KEY}\n")
    assert llm.LiveModelClient()._client.api_key == FAKE_KEY
    monkeypatch.setenv("MODEL_API_KEY", " \n ")
    with pytest.raises(RuntimeError):
        llm.LiveModelClient()


class _Completions:
    """Stands in for client.chat.completions; refuses temperature if asked to."""

    def __init__(self, refuse_temperature: bool):
        self.refuse = refuse_temperature
        self.requests: list[dict] = []

    def create(self, **request):
        self.requests.append(request)
        if self.refuse and "temperature" in request:
            response = httpx.Response(400, request=httpx.Request("POST", "https://api.test/v1"))
            raise openai.BadRequestError("temperature is not supported", response=response, body=None)
        message = type("Message", (), {"content": '{"items": []}', "tool_calls": None})
        choice = type("Choice", (), {"message": message})
        return type("Response", (), {"choices": [choice], "usage": None})


def _live_with(completions: _Completions) -> "llm.LiveModelClient":
    client = llm.LiveModelClient(api_key=FAKE_KEY)
    client._client = type("Client", (), {"chat": type("Chat", (), {"completions": completions})})
    return client


def _ask(client: "llm.LiveModelClient") -> None:
    client.complete_json(
        model="muse-spark-1.3",
        system="s",
        user="u",
        schema_name="x",
        schema={"type": "object"},
        reasoning_effort="low",
    )


def test_live_client_asks_for_repeatable_answers():
    completions = _Completions(refuse_temperature=False)
    _ask(_live_with(completions))
    assert completions.requests[0]["temperature"] == 0


def test_live_client_drops_temperature_once_the_api_refuses_it():
    completions = _Completions(refuse_temperature=True)
    client = _live_with(completions)
    _ask(client)
    _ask(client)
    sent = ["temperature" in request for request in completions.requests]
    # refused once, retried plainly, and never sent again
    assert sent == [True, False, False]
