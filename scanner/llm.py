from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, TypeVar

from pydantic import BaseModel, ValidationError

from scanner.config import (
    CLASSIFY_MODEL,
    LLM_MAX_RETRIES,
    META_BASE_URL,
    MODEL_PRICES,
)
from scanner.lookups import LookupCache, default_cache
from scanner.models import CallLog

T = TypeVar("T", bound=BaseModel)

_SECRET_ASSIGN = re.compile(
    r"(?i)\b(api[_-]?key|token|password|secret)\s*[=:]\s*[^\s'\"\\,;]+"
)


class ModelClient(Protocol):
    def complete_json(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema_name: str,
        schema: dict[str, Any],
        reasoning_effort: str,
    ) -> "RawCompletion": ...

    def complete_turn(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        reasoning_effort: str,
    ) -> "ToolTurn": ...


@dataclass
class RawCompletion:
    text: str
    usage: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolTurn:
    name: str
    arguments: dict[str, Any]
    usage: dict[str, Any] = field(
        default_factory=lambda: {"input_tokens": 10, "output_tokens": 5}
    )


class FakeModelClient:
    """Offline stand-in. Never calls the Meta API."""

    def __init__(
        self,
        handler: Callable[..., Any] | None = None,
        tool_handler: Callable[..., Any] | None = None,
    ):
        self.handler = handler
        self.tool_handler = tool_handler
        self.calls: list[dict[str, Any]] = []

    def complete_json(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema_name: str,
        schema: dict[str, Any],
        reasoning_effort: str,
    ) -> RawCompletion:
        request = {
            "model": model,
            "system": system,
            "user": user,
            "schema_name": schema_name,
            "schema": schema,
            "reasoning_effort": reasoning_effort,
        }
        self.calls.append(request)
        payload = self.handler(request)
        if isinstance(payload, RawCompletion):
            return payload
        if isinstance(payload, str):
            return RawCompletion(
                text=payload, usage={"input_tokens": 10, "output_tokens": 5}
            )
        return RawCompletion(
            text=json.dumps(payload),
            usage={"input_tokens": 10, "output_tokens": 5},
        )

    def complete_turn(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        reasoning_effort: str,
    ) -> ToolTurn:
        request = {
            "model": model,
            "system": system,
            "messages": messages,
            "tools": tools,
            "reasoning_effort": reasoning_effort,
        }
        self.calls.append(request)
        if self.tool_handler is None:
            raise RuntimeError("FakeModelClient has no tool_handler")
        payload = self.tool_handler(request)
        if isinstance(payload, ToolTurn):
            return payload
        return ToolTurn(
            name=payload["name"],
            arguments=dict(payload.get("arguments") or {}),
            usage=payload.get("usage")
            or {"input_tokens": 10, "output_tokens": 5},
        )


class LiveModelClient:
    def __init__(self, api_key: str | None = None):
        from openai import OpenAI

        key = api_key or os.environ.get("MODEL_API_KEY")
        if not key:
            raise RuntimeError("MODEL_API_KEY is not set")
        self._client = OpenAI(base_url=META_BASE_URL, api_key=key)

    def complete_json(
        self,
        *,
        model: str,
        system: str,
        user: str,
        schema_name: str,
        schema: dict[str, Any],
        reasoning_effort: str,
    ) -> RawCompletion:
        response = self._client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            reasoning_effort=reasoning_effort,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": schema_name,
                    "schema": schema,
                    "strict": True,
                },
            },
        )
        text = response.choices[0].message.content or ""
        return RawCompletion(text=text, usage=_usage_dict(response))

    def complete_turn(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        reasoning_effort: str,
    ) -> ToolTurn:
        response = self._client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system}, *messages],
            tools=tools,
            reasoning_effort=reasoning_effort,
            tool_choice="auto",
        )
        usage = _usage_dict(response)
        calls = response.choices[0].message.tool_calls or []
        if not calls:
            raise ValueError("model did not pick a tool")
        call = calls[0]
        args = json.loads(call.function.arguments or "{}")
        return ToolTurn(name=call.function.name, arguments=args, usage=usage)


def redact_secrets(text: str) -> str:
    return _SECRET_ASSIGN.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)


def prompt_hash(model: str, system: str, user: str) -> str:
    blob = f"{model}\n{system}\n{user}".encode()
    return hashlib.sha256(blob).hexdigest()


def cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    prices = MODEL_PRICES.get(model) or MODEL_PRICES[CLASSIFY_MODEL]
    return (
        input_tokens / 1_000_000 * prices["input"]
        + output_tokens / 1_000_000 * prices["output"]
    )


def call_json(
    model: str,
    system: str,
    user: str,
    schema: type[T],
    reasoning_effort: str,
    *,
    client: ModelClient,
    json_schema: dict[str, Any],
    schema_name: str,
    cache: LookupCache | None = None,
    extra_check: Callable[[T], None] | None = None,
    retries: int | None = None,
) -> tuple[T, CallLog]:
    cache = cache or default_cache()
    key = f"llm:{prompt_hash(model, system, user)}"
    hit = cache.get_json(key)
    if hit is not None:
        parsed = schema.model_validate(hit["data"])
        if extra_check is not None:
            extra_check(parsed)
        log = CallLog(
            model=model,
            input_tokens=0,
            output_tokens=0,
            latency_ms=0,
            cost_usd=0.0,
            cached=True,
            api_usage=hit.get("api_usage"),
        )
        return parsed, log

    last_error: Exception | None = None
    attempts = (LLM_MAX_RETRIES if retries is None else retries) + 1
    for _ in range(attempts):
        started = time.perf_counter()
        raw = client.complete_json(
            model=model,
            system=system,
            user=user,
            schema_name=schema_name,
            schema=json_schema,
            reasoning_effort=reasoning_effort,
        )
        latency_ms = (time.perf_counter() - started) * 1000
        in_tok, out_tok, usage = _tokens(raw.usage)
        log = CallLog(
            model=model,
            input_tokens=in_tok,
            output_tokens=out_tok,
            latency_ms=latency_ms,
            cost_usd=cost_usd(model, in_tok, out_tok),
            cached=False,
            api_usage=usage or None,
        )
        try:
            data = json.loads(raw.text)
            parsed = schema.model_validate(data)
            if extra_check is not None:
                extra_check(parsed)
            cache.set_json(key, {"data": parsed.model_dump(mode="json"), "api_usage": usage})
            return parsed, log
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            last_error = exc
            continue
    raise ValueError(f"model returned invalid JSON after retries: {last_error}")


def _tokens(usage: dict[str, Any]) -> tuple[int, int, dict[str, Any]]:
    if not usage:
        return 0, 0, {}
    in_tok = int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0)
    out_tok = int(usage.get("output_tokens") or usage.get("completion_tokens") or 0)
    reasoning = _reasoning_tokens(usage)
    # Some payloads nest reasoning under details but already include it in
    # output/completion tokens; only add when it is clearly extra.
    if reasoning and out_tok < reasoning:
        out_tok += reasoning
    return in_tok, out_tok, dict(usage)


def _reasoning_tokens(usage: dict[str, Any]) -> int:
    for key in ("output_tokens_details", "completion_tokens_details"):
        details = usage.get(key)
        if isinstance(details, dict) and details.get("reasoning_tokens") is not None:
            return int(details["reasoning_tokens"])
    if usage.get("reasoning_tokens") is not None:
        return int(usage["reasoning_tokens"])
    return 0


def _usage_dict(response: Any) -> dict[str, Any]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return {}
    if hasattr(usage, "model_dump"):
        dumped = usage.model_dump()
        return dumped if isinstance(dumped, dict) else {"value": dumped}
    if isinstance(usage, dict):
        return usage
    out: dict[str, Any] = {}
    for name in dir(usage):
        if name.startswith("_"):
            continue
        value = getattr(usage, name, None)
        if isinstance(value, (int, float, str, bool)):
            out[name] = value
    return out
