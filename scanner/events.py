from __future__ import annotations

import json
from typing import Any, Callable

from scanner.llm import redact_secrets
from scanner.models import Finding

OnEvent = Callable[[dict[str, Any]], None]
RESULT_LIMIT = 400


def emit(on_event: OnEvent | None, payload: dict[str, Any]) -> None:
    if on_event is not None:
        on_event(payload)


def summarize(value: Any) -> str:
    text = redact_secrets(json.dumps(value, default=str, sort_keys=True))
    if len(text) > RESULT_LIMIT:
        return text[:RESULT_LIMIT] + "..."
    return text


def finding_public(item: Finding) -> dict[str, Any]:
    evidence = item.evidence or {}
    live = evidence.get("live_fetch") or {}
    return {
        "target": item.target,
        "kind": item.kind,
        "severity": item.severity,
        "model_severity": item.model_severity,
        "floor_reason": item.floor_reason,
        "floor_applied": item.floor_applied,
        "risk": item.risk,
        "fix": item.fix,
        "evidence_line": item.evidence_line,
        "evidence": evidence,
        "tranco_rank": evidence.get("tranco_rank"),
        "parked": bool(live.get("parked")),
        "for_sale": bool(live.get("for_sale")),
        "live_signal": live.get("signal"),
        "action_ref": item.action_ref,
        "action_sha_pinned": item.action_sha_pinned,
        "evidence_level": item.evidence_level,
        "references": item.locations or item.references,
        "cost_usd": item.cost_usd,
    }
