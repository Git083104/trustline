from __future__ import annotations

import json
from collections import Counter
from typing import Any, Callable

from scanner.extract import is_bucket_ref
from scanner.llm import redact_secrets
from scanner.models import Classification, Finding, Reference
from scanner.tools.platform_takeover import matching_platform

OnEvent = Callable[[dict[str, Any]], None]
RESULT_LIMIT = 400
# The page draws a table from these; a monorepo can name thousands of hosts.
LIST_LIMIT = 300
RAW_LIMIT = 160


def public_target(ref: Reference, cl: Classification | None = None) -> tuple[str, str]:
    """The name a takeover is about: a bucket, a platform host, or a registrable domain."""
    if (cl is not None and cl.type == "bucket") or is_bucket_ref(ref):
        return ref.host_or_bucket, "bucket"
    if matching_platform(ref.host_or_bucket):
        return ref.host_or_bucket, "domain"
    return (ref.domain or ref.host_or_bucket), "domain"


def _raw(text: str) -> str:
    text = redact_secrets(text)
    return text if len(text) <= RAW_LIMIT else text[:RAW_LIMIT] + "..."


def gather_public(refs: list[Reference]) -> dict[str, Any]:
    """Layer 1 for the page: targets that could change hands, and what was set aside."""
    targets: dict[str, dict[str, Any]] = {}
    set_aside: dict[str, dict[str, Any]] = {}
    for ref in refs:
        if ref.filter_reason is not None:
            bucket = set_aside.setdefault(ref.filter_reason, {"count": 0, "examples": []})
            bucket["count"] += 1
            if ref.host_or_bucket not in bucket["examples"] and len(bucket["examples"]) < 4:
                bucket["examples"].append(ref.host_or_bucket)
            continue
        name, kind = public_target(ref)
        row = targets.get(name)
        if row is None:
            row = targets[name] = {
                "target": name,
                "kind": kind,
                "platform": (matching_platform(name) or {}).get("name", ""),
                "refs": 0,
                "files": [],
                "first": {"file": ref.file, "line": ref.line, "raw": _raw(ref.raw)},
            }
        row["refs"] += 1
        if ref.file not in row["files"]:
            row["files"].append(ref.file)
    rows = [{**row, "files": len(row["files"])} for row in targets.values()]
    return {"targets": rows[:LIST_LIMIT], "targets_total": len(rows), "set_aside": set_aside}


def classified_public(pairs: list[tuple[Reference, Classification]]) -> dict[str, Any]:
    """Layer 2 for the page: what each actionable reference is and where it runs."""
    items = [
        {
            "target": public_target(ref, cl)[0],
            "file": ref.file,
            "line": ref.line,
            "type": cl.type,
            "runs_in": cl.runs_in,
            "blast_radius": cl.blast_radius,
            "confidence": cl.confidence,
            "reason": redact_secrets(cl.reason),
        }
        for ref, cl in pairs
        if ref.filter_reason is None
    ]
    # the page lists the first LIST_LIMIT items; its summary counts all of them
    runs_in = dict(Counter(item["runs_in"] for item in items))
    return {"items": items[:LIST_LIMIT], "total": len(items), "runs_in": runs_in}


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
        "references": item.locations or item.references,
        "cost_usd": item.cost_usd,
        "uncertain_about": item.uncertain_about,
        "needs_review": item.needs_review,
        "classified_blast_radius": item.classified_blast_radius,
        "blast_radius": item.ranked_blast_radius,
        "blast_override_reason": item.blast_override_reason,
    }
