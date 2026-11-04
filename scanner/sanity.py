"""Gates that keep popular domains from becoming Fix-today without a code fact."""

from __future__ import annotations

from typing import Any

from scanner.compromised import compromised_status
from scanner.tools.platform_takeover import takeover_is_proven
from scanner.tranco import TOP_SAFE_RANK, tranco_rank

FIX_TODAY = frozenset({"critical", "high"})


def has_proven_fact(evidence: dict[str, Any], names: list[str] | None = None) -> bool:
    bucket = evidence.get("bucket_probe") or {}
    if bucket.get("status") == "NoSuchBucket":
        return True
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() == "missing":
        return True
    rdap = evidence.get("rdap") or {}
    if str(rdap.get("status", "")).lower() == "unregistered":
        return True
    if takeover_is_proven(evidence):
        return True
    for name in names or []:
        if compromised_status(name):
            return True
    return False


def unexplained_tranco_fix_today(findings: list[Any]) -> list[str]:
    bad: list[str] = []
    for item in findings:
        severity = getattr(item, "severity", None) or (
            item.get("severity") if isinstance(item, dict) else ""
        )
        if severity not in FIX_TODAY:
            continue
        target = getattr(item, "target", None) or (
            item.get("target") if isinstance(item, dict) else ""
        )
        evidence = getattr(item, "evidence", None) or (
            item.get("evidence") if isinstance(item, dict) else {}
        ) or {}
        rank = tranco_rank(str(target or ""))
        if rank is None:
            host = str((evidence.get("dns") or {}).get("host") or "")
            rank = tranco_rank(host)
        if not isinstance(rank, int) or rank > TOP_SAFE_RANK:
            continue
        names = [str(target or "")]
        if has_proven_fact(evidence, names):
            continue
        bad.append(f"{target} {severity} tranco={rank}")
    return bad
