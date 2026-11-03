from __future__ import annotations

import asyncio
import time
from datetime import date
from typing import Any

from scanner.config import CT_GAP_DAYS, OWNERSHIP_BLAME_BUDGET_S
from scanner.extract import is_github_owner_ref
from scanner.lookups import line_first_seen
from scanner.models import Classification, Investigation, Reference
from scanner.tools import ToolContext

OWNERSHIP_PHRASES = (
    "changed hands",
    "reregistered",
    "new registrant",
    "new owner",
    "ownership changed",
)


def parse_iso_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, date) and not hasattr(value, "hour"):
        return value
    text = str(value)[:10]
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def registration_date(group: dict[str, Any]) -> date | None:
    evidence = group.get("evidence") or {}
    rdap = evidence.get("rdap") or {}
    owner = evidence.get("github_owner") or {}
    if any(is_github_owner_ref(ref) for ref, _cl, _inv in group.get("rows") or []):
        return parse_iso_date(owner.get("created_at"))
    return parse_iso_date(rdap.get("registered"))


def supporting_facts(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    rdap = evidence.get("rdap") or {}
    if rdap.get("transfer"):
        facts.append({"fact": "rdap_transfer", "date": str(rdap["transfer"])[:10]})
    if rdap.get("last_changed"):
        facts.append({"fact": "rdap_last_changed", "date": str(rdap["last_changed"])[:10]})
    live = evidence.get("live_fetch") or {}
    rdap_ns = {str(item).lower() for item in rdap.get("nameservers") or []}
    live_ns = {str(item).lower() for item in live.get("nameservers") or []}
    if rdap_ns and live_ns and rdap_ns != live_ns:
        facts.append(
            {
                "fact": "nameserver_change",
                "rdap": sorted(rdap_ns),
                "live": sorted(live_ns),
            }
        )
    certs = evidence.get("cert_history") or {}
    gap = certs.get("max_gap_days")
    first_org = str(certs.get("first_issuer_org") or "")
    last_org = str(certs.get("last_issuer_org") or "")
    if (
        isinstance(gap, int)
        and gap >= CT_GAP_DAYS
        and first_org
        and last_org
        and first_org != last_org
    ):
        facts.append(
            {
                "fact": "ct_gap_new_issuer",
                "gap_days": gap,
                "first_issuer": first_org,
                "last_issuer": last_org,
            }
        )
    wayback = evidence.get("wayback") or {}
    first_d = wayback.get("first_digest")
    last_d = wayback.get("last_digest")
    if first_d and last_d and first_d != last_d:
        fact = "wayback_flipped_to_parked" if live.get("parked") else "wayback_content_changed"
        facts.append(
            {
                "fact": fact,
                "first_snapshot": wayback.get("first_snapshot"),
                "last_snapshot": wayback.get("last_snapshot"),
            }
        )
    return facts


def is_proven_ownership(evidence: dict[str, Any]) -> bool:
    hands = evidence.get("changed_hands") or {}
    return bool(hands.get("reregistered_after_reference"))


def likely_risk(group: dict[str, Any]) -> str:
    facts = supporting_facts(group.get("evidence") or {})
    bits = []
    for item in facts:
        name = item.get("fact")
        if name == "rdap_transfer":
            bits.append(f"RDAP transfer on {item.get('date')}")
        elif name == "rdap_last_changed":
            bits.append(f"RDAP last changed {item.get('date')}")
        elif name == "nameserver_change":
            bits.append("nameservers differ from RDAP")
        elif name == "ct_gap_new_issuer":
            bits.append(
                f"CT gap {item.get('gap_days')} days then issuer {item.get('last_issuer')}"
            )
        elif name == "wayback_flipped_to_parked":
            bits.append("Wayback snapshot now parked")
        elif name == "wayback_content_changed":
            bits.append("Wayback content changed")
    listed = "; ".join(bits) if bits else "supporting lookups only"
    return f"Likely changed hands. {listed}."


def reregistered_risk(group: dict[str, Any]) -> str:
    hands = (group.get("evidence") or {}).get("changed_hands") or {}
    ref_d = hands.get("reference_date")
    reg_d = hands.get("registration_date")
    src = hands.get("reference_source") or "blame"
    return (
        f"Registered {reg_d} after the reference ({src} {ref_d})."
    )


def ownership_claim_without_fact(risk: str, evidence: dict[str, Any]) -> bool:
    folded = risk.casefold()
    if not any(phrase in folded for phrase in OWNERSHIP_PHRASES):
        return False
    if is_proven_ownership(evidence) or supporting_facts(evidence):
        return False
    return True


def _flagged_group(group: dict[str, Any]) -> bool:
    if group.get("kind") == "bucket":
        return False
    rows = group.get("rows") or []
    if not rows:
        return False
    from scanner.agent import tranco_checked_safe
    from scanner.report import is_claimable

    ref0, _cl, _inv = rows[0]
    if tranco_checked_safe(ref0, group.get("evidence") or {}) and not is_claimable(
        group.get("evidence") or {}
    ):
        return False
    return True


async def attach_changed_hands(
    rows: list[tuple[Reference, Classification, Investigation]],
    *,
    github_owner: str,
    github_repo: str,
    ctx: ToolContext,
    budget_s: float = OWNERSHIP_BLAME_BUDGET_S,
) -> None:
    from scanner.report import group_by_target

    if not rows:
        return
    groups = group_by_target(rows)
    flagged = [group for group in groups if _flagged_group(group)]
    started = time.monotonic()
    for group in flagged:
        await _fill_lookups(group, ctx)
        remaining = budget_s - (time.monotonic() - started)
        seen = None
        if github_owner and github_repo and remaining > 0.05:
            try:
                seen = await asyncio.wait_for(
                    _reference_date(group, github_owner, github_repo, ctx),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                seen = None
        registered = registration_date(group)
        hands: dict[str, Any] = {
            "status": "ok" if seen or registered else "unavailable",
            "supporting": supporting_facts(group["evidence"]),
        }
        if seen:
            hands["reference_date"] = seen["date"]
            hands["reference_source"] = seen.get("source") or "blame"
            hands["path"] = seen.get("path")
            if seen.get("line") is not None:
                hands["line"] = seen["line"]
        if registered:
            hands["registration_date"] = registered.isoformat()
        ref_d = parse_iso_date(hands.get("reference_date"))
        if ref_d and registered and registered > ref_d:
            hands["reregistered_after_reference"] = True
        else:
            hands["reregistered_after_reference"] = False
        group["evidence"]["changed_hands"] = hands
        for _ref, _cl, inv in group["rows"]:
            inv.evidence["changed_hands"] = hands
            extra = group["evidence"]
            if extra.get("cert_history") and "cert_history" not in inv.evidence:
                inv.evidence["cert_history"] = extra["cert_history"]
            if extra.get("wayback") and "wayback" not in inv.evidence:
                inv.evidence["wayback"] = extra["wayback"]


async def _fill_lookups(group: dict[str, Any], ctx: ToolContext) -> None:
    evidence = group["evidence"]
    domain = ""
    url = ""
    for ref, _cl, _inv in group["rows"]:
        if is_github_owner_ref(ref):
            return
        domain = ref.domain or domain
        url = ref.raw if str(ref.raw).startswith("http") else url
    if domain and "cert_history" not in evidence:
        try:
            evidence["cert_history"] = (
                await ctx.cert_history(domain, cache=ctx.cache)
            ).model_dump(mode="json")
        except Exception:
            pass
    if url and "wayback" not in evidence:
        try:
            evidence["wayback"] = (await ctx.wayback(url, cache=ctx.cache)).model_dump(
                mode="json"
            )
        except Exception:
            pass


async def _reference_date(
    group: dict[str, Any],
    owner: str,
    repo: str,
    ctx: ToolContext,
) -> dict[str, Any] | None:
    lookup = getattr(ctx, "line_first_seen", line_first_seen)
    earliest: dict[str, Any] | None = None
    earliest_d: date | None = None
    seen_keys: set[tuple[str, int]] = set()
    for ref, _cl, _inv in group["rows"]:
        path = ref.file
        if not path or path.startswith("http"):
            continue
        key = (path, ref.line)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        hit = await lookup(
            owner, repo, path, ref.line, cache=ctx.cache
        )
        if not isinstance(hit, dict) or hit.get("status") != "ok":
            continue
        parsed = parse_iso_date(hit.get("date"))
        if parsed is None:
            continue
        if earliest_d is None or parsed < earliest_d:
            earliest_d = parsed
            earliest = dict(hit)
    return earliest
