from __future__ import annotations

import json
import re
from typing import Any

from scanner.agent import investigate
from scanner.classify import classify
from scanner.config import (
    EXPIRY_INVESTIGATE_DAYS,
    RANK_MODEL,
    RANK_REASONING_EFFORT,
)
from scanner.extract import extract
from scanner.llm import CallLog, ModelClient, call_json
from scanner.lookups import LookupCache
from scanner.models import (
    Classification,
    Finding,
    Investigation,
    RankModelOut,
    Reference,
    Severity,
)
from scanner.tools import ToolContext

EXECUTING = frozenset({"browser", "server", "build", "deploy", "ci"})
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
STATUS_WORDS = (
    "NoSuchBucket",
    "NXDOMAIN",
    "unregistered",
    "registered",
    "exists",
    "AccessDenied",
    "PermanentRedirect",
    "resolves",
    "unavailable",
)
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
NUM_RE = re.compile(r"\b\d+\b")

RANK_SYSTEM_PROMPT = (
    "You rank takeover risk for one outside target (a bucket or a registrable domain). "
    "Use only the supplied classification and evidence. Do not invent dates, DNS results, "
    "HTTP statuses, or counts. risk is what a stranger could do from this position. "
    "You may raise or lower blast_radius versus classify when evidence shows the reference "
    "matters more or less; if you change it, set blast_override_reason. "
    "fix must be one of the allowed values."
)

RANK_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"],
        },
        "risk": {"type": "string"},
        "fix": {
            "type": "string",
            "enum": [
                "remove dead reference",
                "self-host the asset",
                "pin with subresource integrity",
                "re-register what you abandoned",
                "replace with maintained source",
            ],
        },
        "uncertain_about": {"type": "string"},
        "blast_radius": {"type": "integer", "minimum": 0, "maximum": 3},
        "blast_override_reason": {"type": "string"},
    },
    "required": [
        "severity",
        "risk",
        "fix",
        "uncertain_about",
        "blast_radius",
        "blast_override_reason",
    ],
    "additionalProperties": False,
}


def target_key(ref: Reference, cl: Classification) -> tuple[str, str]:
    if cl.type == "bucket":
        return ref.host_or_bucket, "bucket"
    return (ref.domain or ref.host_or_bucket), "domain"


def group_by_target(
    rows: list[tuple[Reference, Classification, Investigation]],
) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for ref, cl, inv in rows:
        key, kind = target_key(ref, cl)
        if key not in groups:
            groups[key] = {
                "target": key,
                "kind": kind,
                "rows": [],
                "evidence": {},
            }
            order.append(key)
        groups[key]["rows"].append((ref, cl, inv))
        for name, value in inv.evidence.items():
            groups[key]["evidence"][name] = value
    return [groups[key] for key in order]


def claims_from_risk(risk: str) -> list[str]:
    claims = DATE_RE.findall(risk) + NUM_RE.findall(risk)
    folded = risk.casefold()
    for word in STATUS_WORDS:
        if word.casefold() in folded:
            claims.append(word)
    return claims


def missing_claims(risk: str, evidence: dict[str, Any]) -> list[str]:
    blob = json.dumps(evidence, default=str).casefold()
    missing = []
    for claim in claims_from_risk(risk):
        if claim.casefold() not in blob:
            missing.append(claim)
    return missing


def executing_runs_in(rows: list[tuple[Reference, Classification, Investigation]]) -> bool:
    return any(cl.runs_in in EXECUTING for _, cl, _ in rows)


def floor_severity(group: dict[str, Any]) -> str | None:
    if not executing_runs_in(group["rows"]):
        return None
    evidence = group["evidence"]
    bucket = evidence.get("bucket_probe") or {}
    rdap = evidence.get("rdap") or {}
    dns = evidence.get("dns") or {}
    if bucket.get("status") == "NoSuchBucket":
        return "critical"
    if str(rdap.get("status", "")).lower() == "unregistered":
        return "critical"
    if str(dns.get("status", "")).lower() == "nxdomain":
        return "high"
    days = rdap.get("days_to_expiry")
    if isinstance(days, int) and days <= EXPIRY_INVESTIGATE_DAYS:
        return "high"
    return None


def apply_floor(severity: Severity, floor: str | None) -> tuple[Severity, str]:
    if floor is None:
        return severity, ""
    if SEVERITY_ORDER[severity] > SEVERITY_ORDER[floor]:
        return floor, floor  # type: ignore[return-value]
    return severity, ""


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            -item.ranked_blast_radius,
            item.target,
        ),
    )


def rank(
    rows: list[tuple[Reference, Classification, Investigation]],
    *,
    client: ModelClient,
    cache: LookupCache | None = None,
    logs: list[CallLog] | None = None,
) -> list[Finding]:
    findings = [
        _rank_group(group, client=client, cache=cache, logs=logs)
        for group in group_by_target(rows)
    ]
    return sort_findings(findings)


def _rank_group(
    group: dict[str, Any],
    *,
    client: ModelClient,
    cache: LookupCache | None,
    logs: list[CallLog] | None,
) -> Finding:
    rows: list[tuple[Reference, Classification, Investigation]] = group["rows"]
    classified_blast = max(cl.blast_radius for _, cl, _ in rows)
    refs = [f"{ref.file}:{ref.line}" for ref, _, _ in rows]
    evidence = group["evidence"]
    floor = floor_severity(group)
    user = (
        "Rank this target. Cite only evidence facts in risk.\n"
        + json.dumps(
            {
                "target": group["target"],
                "kind": group["kind"],
                "references": [
                    {
                        "file": ref.file,
                        "line": ref.line,
                        "raw": ref.raw,
                        "type": cl.type,
                        "runs_in": cl.runs_in,
                        "blast_radius": cl.blast_radius,
                        "reason": cl.reason,
                    }
                    for ref, cl, _ in rows
                ],
                "classified_blast_radius": classified_blast,
                "evidence": evidence,
            },
            sort_keys=True,
            default=str,
        )
    )

    def check(parsed: RankModelOut) -> None:
        missing = missing_claims(parsed.risk, evidence)
        if missing:
            raise ValueError(f"claims not in evidence: {missing}")

    try:
        parsed, log = call_json(
            RANK_MODEL,
            RANK_SYSTEM_PROMPT,
            user,
            RankModelOut,
            RANK_REASONING_EFFORT,
            client=client,
            json_schema=RANK_JSON_SCHEMA,
            schema_name="ranking",
            cache=cache,
            extra_check=check,
        )
        if logs is not None:
            logs.append(log)
        severity, floor_note = apply_floor(parsed.severity, floor)
        override = parsed.blast_override_reason
        if parsed.blast_radius != classified_blast and not override:
            override = "ranker changed blast_radius versus classify"
        return Finding(
            target=group["target"],
            kind=group["kind"],
            references=refs,
            severity=severity,
            classified_blast_radius=classified_blast,
            ranked_blast_radius=parsed.blast_radius,
            blast_override_reason=override,
            risk=parsed.risk,
            fix=parsed.fix,
            uncertain_about=parsed.uncertain_about,
            floor_applied=floor_note,
            evidence=evidence,
            cost_usd=log.cost_usd,
        )
    except ValueError:
        severity, floor_note = apply_floor("info", floor)
        return Finding(
            target=group["target"],
            kind=group["kind"],
            references=refs,
            severity=severity,
            classified_blast_radius=classified_blast,
            ranked_blast_radius=classified_blast,
            risk="needs review: ranking failed self-check",
            fix="remove dead reference",
            needs_review=True,
            floor_applied=floor_note,
            evidence=evidence,
        )


async def scan(
    source: str,
    *,
    client: ModelClient,
    cache: LookupCache,
    ctx: ToolContext | None = None,
) -> list[Finding]:
    refs = extract(source)
    classified = classify(refs, client=client, include_filtered=True, cache=cache)
    by_loc = {(item.file, item.line): item for item in classified}
    pairs = [
        (ref, by_loc[(ref.file, ref.line)])
        for ref in refs
        if (ref.file, ref.line) in by_loc
    ]
    ctx = ctx or ToolContext(cache=cache)
    investigations = await investigate(pairs, client=client, ctx=ctx)
    inv_by_loc = {(item.file, item.line): item for item in investigations}
    rows = [
        (ref, cl, inv_by_loc[(ref.file, ref.line)])
        for ref, cl in pairs
        if (ref.file, ref.line) in inv_by_loc
    ]
    return rank(rows, client=client, cache=cache)


def format_table(findings: list[Finding]) -> str:
    if not findings:
        return "(no findings)"
    lines = []
    for item in findings:
        refs = ", ".join(item.references)
        lines.append(
            f"{item.severity:8} {item.target} refs={refs} "
            f"blast={item.ranked_blast_radius} fix={item.fix}"
        )
        if item.blast_override_reason:
            lines.append(f"         override: {item.blast_override_reason}")
        if item.floor_applied:
            lines.append(f"         floor={item.floor_applied}")
        if item.needs_review:
            lines.append("         needs_review")
        lines.append(f"         {item.risk}")
    return "\n".join(lines)
