from __future__ import annotations

import json
import re
from typing import Any

from scanner.agent import investigate, should_investigate
from scanner.classify import classify
from dataclasses import dataclass, field

from scanner.config import (
    EXPIRY_INVESTIGATE_DAYS,
    LLM_MAX_RETRIES,
    RANK_MODEL,
    RANK_REASONING_EFFORT,
    SCAN_COST_CAP_USD,
)
from scanner.events import OnEvent, emit, finding_public
from scanner.extract import extract, github_login, is_bucket_ref, is_github_owner_ref
from scanner.tools.platform_takeover import matching_platform
from scanner.llm import CallLog, ModelClient, call_json
from scanner.lookups import LookupCache, consistent_evidence
from scanner.models import (
    Classification,
    Finding,
    Investigation,
    RankModelOut,
    Reference,
    Severity,
)
from scanner.tools import ToolContext


@dataclass
class ScanOutcome:
    findings: list[Finding]
    investigations: list[Investigation] = field(default_factory=list)
    classify_cost_usd: float = 0.0
    agent_cost_usd: float = 0.0
    rank_cost_usd: float = 0.0
    budget_targets: list[str] = field(default_factory=list)

    @property
    def cost_usd(self) -> float:
        return self.classify_cost_usd + self.agent_cost_usd + self.rank_cost_usd

EXECUTING = frozenset({"browser", "server", "build", "deploy", "ci"})
CLAIMABLE_FIX = (
    "Remove or replace this reference. If this was yours, re-create it in your own "
    "account to reclaim the name."
)
NO_ACTION_FIX = "No action needed"
UNKNOWN_STATUSES = frozenset({"unavailable", "error", "timeout", "unknown"})
BANNED_FIELD_NAMES = ("rdap", "runs_in", "blast_radius", "status")
RUNS_IN_PHRASE = {
    "browser": "in the browser",
    "server": "on the server",
    "build": "at build time",
    "deploy": "in deploy",
    "ci": "in CI",
    "test": "in tests",
    "docs_only": "in docs",
}
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
NUM_RE = re.compile(r"\b\d+\b")
REGION_RE = re.compile(r"\b[a-z]{2}-[a-z]+-\d+\b", re.IGNORECASE)
STATUS_PHRASES = (
    "does not exist",
    "doesn't exist",
    "do not exist",
    "nosuchbucket",
    "nxdomain",
    "unregistered",
    "registered",
    "exists",
    "accessdenied",
    "permanentredirect",
    "resolves",
    "forbidden",
)
# If evidence has any token in a row, every token in that row is the same fact.
STATUS_MEANING = (
    frozenset({"nosuchbucket", "404", "does not exist", "doesn't exist", "do not exist"}),
    frozenset({"nxdomain"}),
    frozenset({"unregistered"}),
    frozenset({"registered"}),
    frozenset({"exists", "403", "accessdenied", "forbidden"}),
    frozenset({"permanentredirect", "301"}),
    frozenset({"resolves"}),
)

GITHUB_OWNER_NOTE = (
    "GitHub may retire popular repository names after an owner is deleted or "
    "renamed, which can block this exact path."
)

RANK_SYSTEM_PROMPT = (
    "You rank takeover risk for one outside target (a bucket or a registrable domain). "
    "Use only the supplied classification and evidence. Do not invent dates, DNS results, "
    "HTTP statuses, or counts. "
    "risk is 1-2 plain-English sentences for a developer: what a stranger could do and "
    "where it lands in the repo. Do not use field names such as rdap, runs_in, "
    "blast_radius, or status. "
    "A lookup whose status is unavailable or error is unknown: never treat it as "
    "evidence for or against risk. "
    "A registered, resolving, actively used domain that renews soon is routine. "
    "Expiry matters when combined with signs of abandonment (DNS does not resolve, "
    "or the owner has shut down). Do not raise severity for expiry alone. "
    "If github_owner status is missing, set uncertain_about to exactly: "
    f"{GITHUB_OWNER_NOTE!r}. "
    "You may raise or lower blast_radius versus classify when evidence shows the "
    "reference matters more or less; if you change it, set blast_override_reason. "
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
    if cl.type == "bucket" or is_bucket_ref(ref):
        return ref.host_or_bucket, "bucket"
    if matching_platform(ref.host_or_bucket):
        return ref.host_or_bucket, "domain"
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
        groups[key]["evidence"] = consistent_evidence(groups[key]["evidence"])
    return [groups[key] for key in order]


def finding_payload(group: dict[str, Any]) -> dict[str, Any]:
    rows: list[tuple[Reference, Classification, Investigation]] = group["rows"]
    raws = [ref.raw for ref, _, _ in rows]
    regions = sorted({match.group(0).lower() for raw in raws for match in REGION_RE.finditer(raw)})
    bucket = (group.get("evidence") or {}).get("bucket_probe") or {}
    provider = bucket.get("provider") or ""
    return {
        "target": group["target"],
        "kind": group["kind"],
        "reference_count": len(rows),
        "classified_blast_radius": max(cl.blast_radius for _, cl, _ in rows),
        "provider": provider,
        "regions": regions,
        "references": [
            {
                "file": ref.file,
                "line": ref.line,
                "file_line": f"{ref.file}:{ref.line}",
                "raw": ref.raw,
                "host_or_bucket": ref.host_or_bucket,
                "type": cl.type,
                "runs_in": cl.runs_in,
                "blast_radius": cl.blast_radius,
                "reason": cl.reason,
            }
            for ref, cl, _ in rows
        ],
        "evidence": usable_evidence(group["evidence"]),
    }


def usable_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    usable: dict[str, Any] = {}
    for name, value in evidence.items():
        if isinstance(value, dict):
            status = str(value.get("status", "")).lower()
            if status in UNKNOWN_STATUSES:
                continue
        usable[name] = value
    return usable


def claims_from_risk(risk: str) -> list[str]:
    claims = DATE_RE.findall(risk) + NUM_RE.findall(risk) + REGION_RE.findall(risk)
    folded = risk.casefold()
    for phrase in STATUS_PHRASES:
        if phrase in folded:
            claims.append(phrase)
    return claims


def _meaning_allowed(claim: str, blob: str) -> bool:
    token = claim.casefold()
    if token in blob:
        return True
    for group in STATUS_MEANING:
        if token not in group:
            continue
        if any(member in blob for member in group):
            return True
    return False


def missing_claims(risk: str, allowed: dict[str, Any] | None = None, evidence: dict[str, Any] | None = None) -> list[str]:
    payload = allowed if allowed is not None else {"evidence": usable_evidence(evidence or {})}
    blob = json.dumps(payload, default=str).casefold()
    missing = []
    for claim in claims_from_risk(risk):
        if not _meaning_allowed(claim, blob):
            missing.append(claim)
    return missing


def banned_fields(risk: str) -> list[str]:
    found = []
    for name in BANNED_FIELD_NAMES:
        if re.search(rf"\b{re.escape(name)}\b", risk, re.IGNORECASE):
            found.append(name)
    return found


def cited_unknown(risk: str, evidence: dict[str, Any]) -> list[str]:
    folded = risk.casefold()
    hits: list[str] = []
    for name, value in evidence.items():
        if not isinstance(value, dict):
            continue
        status = str(value.get("status", "")).lower()
        if status not in UNKNOWN_STATUSES:
            continue
        if name.casefold() in folded or status in folded:
            hits.append(name)
    return hits


def executing_runs_in(rows: list[tuple[Reference, Classification, Investigation]]) -> bool:
    return any(cl.runs_in in EXECUTING for _, cl, _ in rows)


def is_claimable(evidence: dict[str, Any]) -> bool:
    evidence = consistent_evidence(evidence)
    bucket = evidence.get("bucket_probe") or {}
    rdap = evidence.get("rdap") or {}
    owner = evidence.get("github_owner") or {}
    platform = evidence.get("platform_takeover") or {}
    if bucket.get("status") == "NoSuchBucket":
        return True
    if str(rdap.get("status", "")).lower() == "unregistered":
        return True
    if str(owner.get("status", "")).lower() == "missing":
        return True
    return (
        str(platform.get("status", "")).lower() == "unclaimed"
        and str(platform.get("takeover") or "") == "vulnerable"
    )


def has_risk_signal(evidence: dict[str, Any]) -> bool:
    usable = usable_evidence(evidence)
    if is_claimable(usable):
        return True
    dns = usable.get("dns") or {}
    rdap = usable.get("rdap") or {}
    platform = usable.get("platform_takeover") or {}
    if str(dns.get("status", "")).lower() == "nxdomain":
        return True
    if str(platform.get("status", "")).lower() == "unclaimed":
        return True
    days = rdap.get("days_to_expiry")
    return isinstance(days, int) and days <= EXPIRY_INVESTIGATE_DAYS


def choose_fix(evidence: dict[str, Any], model_fix: str, final_severity: Severity) -> str:
    if is_claimable(evidence):
        return CLAIMABLE_FIX
    if final_severity == "info" or not has_risk_signal(evidence):
        return NO_ACTION_FIX
    return model_fix


def evidence_line(group: dict[str, Any], *, include_runs_in: bool = True) -> str:
    evidence = consistent_evidence(group.get("evidence") or {})
    usable = usable_evidence(evidence)
    parts: list[str] = []
    dns = usable.get("dns") or {}
    dns_status = str(dns.get("status", "")).lower()
    raw_dns = str((evidence.get("dns") or {}).get("status", "")).lower()
    if raw_dns in {"timeout", "unknown"}:
        parts.append("DNS unknown (timeout)")
    elif dns_status == "nxdomain":
        parts.append("DNS does not resolve")
    elif dns_status == "resolves":
        parts.append("DNS resolves")
    rdap = usable.get("rdap") or {}
    rdap_status = str(rdap.get("status", "")).lower()
    if rdap_status == "unregistered":
        parts.append("domain not registered")
    elif rdap_status == "registered":
        parts.append("domain is registered")
        days = rdap.get("days_to_expiry")
        if isinstance(days, int) and days <= EXPIRY_INVESTIGATE_DAYS:
            parts.append(f"expires in {days} days")
    bucket = usable.get("bucket_probe") or {}
    bucket_status = str(bucket.get("status", ""))
    provider = str(bucket.get("provider") or "")
    if provider == "gcs":
        label = "GCS bucket"
    elif provider == "azure":
        label = "Azure blob"
    elif provider == "s3":
        label = "S3 bucket"
    else:
        label = "bucket"
    if bucket_status == "NoSuchBucket":
        parts.append(f"{label} does not exist")
    elif bucket_status.lower() == "exists":
        parts.append(f"{label} exists")
    owner = usable.get("github_owner") or {}
    if str(owner.get("status", "")).lower() == "missing":
        parts.append("GitHub owner does not exist")
    elif str(owner.get("status", "")).lower() == "exists":
        parts.append("GitHub owner exists")
    platform = usable.get("platform_takeover") or {}
    if str(platform.get("status", "")).lower() == "unclaimed":
        plat_name = platform.get("platform") or "platform"
        takeover = platform.get("takeover") or "edge case"
        parts.append(f"{plat_name} unclaimed ({takeover})")
    certs = usable.get("cert_history") or {}
    if str(certs.get("status", "")).lower() == "ok":
        issuers = certs.get("issuers") or []
        if issuers:
            parts.append("certificates found")
        else:
            parts.append("no certificates found")
    locs = [f"{ref.file}:{ref.line}" for ref, _cl, _inv in group.get("rows") or []]
    if not include_runs_in:
        if locs:
            parts.append("referenced at " + " and ".join(locs))
        return "Evidence: " + " · ".join(parts)
    by_run: dict[str, list[str]] = {}
    for ref, cl, _inv in group.get("rows") or []:
        by_run.setdefault(cl.runs_in, []).append(f"{ref.file}:{ref.line}")
    for runs_in, run_locs in by_run.items():
        place = RUNS_IN_PHRASE.get(runs_in, runs_in)
        joined = " and ".join(run_locs)
        if runs_in == "browser":
            parts.append(f"loaded by {joined} {place}")
        elif runs_in == "deploy":
            parts.append(f"named in {joined} {place}")
        else:
            parts.append(f"referenced at {joined} {place}")
    return "Evidence: " + " · ".join(parts)


def floor_severity(group: dict[str, Any]) -> str | None:
    level, _reason = floor_decision(group)
    return level


def floor_decision(group: dict[str, Any]) -> tuple[str | None, str]:
    if not executing_runs_in(group["rows"]):
        return None, ""
    evidence = consistent_evidence(group["evidence"])
    runs = sorted(
        {cl.runs_in for _, cl, _ in group["rows"] if cl.runs_in in EXECUTING}
    )
    where = ", ".join(runs)
    bucket = evidence.get("bucket_probe") or {}
    rdap = evidence.get("rdap") or {}
    dns = evidence.get("dns") or {}
    if bucket.get("status") == "NoSuchBucket":
        return (
            "critical",
            f"NoSuchBucket in executing position ({where}) is at least critical",
        )
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() == "missing":
        return (
            "critical",
            f"GitHub owner missing in executing position ({where}) is at least critical",
        )
    platform = evidence.get("platform_takeover") or {}
    if str(platform.get("status", "")).lower() == "unclaimed":
        plat_name = platform.get("platform") or "platform"
        takeover = str(platform.get("takeover") or "edge case")
        if takeover == "vulnerable":
            return (
                "critical",
                f"{plat_name} unclaimed ({takeover}) in executing position ({where}) "
                "is at least critical",
            )
        return (
            "high",
            f"{plat_name} unclaimed ({takeover}) in executing position ({where}) "
            "is at least high",
        )
    if str(rdap.get("status", "")).lower() == "unregistered":
        return (
            "critical",
            f"RDAP unregistered in executing position ({where}) is at least critical",
        )
    if str(dns.get("status", "")).lower() == "nxdomain":
        return (
            "high",
            f"NXDOMAIN in executing position ({where}) is at least high",
        )
    return None, ""


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
    on_event: OnEvent | None = None,
) -> list[Finding]:
    findings = sort_findings(
        [
            _rank_group(group, client=client, cache=cache, logs=logs)
            for group in group_by_target(rows)
        ]
    )
    for item in findings:
        emit(on_event, {"type": "ranked", **finding_public(item)})
    return findings


def _rank_group(
    group: dict[str, Any],
    *,
    client: ModelClient,
    cache: LookupCache | None,
    logs: list[CallLog] | None,
) -> Finding:
    payload = finding_payload(group)
    floor, floor_why = floor_decision(group)
    body = json.dumps(payload, sort_keys=True, default=str)
    user = "Rank this target. Cite only facts from the provided evidence and finding.\n" + body
    cost_total = 0.0

    def check(parsed: RankModelOut) -> None:
        missing = missing_claims(parsed.risk, payload)
        banned = banned_fields(parsed.risk)
        unknown = cited_unknown(parsed.risk, group["evidence"])
        problems = []
        if missing:
            problems.append(f"claims not in evidence: {missing}")
        if banned:
            problems.append(f"banned field names: {banned}")
        if unknown:
            problems.append(f"unknown lookups cited: {unknown}")
        owner = group["evidence"].get("github_owner") or {}
        if str(owner.get("status", "")).lower() == "missing":
            if GITHUB_OWNER_NOTE not in (parsed.uncertain_about or ""):
                problems.append("missing GitHub owner retirement note")
        if problems:
            raise ValueError("; ".join(problems))

    for attempt in range(LLM_MAX_RETRIES + 1):
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
                retries=0,
            )
            if logs is not None:
                logs.append(log)
            cost_total += log.cost_usd
            return _finding_from_rank(
                group=group,
                payload=payload,
                parsed=parsed,
                floor=floor,
                floor_why=floor_why,
                cost_total=cost_total,
            )
        except ValueError as exc:
            rejected = str(exc)
            user = (
                "Rank this target. Cite only facts from the provided evidence and finding.\n"
                + body
                + "\nSelf-check rejected these tokens: "
                + rejected
                + ". only use facts from the provided evidence and finding."
            )
            continue

    return _finding_from_rank(
        group=group,
        payload=payload,
        parsed=None,
        floor=floor,
        floor_why=floor_why,
        cost_total=cost_total,
        needs_review=True,
    )


def _finding_from_rank(
    *,
    group: dict[str, Any],
    payload: dict[str, Any],
    parsed: RankModelOut | None,
    floor: str | None,
    floor_why: str,
    cost_total: float,
    needs_review: bool = False,
) -> Finding:
    evidence = group["evidence"]
    refs = [item["file_line"] for item in payload["references"]]
    classified_blast = payload["classified_blast_radius"]
    if parsed is None:
        model_severity: Severity = "info"
        ranked_blast = classified_blast
        override = ""
        risk = "needs review: ranking failed self-check"
        model_fix = "remove dead reference"
        uncertain = ""
    else:
        model_severity = parsed.severity
        ranked_blast = parsed.blast_radius
        if parsed.blast_radius != classified_blast:
            override = parsed.blast_override_reason or (
                "ranker changed blast_radius versus classify"
            )
        else:
            override = ""
        risk = parsed.risk
        model_fix = parsed.fix
        uncertain = parsed.uncertain_about
    final, raised = apply_floor(model_severity, floor)
    floor_reason = floor_why if raised else ""
    return Finding(
        target=group["target"],
        kind=group["kind"],
        references=refs,
        severity=final,
        model_severity=model_severity,
        final_severity=final,
        classified_blast_radius=classified_blast,
        ranked_blast_radius=ranked_blast,
        blast_override_reason=override,
        risk=risk,
        fix=choose_fix(evidence, model_fix, final),
        uncertain_about=uncertain,
        needs_review=needs_review,
        floor_applied=raised,
        floor_reason=floor_reason,
        evidence=evidence,
        evidence_line=evidence_line(group),
        cost_usd=cost_total,
    )


async def scan(
    source: str,
    *,
    client: ModelClient,
    cache: LookupCache,
    ctx: ToolContext | None = None,
    hydrate_only: bool = True,
    cost_cap: float = SCAN_COST_CAP_USD,
    on_event: OnEvent | None = None,
) -> list[Finding]:
    outcome = await run_scan(
        source,
        client=client,
        cache=cache,
        ctx=ctx,
        hydrate_only=hydrate_only,
        cost_cap=cost_cap,
        on_event=on_event,
    )
    return outcome.findings


async def run_scan(
    source: str,
    *,
    client: ModelClient,
    cache: LookupCache,
    ctx: ToolContext | None = None,
    hydrate_only: bool = True,
    allow_partial_cache: bool = False,
    cost_cap: float = SCAN_COST_CAP_USD,
    on_event: OnEvent | None = None,
) -> ScanOutcome:
    refs = extract(source)
    actionable = sum(1 for item in refs if item.filter_reason is None)
    emit(
        on_event,
        {
            "type": "extracted",
            "references": len(refs),
            "actionable": actionable,
            "filtered": len(refs) - actionable,
        },
    )
    class_logs: list[CallLog] = []
    classified = classify(
        refs, client=client, include_filtered=True, cache=cache, logs=class_logs
    )
    by_loc = {(item.file, item.line): item for item in classified}
    pairs = [
        (ref, by_loc[(ref.file, ref.line)])
        for ref in refs
        if (ref.file, ref.line) in by_loc
    ]
    ctx = ctx or ToolContext(cache=cache)
    investigations: list[Investigation] = []
    cached_rows = (
        rows_from_lookup_cache(pairs, cache, complete=not allow_partial_cache)
        if hydrate_only
        else None
    )
    if cached_rows is not None:
        rows = cached_rows
    else:
        investigations = await investigate(
            pairs,
            client=client,
            ctx=ctx,
            cost_cap=cost_cap,
            on_event=on_event,
        )
        inv_by_loc = {(item.file, item.line): item for item in investigations}
        rows = [
            (ref, cl, inv_by_loc[(ref.file, ref.line)])
            for ref, cl in pairs
            if (ref.file, ref.line) in inv_by_loc
        ]
    rank_logs: list[CallLog] = []
    findings = rank(
        rows, client=client, cache=cache, logs=rank_logs, on_event=on_event
    )
    budget = sorted(
        {
            item.host_or_bucket
            for item in investigations
            if item.status == "budget"
        }
    )
    return ScanOutcome(
        findings=findings,
        investigations=investigations,
        classify_cost_usd=sum(log.cost_usd for log in class_logs),
        agent_cost_usd=sum(item.cost_usd for item in investigations),
        rank_cost_usd=sum(log.cost_usd for log in rank_logs),
        budget_targets=budget,
    )


def hydrate_evidence(
    ref: Reference, cl: Classification, cache: LookupCache
) -> dict[str, Any] | None:
    if cl.type == "bucket" or is_bucket_ref(ref):
        raw = ref.raw.lower()
        if "storage.googleapis.com" in raw:
            provider = "gcs"
        elif "blob.core.windows.net" in raw:
            provider = "azure"
        else:
            provider = "s3"
        hit = cache.get_json(f"bucket:{provider}:{ref.host_or_bucket}")
        if hit is None:
            return None
        evidence: dict[str, Any] = {"bucket_probe": hit}
        urls = (
            [ref.raw]
            if ref.raw.startswith("http")
            else [f"https://{ref.host_or_bucket}.s3.amazonaws.com"]
        )
        for url in urls:
            wayback = cache.get_json(f"wayback:{url}")
            if wayback:
                evidence["wayback"] = wayback
                break
        return evidence
    if is_github_owner_ref(ref):
        login = github_login(ref)
        if not login:
            return None
        hit = cache.get_json(f"github_owner:{login.lower()}")
        if hit is None:
            return None
        return {"github_owner": hit}
    dns = cache.get_json(f"dns:{ref.host_or_bucket.lower()}")
    if dns is None:
        return None
    evidence = {"dns": dns}
    if ref.domain:
        rdap = cache.get_json(f"rdap:{ref.domain.lower()}")
        if rdap:
            evidence["rdap"] = rdap
        certs = cache.get_json(f"crtsh:{ref.domain.lower()}")
        if certs:
            evidence["cert_history"] = certs
    wayback = cache.get_json(f"wayback:{ref.raw}")
    if wayback:
        evidence["wayback"] = wayback
    platform = cache.get_json(f"platform:{ref.host_or_bucket.lower()}")
    if platform:
        evidence["platform_takeover"] = platform
    login = github_login(ref)
    if login:
        owner = cache.get_json(f"github_owner:{login.lower()}")
        if owner:
            evidence["github_owner"] = owner
    return consistent_evidence(evidence)


def rows_from_lookup_cache(
    pairs: list[tuple[Reference, Classification]],
    cache: LookupCache,
    *,
    complete: bool = True,
) -> list[tuple[Reference, Classification, Investigation]] | None:
    rows: list[tuple[Reference, Classification, Investigation]] = []
    for ref, cl in pairs:
        if ref.filter_reason is not None:
            continue
        evidence = hydrate_evidence(ref, cl, cache)
        if evidence is None:
            if complete:
                return None
            continue
        if not should_investigate(ref, cl, evidence):
            continue
        rows.append(
            (
                ref,
                cl,
                Investigation(
                    file=ref.file,
                    line=ref.line,
                    host_or_bucket=ref.host_or_bucket,
                    status="done",
                    evidence=evidence,
                ),
            )
        )
    return rows


def format_table(findings: list[Finding]) -> str:
    if not findings:
        return "(no findings)"
    lines = []
    for item in findings:
        refs = ", ".join(item.references)
        lines.append(
            f"{item.final_severity:8} {item.target} refs={refs} "
            f"blast={item.ranked_blast_radius}"
        )
        lines.append(f"         fix={item.fix}")
        if item.blast_override_reason:
            lines.append(f"         override: {item.blast_override_reason}")
        if item.floor_reason:
            lines.append(
                f"         floor: model={item.model_severity} "
                f"final={item.final_severity} reason={item.floor_reason}"
            )
        if item.needs_review:
            lines.append("         needs_review")
        lines.append(f"         {item.risk}")
        if item.evidence_line:
            lines.append(f"         {item.evidence_line}")
    return "\n".join(lines)
