from __future__ import annotations

import asyncio
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from scanner.agent import investigate, should_investigate, tranco_checked_safe
from scanner.classify import UNKNOWN_POSITION, classify
from scanner.deadline import ScanClock
from scanner.ownership import (
    attach_changed_hands,
    is_proven_ownership,
    is_rest_fallback_reregister,
    likely_risk,
    ownership_claim_without_fact,
    reregistered_risk,
    supporting_facts,
)
from dataclasses import dataclass, field

from scanner.config import (
    EXPIRY_INVESTIGATE_DAYS,
    LLM_MAX_RETRIES,
    LLM_REQUEST_TIMEOUT_S,
    OWNERSHIP_BLAME_BUDGET_S,
    RANK_CONCURRENCY,
    RANK_TIMEOUT_S,
    RANK_MODEL,
    RANK_REASONING_EFFORT,
    SCAN_COST_CAP_USD,
)
from scanner.events import OnEvent, emit, finding_public
from scanner.compromised import (
    POLYFILL_FIX,
    SRI_FIX,
    compromised_status,
    is_polyfill_host,
)
from scanner.extract import (
    _registrable,
    empty_coverage,
    extract_scan,
    github_login,
    is_bucket_ref,
    is_github_action_ref,
    is_github_owner_ref,
    is_github_pages_host,
    is_website_source,
    website_coverage,
)
from scanner.tools.platform_takeover import matching_platform, takeover_is_proven
from scanner.tranco import tranco_rank
from scanner.website import extract_website_scan
from scanner.llm import CallLog, ModelClient, OverloadError, call_json, muse_overloaded
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

log = logging.getLogger("trustmap")


@dataclass
class ScanOutcome:
    findings: list[Finding]
    investigations: list[Investigation] = field(default_factory=list)
    classify_cost_usd: float = 0.0
    agent_cost_usd: float = 0.0
    rank_cost_usd: float = 0.0
    budget_targets: list[str] = field(default_factory=list)
    skipped_targets: list[str] = field(default_factory=list)
    code_only_targets: list[str] = field(default_factory=list)
    skip_reasons: list[str] = field(default_factory=list)
    classify_rule_n: int = 0
    classify_model_n: int = 0
    agent_runs: int = 0
    agent_tool_calls: int = 0
    rank_fallbacks: int = 0
    partial: bool = False
    stage_seconds: dict[str, float] = field(default_factory=dict)
    coverage: dict[str, object] = field(default_factory=lambda: empty_coverage().as_dict())
    file_texts: dict[str, str] = field(default_factory=dict)
    source_html: str = ""
    code_only: bool = False
    muse_overloaded: bool = False

    @property
    def cost_usd(self) -> float:
        return self.classify_cost_usd + self.agent_cost_usd + self.rank_cost_usd

EXECUTING = frozenset({"browser", "server", "build", "deploy", "ci"})
CLAIMABLE_FIX = (
    "Remove or replace this reference. If this was yours, re-create it in your own "
    "account to reclaim the name."
)
ACTION_PIN_FIX = "Pin to a full commit SHA."
ACTION_DISABLED_FIX = (
    "Replace this action: GitHub has disabled its repository, so CI cannot read "
    "what it runs. Pin the replacement to a full commit SHA."
)
ACTION_MISSING_FIX = (
    "Remove or replace this action. If this was yours, re-create it in your own "
    "account to reclaim the name. Pin to a full commit SHA."
)
NO_ACTION_FIX = "No action needed"
FIX_SENTENCES = {
    "remove dead reference": (
        "Remove this reference; it points to a host that no longer resolves."
    ),
    "self-host the asset": (
        "Self-host this asset so you are not depending on a third-party origin "
        "you do not control."
    ),
    "pin with subresource integrity": (
        "Add a subresource integrity hash, or self-host this script, so a "
        "taken-over host cannot change what browsers run."
    ),
    "re-register what you abandoned": (
        "Re-register this name in your own account, or remove the reference if "
        "you no longer need it."
    ),
    "replace with maintained source": (
        "Replace this with a source that is still maintained."
    ),
}
STATIC_TAGS = frozenset({"img", "source", "link"})
STATIC_SUFFIXES = (
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
)
DOWNLOAD_TYPES = frozenset({"script", "api"})
LINK_CLICK_RISK = (
    "Anyone who registers {domain} could receive your users' clicks (phishing risk)"
)
HOST_SCOPED_FACTS = frozenset(
    {"dns", "platform_takeover", "live_fetch", "bucket_probe"}
)
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
FIX_TODAY = frozenset({"critical", "high"})
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
    "Code applies severity floors from those facts; you write the explanation. "
    "risk is 1-2 plain-English sentences for a developer: what a stranger could do and "
    "where it lands in the repo. Do not use field names such as rdap, runs_in, "
    "blast_radius, or status. "
    "A lookup whose status is unavailable or error is unknown: never treat it as "
    "evidence for or against risk. "
    "A registered, resolving, actively used domain that renews soon is routine. "
    "tranco_rank is popularity context only: never lower severity below a code floor, "
    "and never treat popularity as a reason to ignore a compromised or claimable-now "
    "target. "
    "Expiry matters when combined with signs of abandonment (DNS does not resolve, "
    "or the owner has shut down). Do not raise severity for expiry alone. "
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


def target_key(
    ref: Reference,
    cl: Classification,
    inv: Investigation | None = None,
) -> tuple[str, str]:
    if cl.type == "bucket" or is_bucket_ref(ref):
        return ref.host_or_bucket, "bucket"
    dns = ((inv.evidence if inv is not None else None) or {}).get("dns") or {}
    if matching_platform(
        ref.host_or_bucket,
        list(dns.get("cnames") or []),
        list(dns.get("addresses") or []),
    ):
        return ref.host_or_bucket.lower().rstrip("."), "domain"
    return (ref.domain or ref.host_or_bucket), "domain"


def group_by_target(
    rows: list[tuple[Reference, Classification, Investigation]],
) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for ref, cl, inv in rows:
        key, kind = target_key(ref, cl, inv)
        if key not in groups:
            groups[key] = {
                "target": key,
                "kind": kind,
                "rows": [],
                "evidence": {},
            }
            order.append(key)
        groups[key]["rows"].append((ref, cl, inv))
        target = str(key).lower().rstrip(".")
        row_host = str(ref.host_or_bucket or "").lower().rstrip(".")
        for name, value in inv.evidence.items():
            if name in HOST_SCOPED_FACTS and isinstance(value, dict):
                fact_host = str(
                    value.get("host") or value.get("name") or ""
                ).lower().rstrip(".")
                if name in {"platform_takeover", "live_fetch", "bucket_probe"}:
                    if fact_host and fact_host != target:
                        continue
                elif name == "dns":
                    if (
                        fact_host
                        and fact_host != target
                        and fact_host != row_host
                    ):
                        continue
            groups[key]["evidence"][name] = value
        groups[key]["evidence"] = consistent_evidence(groups[key]["evidence"])
        if ref.csp_blocks_external_scripts:
            groups[key]["evidence"]["csp_blocks_external_scripts"] = True
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
                "action_ref": ref.action_ref,
                "action_sha_pinned": ref.action_sha_pinned,
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
    from scanner.inert import is_inert_path

    return any(
        cl.runs_in in EXECUTING
        and UNKNOWN_POSITION not in (cl.reason or "")
        and not is_inert_path(ref.file)
        for ref, cl, _ in rows
    )


def _nxdomain_apex(evidence: dict[str, Any], group: dict[str, Any] | None = None) -> bool:
    dns = evidence.get("dns") or {}
    if str(dns.get("status", "")).lower() != "nxdomain":
        return False
    host = str(dns.get("host") or (group or {}).get("target") or "").lower().rstrip(".")
    parent = _registrable(host) if host else ""
    if parent and host == parent:
        return True
    parent_dns = evidence.get("dns_parent") or {}
    rdap = evidence.get("rdap") or {}
    return (
        str(parent_dns.get("status", "")).lower() == "nxdomain"
        and str(rdap.get("status", "")).lower() != "registered"
    )


def fix_today_allowed(group: dict[str, Any]) -> bool:
    """Fix-today needs a claimable-now or proven fact in an executing position."""
    if not executing_runs_in(group.get("rows") or []):
        return False
    evidence = consistent_evidence(group.get("evidence") or {})
    if is_claimable(evidence) or is_proven_ownership(evidence):
        return True
    if takeover_is_proven(evidence):
        platform = evidence.get("platform_takeover") or {}
        if str(platform.get("takeover") or "") == "vulnerable":
            return True
    if _group_compromised(group) == "compromised":
        return True
    return _nxdomain_apex(evidence, group)


def _pages_account_exists(evidence: dict[str, Any]) -> bool:
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() not in {"exists", "ok"}:
        return False
    platform = evidence.get("platform_takeover") or {}
    host = str(platform.get("host") or "")
    return (
        str(platform.get("platform") or "").lower() == "github pages"
        or is_github_pages_host(host)
    )


def _pages_host_from_group(group: dict[str, Any] | None) -> str:
    if not group:
        return ""
    target = str(group.get("target") or "")
    if is_github_pages_host(target):
        return target
    return ""


def is_claimable(evidence: dict[str, Any]) -> bool:
    evidence = consistent_evidence(evidence)
    bucket = evidence.get("bucket_probe") or {}
    rdap = evidence.get("rdap") or {}
    owner = evidence.get("github_owner") or {}
    platform = evidence.get("platform_takeover") or {}
    if bucket.get("status") == "NoSuchBucket":
        return True
    if str(owner.get("status", "")).lower() == "missing":
        return True
    plat_host = str(platform.get("host") or rdap.get("domain") or "")
    pages_plat = (
        str(platform.get("platform") or "").lower() == "github pages"
        or is_github_pages_host(plat_host)
    )
    if pages_plat or _pages_account_exists(evidence):
        return False
    if str(rdap.get("status", "")).lower() == "unregistered":
        host = str(rdap.get("domain") or platform.get("host") or "")
        if is_github_pages_host(host):
            return False
        return True
    if takeover_is_proven(evidence) and str(platform.get("takeover") or "") == "vulnerable":
        if pages_plat or is_github_pages_host(plat_host):
            return False
        return True
    return False


def skip_model_rank(group: dict[str, Any]) -> bool:
    evidence = group["evidence"]
    ref0 = group["rows"][0][0]
    cl0 = group["rows"][0][1]
    if _pages_host_from_group(group):
        owner = evidence.get("github_owner") or {}
        if str(owner.get("status", "")).lower() in {"exists", "ok"}:
            return True
    if cl0.runs_in == "docs_only" or _all_plain_links(group):
        return True
    if (
        is_claimable(evidence)
        or is_proven_ownership(evidence)
        or is_rest_fallback_reregister(evidence)
        or supporting_facts(evidence)
        or floor_decision(group)[0] is not None
    ):
        return False
    if tranco_checked_safe(ref0, evidence):
        return True
    repo = evidence.get("github_repo") or {}
    if str(repo.get("status", "")).lower() == "exists" and is_github_action_ref(ref0):
        return True
    return True


def template_risk(group: dict[str, Any]) -> str:
    line = evidence_line(group)
    floor, why = floor_decision(group)
    if why:
        return f"{line} {why}".strip()
    if finding_evidence_level(group) == "likely":
        return likely_risk(group)
    if is_proven_ownership(group.get("evidence") or {}):
        return f"{line} {reregistered_risk(group)}".strip()
    if skip_model_rank(group):
        pages = _pages_host_from_group(group)
        owner = (group.get("evidence") or {}).get("github_owner") or {}
        if pages and str(owner.get("status", "")).lower() in {"exists", "ok"}:
            return f"{line} GitHub account still exists."
        return f"{line} Claimable or listed as compromised; no model rank.".strip()
    return f"{line} Ranking skipped; using lookup facts.".strip()


def _template_finding(group: dict[str, Any], *, deadline: bool) -> Finding:
    payload = finding_payload(group)
    floor, floor_why = floor_decision(group)
    parsed = RankModelOut(
        severity="info",
        risk=template_risk(group),
        fix="remove dead reference",
        uncertain_about="",
        blast_radius=payload["classified_blast_radius"],
        blast_override_reason="",
    )
    finding = _finding_from_rank(
        group=group,
        payload=payload,
        parsed=parsed,
        floor=floor,
        floor_why=floor_why,
        cost_total=0.0,
    )
    finding = finding.model_copy(update={"explained_by": "template"})
    if deadline:
        finding = finding.model_copy(update={"needs_review": True})
    return finding


def has_risk_signal(evidence: dict[str, Any]) -> bool:
    usable = usable_evidence(evidence)
    if is_claimable(usable):
        return True
    dns = usable.get("dns") or {}
    rdap = usable.get("rdap") or {}
    platform = usable.get("platform_takeover") or {}
    if str(dns.get("status", "")).lower() == "nxdomain":
        return True
    if takeover_is_proven(usable):
        return True
    repo = usable.get("github_repo") or {}
    if str(repo.get("status", "")).lower() in {"missing", "disabled"}:
        return True
    days = rdap.get("days_to_expiry")
    if isinstance(days, int) and days <= EXPIRY_INVESTIGATE_DAYS:
        return True
    live = usable.get("live_fetch") or {}
    if live.get("parked") or live.get("for_sale"):
        return True
    return is_proven_ownership(evidence) or bool(supporting_facts(evidence))


def _browser_script_rows(
    rows: list[tuple[Reference, Classification, Investigation]],
) -> list[tuple[Reference, Classification, Investigation]]:
    return [
        (ref, cl, inv)
        for ref, cl, inv in rows
        if cl.runs_in == "browser"
        and (ref.tag == "script" or cl.type == "script")
    ]


def _all_browser_scripts_sri(
    rows: list[tuple[Reference, Classification, Investigation]],
) -> bool:
    scripts = _browser_script_rows(rows)
    return bool(scripts) and all(ref.sri is True for ref, _cl, _inv in scripts)


def human_fix(fix: str) -> str:
    return FIX_SENTENCES.get(fix, fix)


def _is_static_asset(ref: Reference, cl: Classification) -> bool:
    if ref.tag == "iframe":
        return False
    blob = f"{ref.context} {ref.file} {ref.raw}".lower()
    if "product_image" in blob:
        return True
    if cl.type in DOWNLOAD_TYPES:
        return False
    if cl.type == "asset" or ref.tag in STATIC_TAGS:
        return True
    path = (ref.raw or "").split("?", 1)[0].lower()
    return path.endswith(STATIC_SUFFIXES)


def _has_download_ref(group: dict[str, Any]) -> bool:
    for ref, cl, _inv in group.get("rows") or []:
        if cl.runs_in not in EXECUTING:
            continue
        if cl.type == "link" or ref.tag in {"a", "markdown"}:
            continue
        if _is_static_asset(ref, cl):
            continue
        return True
    return False


def _has_static_asset(group: dict[str, Any]) -> bool:
    return any(
        cl.runs_in in EXECUTING and _is_static_asset(ref, cl)
        for ref, cl, _inv in group.get("rows") or []
    )


def _claimable_now_floor(
    group: dict[str, Any], signal: str, where: str
) -> tuple[str | None, str]:
    if _has_download_ref(group):
        return _claimable_sri_floor(
            "critical",
            f"{signal} for a script/api/config download in executing position "
            f"({where}) is at least critical",
            group,
        )
    if _has_static_asset(group):
        return (
            "high",
            f"{signal} for a static asset in executing position ({where}) "
            "is at least high",
        )
    return _claimable_sri_floor(
        "critical",
        f"{signal} in executing position ({where}) is at least critical",
        group,
    )


def _group_compromised(
    group: dict[str, Any],
) -> str | None:
    names: list[str] = [group.get("target") or ""]
    for ref, _cl, _inv in group.get("rows") or []:
        names.append(ref.host_or_bucket)
        names.append(ref.domain)
    return compromised_status(*names)


def choose_fix(
    evidence: dict[str, Any],
    model_fix: str,
    final_severity: Severity,
    rows: list[tuple[Reference, Classification, Investigation]] | None = None,
) -> str:
    rows = rows or []
    names = [ref.host_or_bucket for ref, _cl, _inv in rows] + [
        ref.domain for ref, _cl, _inv in rows
    ]
    if is_polyfill_host(*names):
        return POLYFILL_FIX
    third_party_no_sri = False
    for ref, cl, _inv in _browser_script_rows(rows):
        if ref.sri is True:
            continue
        if ref.page_url and ref.host_or_bucket:
            page_host = (ref.page_url.split("://", 1)[-1].split("/", 1)[0].split(":")[0])
            if ref.host_or_bucket.lower() != page_host.lower():
                third_party_no_sri = True
    if third_party_no_sri:
        return SRI_FIX
    if any(is_github_action_ref(ref) for ref, _cl, _inv in rows):
        owner = evidence.get("github_owner") or {}
        repo = evidence.get("github_repo") or {}
        if (
            str(owner.get("status", "")).lower() == "missing"
            or str(repo.get("status", "")).lower() == "missing"
        ):
            return ACTION_MISSING_FIX
        if str(repo.get("status", "")).lower() == "disabled":
            return ACTION_DISABLED_FIX
        text = human_fix(model_fix) if has_risk_signal(evidence) else NO_ACTION_FIX
        if ACTION_PIN_FIX not in text:
            if text == NO_ACTION_FIX:
                return ACTION_PIN_FIX
            return f"{text.rstrip('.')} {ACTION_PIN_FIX}"
        return text
    if is_claimable(evidence):
        return CLAIMABLE_FIX
    if final_severity == "info" or not has_risk_signal(evidence):
        return NO_ACTION_FIX
    return human_fix(model_fix)


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
    repo = usable.get("github_repo") or {}
    if str(repo.get("status", "")).lower() == "missing":
        parts.append("GitHub repo does not exist")
    elif str(repo.get("status", "")).lower() == "disabled":
        parts.append("GitHub repo disabled")
    elif str(repo.get("status", "")).lower() == "exists":
        parts.append("GitHub repo exists")
    platform = usable.get("platform_takeover") or {}
    if takeover_is_proven(usable):
        plat_name = platform.get("platform") or "platform"
        takeover = platform.get("takeover") or "edge case"
        plat_host = str(platform.get("host") or "").rstrip(".")
        named = f"{plat_name} unclaimed ({takeover})"
        if plat_host:
            named = f"{named} on {plat_host}"
        parts.append(named)
    status = _group_compromised(group)
    if status == "compromised":
        parts.append("compromised domain")
    elif status == "associated":
        parts.append("associated domain")
    sri_values = [ref.sri for ref, _cl, _inv in group.get("rows") or []]
    live = usable.get("live_fetch") or {}
    if live.get("for_sale"):
        parts.append("domain listed for sale")
    elif live.get("parked"):
        parts.append("domain is parked")
    rank = evidence.get("tranco_rank")
    if isinstance(rank, int):
        parts.append(f"Tranco rank {rank}")
    if False in sri_values:
        parts.append("SRI missing")
    elif True in sri_values:
        parts.append("SRI present")
    hands = usable.get("changed_hands") or {}
    if hands.get("reregistered_after_reference"):
        parts.append(
            f"registered {hands.get('registration_date')} after reference "
            f"{hands.get('reference_date')}"
        )
    elif hands.get("reference_date"):
        src = hands.get("reference_source") or "blame"
        parts.append(f"{src} {hands.get('reference_date')}")
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


def apply_website_roles(
    pairs: list[tuple[Reference, Classification]],
) -> list[tuple[Reference, Classification]]:
    updated: list[tuple[Reference, Classification]] = []
    for ref, cl in pairs:
        if ref.tag != "script":
            updated.append((ref, cl))
            continue
        changes: dict[str, Any] = {"runs_in": "browser"}
        if cl.type != "bucket" and not is_github_owner_ref(ref):
            changes["type"] = "script"
        updated.append((ref, cl.model_copy(update=changes)))
    return updated


def _reference_locations(group: dict[str, Any]) -> list[dict[str, Any]]:
    locations = []
    for ref, cl, _inv in group.get("rows") or []:
        locations.append(
            {
                "page_url": ref.page_url,
                "file": ref.file,
                "line": ref.line,
                "tag": ref.tag,
                "attribute": ref.attribute,
                "raw": ref.raw,
                "sri": ref.sri,
                "loaded_by": ref.loaded_by,
                "runs_in": cl.runs_in,
            }
        )
    return locations


def finding_evidence_level(group: dict[str, Any]) -> str:
    evidence = group.get("evidence") or {}
    rows = group.get("rows") or []
    ref0 = rows[0][0] if rows else None
    if is_claimable(evidence) or is_proven_ownership(evidence):
        return "proven"
    if ref0 is not None and _group_compromised(group) in {"compromised", "associated"}:
        return "proven"
    if is_rest_fallback_reregister(evidence) or supporting_facts(evidence):
        return "likely"
    return ""


def floor_severity(group: dict[str, Any]) -> str | None:
    level, _reason = floor_decision(group)
    return level


def _mention_floor(group: dict[str, Any]) -> tuple[str | None, str]:
    evidence = consistent_evidence(group["evidence"])
    dns = evidence.get("dns") or {}
    live = evidence.get("live_fetch") or {}
    if _group_compromised(group):
        signal = "Compromised domain"
    elif is_claimable(evidence):
        signal = "Claimable now"
    elif str(dns.get("status", "")).lower() == "nxdomain":
        signal = "DNS does not resolve"
    elif live.get("for_sale"):
        signal = "Domain listed for sale"
    elif live.get("parked"):
        signal = "Domain parked"
    else:
        return None, ""
    return "low", f"{signal}, but only named in docs, tests or comments, so it is low"


def _all_plain_links(group: dict[str, Any]) -> bool:
    rows = [
        (ref, cl)
        for ref, cl, _inv in group.get("rows") or []
        if cl.runs_in in EXECUTING
    ]
    if not rows:
        return False
    return all(
        cl.type == "link" or ref.tag in {"a", "markdown"}
        for ref, cl in rows
    )


def floor_decision(group: dict[str, Any]) -> tuple[str | None, str]:
    if not executing_runs_in(group["rows"]):
        return _mention_floor(group)
    evidence = consistent_evidence(group["evidence"])
    if _all_plain_links(group):
        domain = str(group.get("target") or "")
        if is_claimable(evidence) or takeover_is_proven(evidence):
            return "medium", LINK_CLICK_RISK.format(domain=domain)
        return _mention_floor(group)
    runs = sorted(
        {cl.runs_in for _, cl, _ in group["rows"] if cl.runs_in in EXECUTING}
    )
    where = ", ".join(runs)
    sri_ok = _all_browser_scripts_sri(group["rows"])
    has_script = bool(_browser_script_rows(group["rows"]))
    status = _group_compromised(group)
    if status == "compromised" and has_script and not sri_ok:
        return (
            "critical",
            f"compromised domain in a browser script without SRI ({where}) "
            "is at least critical",
        )
    if status == "associated" and has_script:
        return (
            "high",
            f"associated domain in a browser script ({where}) is at least high",
        )
    bucket = evidence.get("bucket_probe") or {}
    rdap = evidence.get("rdap") or {}
    dns = evidence.get("dns") or {}
    if bucket.get("status") == "NoSuchBucket":
        return _claimable_now_floor(group, "NoSuchBucket", where)
    owner = evidence.get("github_owner") or {}
    pages_host = _pages_host_from_group(group)
    if pages_host:
        login = github_login(group["rows"][0][0]) if group.get("rows") else pages_host.split(".", 1)[0]
        if str(owner.get("status", "")).lower() == "missing":
            return _claimable_now_floor(group, "GitHub Pages account missing", where)
        if str(owner.get("status", "")).lower() in {"exists", "ok"}:
            repo = evidence.get("github_repo") or {}
            if str(repo.get("status", "")).lower() == "missing":
                who = login or "that account"
                return (
                    "low",
                    f"only {who} can recreate it",
                )
        return None, ""
    if str(owner.get("status", "")).lower() == "missing":
        return _claimable_now_floor(group, "GitHub owner missing", where)
    repo = evidence.get("github_repo") or {}
    if str(repo.get("status", "")).lower() == "missing":
        return (
            "high",
            "GitHub repo missing in executing position "
            f"({where}) is at least high",
        )
    if str(repo.get("status", "")).lower() == "disabled":
        return (
            "medium",
            "GitHub repo disabled in executing position "
            f"({where}) is at least medium",
        )
    platform = evidence.get("platform_takeover") or {}
    if takeover_is_proven(evidence):
        plat_name = platform.get("platform") or "platform"
        takeover = str(platform.get("takeover") or "edge case")
        plat_host = str(platform.get("host") or group.get("target") or "")
        if takeover != "vulnerable":
            return (
                "low",
                f"{plat_name} unclaimed ({takeover}) on {plat_host} is review",
            )
        return _claimable_now_floor(
            group, f"{plat_name} unclaimed ({takeover}) on {plat_host}", where
        )
    if str(rdap.get("status", "")).lower() == "unregistered":
        return _claimable_now_floor(group, "RDAP unregistered", where)
    if is_proven_ownership(evidence):
        return _claimable_now_floor(group, "registered after the reference", where)
    live = evidence.get("live_fetch") or {}
    for_sale = bool(live.get("for_sale"))
    parked = bool(live.get("parked"))
    if for_sale or parked:
        website = any(ref.page_url for ref, _cl, _inv in group["rows"])
        if (
            website
            and for_sale
            and has_script
            and not sri_ok
        ):
            return (
                "critical",
                "Domain is listed for sale → raised to critical.",
            )
        note = (
            "Domain is listed for sale → raised to high."
            if for_sale
            else "Domain is parked → raised to high."
        )
        return "high", note
    if str(dns.get("status", "")).lower() == "nxdomain":
        if (
            _has_static_asset(group)
            and not _has_download_ref(group)
            and not is_claimable(evidence)
        ):
            return None, ""
        return _nxdomain_floor(group, evidence, dns, where)
    parent_dns = evidence.get("dns_parent") or {}
    if (
        str(parent_dns.get("status", "")).lower() == "nxdomain"
        and str(rdap.get("status", "")).lower() != "registered"
    ):
        return (
            "high",
            f"Apex NXDOMAIN in executing position ({where}) is at least high",
        )
    return _executing_list_floor(group, evidence, where)


def _nxdomain_floor(
    group: dict[str, Any], evidence: dict[str, Any], dns: dict[str, Any], where: str
) -> tuple[str | None, str]:
    host = str(dns.get("host") or group.get("target") or "").lower().rstrip(".")
    parent = _registrable(host) if host else ""
    rdap = evidence.get("rdap") or {}
    platform = evidence.get("platform_takeover") or {}
    dangling = takeover_is_proven(evidence)
    parent_unregistered = str(rdap.get("status", "")).lower() in {
        "unregistered",
        "nxdomain",
    }
    host_is_apex = bool(parent) and host == parent
    parent_dns = evidence.get("dns_parent") or {}
    rdap_registered = str(rdap.get("status", "")).lower() == "registered"
    parent_nx = (
        str(parent_dns.get("status", "")).lower() == "nxdomain" and not rdap_registered
    )
    if dangling or parent_unregistered or parent_nx or host_is_apex:
        return (
            "high",
            f"NXDOMAIN in executing position ({where}) is at least high",
        )
    if parent:
        return (
            "low",
            f"Subdomain no longer resolves; only the owner of {parent} can recreate it.",
        )
    return (
        "high",
        f"NXDOMAIN in executing position ({where}) is at least high",
    )


def _executing_list_floor(
    group: dict[str, Any], evidence: dict[str, Any], where: str
) -> tuple[str | None, str]:
    sri_ok = _all_browser_scripts_sri(group["rows"])
    has_script = bool(_browser_script_rows(group["rows"]))
    status = _group_compromised(group)
    if status == "compromised" and not (has_script and sri_ok):
        return (
            "high",
            f"compromised domain in executing position ({where}) is at least high",
        )
    if status == "associated":
        return (
            "medium",
            f"associated domain in executing position ({where}) is at least medium",
        )
    return None, ""


def risk_contradicts_rule(risk: str, floor_why: str) -> bool:
    if not floor_why:
        return False
    why = floor_why.lower()
    text = risk.lower()
    if "only the owner of" in why:
        return any(
            token in text
            for token in (
                "stranger",
                "anyone could",
                "claim",
                "take over",
                "unregistered",
                "takeover",
            )
        )
    return False


def _claimable_sri_floor(
    level: str | None, reason: str, group: dict[str, Any]
) -> tuple[str | None, str]:
    if level != "critical":
        return level, reason
    rows = group["rows"]
    if _all_browser_scripts_sri(rows) and _browser_script_rows(rows):
        return (
            "medium",
            "claimable-now with SRI in executing position is at least medium",
        )
    return level, reason


def _github_owner_note(uncertain: str, evidence: dict[str, Any]) -> str:
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() != "missing":
        return uncertain
    if GITHUB_OWNER_NOTE in uncertain:
        return uncertain
    if uncertain.strip():
        return uncertain.rstrip() + " " + GITHUB_OWNER_NOTE
    return GITHUB_OWNER_NOTE


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
    clock: ScanClock | None = None,
    skipped: list[str] | None = None,
    fallbacks: list[str] | None = None,
    code_only: bool = False,
) -> list[Finding]:
    groups = group_by_target(rows)
    if not groups:
        return []
    results: list[Finding | None] = [None] * len(groups)
    # One list per group, merged in group order afterwards, so the cost log
    # does not depend on which worker finished first.
    group_logs: list[list[CallLog]] = [[] for _ in groups]

    def rank_one(index: int) -> None:
        group = groups[index]
        known = skip_model_rank(group) or code_only or muse_overloaded()
        remaining = clock.remaining_stage() if clock is not None else RANK_TIMEOUT_S
        if code_only or muse_overloaded():
            finding = _template_finding(group, deadline=False)
        elif not known and clock is not None and remaining < 0.05:
            finding = _template_finding(group, deadline=True)
            if fallbacks is not None:
                fallbacks.append(group["target"])
            clock.note_skip(
                "rank",
                "stage budget exhausted; kept code verdict",
                [group["target"]],
            )
        else:
            timeout_s = None
            if not known:
                timeout_s = min(
                    RANK_TIMEOUT_S,
                    clock.remaining_stage() if clock is not None else RANK_TIMEOUT_S,
                )
            try:
                finding = _rank_group(
                    group,
                    client=client,
                    cache=cache,
                    logs=group_logs[index],
                    timeout_s=timeout_s,
                )
            except (TimeoutError, OverloadError):
                finding = _template_finding(group, deadline=True)
                if fallbacks is not None:
                    fallbacks.append(group["target"])
                if clock is not None and not muse_overloaded():
                    clock.note_skip(
                        "rank",
                        f"model call exceeded {timeout_s}s; kept code verdict",
                        [group["target"]],
                    )
        results[index] = finding
        # Tell the page as each target is ranked, not after all of them.
        emit(on_event, {"type": "ranked", **finding_public(finding)})

    workers = min(RANK_CONCURRENCY, len(groups))
    if workers <= 1:
        rank_one(0)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for future in [pool.submit(rank_one, i) for i in range(len(groups))]:
                future.result()
    if logs is not None:
        for bundle in group_logs:
            logs.extend(bundle)
    return sort_findings([item for item in results if item is not None])


def _rank_group(
    group: dict[str, Any],
    *,
    client: ModelClient,
    cache: LookupCache | None,
    logs: list[CallLog] | None,
    timeout_s: float | None = None,
) -> Finding:
    payload = finding_payload(group)
    floor, floor_why = floor_decision(group)
    ref0 = group["rows"][0][0]
    if tranco_checked_safe(ref0, group["evidence"]) and floor is None:
        rank = group["evidence"].get("tranco_rank")
        parsed = RankModelOut(
            severity="info",
            risk=f"Checked and safe. Tranco rank {rank}.",
            fix="remove dead reference",
            uncertain_about="",
            blast_radius=payload["classified_blast_radius"],
            blast_override_reason="",
        )
        return _finding_from_rank(
            group=group,
            payload=payload,
            parsed=parsed,
            floor=floor,
            floor_why=floor_why,
            cost_total=0.0,
        )
    if skip_model_rank(group):
        return _template_finding(group, deadline=False)
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
        if ownership_claim_without_fact(parsed.risk, group["evidence"]):
            problems.append("ownership change claimed without a code fact")
        if risk_contradicts_rule(parsed.risk, floor_why):
            problems.append("risk contradicts the finding's rule note")
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
                timeout_s=timeout_s,
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

    finding = _finding_from_rank(
        group=group,
        payload=payload,
        parsed=None,
        floor=floor,
        floor_why=floor_why,
        cost_total=cost_total,
        needs_review=True,
    )
    return finding.model_copy(
        update={"explained_by": "template", "risk": template_risk(group)}
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
    uncertain = _github_owner_note(uncertain, evidence)
    level = finding_evidence_level(group)
    if parsed is None:
        if level == "likely":
            risk = likely_risk(group)
            model_severity = "medium"
        elif level == "proven" and is_proven_ownership(evidence) and not is_claimable(evidence):
            risk = reregistered_risk(group)
    final, raised = apply_floor(model_severity, floor)
    floor_reason = floor_why if raised else ""
    action_ref = ""
    action_sha_pinned = None
    for ref, _cl, _inv in group["rows"]:
        if ref.action_ref:
            action_ref = ref.action_ref
            action_sha_pinned = ref.action_sha_pinned
            break
    finding = Finding(
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
        fix=choose_fix(evidence, model_fix, final, group["rows"]),
        uncertain_about=uncertain,
        needs_review=needs_review,
        floor_applied=raised,
        floor_reason=floor_reason,
        evidence=evidence,
        evidence_line=evidence_line(group),
        cost_usd=cost_total,
        locations=_reference_locations(group),
        action_ref=action_ref,
        action_sha_pinned=action_sha_pinned,
        evidence_level=level,
    )
    from scanner.copy import decorate
    from scanner.inert import is_inert_path

    if _pages_host_from_group(group):
        owner = evidence.get("github_owner") or {}
        if str(owner.get("status", "")).lower() in {"exists", "ok"}:
            repo = evidence.get("github_repo") or {}
            cap = "low" if str(repo.get("status", "")).lower() == "missing" else "info"
            login = github_login(group["rows"][0][0]) if group.get("rows") else ""
            note = (
                f"only {login} can recreate it"
                if cap == "low"
                else "GitHub account still exists"
            )
            if SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[cap]:
                finding = finding.model_copy(
                    update={
                        "severity": cap,
                        "final_severity": cap,
                        "ceiling_note": note,
                    }
                )
    if group["rows"] and all(is_inert_path(ref.file) for ref, _cl, _inv in group["rows"]):
        if is_claimable(evidence):
            if SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER["low"]:
                finding = finding.model_copy(
                    update={"severity": "low", "final_severity": "low", "ceiling_note": "inert file"}
                )
        elif finding.severity in FIX_TODAY:
            finding = finding.model_copy(
                update={"severity": "info", "final_severity": "info", "ceiling_note": "inert file"}
            )
    platform = evidence.get("platform_takeover") or {}
    if (
        takeover_is_proven(evidence)
        and str(platform.get("takeover") or "") != "vulnerable"
        and SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER["low"]
    ):
        finding = finding.model_copy(
            update={
                "severity": "low",
                "final_severity": "low",
                "ceiling_note": "edge-case platform takeover is review",
            }
        )
    if _all_plain_links(group) and SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER["medium"]:
        domain = str(group.get("target") or finding.target)
        finding = finding.model_copy(
            update={
                "severity": "medium",
                "final_severity": "medium",
                "risk": LINK_CLICK_RISK.format(domain=domain),
                "ceiling_note": "plain link",
            }
        )
    from scanner.sanity import has_proven_fact, unexplained_tranco_fix_today

    names = [str(finding.target), str(group.get("target") or "")]
    for ref, _cl, _inv in group.get("rows") or []:
        names.extend([ref.host_or_bucket, ref.domain])
    if unexplained_tranco_fix_today([finding]) and not has_proven_fact(
        evidence, names
    ):
        finding = finding.model_copy(
            update={
                "severity": "info",
                "final_severity": "info",
                "ceiling_note": "popular domain without a proven takeover fact",
            }
        )
    if finding.severity in FIX_TODAY and not fix_today_allowed(group):
        finding = finding.model_copy(
            update={
                "severity": "low",
                "final_severity": "low",
                "ceiling_note": "not claimable in an executing position",
            }
        )
    return decorate(finding)


async def scan(
    source: str,
    *,
    client: ModelClient,
    cache: LookupCache,
    ctx: ToolContext | None = None,
    hydrate_only: bool = True,
    cost_cap: float = SCAN_COST_CAP_USD,
    on_event: OnEvent | None = None,
    clock: ScanClock | None = None,
    code_only: bool = False,
) -> list[Finding]:
    outcome = await run_scan(
        source,
        client=client,
        cache=cache,
        ctx=ctx,
        hydrate_only=hydrate_only,
        cost_cap=cost_cap,
        on_event=on_event,
        clock=clock,
        code_only=code_only,
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
    clock: ScanClock | None = None,
    code_only: bool = False,
) -> ScanOutcome:
    clock = clock or ScanClock()
    skipped: list[str] = []
    code_only_hosts: list[str] = []
    origin_owner = ""
    origin_repo = ""
    file_texts: dict[str, str] = {}
    source_html = ""
    clock.begin_stage("extract")
    from scanner.copy import set_owned_names

    if is_website_source(source):
        extracted_web = await extract_website_scan(source)
        refs = extracted_web.references
        source_html = extracted_web.html
        file_texts["index.html"] = extracted_web.html
        web_cov = website_coverage()
        web_cov.ignored_non_hosts = extracted_web.ignored_non_hosts
        coverage = web_cov.as_dict()
        set_owned_names([])
    else:
        # Cloning and reading a repository blocks; keep it off the event loop so
        # the scan's own SSE stream keeps flowing while it runs.
        extracted = await asyncio.to_thread(extract_scan, source)
        refs = extracted.references
        coverage = extracted.coverage.as_dict()
        origin_owner = extracted.github_owner
        origin_repo = extracted.github_repo
        file_texts = dict(extracted.file_texts)
        set_owned_names(extracted.owned_names)
    actionable = sum(1 for item in refs if item.filter_reason is None)
    emit(
        on_event,
        {
            "type": "extracted",
            "references": len(refs),
            "actionable": actionable,
            "filtered": len(refs) - actionable,
            "coverage": coverage,
        },
    )
    class_logs: list[CallLog] = []
    clock.begin_stage("classify")
    classified = await asyncio.to_thread(
        classify,
        refs,
        client=client,
        include_filtered=True,
        cache=cache,
        logs=class_logs,
        clock=clock,
        skipped=skipped,
        code_only_hosts=code_only_hosts,
        code_only=code_only,
    )
    pairs = list(zip(refs, classified, strict=True))
    if is_website_source(source):
        pairs = apply_website_roles(pairs)
    ctx = ctx or ToolContext(cache=cache)
    investigations: list[Investigation] = []
    cached_rows = (
        rows_from_lookup_cache(pairs, cache, complete=not allow_partial_cache)
        if hydrate_only
        else None
    )
    clock.begin_stage("agent")
    if cached_rows is not None:
        rows = cached_rows
    else:
        investigations = await investigate(
            pairs,
            client=client,
            ctx=ctx,
            cost_cap=cost_cap,
            on_event=on_event,
            clock=clock,
            skipped_hosts=skipped,
            code_only_hosts=code_only_hosts,
            github_owner=origin_owner,
            github_repo=origin_repo,
            code_only=code_only,
        )
        inv_by_loc = {(item.file, item.line): item for item in investigations}
        rows = [
            (ref, cl, inv_by_loc[(ref.file, ref.line)])
            for ref, cl in pairs
            if (ref.file, ref.line) in inv_by_loc
        ]
    rank_logs: list[CallLog] = []
    if cached_rows is not None:
        blame_left = (
            clock.remaining_stage() if clock.stage == "agent" else clock.remaining_total()
        )
        budget = min(OWNERSHIP_BLAME_BUDGET_S, max(0.0, blame_left))
        await attach_changed_hands(
            rows,
            github_owner=origin_owner,
            github_repo=origin_repo,
            ctx=ctx,
            budget_s=budget,
        )
    clock.begin_stage("rank")
    fallbacks: list[str] = []
    findings = await asyncio.to_thread(
        rank,
        rows,
        client=client,
        cache=cache,
        logs=rank_logs,
        on_event=on_event,
        clock=clock,
        skipped=skipped,
        fallbacks=fallbacks,
        code_only=code_only,
    )
    clock.end_stage()
    budget = sorted(
        {
            item.host_or_bucket
            for item in investigations
            if item.status == "budget"
        }
    )
    unique_skipped = sorted(set(skipped))
    unique_code_only = sorted(set(code_only_hosts) | set(fallbacks))
    if unique_skipped:
        log.warning(
            "scan skipped %s because %s",
            unique_skipped,
            clock.skip_events or ["unknown stage ran out of time"],
        )
    log.info(
        "classify split rules=%s model=%s",
        clock.classify_rule_n,
        clock.classify_model_n,
    )
    agent_runs = sum(1 for item in investigations if item.trace)
    agent_tool_calls = sum(
        1 for item in investigations for event in item.trace if event.kind == "act"
    )
    return ScanOutcome(
        findings=findings,
        investigations=investigations,
        classify_cost_usd=sum(log.cost_usd for log in class_logs),
        agent_cost_usd=sum(item.cost_usd for item in investigations),
        rank_cost_usd=sum(log.cost_usd for log in rank_logs),
        budget_targets=budget,
        skipped_targets=unique_skipped,
        code_only_targets=unique_code_only,
        skip_reasons=list(clock.skip_events),
        classify_rule_n=clock.classify_rule_n,
        classify_model_n=clock.classify_model_n,
        agent_runs=agent_runs,
        agent_tool_calls=agent_tool_calls,
        rank_fallbacks=len(set(fallbacks)),
        partial=bool(unique_skipped),
        stage_seconds=dict(clock.stage_seconds),
        coverage=coverage,
        file_texts=file_texts,
        source_html=source_html,
        code_only=code_only,
        muse_overloaded=muse_overloaded(),
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
        evidence: dict[str, Any] = {
            "bucket_probe": hit,
            "tranco_rank": tranco_rank(ref.domain or ""),
        }
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
        return {
            "github_owner": hit,
            "tranco_rank": tranco_rank(ref.domain or ""),
        }
    if is_github_action_ref(ref):
        login = github_login(ref)
        if not login:
            return None
        owner = cache.get_json(f"github_owner:{login.lower()}")
        repo = cache.get_json(
            f"github_repo:{ref.action_owner.lower()}/{ref.action_repo.lower()}"
        )
        if owner is None or repo is None:
            return None
        return {
            "github_owner": owner,
            "github_repo": repo,
            "tranco_rank": tranco_rank(ref.domain or ""),
        }
    dns = cache.get_json(f"dns:{ref.host_or_bucket.lower()}")
    if dns is None:
        return None
    evidence = {"dns": dns, "tranco_rank": tranco_rank(ref.domain or "")}
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
        evidence["tranco_rank"] = tranco_rank(ref.domain or "")
        if tranco_checked_safe(ref, evidence):
            rank = evidence["tranco_rank"]
            rows.append(
                (
                    ref,
                    cl,
                    Investigation(
                        file=ref.file,
                        line=ref.line,
                        host_or_bucket=ref.host_or_bucket,
                        status="done",
                        summary=f"Tranco rank {rank}",
                        evidence=evidence,
                    ),
                )
            )
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
