from __future__ import annotations

import asyncio
import json
from typing import Any

from scanner.config import (
    AGENT_MODEL,
    AGENT_REASONING_EFFORT,
    EXPIRY_INVESTIGATE_DAYS,
    LLM_REQUEST_TIMEOUT_S,
    MAX_AGENT_TOOL_CALLS,
    MAX_INVESTIGATION_CONCURRENCY,
    PRECHECK_CONCURRENCY,
    SCAN_COST_CAP_USD,
)
from scanner.deadline import ScanClock
from scanner.llm import CallLog, ModelClient, ToolTurn, cost_usd
from scanner.llm import _run_timed, _tokens
from scanner.lookups import consistent_evidence
from scanner.models import (
    Classification,
    Investigation,
    Reference,
    TraceEvent,
)
from scanner.events import OnEvent, emit, summarize
from scanner.compromised import compromised_status
from scanner.extract import (
    github_login,
    is_bucket_ref as _is_bucket_ref,
    is_github_action_ref,
    is_github_owner_ref,
)
from scanner.tools.platform_takeover import matching_platform
from scanner.tools import ToolContext, definitions, run as run_tool
from scanner.tranco import TOP_SAFE_RANK, tranco_rank

AGENT_SYSTEM_PROMPT = (
    "You investigate one outside reference for takeover risk. "
    "Code already ran dns and rdap for hosts, bucket_probe for buckets, "
    "github_owner for GitHub accounts, and platform_takeover when a host or CNAME "
    "matches a listed platform; those results are in the first message and decide "
    "severity. Confirm those facts. Gather context with live_fetch, cert_history, "
    "wayback, or ownership tools when useful. "
    "tranco_rank is popularity context only: never use it to lower a claimable-now "
    "or compromised finding. Each turn pick exactly one tool. Call done(summary) "
    "when finished: say where the reference executes and what an attacker gains if "
    "they claim it. Do not invent dates, DNS results, or HTTP statuses."
)

BUDGET_NOTE = "not investigated (budget)"
DEADLINE_NOTE = "not investigated (deadline)"
PRECHECK_NOTE = "precheck conclusive"


def _bucket_provider(raw: str) -> str:
    lowered = raw.lower()
    if "storage.googleapis.com" in lowered:
        return "gcs"
    if "blob.core.windows.net" in lowered:
        return "azure"
    return "s3"


def has_hard_signal(evidence: dict[str, Any]) -> bool:
    evidence = consistent_evidence(evidence)
    bucket = evidence.get("bucket_probe") or {}
    if bucket.get("status") == "NoSuchBucket":
        return True
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() == "missing":
        return True
    repo = evidence.get("github_repo") or {}
    if str(repo.get("status", "")).lower() == "missing":
        return True
    platform = evidence.get("platform_takeover") or {}
    if str(platform.get("status", "")).lower() == "unclaimed":
        return True
    dns = evidence.get("dns") or {}
    if str(dns.get("status", "")).lower() == "nxdomain":
        return True
    rdap = evidence.get("rdap") or {}
    if str(rdap.get("status", "")).lower() == "unregistered":
        return True
    days = rdap.get("days_to_expiry")
    if isinstance(days, int) and days <= EXPIRY_INVESTIGATE_DAYS:
        return True
    return False


def precheck_conclusive(ref: Reference, evidence: dict[str, Any]) -> bool:
    if compromised_status(ref.host_or_bucket, ref.domain):
        return True
    evidence = consistent_evidence(evidence)
    bucket = evidence.get("bucket_probe") or {}
    if bucket.get("status") == "NoSuchBucket":
        return True
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() == "missing":
        return True
    repo = evidence.get("github_repo") or {}
    if str(repo.get("status", "")).lower() == "missing":
        return True
    platform = evidence.get("platform_takeover") or {}
    if str(platform.get("status", "")).lower() == "unclaimed":
        return True
    dns = evidence.get("dns") or {}
    if str(dns.get("status", "")).lower() == "nxdomain":
        return True
    rdap = evidence.get("rdap") or {}
    return str(rdap.get("status", "")).lower() == "unregistered"


def _tranco_domain(ref: Reference) -> str:
    if ref.domain:
        return ref.domain
    # Action refs keep domain empty so github.com is not allowlist-filtered.
    if is_github_action_ref(ref) or is_github_owner_ref(ref):
        return "github.com"
    return ""


def _attach_tranco(ref: Reference, evidence: dict[str, Any]) -> dict[str, Any]:
    evidence["tranco_rank"] = tranco_rank(_tranco_domain(ref))
    return evidence


def tranco_checked_safe(ref: Reference, evidence: dict[str, Any]) -> bool:
    rank = evidence.get("tranco_rank")
    if not isinstance(rank, int):
        rank = tranco_rank(_tranco_domain(ref))
    if not isinstance(rank, int) or rank > TOP_SAFE_RANK:
        return False
    dns = evidence.get("dns") or {}
    repo = evidence.get("github_repo") or {}
    dns_ok = str(dns.get("status", "")).lower() == "resolves"
    repo_live = str(repo.get("status", "")).lower() == "exists"
    # GitHub Action precheck records the repo, not DNS; a live repo on a
    # Tranco-listed host is still a code verdict.
    if not dns_ok and not repo_live:
        return False
    if has_hard_signal(evidence):
        return False
    if compromised_status(ref.host_or_bucket, ref.domain or _tranco_domain(ref)):
        return False
    return True


async def precheck(
    ref: Reference, cl: Classification, ctx: ToolContext
) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    if cl.type == "bucket" or _is_bucket_ref(ref):
        evidence["bucket_probe"] = await run_tool(
            "bucket_probe",
            {
                "name": ref.host_or_bucket,
                "provider": _bucket_provider(ref.raw),
            },
            ctx,
        )
        return _attach_tranco(ref, evidence)
    if is_github_action_ref(ref):
        login = github_login(ref)
        if login:
            evidence["github_owner"] = await run_tool(
                "github_owner", {"owner": login}, ctx
            )
        evidence["github_repo"] = (
            await ctx.github_repo(
                ref.action_owner, ref.action_repo, cache=ctx.cache
            )
        ).model_dump(mode="json")
        return _attach_tranco(ref, evidence)
    if is_github_owner_ref(ref):
        login = github_login(ref)
        if login:
            evidence["github_owner"] = await run_tool(
                "github_owner", {"owner": login}, ctx
            )
        return _attach_tranco(ref, evidence)
    evidence["dns"] = await run_tool("dns", {"host": ref.host_or_bucket}, ctx)
    domain = ref.domain or ""
    if domain:
        evidence["rdap"] = await run_tool("rdap", {"domain": domain}, ctx)
    dns = evidence.get("dns") or {}
    cnames = list(dns.get("cnames") or [])
    if matching_platform(ref.host_or_bucket, cnames):
        evidence["platform_takeover"] = await run_tool(
            "platform_takeover",
            {
                "host": ref.host_or_bucket,
                "cnames": cnames,
                "dns_status": dns.get("status"),
            },
            ctx,
        )
    login = github_login(ref)
    if login:
        evidence["github_owner"] = await run_tool(
            "github_owner", {"owner": login}, ctx
        )
    return _attach_tranco(ref, consistent_evidence(evidence))


def should_investigate(ref: Reference, cl: Classification, evidence: dict[str, Any]) -> bool:
    if ref.filter_reason is not None:
        return False
    if tranco_checked_safe(ref, evidence) and not precheck_conclusive(ref, evidence):
        return False
    if cl.runs_in == "docs_only" and not precheck_conclusive(ref, evidence):
        return False
    if cl.blast_radius == 0 and not precheck_conclusive(ref, evidence):
        hands = evidence.get("changed_hands") or {}
        if not hands.get("reregistered_after_reference") and not hands.get("supporting"):
            return False
    return (
        precheck_conclusive(ref, evidence)
        or has_hard_signal(evidence)
        or bool((evidence.get("changed_hands") or {}).get("reregistered_after_reference"))
        or bool((evidence.get("changed_hands") or {}).get("supporting"))
        or cl.blast_radius >= 1
    )


def _precheck_key(ref: Reference, cl: Classification) -> tuple:
    """Everything precheck() reads. Two references sharing this get one lookup."""
    is_bucket = cl.type == "bucket" or _is_bucket_ref(ref)
    return (
        cl.type,
        ref.host_or_bucket,
        ref.domain or "",
        ref.action_owner or "",
        ref.action_repo or "",
        _bucket_provider(ref.raw) if is_bucket else "",
        is_github_action_ref(ref),
        is_github_owner_ref(ref),
    )


def _target_key(ref: Reference, cl: Classification) -> tuple:
    """A takeover is a property of the target, not of each line that names it."""
    return (ref.host_or_bucket, cl.type, cl.runs_in, cl.blast_radius)


async def _precheck_all(
    actionable: list[tuple[Reference, Classification]], ctx: ToolContext
) -> dict[tuple, dict[str, Any]]:
    leads: dict[tuple, tuple[Reference, Classification]] = {}
    for ref, cl in actionable:
        leads.setdefault(_precheck_key(ref, cl), (ref, cl))
    sem = asyncio.Semaphore(PRECHECK_CONCURRENCY)

    async def one(key: tuple) -> tuple[tuple, dict[str, Any]]:
        ref, cl = leads[key]
        async with sem:
            return key, await precheck(ref, cl, ctx)

    return dict(await asyncio.gather(*(one(key) for key in leads)))


async def investigate(
    pairs: list[tuple[Reference, Classification]],
    *,
    client: ModelClient,
    ctx: ToolContext,
    cost_cap: float = SCAN_COST_CAP_USD,
    max_concurrent: int = MAX_INVESTIGATION_CONCURRENCY,
    on_event: OnEvent | None = None,
    clock: ScanClock | None = None,
    skipped_hosts: list[str] | None = None,
    github_owner: str = "",
    github_repo: str = "",
) -> list[Investigation]:
    actionable = [(ref, cl) for ref, cl in pairs if ref.filter_reason is None]
    evidence_by_key = await _precheck_all(actionable, ctx)
    checked: list[tuple[Reference, Classification, dict[str, Any]]] = []
    for ref, cl in actionable:
        evidence = dict(evidence_by_key[_precheck_key(ref, cl)])
        checked.append((ref, cl, evidence))
        emit(
            on_event,
            {
                "type": "precheck",
                "target": _event_target(ref, cl),
                "kind": _event_kind(ref, cl),
                "hard_signal": has_hard_signal(evidence),
            },
        )
    eligible: list[tuple[Reference, Classification, dict[str, Any]]] = []
    held: list[Investigation] = []
    for ref, cl, evidence in checked:
        if tranco_checked_safe(ref, evidence) and not precheck_conclusive(ref, evidence):
            rank = evidence["tranco_rank"]
            held.append(
                Investigation(
                    file=ref.file,
                    line=ref.line,
                    host_or_bucket=ref.host_or_bucket,
                    status="done",
                    summary=f"Tranco rank {rank}",
                    evidence=evidence,
                )
            )
            continue
        if should_investigate(ref, cl, evidence):
            eligible.append((ref, cl, evidence))
    if not eligible:
        return held

    results: list[Investigation | None] = [None] * len(eligible)
    spent = 0.0
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(max_concurrent)

    # One agent run per target, not per line that names it. A repo that
    # references the same host from forty places asked the same question forty
    # times; the answer is about the host, so it is asked once and shared.
    groups: dict[tuple, list[int]] = {}
    for index, (ref, cl, _) in enumerate(eligible):
        groups.setdefault(_target_key(ref, cl), []).append(index)

    def share(inv: Investigation, index: int) -> Investigation:
        ref, cl, _ = eligible[index]
        return inv.model_copy(
            update={"file": ref.file, "line": ref.line, "cost_usd": 0.0}
        )

    async def worker(members: list[int]) -> None:
        nonlocal spent
        lead = members[0]
        ref, cl, evidence = eligible[lead]
        async with sem:
            async with lock:
                if clock is not None and clock.expired():
                    hosts = []
                    for index in members:
                        other_ref, other_cl, other_ev = eligible[index]
                        results[index] = _deadline_skip(other_ref, other_cl, other_ev)
                        hosts.append(other_ref.host_or_bucket)
                    clock.note_skip(
                        "agent",
                        "stage budget exhausted before tool loop; kept code verdict",
                        hosts,
                    )
                    return
                if spent >= cost_cap:
                    for index in members:
                        other_ref, other_cl, _ = eligible[index]
                        results[index] = _budget_skip(other_ref, other_cl)
                    return
            inv = await investigate_one(
                ref,
                cl,
                client=client,
                ctx=ctx,
                evidence=evidence,
                on_event=on_event,
                clock=clock,
            )
            async with lock:
                spent += inv.cost_usd
            results[lead] = inv
            for index in members[1:]:
                results[index] = share(inv, index)

    def _prio(members: list[int]) -> int:
        ref, _cl, evidence = eligible[members[0]]
        if precheck_conclusive(ref, evidence):
            return 0
        hands = evidence.get("changed_hands") or {}
        if hands.get("reregistered_after_reference") or hands.get("supporting"):
            return 1
        return 2

    ordered = sorted(groups.values(), key=_prio)
    coros = [worker(members) for members in ordered]
    if clock is not None:
        left = max(0.05, clock.remaining_stage())
        # One tool-loop wave so rank still gets a 20s timeout.
        wave = min(left, LLM_REQUEST_TIMEOUT_S + 2.0)
        try:
            await asyncio.wait_for(asyncio.gather(*coros), timeout=wave)
        except asyncio.TimeoutError:
            hosts = []
            for index, item in enumerate(results):
                if item is not None:
                    continue
                other_ref, other_cl, other_ev = eligible[index]
                results[index] = _deadline_skip(other_ref, other_cl, other_ev)
                hosts.append(other_ref.host_or_bucket)
            if hosts:
                clock.note_skip(
                    "agent",
                    "stage budget exhausted during tool loop; kept code verdict",
                    hosts,
                )
    else:
        await asyncio.gather(*coros)
    out = held + [item for item in results if item is not None]
    if github_owner or github_repo:
        from scanner.config import OWNERSHIP_BLAME_BUDGET_S
        from scanner.ownership import attach_changed_hands

        by_loc = {(item.file, item.line): item for item in out}
        rows = [
            (ref, cl, by_loc[(ref.file, ref.line)])
            for ref, cl, _ in checked
            if (ref.file, ref.line) in by_loc
        ]
        leftover = clock.remaining_stage() if clock is not None else OWNERSHIP_BLAME_BUDGET_S
        if leftover >= LLM_REQUEST_TIMEOUT_S:
            await attach_changed_hands(
                rows,
                github_owner=github_owner,
                github_repo=github_repo,
                ctx=ctx,
                budget_s=min(OWNERSHIP_BLAME_BUDGET_S, leftover - LLM_REQUEST_TIMEOUT_S + 5),
            )
        out = [inv for _ref, _cl, inv in rows]
    return out


async def investigate_one(
    ref: Reference,
    cl: Classification,
    *,
    client: ModelClient,
    ctx: ToolContext,
    evidence: dict[str, Any] | None = None,
    on_event: OnEvent | None = None,
    clock: ScanClock | None = None,
) -> Investigation:
    if evidence is None:
        evidence = await precheck(ref, cl, ctx)
    else:
        evidence = dict(evidence)

    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": json.dumps(
                {
                    "reference": {
                        "file": ref.file,
                        "line": ref.line,
                        "raw": ref.raw,
                        "host_or_bucket": ref.host_or_bucket,
                        "domain": ref.domain,
                        "type": cl.type,
                        "runs_in": cl.runs_in,
                        "blast_radius": cl.blast_radius,
                    },
                    "precomputed": evidence,
                },
                sort_keys=True,
            ),
        }
    ]
    trace: list[TraceEvent] = []
    cost_total = 0.0
    summary = ""
    tools = definitions()

    for _ in range(MAX_AGENT_TOOL_CALLS):
        if clock is not None and clock.expired():
            break
        timeout_s = clock.request_timeout() if clock is not None else None
        try:
            turn, log = await asyncio.to_thread(
                _model_turn, client, messages, tools, timeout_s
            )
        except TimeoutError:
            break
        cost_total += log.cost_usd
        trace.append(
            TraceEvent(
                kind="plan",
                tool=turn.name,
                arguments=turn.arguments,
                tokens=log.input_tokens + log.output_tokens,
                cost_usd=log.cost_usd,
                note=f"pick {turn.name}",
            )
        )
        emit(
            on_event,
            {
                "type": "plan",
                "target": _event_target(ref, cl),
                "tool": turn.name,
                "args": turn.arguments,
                "tokens": log.input_tokens + log.output_tokens,
                "cost_usd": log.cost_usd,
            },
        )
        trace.append(
            TraceEvent(
                kind="act",
                tool=turn.name,
                arguments=turn.arguments,
            )
        )
        emit(
            on_event,
            {
                "type": "act",
                "target": _event_target(ref, cl),
                "tool": turn.name,
                "args": turn.arguments,
            },
        )
        try:
            result = await run_tool(turn.name, turn.arguments, ctx)
            refused = False
        except Exception as exc:
            result = {"error": str(exc)}
            refused = True
        if turn.name != "done" and not refused:
            evidence[turn.name] = result
            evidence = consistent_evidence(evidence)
        observe = "refused" if refused else "ok"
        trace.append(
            TraceEvent(
                kind="observe",
                tool=turn.name,
                arguments=turn.arguments,
                result=result,
                note=observe,
            )
        )
        emit(
            on_event,
            {
                "type": "observe",
                "target": _event_target(ref, cl),
                "tool": turn.name,
                "args": turn.arguments,
                "result_summary": summarize(result),
                "tokens": 0,
                "cost_usd": 0.0,
            },
        )
        messages.append(
            {
                "role": "assistant",
                "content": json.dumps(
                    {"tool": turn.name, "arguments": turn.arguments}
                ),
            }
        )
        messages.append(
            {"role": "user", "content": json.dumps({"observe": observe, "result": result})}
        )
        if turn.name == "done" and not refused:
            summary = str(result.get("summary") or "")
            break

    return Investigation(
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        status="done",
        summary=summary,
        evidence=evidence,
        trace=trace,
        cost_usd=cost_total,
    )


def _event_kind(ref: Reference, cl: Classification) -> str:
    if cl.type == "bucket" or _is_bucket_ref(ref):
        return "bucket"
    return "domain"


def _event_target(ref: Reference, cl: Classification) -> str:
    if _event_kind(ref, cl) == "bucket":
        return ref.host_or_bucket
    if matching_platform(ref.host_or_bucket):
        return ref.host_or_bucket
    return ref.domain or ref.host_or_bucket


def _budget_skip(ref: Reference, cl: Classification) -> Investigation:
    return Investigation(
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        status="budget",
        summary=BUDGET_NOTE,
    )


def _deadline_skip(
    ref: Reference, cl: Classification, evidence: dict[str, Any]
) -> Investigation:
    return Investigation(
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        status="deadline",
        summary=DEADLINE_NOTE,
        evidence=evidence,
    )


def _model_turn(
    client: ModelClient,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    timeout_s: float | None = None,
) -> tuple[ToolTurn, CallLog]:
    turn = _run_timed(
        lambda: client.complete_turn(
            model=AGENT_MODEL,
            system=AGENT_SYSTEM_PROMPT,
            messages=messages,
            tools=tools,
            reasoning_effort=AGENT_REASONING_EFFORT,
            timeout_s=timeout_s,
        ),
        timeout_s,
    )
    in_tok, out_tok, usage = _tokens(turn.usage)
    log = CallLog(
        model=AGENT_MODEL,
        input_tokens=in_tok,
        output_tokens=out_tok,
        cost_usd=cost_usd(AGENT_MODEL, in_tok, out_tok),
        api_usage=usage or None,
    )
    return turn, log
