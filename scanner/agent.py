from __future__ import annotations

import asyncio
import json
from typing import Any

from scanner.config import (
    AGENT_MODEL,
    AGENT_REASONING_EFFORT,
    EXPIRY_INVESTIGATE_DAYS,
    MAX_AGENT_TOOL_CALLS,
    MAX_INVESTIGATION_CONCURRENCY,
    SCAN_COST_CAP_USD,
)
from scanner.llm import CallLog, ModelClient, ToolTurn, cost_usd
from scanner.llm import _tokens
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
    "matches a listed platform; those results are in the first message. "
    "tranco_rank is popularity context only: never use it to lower a claimable-now "
    "or compromised finding. Each turn pick exactly one tool. Call done(summary) "
    "when finished. Do not invent dates, DNS results, or HTTP statuses."
)

BUDGET_NOTE = "not investigated (budget)"


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


def _attach_tranco(ref: Reference, evidence: dict[str, Any]) -> dict[str, Any]:
    evidence["tranco_rank"] = tranco_rank(ref.domain or "")
    return evidence


def tranco_checked_safe(ref: Reference, evidence: dict[str, Any]) -> bool:
    rank = evidence.get("tranco_rank")
    if not isinstance(rank, int) or rank > TOP_SAFE_RANK:
        return False
    dns = evidence.get("dns") or {}
    if str(dns.get("status", "")).lower() != "resolves":
        return False
    if has_hard_signal(evidence):
        return False
    if compromised_status(ref.host_or_bucket, ref.domain):
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
    return has_hard_signal(evidence) or cl.blast_radius >= 1


async def investigate(
    pairs: list[tuple[Reference, Classification]],
    *,
    client: ModelClient,
    ctx: ToolContext,
    cost_cap: float = SCAN_COST_CAP_USD,
    max_concurrent: int = MAX_INVESTIGATION_CONCURRENCY,
    on_event: OnEvent | None = None,
) -> list[Investigation]:
    actionable = [(ref, cl) for ref, cl in pairs if ref.filter_reason is None]
    checked: list[tuple[Reference, Classification, dict[str, Any]]] = []
    for ref, cl in actionable:
        evidence = await precheck(ref, cl, ctx)
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
    skipped: list[Investigation] = []
    for ref, cl, evidence in checked:
        if tranco_checked_safe(ref, evidence):
            rank = evidence["tranco_rank"]
            skipped.append(
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
        return skipped

    results: list[Investigation | None] = [None] * len(eligible)
    spent = 0.0
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(max_concurrent)

    async def worker(
        index: int, item: tuple[Reference, Classification, dict[str, Any]]
    ) -> None:
        nonlocal spent
        ref, cl, evidence = item
        async with sem:
            async with lock:
                if spent >= cost_cap:
                    results[index] = _budget_skip(ref, cl)
                    return
            inv = await investigate_one(
                ref,
                cl,
                client=client,
                ctx=ctx,
                evidence=evidence,
                on_event=on_event,
            )
            async with lock:
                spent += inv.cost_usd
            results[index] = inv

    await asyncio.gather(*(worker(i, item) for i, item in enumerate(eligible)))
    return skipped + [item for item in results if item is not None]


async def investigate_one(
    ref: Reference,
    cl: Classification,
    *,
    client: ModelClient,
    ctx: ToolContext,
    evidence: dict[str, Any] | None = None,
    on_event: OnEvent | None = None,
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
        turn, log = await asyncio.to_thread(_model_turn, client, messages, tools)
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


def _model_turn(
    client: ModelClient,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
) -> tuple[ToolTurn, CallLog]:
    turn = client.complete_turn(
        model=AGENT_MODEL,
        system=AGENT_SYSTEM_PROMPT,
        messages=messages,
        tools=tools,
        reasoning_effort=AGENT_REASONING_EFFORT,
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
