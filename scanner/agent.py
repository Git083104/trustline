from __future__ import annotations

import asyncio
import json
from typing import Any

from scanner.config import (
    AGENT_MODEL,
    AGENT_REASONING_EFFORT,
    MAX_AGENT_TOOL_CALLS,
    MAX_INVESTIGATION_CONCURRENCY,
    SCAN_COST_CAP_USD,
)
from scanner.llm import CallLog, ModelClient, ToolTurn, cost_usd
from scanner.llm import _tokens
from scanner.models import (
    Classification,
    Investigation,
    Reference,
    TraceEvent,
)
from scanner.tools import ToolContext, definitions, run as run_tool

AGENT_SYSTEM_PROMPT = (
    "You investigate one outside reference for takeover risk. "
    "Code already ran dns for hosts or bucket_probe for buckets; those results are in the "
    "first message. Each turn pick exactly one tool. Call done(summary) when finished. "
    "Do not invent dates, DNS results, or HTTP statuses."
)

BUDGET_NOTE = "not investigated (budget)"


def _bucket_provider(raw: str) -> str:
    lowered = raw.lower()
    if "storage.googleapis.com" in lowered:
        return "gcs"
    return "s3"


async def investigate(
    pairs: list[tuple[Reference, Classification]],
    *,
    client: ModelClient,
    ctx: ToolContext,
    cost_cap: float = SCAN_COST_CAP_USD,
    max_concurrent: int = MAX_INVESTIGATION_CONCURRENCY,
) -> list[Investigation]:
    eligible = [
        (ref, cl)
        for ref, cl in pairs
        if ref.filter_reason is None and cl.blast_radius >= 1
    ]
    if not eligible:
        return []

    results: list[Investigation | None] = [None] * len(eligible)
    spent = 0.0
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(max_concurrent)

    async def worker(index: int, pair: tuple[Reference, Classification]) -> None:
        nonlocal spent
        async with sem:
            async with lock:
                if spent >= cost_cap:
                    results[index] = _budget_skip(pair[0], pair[1])
                    return
            inv = await investigate_one(pair[0], pair[1], client=client, ctx=ctx)
            async with lock:
                spent += inv.cost_usd
            results[index] = inv

    await asyncio.gather(*(worker(i, pair) for i, pair in enumerate(eligible)))
    return [item for item in results if item is not None]


async def investigate_one(
    ref: Reference,
    cl: Classification,
    *,
    client: ModelClient,
    ctx: ToolContext,
) -> Investigation:
    evidence: dict[str, Any] = {}
    if cl.type == "bucket":
        provider = _bucket_provider(ref.raw)
        evidence["bucket_probe"] = await run_tool(
            "bucket_probe",
            {"name": ref.host_or_bucket, "provider": provider},
            ctx,
        )
    else:
        evidence["dns"] = await run_tool(
            "dns", {"host": ref.host_or_bucket}, ctx
        )

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
        turn, log = _model_turn(client, messages, tools)
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
        trace.append(
            TraceEvent(
                kind="act",
                tool=turn.name,
                arguments=turn.arguments,
            )
        )
        try:
            result = await run_tool(turn.name, turn.arguments, ctx)
            refused = False
        except Exception as exc:
            result = {"error": str(exc)}
            refused = True
        if turn.name != "done" and not refused:
            evidence[turn.name] = result
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
