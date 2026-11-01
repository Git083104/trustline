from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from api.classify_target import TargetError, classify_target
from api.demo import demo_gap_ms, demo_report, load_demo
from api.jobs import Job, JobStore
from api.limits import LimitsStore, client_ip
from scanner.config import SCAN_COST_CAP_USD
from scanner.llm import LiveModelClient, ModelClient, redact_secrets
from scanner.lookups import LookupCache, default_cache
from scanner.report import ScanOutcome, run_scan
from scanner.tools import ToolContext

ScanRunner = Callable[..., Awaitable[ScanOutcome]]


class ScanIn(BaseModel):
    target: str
    kind: Literal["repo", "path", "website"] | None = None


def _cors_origins() -> list[str]:
    raw = os.environ.get("TRUSTMAP_CORS_ORIGINS", "*")
    if raw.strip() == "*":
        return ["*"]
    return [item.strip() for item in raw.split(",") if item.strip()]


def _sse(event: dict[str, Any]) -> str:
    return f"data: {json.dumps(event)}\n\n"


def create_app(
    *,
    model_client: ModelClient | None = None,
    cache: LookupCache | None = None,
    ctx: ToolContext | None = None,
    cost_cap: float = SCAN_COST_CAP_USD,
    runner: ScanRunner | None = None,
    limits: LimitsStore | None = None,
) -> FastAPI:
    app = FastAPI(title="Trustmap")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_methods=["*"],
        allow_headers=["*"],
    )
    store = JobStore()
    running: set[asyncio.Task] = set()
    app.state.store = store
    scan_runner = runner or run_scan
    client_holder: dict[str, ModelClient | None] = {"client": model_client}
    lookup_default = cache or default_cache()
    limit_store = limits or LimitsStore(lookup_default.path)

    def client() -> ModelClient:
        held = client_holder["client"]
        if held is None:
            held = LiveModelClient()
            client_holder["client"] = held
        return held

    @app.get("/api/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/api/scan/demo")
    def demo() -> dict[str, Any]:
        return demo_report()

    @app.get("/api/scan/demo/events")
    async def demo_events(
        speed: str | None = Query(default=None),
    ) -> StreamingResponse:
        try:
            gap_ms = demo_gap_ms(speed)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        payload = load_demo()
        events = list(payload["events"])

        async def gen() -> AsyncIterator[str]:
            for index, event in enumerate(events):
                if index and gap_ms:
                    await asyncio.sleep(gap_ms / 1000)
                yield _sse(event)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.post("/api/scan", response_model=None)
    async def start_scan(body: ScanIn, request: Request):
        try:
            kind, target = classify_target(body.target, body.kind)
        except TargetError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.body)
        ip = client_ip(request, hops=limit_store.trusted_hops)
        job = Job(kind=kind, target=target)
        blocked = limit_store.admit(ip, job.scan_id, cost_cap)
        if blocked:
            return JSONResponse(status_code=429, content={"error": blocked})
        store.add(job)
        job.emit(
            {
                "type": "started",
                "kind": kind,
                "target": target,
                "cost_cap_usd": cost_cap,
            }
        )
        task = asyncio.create_task(_run_job(job))
        running.add(task)
        task.add_done_callback(running.discard)
        return {"scan_id": job.scan_id, "kind": kind, "target": target}

    async def _run_job(job: Job) -> None:
        def on_event(payload: dict[str, Any]) -> None:
            job.emit(payload)

        actual = 0.0
        try:
            lookup = cache or lookup_default
            outcome = await scan_runner(
                job.target,
                client=client(),
                cache=lookup,
                ctx=ctx or ToolContext(cache=lookup),
                hydrate_only=False,
                cost_cap=cost_cap,
                on_event=on_event,
            )
            actual = outcome.cost_usd
            job.finish(outcome)
        except Exception as exc:
            job.fail(redact_secrets(str(exc)))
        finally:
            limit_store.reconcile(job.scan_id, actual)

    @app.get("/api/scan/{scan_id}/events")
    async def scan_events(scan_id: str) -> StreamingResponse:
        job = store.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown scan")

        async def gen() -> AsyncIterator[str]:
            async for event in job.stream():
                yield _sse(event)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/api/scan/{scan_id}", response_model=None)
    def scan_report(scan_id: str):
        job = store.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown scan")
        if job.status == "running":
            raise HTTPException(status_code=409, detail="scan still running")
        if job.status == "error":
            return JSONResponse(
                status_code=500,
                content={
                    "scan_id": job.scan_id,
                    "status": "error",
                    "error": job.error,
                },
            )
        assert job.report is not None
        return job.report

    return app


app = create_app
