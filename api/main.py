from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import ipaddress

from api.classify_target import TargetError, classify_target
from api.demo import demo_report, demo_waits_ms, load_demo
from api.jobs import Job, JobStore
from api.limits import LimitsStore, client_ip
from scanner.config import SCAN_COST_CAP_USD
from scanner.ssrf import SCAN_BLOCKED, ScanBlockedError, parse_public_url, refuse_blocked_ips
from scanner.llm import LiveModelClient, ModelClient, failure_message, redact_secrets  # noqa: F401
from scanner.lookups import LookupCache, default_cache
from scanner.report import ScanOutcome, run_scan
from scanner.tools import ToolContext

ScanRunner = Callable[..., Awaitable[ScanOutcome]]
STATIC = Path(__file__).resolve().parent / "static"
LIVE_UNCONFIGURED = "Live scans aren't configured; try the demo"
log = logging.getLogger("trustline")


def warn_ephemeral_ledger(path: Path) -> None:
    serverless = bool(
        os.environ.get("VERCEL")
        or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        or os.environ.get("NETLIFY")
    )
    resolved = str(path.resolve())
    in_tmp = (
        resolved.startswith("/tmp")
        or resolved.startswith("/private/tmp")
        or "/tmp/" in resolved
    )
    if serverless and in_tmp:
        log.warning(
            "Running serverless with the spend ledger at %s; "
            "limits reset between invocations",
            path,
        )


def _load_local_env() -> None:
    for candidate in (Path(".env"), Path(__file__).resolve().parents[1] / ".env"):
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            return


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


def _refuse_blocked_website(target: str) -> None:
    try:
        _scheme, host, _port, _path = parse_public_url(target)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if host.lower() in {"localhost", "metadata.google.internal"}:
                raise ScanBlockedError() from None
        else:
            refuse_blocked_ips([host])
    except ScanBlockedError as exc:
        raise TargetError(400, {"error": SCAN_BLOCKED}) from exc


def create_app(
    *,
    model_client: ModelClient | None = None,
    cache: LookupCache | None = None,
    ctx: ToolContext | None = None,
    cost_cap: float = SCAN_COST_CAP_USD,
    runner: ScanRunner | None = None,
    limits: LimitsStore | None = None,
) -> FastAPI:
    _load_local_env()
    app = FastAPI(
        title="Tether",
        description="Find abandoned outside infrastructure a repository or website still trusts.",
    )
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
    warn_ephemeral_ledger(limit_store.path)

    def client() -> ModelClient:
        held = client_holder["client"]
        if held is None:
            held = LiveModelClient()
            client_holder["client"] = held
        return held

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

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
        payload = load_demo()
        events = list(payload["events"])
        try:
            waits = demo_waits_ms(events, speed)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        async def gen() -> AsyncIterator[str]:
            for index, event in enumerate(events):
                if waits[index]:
                    await asyncio.sleep(waits[index] / 1000)
                yield _sse(event)

        return StreamingResponse(gen(), media_type="text/event-stream")

    def live_ready() -> bool:
        if model_client is not None:
            return True
        return bool(os.environ.get("MODEL_API_KEY", "").strip())

    @app.post("/api/scan", response_model=None)
    async def start_scan(body: ScanIn, request: Request):
        try:
            kind, target = classify_target(body.target, body.kind)
            if kind == "website":
                _refuse_blocked_website(target)
        except TargetError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.body)
        if not live_ready():
            return JSONResponse(status_code=503, content={"error": LIVE_UNCONFIGURED})
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

    @app.post("/api/scan/stream")
    async def start_scan_stream(body: ScanIn, request: Request):
        started = await start_scan(body, request)
        if isinstance(started, JSONResponse):
            return started
        job = store.get(started["scan_id"])
        if job is None:
            raise HTTPException(status_code=500, detail="scan job missing")

        async def gen() -> AsyncIterator[str]:
            async for event in job.stream():
                yield _sse(event)

        return StreamingResponse(gen(), media_type="text/event-stream")

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
            job.fail(failure_message(exc))
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
