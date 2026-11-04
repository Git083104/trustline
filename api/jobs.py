from __future__ import annotations

import asyncio
import threading
import time
import uuid
from typing import Any, AsyncIterator

from api.limits import CODE_ONLY_BANNER, OVERLOAD_BANNER
from scanner.events import finding_public
from scanner.report import ScanOutcome


def _running_loop() -> asyncio.AbstractEventLoop | None:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


class Job:
    def __init__(self, *, kind: str, target: str) -> None:
        self.scan_id = uuid.uuid4().hex[:8]
        self.kind = kind
        self.target = target
        self.status = "running"
        self.events: list[dict[str, Any]] = []
        self._waiters: list[asyncio.Event] = []
        self.report: dict[str, Any] | None = None
        self.error: str | None = None
        self.file_texts: dict[str, str] = {}
        self.findings_models: list[Any] = []
        self.code_only = False
        self._loop = _running_loop()
        self._lock = threading.Lock()

    def emit(self, payload: dict[str, Any]) -> None:
        event = {
            **payload,
            "scan_id": self.scan_id,
            "ts": time.time(),
        }
        # rank emits from a pool of threads, so the swap below must not race
        with self._lock:
            self.events.append(event)
            waiters, self._waiters = self._waiters, []
        if not waiters:
            return
        # The blocking scan stages run in a worker thread, so waking an
        # asyncio.Event has to hop back to the loop it belongs to.
        loop = self._loop
        same_thread = loop is None or _running_loop() is loop
        for waiter in waiters:
            if same_thread:
                waiter.set()
            else:
                loop.call_soon_threadsafe(waiter.set)

    def finish(self, outcome: ScanOutcome) -> None:
        self.report = {
            "scan_id": self.scan_id,
            "kind": self.kind,
            "target": self.target,
            "status": "done",
            "cost_usd": outcome.cost_usd,
            "classify_cost_usd": outcome.classify_cost_usd,
            "agent_cost_usd": outcome.agent_cost_usd,
            "rank_cost_usd": outcome.rank_cost_usd,
            "budget_targets": outcome.budget_targets,
            "skipped_targets": outcome.skipped_targets,
            "code_only_targets": outcome.code_only_targets,
            "partial": outcome.partial,
            "stage_seconds": outcome.stage_seconds,
            "coverage": outcome.coverage,
            "agent_runs": outcome.agent_runs,
            "classify_rule_n": outcome.classify_rule_n,
            "classify_model_n": outcome.classify_model_n,
            "rank_fallbacks": outcome.rank_fallbacks,
            "code_only": self.code_only or outcome.code_only or outcome.muse_overloaded,
            "code_only_banner": (
                OVERLOAD_BANNER
                if outcome.muse_overloaded
                else CODE_ONLY_BANNER
                if self.code_only or outcome.code_only
                else ""
            ),
            "muse_overloaded": outcome.muse_overloaded,
            "findings": [finding_public(item) for item in outcome.findings],
        }
        self.status = "done"
        self.file_texts = dict(outcome.file_texts)
        self.findings_models = list(outcome.findings)
        self.emit(
            {
                "type": "done",
                "finding_count": len(outcome.findings),
                "cost_usd": outcome.cost_usd,
                "classify_cost_usd": outcome.classify_cost_usd,
                "agent_cost_usd": outcome.agent_cost_usd,
                "rank_cost_usd": outcome.rank_cost_usd,
                "budget_targets": outcome.budget_targets,
                "skipped_targets": outcome.skipped_targets,
                "code_only_targets": outcome.code_only_targets,
                "partial": outcome.partial,
                "agent_runs": outcome.agent_runs,
                "rank_fallbacks": outcome.rank_fallbacks,
                "code_only": self.code_only or outcome.code_only,
            }
        )

    def fail(self, message: str) -> None:
        self.status = "error"
        self.error = message
        self.emit({"type": "error", "message": message})

    async def stream(
        self, heartbeat: float | None = None
    ) -> AsyncIterator[dict[str, Any] | None]:
        """Every event from the first, then live ones. With a heartbeat, yields None
        after that many quiet seconds so the caller can keep the connection open."""
        index = 0
        while True:
            while index < len(self.events):
                event = self.events[index]
                index += 1
                yield event
                if event["type"] in {"done", "error"}:
                    return
            self._loop = _running_loop()
            waiter = asyncio.Event()
            with self._lock:
                if len(self.events) > index:
                    continue
                self._waiters.append(waiter)
            try:
                await asyncio.wait_for(waiter.wait(), heartbeat)
            except asyncio.TimeoutError:
                yield None


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}

    def add(self, job: Job) -> None:
        self._jobs[job.scan_id] = job

    def get(self, scan_id: str) -> Job | None:
        return self._jobs.get(scan_id)
