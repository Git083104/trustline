from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, AsyncIterator

from scanner.events import finding_public
from scanner.report import ScanOutcome


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

    def emit(self, payload: dict[str, Any]) -> None:
        event = {
            **payload,
            "scan_id": self.scan_id,
            "ts": time.time(),
        }
        self.events.append(event)
        waiters, self._waiters = self._waiters, []
        for waiter in waiters:
            waiter.set()

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
            "findings": [finding_public(item) for item in outcome.findings],
        }
        self.status = "done"
        self.emit(
            {
                "type": "done",
                "finding_count": len(outcome.findings),
                "cost_usd": outcome.cost_usd,
                "classify_cost_usd": outcome.classify_cost_usd,
                "agent_cost_usd": outcome.agent_cost_usd,
                "rank_cost_usd": outcome.rank_cost_usd,
                "budget_targets": outcome.budget_targets,
            }
        )

    def fail(self, message: str) -> None:
        self.status = "error"
        self.error = message
        self.emit({"type": "error", "message": message})

    async def stream(self) -> AsyncIterator[dict[str, Any]]:
        index = 0
        while True:
            while index < len(self.events):
                event = self.events[index]
                index += 1
                yield event
                if event["type"] in {"done", "error"}:
                    return
            waiter = asyncio.Event()
            self._waiters.append(waiter)
            await waiter.wait()


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}

    def add(self, job: Job) -> None:
        self._jobs[job.scan_id] = job

    def get(self, scan_id: str) -> Job | None:
        return self._jobs.get(scan_id)
