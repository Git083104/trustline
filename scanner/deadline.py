from __future__ import annotations

import os
import time

from scanner.config import (
    AGENT_DEADLINE_S,
    CLASSIFY_DEADLINE_S,
    LLM_REQUEST_TIMEOUT_S,
    RANK_DEADLINE_S,
    SCAN_DEADLINE_S,
)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return float(raw)


class DeadlineExceeded(TimeoutError):
    pass


class ScanClock:
    def __init__(
        self,
        total_s: float | None = None,
        classify_s: float | None = None,
        agent_s: float | None = None,
        rank_s: float | None = None,
        request_cap_s: float | None = None,
    ) -> None:
        self.total_s = (
            total_s
            if total_s is not None
            else _env_float("TRUSTMAP_SCAN_DEADLINE_S", SCAN_DEADLINE_S)
        )
        self.stage_limits = {
            "classify": classify_s
            if classify_s is not None
            else _env_float("TRUSTMAP_CLASSIFY_DEADLINE_S", CLASSIFY_DEADLINE_S),
            "agent": agent_s
            if agent_s is not None
            else _env_float("TRUSTMAP_AGENT_DEADLINE_S", AGENT_DEADLINE_S),
            "rank": rank_s
            if rank_s is not None
            else _env_float("TRUSTMAP_RANK_DEADLINE_S", RANK_DEADLINE_S),
        }
        self.request_cap_s = (
            request_cap_s
            if request_cap_s is not None
            else _env_float("TRUSTMAP_LLM_TIMEOUT_S", LLM_REQUEST_TIMEOUT_S)
        )
        self.started = time.monotonic()
        self.stage = ""
        self.stage_started = self.started
        self.stage_limit = self.total_s
        self.stage_seconds: dict[str, float] = {}

    def remaining_total(self) -> float:
        return self.total_s - (time.monotonic() - self.started)

    def remaining_stage(self) -> float:
        left_stage = self.stage_limit - (time.monotonic() - self.stage_started)
        return min(left_stage, self.remaining_total())

    def begin_stage(self, name: str) -> None:
        if self.stage:
            self.stage_seconds[self.stage] = time.monotonic() - self.stage_started
        self.stage = name
        self.stage_started = time.monotonic()
        allotted = self.stage_limits.get(name, self.remaining_total())
        self.stage_limit = max(0.0, min(allotted, self.remaining_total()))

    def end_stage(self) -> None:
        if self.stage:
            self.stage_seconds[self.stage] = time.monotonic() - self.stage_started
            self.stage = ""

    def expired(self) -> bool:
        return self.remaining_stage() <= 0.05

    def request_timeout(self) -> float:
        return max(0.0, min(self.request_cap_s, self.remaining_stage()))
