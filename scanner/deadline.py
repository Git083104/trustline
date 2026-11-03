from __future__ import annotations

import logging
import os
import time

from scanner.config import (
    AGENT_RESERVE_S,
    LLM_REQUEST_TIMEOUT_S,
    RANK_RESERVE_S,
    REPORT_RESERVE_S,
    SCAN_DEADLINE_S,
)

log = logging.getLogger("trustmap")


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
        report_reserve_s: float | None = None,
        agent_reserve_s: float | None = None,
        rank_reserve_s: float | None = None,
        request_cap_s: float | None = None,
        classify_s: float | None = None,
        agent_s: float | None = None,
        rank_s: float | None = None,
    ) -> None:
        self.total_s = (
            total_s
            if total_s is not None
            else _env_float("TRUSTMAP_SCAN_DEADLINE_S", SCAN_DEADLINE_S)
        )
        self.report_reserve_s = (
            report_reserve_s
            if report_reserve_s is not None
            else _env_float("TRUSTMAP_REPORT_RESERVE_S", REPORT_RESERVE_S)
        )
        self.agent_reserve_s = (
            agent_reserve_s
            if agent_reserve_s is not None
            else _env_float("TRUSTMAP_AGENT_RESERVE_S", AGENT_RESERVE_S)
        )
        self.rank_reserve_s = (
            rank_reserve_s
            if rank_reserve_s is not None
            else _env_float("TRUSTMAP_RANK_RESERVE_S", RANK_RESERVE_S)
        )
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
        self.skip_events: list[str] = []
        self.classify_rule_n = 0
        self.classify_model_n = 0
        # unused kwargs kept so older tests can still pass classify_s/agent_s/rank_s
        _ = (classify_s, agent_s, rank_s)

    def remaining_total(self) -> float:
        return self.total_s - (time.monotonic() - self.started)

    def later_reserve(self, name: str) -> float:
        report = self.report_reserve_s
        if name == "rank":
            return report
        if name == "agent":
            return self.rank_reserve_s + report
        if name in {"extract", "classify"}:
            return self.agent_reserve_s + self.rank_reserve_s + report
        return report

    def remaining_stage(self) -> float:
        left_stage = self.stage_limit - (time.monotonic() - self.stage_started)
        return min(left_stage, self.remaining_total())

    def begin_stage(self, name: str) -> None:
        if self.stage:
            self.stage_seconds[self.stage] = time.monotonic() - self.stage_started
        self.stage = name
        self.stage_started = time.monotonic()
        left = self.remaining_total()
        later = self.later_reserve(name)
        self.stage_limit = max(0.0, left - later)

    def end_stage(self) -> None:
        if self.stage:
            self.stage_seconds[self.stage] = time.monotonic() - self.stage_started
            self.stage = ""

    def expired(self) -> bool:
        return self.remaining_stage() <= 0.05

    def request_timeout(self) -> float:
        return max(0.0, min(self.request_cap_s, self.remaining_stage()))

    def note_skip(self, stage: str, why: str, targets: list[str] | None = None) -> None:
        names = ", ".join(targets[:8]) if targets else ""
        extra = f" ({len(targets)} targets: {names})" if targets else ""
        line = f"{stage}: {why}{extra}"
        self.skip_events.append(line)
        log.warning("scan skipped %s", line)
