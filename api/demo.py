from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.config import DEMO_EVENT_GAP_MS

DEMO_PATH = Path(__file__).parent / "demo_scan.json"


def load_demo() -> dict[str, Any]:
    return json.loads(DEMO_PATH.read_text())


DEMO_GAP_CAP_MS = 1500


def demo_gap_ms(speed: str | None) -> int:
    if speed is None or speed == "":
        return DEMO_EVENT_GAP_MS
    try:
        value = int(speed)
    except ValueError as exc:
        raise ValueError("speed must be an integer number of milliseconds") from exc
    if value < 0:
        raise ValueError("speed must be >= 0")
    return value


def demo_waits_ms(events: list[dict[str, Any]], speed: str | None) -> list[int]:
    if speed is not None and speed != "":
        gap = demo_gap_ms(speed)
        return [0] + [gap] * (max(len(events) - 1, 0))
    waits = [0]
    for index in range(1, len(events)):
        prev = events[index - 1].get("ts")
        current = events[index].get("ts")
        if isinstance(prev, (int, float)) and isinstance(current, (int, float)):
            delta_ms = max(0.0, (float(current) - float(prev)) * 1000.0)
            waits.append(int(round(min(delta_ms, DEMO_GAP_CAP_MS))))
        else:
            waits.append(DEMO_EVENT_GAP_MS)
    return waits


def demo_report(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = payload if payload is not None else load_demo()
    return {key: data[key] for key in data if key != "events"}
