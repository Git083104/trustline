from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.config import DEMO_EVENT_GAP_MS

DEMO_PATH = Path(__file__).parent / "demo_scan.json"


def load_demo() -> dict[str, Any]:
    return json.loads(DEMO_PATH.read_text())


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


def demo_report(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = payload if payload is not None else load_demo()
    return {key: data[key] for key in data if key != "events"}
