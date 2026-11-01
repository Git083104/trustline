from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

COMPROMISED_PATH = Path(__file__).parent / "compromised.json"
POLYFILL_FIX = (
    "Remove it, or use cdnjs.cloudflare.com/polyfill or polyfill-fastly.io"
)
SRI_FIX = "Add an integrity hash or self-host"
POLYFILL_HOSTS = frozenset(
    {"cdn.polyfill.io", "polyfill.io", "polyfill.com"}
)


@lru_cache(maxsize=1)
def _table() -> dict[str, dict[str, str]]:
    return json.loads(COMPROMISED_PATH.read_text())


def compromised_status(*names: str) -> str | None:
    table = _table()
    found: str | None = None
    for name in names:
        hit = table.get((name or "").lower().rstrip("."))
        if not hit:
            continue
        status = hit.get("status")
        if status == "compromised":
            return "compromised"
        if status == "associated":
            found = "associated"
    return found


def is_polyfill_host(*names: str) -> bool:
    return any((name or "").lower().rstrip(".") in POLYFILL_HOSTS for name in names)


def compromised_source(status: str) -> str:
    for row in _table().values():
        if row.get("status") == status:
            return row.get("source") or ""
    return ""
