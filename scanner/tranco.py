from __future__ import annotations

import gzip
from functools import lru_cache
from pathlib import Path

LIST_PATH = Path(__file__).parent / "data" / "tranco_top100k.txt.gz"
TOP_SAFE_RANK = 10_000


@lru_cache(maxsize=1)
def _ranks() -> dict[str, int]:
    ranks: dict[str, int] = {}
    with gzip.open(LIST_PATH, "rt", encoding="utf-8") as handle:
        for index, line in enumerate(handle, start=1):
            domain = line.strip().lower().rstrip(".")
            if domain:
                ranks[domain] = index
    return ranks


def tranco_rank(domain: str | None) -> int | None:
    name = (domain or "").strip().lower().rstrip(".")
    if not name:
        return None
    return _ranks().get(name)
