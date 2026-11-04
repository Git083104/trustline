#!/usr/bin/env python3
"""Scan every Repos to try and Websites to try entry once to fill caches.

Usage: python scripts/warm.py BASE_URL
Run against production after each deploy.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "api" / "static" / "targets.json"


def _entries(data: dict) -> list[str]:
    out: list[str] = []
    for site in data.get("websites") or []:
        url = (site.get("url") or "").strip()
        if url:
            out.append(url)
    for group in data.get("groups") or []:
        for repo in group.get("repos") or []:
            name = (repo.get("repo") or "").strip()
            if name:
                out.append(f"https://github.com/{name}")
    return out


def _request(url: str, *, method: str = "GET", body: bytes | None = None, timeout: float = 95.0):
    req = Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    token = os.environ.get("TRUSTMAP_ADMIN_TOKEN", "").strip()
    if token:
        req.add_header("X-Trustmap-Token", token)
    with urlopen(req, timeout=timeout) as response:
        return response.status, response.read()


def _parse_sse(text: str) -> list[dict]:
    events = []
    for block in text.split("\n\n"):
        line = block.strip()
        if line.startswith("data: "):
            events.append(json.loads(line[6:]))
    return events


def _scan(base: str, target: str) -> tuple[float, str]:
    payload = json.dumps({"target": target}).encode()
    started = time.perf_counter()
    try:
        status, raw = _request(
            f"{base}/api/scan/stream",
            method="POST",
            body=payload,
            timeout=95.0,
        )
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        elapsed = time.perf_counter() - started
        return elapsed, f"FAIL {elapsed:.1f}s  {target}  {exc}"
    elapsed = time.perf_counter() - started
    events = _parse_sse(raw.decode("utf-8", "replace")) if raw else []
    done = next((item for item in reversed(events) if item.get("type") == "done"), None)
    error = next((item for item in reversed(events) if item.get("type") == "error"), None)
    if status != 200 or (done is None and error is None):
        return elapsed, f"FAIL {elapsed:.1f}s  {target}  status={status}"
    if error and done is None:
        return elapsed, f"FAIL {elapsed:.1f}s  {target}  {error.get('message')}"
    n = done.get("finding_count") if done else None
    return elapsed, f"{elapsed:.1f}s  {target}  findings={n}"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python scripts/warm.py BASE_URL", file=sys.stderr)
        return 2
    load_dotenv(ROOT / ".env", override=False)
    base = sys.argv[1].rstrip("/")
    data = json.loads(TARGETS.read_text())
    targets = _entries(data)
    print(f"warm {base}  {len(targets)} targets")
    failed = 0
    for target in targets:
        elapsed, line = _scan(base, target)
        print(line)
        if line.startswith("FAIL"):
            failed += 1
        _ = elapsed
    print(f"{len(targets) - failed} scanned, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
