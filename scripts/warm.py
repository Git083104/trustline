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

from scanner.sanity import unexplained_tranco_fix_today

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
    try:
        with urlopen(req, timeout=timeout) as response:
            return response.status, response.read()
    except HTTPError as exc:
        return exc.code, exc.read()


def _parse_sse(text: str) -> list[dict]:
    events = []
    for block in text.split("\n\n"):
        line = block.strip()
        if line.startswith("data: "):
            events.append(json.loads(line[6:]))
    return events


def expect_line(findings: list[dict]) -> str:
    fix = [
        item
        for item in findings
        if item.get("severity") in {"critical", "high"}
    ]
    if not fix:
        return "Expect: clean"
    crit = sum(1 for item in fix if item.get("severity") == "critical")
    high = sum(1 for item in fix if item.get("severity") == "high")
    bits = []
    if crit:
        bits.append(f"{crit} critical")
    if high:
        bits.append(f"{high} high")
    names = [str(item.get("target") or "") for item in fix]
    if len(names) == 1:
        return f"Expect: {bits[0]} · {names[0]}"
    if len(names) <= 4:
        return f"Expect: {' · '.join(bits)} · {', '.join(names)}"
    return f"Expect: {' · '.join(bits)}"


def _scan(base: str, target: str) -> tuple[float, str, dict | None]:
    payload = json.dumps({"target": target}).encode()
    started = time.perf_counter()
    try:
        status, raw = _request(
            f"{base}/api/scan",
            method="POST",
            body=payload,
            timeout=30.0,
        )
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        elapsed = time.perf_counter() - started
        return elapsed, f"FAIL {elapsed:.1f}s  {target}  {exc}", None
    try:
        started_body = json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        elapsed = time.perf_counter() - started
        return elapsed, f"FAIL {elapsed:.1f}s  {target}  status={status}", None
    scan_id = started_body.get("scan_id")
    if status != 200 or not scan_id:
        elapsed = time.perf_counter() - started
        err = started_body.get("error") or started_body
        return elapsed, f"FAIL {elapsed:.1f}s  {target}  status={status} {err}", None
    report = None
    for _ in range(36):
        time.sleep(4)
        try:
            st, body = _request(f"{base}/api/scan/{scan_id}", timeout=20.0)
        except HTTPError as exc:
            if exc.code == 409:
                continue
            elapsed = time.perf_counter() - started
            return elapsed, f"FAIL {elapsed:.1f}s  {target}  {exc}", None
        if st == 409:
            continue
        if st != 200:
            elapsed = time.perf_counter() - started
            return elapsed, f"FAIL {elapsed:.1f}s  {target}  status={st}", None
        report = json.loads(body.decode("utf-8", "replace"))
        break
    elapsed = time.perf_counter() - started
    if report is None:
        return elapsed, f"FAIL {elapsed:.1f}s  {target}  timeout", None
    if report.get("status") == "error":
        return elapsed, f"FAIL {elapsed:.1f}s  {target}  {report.get('error')}", report
    findings = report.get("findings") or []
    n = len(findings)
    cost = float(report.get("cost_usd") or 0)
    classify_cost = float(report.get("classify_cost_usd") or 0)
    fallbacks = int(report.get("rank_fallbacks") or 0)
    skipped = report.get("skipped_targets") or []
    model_n = int(report.get("classify_model_n") or 0)
    rule_n = int(report.get("classify_rule_n") or 0)
    denom = max(1, n)
    line = expect_line(findings)
    extra = (
        f"cost=${cost:.2f} classify=${classify_cost:.2f} "
        f"rules={rule_n} model={model_n} "
        f"rank_fallbacks={fallbacks}/{denom} skipped={len(skipped)}"
    )
    return elapsed, f"{elapsed:.1f}s  {target}  findings={n}  {line}  {extra}", report


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python scripts/warm.py BASE_URL", file=sys.stderr)
        return 2
    load_dotenv(ROOT / ".env", override=False)
    base = sys.argv[1].rstrip("/")
    data = json.loads(TARGETS.read_text())
    targets = _entries(data)
    print(f"warm {base}  {len(targets)} targets", flush=True)
    failed = 0
    for target in targets:
        elapsed, line, report = _scan(base, target)
        print(line, flush=True)
        if line.startswith("FAIL"):
            failed += 1
            continue
        findings = (report or {}).get("findings") or []
        for item in findings:
            if item.get("severity") in {"critical", "high"}:
                print(
                    f"  Fix-today {item.get('target')} {item.get('severity')}  "
                    f"{item.get('evidence_line')}",
                    flush=True,
                )
        bad = unexplained_tranco_fix_today(findings)
        if bad:
            failed += 1
            print(f"FAIL sanity {target}: " + "; ".join(bad), flush=True)
        _ = elapsed
    print(f"{len(targets) - failed} scanned, {failed} failed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
