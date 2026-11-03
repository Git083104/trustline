#!/usr/bin/env python3
"""Smoke-check a running Tether instance. Usage: python scripts/smoke.py BASE_URL"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _print(ok: bool, name: str, detail: str, ms: float) -> None:
    status = "PASS" if ok else "FAIL"
    print(f"{status}  {name}  {ms:.0f}ms  {detail}")


def _request(url: str, *, method: str = "GET", body: bytes | None = None, timeout: float = 30.0):
    started = time.perf_counter()
    req = Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as response:
            raw = response.read()
            return response.status, raw, (time.perf_counter() - started) * 1000
    except HTTPError as exc:
        raw = exc.read()
        return exc.code, raw, (time.perf_counter() - started) * 1000


def _parse_sse(text: str) -> list[dict]:
    events = []
    for block in text.split("\n\n"):
        line = block.strip()
        if line.startswith("data: "):
            events.append(json.loads(line[6:]))
    return events


def check_health(base: str) -> bool:
    status, raw, ms = _request(f"{base}/api/health")
    ok = status == 200 and json.loads(raw) == {"ok": True}
    _print(ok, "GET /api/health", raw.decode()[:120], ms)
    return ok


def check_home(base: str) -> bool:
    status, raw, ms = _request(f"{base}/")
    text = raw.decode("utf-8", "replace")
    ok = status == 200 and "Tether" in text
    _print(ok, "GET /", f"status={status} has_tether={('Tether' in text)}", ms)
    all_ok = ok
    for asset in ("/static/app.css", "/static/app.js"):
        st, _body, asset_ms = _request(f"{base}{asset}")
        asset_ok = st == 200
        _print(asset_ok, f"GET {asset}", f"status={st}", asset_ms)
        all_ok = all_ok and asset_ok
    return all_ok


def check_demo(base: str) -> bool:
    started = time.perf_counter()
    status, raw, _ms = _request(f"{base}/api/scan/demo/events?speed=0", timeout=60)
    events = _parse_sse(raw.decode("utf-8", "replace")) if raw else []
    types = [item.get("type") for item in events]
    ok = status == 200 and "done" in types
    _print(ok, "GET /api/scan/demo/events", f"status={status} types={types[-3:]}", (time.perf_counter() - started) * 1000)
    return ok


def check_live_stream(base: str) -> bool:
    payload = json.dumps(
        {"target": "https://github.com/jwang2007/paperplane-shop"}
    ).encode()
    started = time.perf_counter()
    try:
        status, raw, _ms = _request(
            f"{base}/api/scan/stream",
            method="POST",
            body=payload,
            timeout=90,
        )
    except URLError as exc:
        _print(False, "POST /api/scan/stream paperplane", str(exc), (time.perf_counter() - started) * 1000)
        return False
    elapsed = time.perf_counter() - started
    events = _parse_sse(raw.decode("utf-8", "replace")) if raw else []
    done = next((item for item in reversed(events) if item.get("type") == "done"), None)
    ok = (
        status == 200
        and done is not None
        and elapsed <= 90
        and done.get("partial") is False
        and len(done.get("skipped_targets") or []) == 0
    )
    detail = (
        f"elapsed={elapsed:.2f}s findings={done.get('finding_count') if done else None} "
        f"cost={done.get('cost_usd') if done else None} agent_runs={done.get('agent_runs') if done else None} "
        f"partial={done.get('partial') if done else None} skipped={done.get('skipped_targets') if done else None}"
    )
    _print(ok, "POST /api/scan/stream paperplane", detail, elapsed * 1000)
    return ok


def check_website_demo(base: str) -> bool:
    payload = json.dumps({"target": "https://git083104.github.io/paperplane-shop/"}).encode()
    started = time.perf_counter()
    try:
        status, raw, _ms = _request(
            f"{base}/api/scan/stream",
            method="POST",
            body=payload,
            timeout=90,
        )
    except URLError as exc:
        _print(False, "POST /api/scan/stream website", str(exc), (time.perf_counter() - started) * 1000)
        return False
    elapsed = time.perf_counter() - started
    events = _parse_sse(raw.decode("utf-8", "replace")) if raw else []
    done = next((item for item in reversed(events) if item.get("type") == "done"), None)
    ok = status == 200 and done is not None
    _print(
        ok,
        "POST /api/scan/stream website",
        f"elapsed={elapsed:.2f}s findings={done.get('finding_count') if done else None}",
        elapsed * 1000,
    )
    return ok


def check_fix_patch(base: str) -> bool:
    status, raw, ms = _request(f"{base}/api/scan/demo/fix.patch", timeout=30)
    text = raw.decode("utf-8", "replace")
    ok = status == 200 and (
        "polyfill" in text.lower() or "TETHER" in text or "cdnjs" in text.lower()
    )
    _print(ok, "GET /api/scan/demo/fix.patch", f"status={status} bytes={len(raw)}", ms)
    return ok


def check_ssrf(base: str) -> bool:
    all_ok = True
    for url in ("http://169.254.169.254", "http://127.0.0.1"):
        body = json.dumps({"target": url}).encode()
        status, raw, ms = _request(f"{base}/api/scan", method="POST", body=body, timeout=20)
        payload = {}
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"raw": raw.decode("utf-8", "replace")[:80]}
        ok = 400 <= status < 500
        _print(ok, f"POST /api/scan {url}", f"status={status} body={payload}", ms)
        all_ok = all_ok and ok
    return all_ok


def check_local_429() -> bool:
    from fastapi.testclient import TestClient

    from api.limits import HOURLY_LIMIT_MSG, LimitsStore
    from api.main import create_app
    from scanner.llm import FakeModelClient
    from scanner.lookups import LookupCache
    from scanner.report import ScanOutcome

    async def runner(*args, **kwargs):
        return ScanOutcome(findings=[])

    started = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        limits = LimitsStore(
            tmp_path / "limits.db",
            ip_per_hour=1,
            daily_cap=10,
            max_concurrent=10,
            scan_reserve=1,
        )
        app = create_app(
            model_client=FakeModelClient(handler=lambda r: {}),
            cache=LookupCache(tmp_path / "c.db"),
            runner=runner,
            limits=limits,
        )
        with TestClient(app) as client:
            first = client.post(
                "/api/scan", json={"target": "https://github.com/acme/widgets"}
            )
            second = client.post(
                "/api/scan", json={"target": "https://github.com/acme/widgets"}
            )
        ok = first.status_code == 200 and second.status_code == 429
        detail = (
            f"first={first.status_code} second={second.status_code} "
            f"body={second.json()} expected={HOURLY_LIMIT_MSG}"
        )
        _print(ok, "local 429 (IP_SCANS_PER_HOUR=1)", detail, (time.perf_counter() - started) * 1000)
        return ok


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python scripts/smoke.py BASE_URL", file=sys.stderr)
        return 2
    base = sys.argv[1].rstrip("/")
    print(f"smoke {base}")
    results = [
        check_health(base),
        check_home(base),
        check_demo(base),
        check_live_stream(base),
        check_website_demo(base),
        check_fix_patch(base),
        check_ssrf(base),
        check_local_429(),
    ]
    failed = results.count(False)
    print(f"{len(results) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
