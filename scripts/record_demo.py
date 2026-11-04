"""Re-record api/demo_scan.json, the scan that "Watch the demo scan" replays.

    uv run python scripts/record_demo.py           # offline: stubbed lookups, scripted model
    uv run python scripts/record_demo.py --live    # real lookups and Muse Spark
    uv run python scripts/record_demo.py --from-url https://trustline-cxqq.onrender.com

--live needs MODEL_API_KEY (from .env or the environment) and spends a few cents.
Both modes scan tests/fixtures/demo_repo through the real API, so the file holds
exactly the events a live scan streams.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env", override=False)

from fastapi.testclient import TestClient  # noqa: E402

from api.main import create_app  # noqa: E402
from scanner.llm import FakeModelClient, LiveModelClient  # noqa: E402
from scanner.lookups import LookupCache  # noqa: E402
from scanner.models import BucketProbeResult, CertHistoryResult, WaybackResult  # noqa: E402

TARGET = "tests/fixtures/demo_repo"
OUT = ROOT / "api" / "demo_scan.json"

# (reason, blast radius) the scripted classifier gives each kind of reference
REASONS = {
    ("script", "browser"): ("A script tag loads this into every visitor's browser.", 3),
    ("script", "ci"): ("CI downloads and runs this on every build.", 3),
    ("script", "build"): ("The image build downloads and runs this.", 3),
    ("bucket", "deploy"): ("Deploy config reads from and publishes to this bucket.", 2),
    ("api", "browser"): ("Browser code sends requests to this API.", 2),
    ("api", "server"): ("Server code sends requests to this API.", 2),
    ("api", "test"): ("Only tests call this API.", 0),
    ("asset", "browser"): ("The page loads this asset for every visitor.", 1),
    ("docs_link", "docs_only"): ("A link in documentation; nothing loads it.", 0),
}

DONE_NOTES = {
    "bucket_gone": "No archived copies, and the bucket name is free for anyone to create.",
    "bucket_held": "Bucket exists and answers with access denied, so its owner still holds it.",
    "domain_gone": "Domain lapsed after years of serving lib.js; anyone can register it.",
    "pages": "GitHub Pages answers with its unclaimed-site page.",
    "owner_gone": "The GitHub account is gone, so the name can be registered.",
    "repo_gone": "The owner exists but this repository is gone.",
    "held": "Owner and repository both exist.",
}


def scripted_client() -> FakeModelClient:
    from tests.test_agent import _scripted_client
    from tests.test_report import _fixture_handler

    base = _fixture_handler()

    def handler(request):
        out = base(request)
        if request.get("schema_name") == "ranking":
            payload = json.loads(request["user"][request["user"].find("{"): request["user"].rfind("}") + 1])
            if out["severity"] == "info" and payload.get("target", "").startswith("github.com/"):
                out["risk"] = "The action's owner and repository both exist, so nobody else can publish under this name."
                out["fix"] = "remove dead reference"
            return out
        for item in out.get("items", []):
            reason, blast = REASONS.get((item["type"], item["runs_in"]), ("Referenced in code.", 1))
            item["reason"] = reason
            if item["blast_radius"]:
                item["blast_radius"] = blast
        return out

    def tool_handler(request):
        first = json.loads(request["messages"][0]["content"])
        turns = sum(1 for msg in request["messages"] if msg["role"] == "assistant")
        ref = first["reference"]
        pre = first.get("precomputed", {})
        target = ref["domain"] or ref["host_or_bucket"]
        bucket = pre.get("bucket_probe") or {}
        if bucket:
            if bucket.get("status") != "NoSuchBucket":
                return _done("bucket_held")
            if turns == 0:
                url = ref["raw"] if ref["raw"].startswith("http") else f"https://{ref['host_or_bucket']}.s3.amazonaws.com/"
                return {"name": "wayback", "arguments": {"url": url}}
            return _done("bucket_gone")
        if (pre.get("rdap") or {}).get("status") == "unregistered":
            if turns == 0:
                return {"name": "cert_history", "arguments": {"domain": target}}
            if turns == 1:
                return {"name": "wayback", "arguments": {"url": ref["raw"]}}
            return _done("domain_gone")
        if pre.get("platform_takeover"):
            return _done("pages")
        owner = pre.get("github_owner") or {}
        repo = pre.get("github_repo") or {}
        if owner.get("status") == "missing":
            return _done("owner_gone")
        if repo.get("status") == "missing":
            return _done("repo_gone")
        if owner or repo:
            return _done("held")
        return _scripted_client().tool_handler(request)

    return FakeModelClient(handler=handler, tool_handler=tool_handler)


def _done(key: str) -> dict:
    return {"name": "done", "arguments": {"summary": DONE_NOTES[key]}}


def scripted_ctx(tmp: Path):
    from tests.test_agent import _ctx

    async def bucket(name, provider, cache=None, **kwargs):
        held = "acme-static-assets" in name
        return BucketProbeResult(name=name, provider=provider, status="exists" if held else "NoSuchBucket", http_status=403 if held else 404)

    async def certs(domain, cache=None, **kwargs):
        return CertHistoryResult(domain=domain, status="ok", issuers=["Let's Encrypt"], first_seen=date(2019, 3, 2), last_seen=date(2023, 5, 30))

    async def wayback(url, cache=None, **kwargs):
        if "7f3k2" not in url:
            return WaybackResult(url=url, status="unavailable")
        return WaybackResult(url=url, status="ok", first_snapshot="20190311042210", last_snapshot="20230602171544")

    ctx = _ctx(tmp, bucket_probe=bucket)
    ctx.cert_history = certs
    ctx.wayback = wayback
    return ctx


def record(live: bool) -> dict:
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        cache = LookupCache(tmp / "demo.db")
        if live:
            app = create_app(model_client=LiveModelClient(), cache=cache)
        else:
            app = create_app(model_client=scripted_client(), cache=cache, ctx=scripted_ctx(tmp))
        with TestClient(app) as client:
            started = client.post("/api/scan", json={"target": TARGET})
            started.raise_for_status()
            scan_id = started.json()["scan_id"]
            stream = client.get(f"/api/scan/{scan_id}/events").text
            report = client.get(f"/api/scan/{scan_id}").json()
    events = [json.loads(block.strip()[6:]) for block in stream.split("\n\n") if block.strip().startswith("data: ")]
    if events[-1]["type"] != "done":
        raise SystemExit(f"scan did not finish: {events[-1]}")
    for event in events:
        event["scan_id"] = "demo"
    events[0]["recorded_with"] = "live" if live else "scripted"
    report["scan_id"] = "demo"
    report["recorded_with"] = events[0]["recorded_with"]
    return {**report, "events": events}


def record_remote(base: str, target: str) -> dict:
    """POST a live scan to a running Tether and save the stream as the demo fixture."""
    import os
    from urllib.request import Request, urlopen

    base = base.rstrip("/")
    payload = json.dumps({"target": target}).encode()
    req = Request(f"{base}/api/scan", data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    token = os.environ.get("TRUSTMAP_ADMIN_TOKEN", "").strip()
    if token:
        req.add_header("X-Trustmap-Token", token)
    with urlopen(req, timeout=30) as response:
        started = json.loads(response.read())
    scan_id = started["scan_id"]
    with urlopen(f"{base}/api/scan/{scan_id}/events", timeout=180) as response:
        stream = response.read().decode()
    with urlopen(f"{base}/api/scan/{scan_id}", timeout=30) as response:
        report = json.loads(response.read())
    events = [
        json.loads(block.strip()[6:])
        for block in stream.split("\n\n")
        if block.strip().startswith("data: ")
    ]
    if not events or events[-1].get("type") != "done":
        raise SystemExit(f"scan did not finish: {events[-1] if events else 'no events'}")
    stamp = date.today().isoformat()
    for event in events:
        event["scan_id"] = "demo"
    events[0]["recorded_with"] = "live"
    report["scan_id"] = "demo"
    report["recorded_with"] = "live"
    report["recorded_at"] = stamp
    report["target"] = target
    return {**report, "events": events}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--live", action="store_true", help="use Muse Spark and real lookups")
    parser.add_argument("--from-url", metavar="BASE", help="record a live scan from a running Tether")
    parser.add_argument(
        "--target",
        default="https://github.com/Git083104/tether-demo-shop",
        help="repository to scan when --from-url is set",
    )
    args = parser.parse_args()
    if args.from_url:
        data = record_remote(args.from_url, args.target)
    else:
        data = record(args.live)
    OUT.write_text(json.dumps(data, indent=2) + "\n")
    severities = [item["severity"] for item in data["findings"]]
    print(
        f"wrote {OUT.relative_to(ROOT)}: {len(data['events'])} events, {len(severities)} findings "
        f"({severities.count('critical')} critical, {severities.count('high')} high) "
        f"rank_fallbacks={data.get('rank_fallbacks')} skipped={data.get('skipped_targets')}"
    )


if __name__ == "__main__":
    main()
