"""Weekly watch: one GitHub issue for Fix-today findings. No email, no accounts."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from typing import Any

from scanner.copy import issue_markdown
from scanner.models import Finding

ISSUE_MARKER = "<!-- tether-watch -->"
TITLE_PREFIX = "Tether: "


def fix_today(findings: list[Finding]) -> list[Finding]:
    return [item for item in findings if item.severity in {"critical", "high"}]


def issue_title(count: int) -> str:
    return f"Tether: {count} takeover risks"


def issue_body(findings: list[Finding]) -> str:
    rows = fix_today(findings)
    if not rows:
        return ISSUE_MARKER + "\nNo takeover risks to fix today.\n"
    parts = [ISSUE_MARKER, ""]
    for item in rows:
        title, body = issue_markdown(item)
        parts.append(f"### {title}\n")
        parts.append(body)
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


def slack_text(*, count: int, issue_url: str) -> str:
    if count:
        return f"Tether: {count} takeover risks. {issue_url}".strip()
    return f"Tether: 0 takeover risks. {issue_url}".strip()


def _api(url: str, *, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any] | list[Any]:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as response:
        raw = response.read()
    if not raw:
        return {}
    return json.loads(raw.decode())


def find_watch_issue(issues: list[dict[str, Any]]) -> dict[str, Any] | None:
    for issue in issues:
        title = str(issue.get("title") or "")
        body = str(issue.get("body") or "")
        if ISSUE_MARKER in body or title.startswith(TITLE_PREFIX):
            return issue
    return None


def apply_issue_state(
    *,
    existing: dict[str, Any] | None,
    count: int,
    findings: list[Finding],
) -> dict[str, Any]:
    title = issue_title(count)
    body = issue_body(findings)
    if count == 0:
        if existing is None:
            return {"action": "none"}
        return {
            "action": "close",
            "number": existing.get("number"),
            "title": issue_title(0),
            "body": body,
            "state": "closed",
        }
    if existing is None:
        return {"action": "create", "title": title, "body": body, "state": "open"}
    return {
        "action": "update",
        "number": existing.get("number"),
        "title": title,
        "body": body,
        "state": "open",
    }


def post_slack(webhook: str, text: str) -> None:
    req = urllib.request.Request(
        webhook,
        data=json.dumps({"text": text}).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        response.read()


def sync_issue(*, repo: str, findings: list[Finding]) -> dict[str, Any]:
    count = len(fix_today(findings))
    issues = _api(f"https://api.github.com/repos/{repo}/issues?state=all&per_page=50")
    if not isinstance(issues, list):
        issues = []
    existing = find_watch_issue(issues)
    plan = apply_issue_state(existing=existing, count=count, findings=findings)
    html_url = ""
    if plan["action"] == "create":
        created = _api(
            f"https://api.github.com/repos/{repo}/issues",
            method="POST",
            body={"title": plan["title"], "body": plan["body"]},
        )
        if isinstance(created, dict):
            html_url = str(created.get("html_url") or "")
    elif plan["action"] in {"update", "close"}:
        updated = _api(
            f"https://api.github.com/repos/{repo}/issues/{plan['number']}",
            method="PATCH",
            body={"title": plan["title"], "body": plan["body"], "state": plan["state"]},
        )
        if isinstance(updated, dict):
            html_url = str(updated.get("html_url") or "")
    elif existing:
        html_url = str(existing.get("html_url") or "")
    webhook = os.environ.get("TETHER_SLACK_WEBHOOK", "").strip()
    if webhook:
        try:
            post_slack(webhook, slack_text(count=count, issue_url=html_url))
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
    return {"count": count, "action": plan["action"], "url": html_url}


def main(argv: list[str] | None = None) -> int:
    import asyncio

    from scanner.llm import LiveModelClient
    from scanner.lookups import LookupCache
    from scanner.report import scan

    parser = argparse.ArgumentParser(prog="trustmap-watch")
    parser.add_argument("--source", default=".")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    args = parser.parse_args(argv)
    if not args.repo:
        raise SystemExit("GITHUB_REPOSITORY or --repo is required")
    cache = LookupCache(os.environ.get("TRUSTMAP_CACHE_DB", "trustmap.db"))
    findings = asyncio.run(
        scan(args.source, client=LiveModelClient(), cache=cache, hydrate_only=True)
    )
    print(json.dumps(sync_issue(repo=args.repo, findings=findings)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
