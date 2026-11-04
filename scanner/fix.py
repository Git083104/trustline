"""Deterministic patches from scan findings. Detection only; never pushes unless CLI --open-pr."""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field

from scanner.compromised import POLYFILL_HOSTS, compromised_status
from scanner.extract import SHA_RE, USES_RE
from scanner.inert import is_inert_path, is_source_code
from scanner.llm import ModelClient, call_json
from scanner.lookups import LookupCache, _github_headers
from scanner.models import Finding
from scanner.report import is_claimable

POLYFILL_CDN = "https://cdnjs.cloudflare.com/polyfill/v3/polyfill.min.js"
POLYFILL_RE = re.compile(
    r"https?://(?:cdn\.)?polyfill\.io/[^\"'\s<>]+", re.IGNORECASE
)
VERSIONED_RE = re.compile(r"(?:/|@)v?\d+\.\d+", re.IGNORECASE)
SKIP_PATH_RE = re.compile(r"(^|/)(tests?|fixtures?)(/|$)", re.IGNORECASE)
SKIP_RUNS = frozenset({"test", "docs_only"})
TETHER_NOTE = (
    "TETHER: {host} can be claimed by anyone ({evidence}). "
    "Replace with a source you control."
)


@dataclass
class Edit:
    file: str
    line: int
    before: str
    after: str
    finding_id: str
    kind: str


@dataclass
class FixPlan:
    edits: list[Edit] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    patch: str = ""
    title: str = ""
    body: str = ""


class PrCopy(BaseModel):
    title: str
    body: str
    sections: list[str] = Field(default_factory=list)


PR_SCHEMA = PrCopy.model_json_schema()
PR_SYSTEM = (
    "You write a GitHub pull request for deterministic Tether patches. "
    "Use only facts from the JSON. Do not invent dates, DNS, or hashes."
)


def finding_id(item: Finding) -> str:
    return item.target


def skip_file(path: str) -> bool:
    posix = path.replace("\\", "/").lower()
    if is_inert_path(posix) or is_source_code(posix):
        return True
    if posix.endswith(".md"):
        return True
    return bool(SKIP_PATH_RE.search(posix))


def _part_of_multiline(text: str, line_no: int) -> bool:
    lines = text.splitlines()
    if not (1 <= line_no <= len(lines)):
        return False
    line = lines[line_no - 1].rstrip()
    if line.endswith(("\\", ",", "{", "(", "[")):
        return True
    if line_no > 1 and lines[line_no - 2].rstrip().endswith(("\\", ",", "{", "(", "[")):
        return True
    return False


def _already_edited(before: str) -> bool:
    return "TETHER:" in before or "cdnjs.cloudflare.com/polyfill" in before


def _claim_evidence(evidence: dict[str, Any]) -> str:
    bucket = evidence.get("bucket_probe") or {}
    if bucket.get("status") == "NoSuchBucket":
        return str(bucket.get("status"))
    rdap = evidence.get("rdap") or {}
    if str(rdap.get("status", "")).lower() == "unregistered":
        return "domain not registered"
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() == "missing":
        return "GitHub owner missing"
    platform = evidence.get("platform_takeover") or {}
    if str(platform.get("status", "")).lower() == "unclaimed":
        return "unclaimed platform"
    dns = evidence.get("dns") or {}
    if str(dns.get("status", "")).lower() == "nxdomain":
        return "DNS does not resolve"
    return "claimable"


def _locations(item: Finding) -> list[dict[str, Any]]:
    if item.locations:
        return list(item.locations)
    out = []
    for ref in item.references:
        if isinstance(ref, str) and ":" in ref:
            file, _, line = ref.rpartition(":")
            try:
                out.append({"file": file, "line": int(line), "raw": "", "runs_in": "ci"})
            except ValueError:
                continue
        elif isinstance(ref, dict):
            out.append(ref)
    return out


def _line_at(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return ""


def _replace_line(text: str, line_no: int, new_line: str) -> str:
    lines = text.splitlines(keepends=True)
    if not (1 <= line_no <= len(lines)):
        return text
    nl = "\n"
    raw = lines[line_no - 1]
    if raw.endswith("\r\n"):
        nl = "\r\n"
    elif raw.endswith("\n"):
        nl = "\n"
    else:
        nl = ""
    parts = new_line.split("\n")
    rebuilt = []
    for index, part in enumerate(parts):
        suffix = nl if nl and (index < len(parts) - 1 or True) else ""
        rebuilt.append(part + suffix)
    if not nl:
        rebuilt = [new_line]
    lines[line_no - 1 : line_no] = rebuilt
    return "".join(lines)


def _comment_line(path: str, line: str, note: str) -> str:
    stripped = line.lstrip()
    indent = line[: len(line) - len(stripped)]
    lower = path.lower()
    if lower.endswith((".html", ".htm")):
        return f"{indent}<!-- {note} {stripped} -->"
    if lower.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
        return f"{indent}// {note}\n{indent}// {stripped}"
    if lower.endswith(("dockerfile",)) or Path(path).name.lower() == "dockerfile":
        return f"{indent}# {note}\n{indent}# {stripped}"
    return f"{indent}# {note}\n{indent}# {stripped}"


def _is_polyfill_url(raw: str) -> bool:
    host = (urlparse(raw).hostname or "").lower()
    return host in POLYFILL_HOSTS or host.endswith(".polyfill.io")


def _versioned_stable(raw: str) -> bool:
    return bool(VERSIONED_RE.search(raw))


def _syntax_ok(path: str, text: str) -> bool:
    lower = path.lower()
    name = Path(path).name.lower()
    try:
        if lower.endswith((".yml", ".yaml")):
            yaml.safe_load(text)
            return True
        if lower.endswith((".html", ".htm")):
            HTMLParser().feed(text)
            return True
        if name == "dockerfile":
            return True
    except Exception:
        return False
    return True


def sri_hash(body: bytes) -> str:
    digest = hashlib.sha384(body).digest()
    return "sha384-" + base64.b64encode(digest).decode("ascii")


def unified_patch(files_before: dict[str, str], files_after: dict[str, str]) -> str:
    chunks: list[str] = []
    for path in sorted(files_after):
        before = files_before.get(path, "")
        after = files_after[path]
        if before == after:
            continue
        diff = difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
        chunks.append("".join(diff))
    return "".join(chunks)


def propose_fixes(
    findings: list[Finding],
    file_texts: dict[str, str],
    *,
    resolve_sha: Callable[[str, str, str], str | None] | None = None,
    fetch_body: Callable[[str], bytes | None] | None = None,
) -> FixPlan:
    if resolve_sha is None:
        resolve_sha = resolve_action_sha
    if fetch_body is None:
        fetch_body = fetch_sri_body
    working = dict(file_texts)
    edits: list[Edit] = []

    def apply_edit(path: str, line_no: int, before: str, after: str, item: Finding, kind: str) -> bool:
        current = working.get(path)
        if current is None:
            return False
        updated = _replace_line(current, line_no, after)
        if not _syntax_ok(path, updated):
            return False
        working[path] = updated
        edits.append(
            Edit(
                file=path,
                line=line_no,
                before=before,
                after=after,
                finding_id=finding_id(item),
                kind=kind,
            )
        )
        return True

    for item in findings:
        evidence = item.evidence or {}
        claimable = is_claimable(evidence)
        for loc in _locations(item):
            runs = str(loc.get("runs_in") or "")
            if runs in SKIP_RUNS:
                continue
            path = loc.get("file") or ""
            if path in working and skip_file(path):
                continue
            file_key = path if path in working else (
                "index.html" if "index.html" in working else path
            )
            if file_key not in working or skip_file(file_key):
                continue
            line_no = int(loc.get("line") or 0)
            before = _line_at(working[file_key], line_no)
            raw = str(loc.get("raw") or item.action_ref or "")
            if item.target and item.target not in before and raw not in before:
                for index, line in enumerate(working[file_key].splitlines(), 1):
                    if item.target in line or (raw and raw in line):
                        line_no = index
                        before = line
                        break
            if not before.strip():
                continue
            if _already_edited(before) or _part_of_multiline(working[file_key], line_no):
                continue
            lower = file_key.lower()
            html = lower.endswith((".html", ".htm"))
            workflow = ".github/workflows/" in lower.replace("\\", "/") or lower.endswith((".yml", ".yaml"))

            if item.action_ref and not item.action_sha_pinned and workflow:
                match = USES_RE.match(before.strip())
                if match and resolve_sha and item.action_ref:
                    owner = loc.get("action_owner") or ""
                    repo = loc.get("action_repo") or ""
                    host = item.target.replace("github.com/", "")
                    if "/" in host and not owner:
                        owner, repo = host.split("/", 1)
                    sha = resolve_sha(owner, repo, item.action_ref)
                    if sha and SHA_RE.match(sha):
                        prefix = re.match(r"^(\s*(?:-\s+)?)uses:", before, re.I)
                        lead = prefix.group(1) if prefix else before[: len(before) - len(before.lstrip())]
                        after = f"{lead}uses: {owner}/{repo}@{sha}  # {item.action_ref}"
                        apply_edit(file_key, line_no, before, after, item, "pin-sha")
                        continue

            if html and (POLYFILL_RE.search(before) or _is_polyfill_url(raw)):
                after = POLYFILL_RE.sub(POLYFILL_CDN, before)
                if after != before:
                    apply_edit(file_key, line_no, before, after, item, "polyfill")
                    continue

            repo_st = str((evidence.get("github_repo") or {}).get("status", "")).lower()
            if workflow and item.action_ref and repo_st in {"missing", "disabled", "not_found"}:
                note = TETHER_NOTE.format(host=item.target, evidence="GitHub Action missing")
                after = _comment_line(file_key, before, note)
                apply_edit(file_key, line_no, before, after, item, "disable-ci")
                continue

            if html and compromised_status(item.target, "") and not _is_polyfill_url(raw):
                note = TETHER_NOTE.format(host=item.target, evidence="known compromised CDN")
                after = _comment_line(file_key, before, note)
                apply_edit(file_key, line_no, before, after, item, "remove-tag")
                continue

            if claimable and runs not in SKIP_RUNS and (html or workflow):
                note = TETHER_NOTE.format(
                    host=item.target, evidence=_claim_evidence(evidence)
                )
                after = _comment_line(file_key, before, note)
                apply_edit(file_key, line_no, before, after, item, "comment")
                continue

            if (
                html
                and not claimable
                and loc.get("tag") in {"script", "link"}
                and loc.get("sri") is False
                and _versioned_stable(raw)
                and fetch_body is not None
            ):
                body = fetch_body(raw)
                if body:
                    digest = sri_hash(body)
                    if "integrity=" not in before:
                        after = before.replace(
                            "<script ",
                            f'<script integrity="{digest}" crossorigin="anonymous" ',
                            1,
                        )
                        if after == before:
                            after = before.replace(
                                "<script",
                                f'<script integrity="{digest}" crossorigin="anonymous"',
                                1,
                            )
                        if after != before:
                            apply_edit(file_key, line_no, before, after, item, "sri")

    patch = unified_patch(file_texts, working)
    return FixPlan(edits=edits, files=working, patch=patch)


def template_pr(plan: FixPlan, findings: list[Finding]) -> tuple[str, str]:
    n = len(plan.edits)
    title = f"Tether: pin or remove {n} abandoned reference" + ("" if n == 1 else "s")
    chunks = [
        "Tether proposed these edits from scan evidence. Review each one before merging.",
        "",
    ]
    by_id = {finding_id(item): item for item in findings}
    for edit in plan.edits:
        item = by_id.get(edit.finding_id)
        evidence = (item.evidence if item else {}) or {}
        rdap = evidence.get("rdap") or {}
        expiry = rdap.get("expiry") or rdap.get("days_to_expiry") or ""
        chunks.append(f"## {edit.finding_id}")
        chunks.append("")
        if item:
            chunks.append(item.risk)
            chunks.append("")
            chunks.append(item.evidence_line)
            if expiry:
                chunks.append(f"RDAP expiry fact: {expiry}")
        chunks.append("")
        chunks.append(f"`{edit.file}:{edit.line}` ({edit.kind})")
        chunks.append("")
        chunks.append("```diff")
        chunks.append(f"- {edit.before}")
        chunks.append(f"+ {edit.after}")
        chunks.append("```")
        chunks.append("")
        chunks.append("Next: merge only if you still need this dependency, then replace it with a source you control.")
        chunks.append("")
    return title, "\n".join(chunks).strip() + "\n"


def write_pr_copy(
    plan: FixPlan,
    findings: list[Finding],
    *,
    client: ModelClient | None = None,
    cache: LookupCache | None = None,
) -> tuple[str, str]:
    title, body = template_pr(plan, findings)
    if client is None:
        return title, body
    facts = {
        "edits": [
            {
                "file": edit.file,
                "line": edit.line,
                "kind": edit.kind,
                "finding_id": edit.finding_id,
                "before": edit.before,
                "after": edit.after,
            }
            for edit in plan.edits
        ],
        "findings": [
            {
                "target": item.target,
                "severity": item.severity,
                "risk": item.risk,
                "evidence_line": item.evidence_line,
                "evidence": item.evidence,
            }
            for item in findings
            if finding_id(item) in {edit.finding_id for edit in plan.edits}
        ],
    }
    blob = json.dumps(facts, default=str, sort_keys=True)

    def extra_check(parsed: PrCopy) -> None:
        from scanner.report import missing_claims

        combined = parsed.title + "\n" + parsed.body
        for item in facts["findings"]:
            if item["target"] not in combined:
                raise ValueError("missing target")
            leftover = missing_claims(combined, item.get("evidence") or {})
            if leftover:
                raise ValueError(f"unsupported claims: {leftover}")

    try:
        parsed, _log = call_json(
            "muse-spark-1.3",
            PR_SYSTEM,
            blob,
            PrCopy,
            "low",
            client=client,
            json_schema=PR_SCHEMA,
            schema_name="pr_copy",
            cache=cache,
            extra_check=extra_check,
        )
        return parsed.title, parsed.body
    except (ValueError, Exception):
        return title, body


def resolve_action_sha(owner: str, repo: str, ref: str) -> str | None:
    import httpx

    token = os.environ.get("GITHUB_TOKEN", "").strip() or None
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{ref}"
    with httpx.Client(timeout=10.0, follow_redirects=True) as client:
        response = client.get(url, headers=_github_headers(token))
    if response.status_code >= 400:
        return None
    data = response.json()
    sha = data.get("sha") if isinstance(data, dict) else None
    return sha if isinstance(sha, str) and SHA_RE.match(sha) else None


def fetch_sri_body(url: str) -> bytes | None:
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    from scanner.ssrf import ScanBlockedError
    from scanner.website import safe_get

    async def _load() -> bytes | None:
        try:
            page = await safe_get(url, max_bytes=2_000_000)
        except ScanBlockedError:
            return None
        return page.body.encode("utf-8", errors="replace")

    def _run() -> bytes | None:
        return asyncio.run(_load())

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return _run()
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(_run).result(timeout=20)


def apply_plan_to_repo(root: Path, plan: FixPlan) -> None:
    for rel, text in plan.files.items():
        target = root / rel
        if target.is_file():
            target.write_text(text)


def open_pull_request(root: Path, title: str, body: str) -> str:
    import subprocess

    today = date.today().isoformat()
    branch = f"tether/fix-{today}"
    subprocess.run(["git", "-C", str(root), "checkout", "-B", branch], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-m", title], check=True)
    subprocess.run(
        ["git", "-C", str(root), "push", "-u", "origin", branch],
        check=True,
        env=os.environ.copy(),
    )
    body_path = root / ".tether-pr-body.md"
    body_path.write_text(body)
    try:
        created = subprocess.run(
            [
                "gh",
                "pr",
                "create",
                "--title",
                title,
                "--body-file",
                str(body_path),
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        if body_path.exists():
            body_path.unlink()
    return (created.stdout or "").strip()
