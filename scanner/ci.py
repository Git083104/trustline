from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
from typing import Any, Literal

from pydantic import BaseModel, Field

from scanner.agent import precheck
from scanner.extract import (
    DOC_SUFFIXES,
    S3_SCHEME_RE,
    SOURCE_SUFFIXES,
    URL_RE,
    _scan_text,
    is_bucket_ref,
)
from scanner.llm import redact_secrets
from scanner.lookups import LookupCache, default_cache
from scanner.models import Classification, Investigation, Reference
from scanner.report import (
    STATIC_SUFFIXES,
    choose_fix,
    floor_decision,
    group_by_target,
)
from scanner.tools import ToolContext

MUSE_CODE_VERSION = "1.4.14"
SKIP_NO_SECRET = (
    "MODEL_API_KEY is not available (fork pull requests do not receive repo secrets). "
    "Skipping Trustmap. This is not a failure."
)
MAX_DIFF_CHARS = 200_000
Severity = Literal["critical", "high", "medium", "low", "info"]

CI_PROMPT = """You review added lines from a pull request for abandoned infrastructure a repo still trusts.

Rules:
- Use only Trustmap MCP tools (dns, rdap, bucket_probe, cert_history, wayback, platform_takeover, github_owner, live_fetch).
- Do not call scan. Do not use shell. Do not write files. Do not browse the workspace.
- Extract hosts, URLs, and bucket names from the added lines only.
- Lookups produce the facts. Do not invent DNS, RDAP, HTTP, or expiry values.
- Return JSON that matches the output schema. findings may be empty.
- severity must be the Trustmap severity for that target (critical/high/medium/low/info).

Added lines:
"""


class CiFinding(BaseModel):
    target: str
    kind: str
    severity: Severity
    risk: str
    fix: str
    evidence_line: str = ""
    references: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class CiReport(BaseModel):
    findings: list[CiFinding]
    notes: str = ""


FINDINGS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "kind": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "risk": {"type": "string"},
                    "fix": {"type": "string"},
                    "evidence_line": {"type": "string"},
                    "references": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "target",
                    "kind",
                    "severity",
                    "risk",
                    "fix",
                    "evidence_line",
                    "references",
                ],
                "additionalProperties": False,
            },
        },
        "notes": {"type": "string"},
    },
    "required": ["findings", "notes"],
    "additionalProperties": False,
}


def secret_available(value: str | None) -> bool:
    return bool((value or "").strip())


def skip_message() -> str:
    return SKIP_NO_SECRET


def added_lines_from_diff(diff_text: str) -> str:
    lines: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    return "\n".join(lines)


def git_diff(base: str, head: str) -> str:
    proc = subprocess.run(
        ["git", "diff", "--no-color", "--no-ext-diff", f"{base}...{head}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout


def candidates_in_text(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.finditer(text):
        raw = match.group(0).rstrip(".,;:)]}>'\"")
        if raw not in seen:
            seen.add(raw)
            found.append(raw)
    for match in S3_SCHEME_RE.finditer(text):
        raw = match.group(0)
        if raw not in seen:
            seen.add(raw)
            found.append(raw)
    return found


def build_prompt(added: str) -> str:
    body = added if len(added) <= MAX_DIFF_CHARS else added[:MAX_DIFF_CHARS]
    return CI_PROMPT + body + "\n"


def muse_settings(python_exe: str, cache_db: str | None = None) -> dict[str, Any]:
    """settings.json for Muse Code 1.4.14. Key is mcpServers (not cookbook-only)."""
    env = {"MODEL_API_KEY": "${MODEL_API_KEY}"}
    if cache_db:
        env["TRUSTMAP_CACHE_DB"] = cache_db
    return {
        "schema_version": 1,
        "mcpServers": {
            "trustmap": {
                "transport": "stdio",
                "command": python_exe,
                "args": ["-m", "scanner.mcp_server"],
                "env": env,
                "mode": "required",
            }
        },
    }


def muse_argv(*, prompt_file: str, schema_file: str, muse_bin: str = "muse") -> list[str]:
    return [
        muse_bin,
        "exec",
        "--disable-shell",
        "--disable-write",
        "--disable-approval",
        "--disable-web-tools",
        "--disable-request-user-input",
        "--disable-reminders",
        "--approval-mode",
        "never",
        "--sandbox-network",
        "restricted",
        "--output-schema",
        schema_file,
        "--json",
        "--prompt-file",
        prompt_file,
        "--max-model-steps",
        "40",
        "-c",
        'run.toolset=["mcp__trustmap__*"]',
    ]


def redact_ci_text(text: str) -> str:
    out = redact_secrets(text)
    for name in ("MODEL_API_KEY", "META_API_KEY"):
        value = (os.environ.get(name) or "").strip()
        if value:
            out = out.replace(value, "[REDACTED]")
    return out


def _json_objects(text: str) -> list[Any]:
    text = text.strip()
    out: list[Any] = []
    try:
        out.append(json.loads(text))
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        idx = 0
        while idx < len(text):
            while idx < len(text) and text[idx] not in "{[":
                idx += 1
            if idx >= len(text):
                break
            try:
                value, end = decoder.raw_decode(text, idx)
            except json.JSONDecodeError:
                idx += 1
                continue
            out.append(value)
            idx = end
    return out


def _as_report(value: Any) -> CiReport | None:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return _as_report(json.loads(text))
            except json.JSONDecodeError:
                return None
        return None
    if isinstance(value, dict):
        if "findings" in value and isinstance(value["findings"], list):
            try:
                return CiReport.model_validate(value)
            except Exception:
                pass
        payload = value.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("text"), str):
            found = _as_report(payload["text"])
            if found is not None:
                return found
        for key in ("output", "result", "data", "structured_output", "payload"):
            if key in value:
                found = _as_report(value[key])
                if found is not None:
                    return found
    if isinstance(value, list):
        for item in reversed(value):
            found = _as_report(item)
            if found is not None:
                return found
    return None


LOOKUP_TOOLS = frozenset(
    {
        "dns",
        "rdap",
        "bucket_probe",
        "cert_history",
        "wayback",
        "platform_takeover",
        "github_owner",
        "live_fetch",
    }
)


def _lookup_name(name: str) -> str | None:
    short = name.split("__")[-1] if name else ""
    return short if short in LOOKUP_TOOLS else None


def _hosts_in_payload(payload: dict[str, Any]) -> set[str]:
    hosts: set[str] = set()
    for key in ("host", "domain", "name", "owner"):
        value = str(payload.get(key) or "").strip().lower()
        if value:
            hosts.add(value)
    url = str(payload.get("url") or "")
    if "://" in url:
        host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
        if host:
            hosts.add(host.lower())
    return hosts


def _tool_evidence_index(objects: list[Any]) -> list[tuple[set[str], str, dict[str, Any]]]:
    rows: list[tuple[set[str], str, dict[str, Any]]] = []
    for value in objects:
        if not isinstance(value, dict):
            continue
        payload = value.get("payload")
        if not isinstance(payload, dict):
            continue
        facts = payload.get("correlation_facts") or {}
        name = _lookup_name(str(facts.get("tool_name") or payload.get("tool") or ""))
        raw = payload.get("text")
        if name is None or not isinstance(raw, str):
            continue
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(body, dict):
            continue
        rows.append((_hosts_in_payload(body), name, body))
    return rows


def evidence_for_finding(item: CiFinding) -> dict[str, Any]:
    evidence = dict(item.evidence)
    for ref in item.references:
        if ":" not in ref:
            continue
        tool, rest = ref.split(":", 1)
        name = _lookup_name(tool.strip())
        if name is None or "=" not in rest:
            continue
        field, value = rest.split("=", 1)
        slot = evidence.setdefault(name, {})
        if isinstance(slot, dict):
            slot[field.strip()] = value.strip()
    return evidence


def parse_muse_output(text: str) -> CiReport:
    objects = _json_objects(text)
    report: CiReport | None = None
    for value in reversed(objects):
        report = _as_report(value)
        if report is not None:
            break
    if report is None:
        raise ValueError("muse output is not valid Trustmap findings JSON")
    tools = _tool_evidence_index(objects)
    for item in report.findings:
        merged = dict(item.evidence)
        target = item.target.lower()
        for hosts, name, body in tools:
            if target in hosts:
                merged[name] = body
        item.evidence = merged
    return report


def references_from_diff(diff_text: str) -> list[Reference]:
    found: dict[tuple[str, str, int], Reference] = {}
    current = "unknown"
    added: dict[str, list[str]] = {}
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            added.setdefault(current, [])
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added.setdefault(current, []).append(line[1:])
    for rel, lines in added.items():
        _scan_text(rel, "\n".join(lines) + ("\n" if lines else ""), found)
    return sorted(found.values(), key=lambda ref: (ref.file, ref.line, ref.raw))


def ci_classification(ref: Reference) -> Classification:
    path = (ref.file or "").replace("\\", "/").lower()
    blob = f"{ref.context} {ref.raw} {ref.file}".lower()
    raw_path = (ref.raw or "").split("?", 1)[0].lower()
    if is_bucket_ref(ref):
        kind: Literal["script", "api", "asset", "bucket", "docs_link", "other"] = "bucket"
    elif "<script" in blob or raw_path.endswith((".js", ".mjs", ".cjs")):
        kind = "script"
    elif raw_path.endswith(STATIC_SUFFIXES) or any(
        tag in blob for tag in ("<img", "<link", "<source")
    ):
        kind = "asset"
    else:
        kind = "other"
    if path.endswith(tuple(DOC_SUFFIXES)) or "/docs/" in f"/{path}/":
        runs: Literal[
            "browser", "server", "build", "deploy", "ci", "test", "docs_only"
        ] = "docs_only"
    elif path.startswith(".github/workflows/") or path.endswith((".yml", ".yaml")):
        runs = "ci" if path.startswith(".github/") else "deploy"
    elif path.endswith((".html", ".htm", ".css", ".js", ".jsx", ".ts", ".tsx")):
        runs = "browser"
    elif path.endswith(tuple(SOURCE_SUFFIXES)):
        runs = "server"
    elif kind == "script":
        runs = "browser"
    else:
        runs = "browser"
    return Classification(
        id=f"{ref.file}:{ref.line}",
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        type=kind,
        runs_in=runs,
        blast_radius=0,
        confidence=1,
        reason="ci heuristic",
    )


async def floor_groups_for_refs(
    refs: list[Reference],
    *,
    cache: LookupCache,
    ctx: ToolContext | None = None,
) -> list[dict[str, Any]]:
    ctx = ctx or ToolContext(cache=cache)
    rows: list[tuple[Reference, Classification, Investigation]] = []
    for ref in refs:
        if ref.filter_reason is not None:
            continue
        cl = ci_classification(ref)
        evidence = await precheck(ref, cl, ctx)
        rows.append(
            (
                ref,
                cl,
                Investigation(
                    file=ref.file,
                    line=ref.line,
                    host_or_bucket=ref.host_or_bucket,
                    status="done",
                    evidence=evidence,
                ),
            )
        )
    return group_by_target(rows)


def floors_from_groups(groups: list[dict[str, Any]]) -> dict[str, str | None]:
    return {group["target"]: floor_decision(group)[0] for group in groups}


def has_critical_floor(floors: dict[str, str | None]) -> bool:
    return any(level == "critical" for level in floors.values())


def has_critical(report: CiReport) -> bool:
    return any(item.severity == "critical" for item in report.findings)


def overlay_floors(report: CiReport, groups: list[dict[str, Any]]) -> CiReport:
    by_target = {group["target"]: group for group in groups}
    for item in report.findings:
        group = by_target.get(item.target)
        if group is None:
            for key, candidate in by_target.items():
                if item.target == key or item.target.endswith(f".{key}") or key.endswith(
                    f".{item.target}"
                ):
                    group = candidate
                    break
        if group is None:
            item.severity = "info"
            continue
        item.evidence = group.get("evidence") or item.evidence
        level, _reason = floor_decision(group)
        item.severity = level or "info"
    return report


def comment_body(report: CiReport, *, skipped: str | None = None) -> str:
    if skipped:
        return skipped
    if not report.findings:
        notes = report.notes.strip()
        extra = f"\n\n{notes}" if notes else ""
        return "Trustmap found no takeover risks in added PR lines." + extra
    lines = ["## Trustmap", "", "Findings from added lines in this PR:", ""]
    for item in report.findings:
        lines.append(f"### {item.target} (`{item.severity}`)")
        lines.append("")
        lines.append(redact_secrets(item.risk))
        lines.append("")
        fix = choose_fix(
            evidence_for_finding(item),
            item.fix,
            item.severity,
        )
        lines.append(f"**Fix:** {redact_secrets(fix)}")
        if item.evidence_line:
            lines.append("")
            lines.append(redact_secrets(item.evidence_line))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scanner.ci")
    sub = parser.add_subparsers(dest="cmd", required=True)

    access = sub.add_parser("access-check")
    access.add_argument("--key-env", default="MODEL_API_KEY")

    added = sub.add_parser("write-added-diff")
    added.add_argument("--base", required=True)
    added.add_argument("--head", required=True)
    added.add_argument("--out", required=True)
    added.add_argument("--full-out", default="")

    prompt = sub.add_parser("write-prompt")
    prompt.add_argument("--diff-file", required=True)
    prompt.add_argument("--out", required=True)

    schema = sub.add_parser("write-schema")
    schema.add_argument("--out", required=True)

    settings = sub.add_parser("write-settings")
    settings.add_argument("--python", required=True)
    settings.add_argument("--out", required=True)
    settings.add_argument("--cache-db", default="")

    argv_p = sub.add_parser("write-muse-argv")
    argv_p.add_argument("--prompt-file", required=True)
    argv_p.add_argument("--schema-file", required=True)
    argv_p.add_argument("--muse-bin", default="muse")
    argv_p.add_argument("--out", required=True)

    dump = sub.add_parser("dump-failure")
    dump.add_argument("--in-file", required=True)

    parse = sub.add_parser("parse")
    parse.add_argument("--in-file", required=True)
    parse.add_argument("--out", required=True)

    comment = sub.add_parser("comment")
    comment.add_argument("--in-file", required=True)
    comment.add_argument("--out", required=True)
    comment.add_argument("--diff-file", default="")

    gate = sub.add_parser("gate")
    gate.add_argument("--diff-file", required=True)

    candidates = sub.add_parser("has-candidates")
    candidates.add_argument("--diff-file", required=True)

    args = parser.parse_args(argv)

    if args.cmd == "access-check":
        if secret_available(os.environ.get(args.key_env)):
            print("skip=false")
            return 0
        print("skip=true")
        print(SKIP_NO_SECRET)
        return 0

    if args.cmd == "write-added-diff":
        full = git_diff(args.base, args.head)
        if args.full_out:
            _write(args.full_out, full if full.endswith("\n") or not full else full + "\n")
        text = added_lines_from_diff(full)
        _write(args.out, text if text.endswith("\n") or not text else text + "\n")
        return 0

    if args.cmd == "write-prompt":
        added_text = _read(args.diff_file)
        _write(args.out, build_prompt(added_text))
        return 0

    if args.cmd == "write-schema":
        _write(args.out, json.dumps(FINDINGS_SCHEMA, indent=2) + "\n")
        return 0

    if args.cmd == "write-settings":
        _write(
            args.out,
            json.dumps(
                muse_settings(args.python, cache_db=args.cache_db or None),
                indent=2,
            )
            + "\n",
        )
        return 0

    if args.cmd == "write-muse-argv":
        _write(
            args.out,
            json.dumps(
                muse_argv(
                    prompt_file=args.prompt_file,
                    schema_file=args.schema_file,
                    muse_bin=args.muse_bin,
                )
            )
            + "\n",
        )
        return 0

    if args.cmd == "dump-failure":
        print(redact_ci_text(_read(args.in_file)))
        return 0

    if args.cmd == "parse":
        report = parse_muse_output(_read(args.in_file))
        _write(args.out, report.model_dump_json(indent=2) + "\n")
        return 0

    if args.cmd == "comment":
        report = CiReport.model_validate_json(_read(args.in_file))
        if args.diff_file:
            groups = asyncio.run(
                floor_groups_for_refs(
                    references_from_diff(_read(args.diff_file)),
                    cache=default_cache(),
                )
            )
            report = overlay_floors(report, groups)
        _write(args.out, comment_body(report))
        return 0

    if args.cmd == "gate":
        groups = asyncio.run(
            floor_groups_for_refs(
                references_from_diff(_read(args.diff_file)),
                cache=default_cache(),
            )
        )
        return 1 if has_critical_floor(floors_from_groups(groups)) else 0

    if args.cmd == "has-candidates":
        return 0 if candidates_in_text(_read(args.diff_file)) else 2

    raise AssertionError(args.cmd)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


if __name__ == "__main__":
    raise SystemExit(main())
