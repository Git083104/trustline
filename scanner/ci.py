from __future__ import annotations

import argparse
import json
import os
import subprocess
from typing import Any, Literal

from pydantic import BaseModel, Field

from scanner.extract import S3_SCHEME_RE, URL_RE
from scanner.llm import redact_secrets

MUSE_CODE_VERSION = "1.4.14"
SKIP_NO_SECRET = (
    "MODEL_API_KEY is not available (fork pull requests do not receive repo secrets). "
    "Skipping Trustmap. This is not a failure."
)
MAX_DIFF_CHARS = 200_000
Severity = Literal["critical", "high", "medium", "low", "info"]

CI_PROMPT = """You review added lines from a pull request for abandoned infrastructure a repo still trusts.

Rules:
- Use only Trustmap MCP tools (dns, rdap, bucket_probe, cert_history, wayback, platform_takeover, github_owner).
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


def muse_settings(python_exe: str) -> dict[str, Any]:
    """settings.json for Muse Code 1.4.14. Key is mcpServers (not cookbook-only)."""
    return {
        "schema_version": 1,
        "mcpServers": {
            "trustmap": {
                "transport": "stdio",
                "command": python_exe,
                "args": ["-m", "scanner.mcp_server"],
                "env": {"MODEL_API_KEY": "${MODEL_API_KEY}"},
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


def parse_muse_output(text: str) -> CiReport:
    for value in reversed(_json_objects(text)):
        report = _as_report(value)
        if report is not None:
            return report
    raise ValueError("muse output is not valid Trustmap findings JSON")


def has_critical(report: CiReport) -> bool:
    return any(item.severity == "critical" for item in report.findings)


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
        lines.append(f"**Fix:** {redact_secrets(item.fix)}")
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

    prompt = sub.add_parser("write-prompt")
    prompt.add_argument("--diff-file", required=True)
    prompt.add_argument("--out", required=True)

    schema = sub.add_parser("write-schema")
    schema.add_argument("--out", required=True)

    settings = sub.add_parser("write-settings")
    settings.add_argument("--python", required=True)
    settings.add_argument("--out", required=True)

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

    gate = sub.add_parser("gate")
    gate.add_argument("--in-file", required=True)

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
        text = added_lines_from_diff(git_diff(args.base, args.head))
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
        _write(args.out, json.dumps(muse_settings(args.python), indent=2) + "\n")
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
        _write(args.out, comment_body(report))
        return 0

    if args.cmd == "gate":
        report = CiReport.model_validate_json(_read(args.in_file))
        return 1 if has_critical(report) else 0

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
