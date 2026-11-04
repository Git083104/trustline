from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from scanner.extract import extract_scan, is_website_source
from scanner.fix import apply_plan_to_repo, open_pull_request, propose_fixes, write_pr_copy
from scanner.llm import LiveModelClient
from scanner.lookups import LookupCache
from scanner.report import format_table, scan


def main(argv: list[str] | None = None) -> int:
    load_dotenv(Path(".env"), override=True)
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in {"scan", "fix", "-h", "--help"}:
        argv = ["scan", *argv]
    parser = argparse.ArgumentParser(prog="trustmap")
    sub = parser.add_subparsers(dest="cmd")
    scan_p = sub.add_parser("scan", help="scan a path, GitHub URL, or website")
    scan_p.add_argument("source")
    scan_p.add_argument("--json", dest="json_out", help="write findings JSON")
    scan_p.add_argument(
        "--format",
        dest="fmt",
        choices=("table", "json", "sarif"),
        default="table",
        help="stdout format; sarif is SARIF 2.1.0",
    )
    fix_p = sub.add_parser("fix", help="write deterministic patches from a local repo scan")
    fix_p.add_argument("repo_path")
    fix_p.add_argument("--open-pr", action="store_true")
    fix_p.add_argument("--json", dest="json_out")
    args = parser.parse_args(argv)
    if args.cmd == "fix":
        return _fix(args)
    source = args.source if args.cmd == "scan" else None
    if source is None:
        parser.print_help()
        return 2
    return _scan(source, args.json_out, getattr(args, "fmt", "table"))


def _scan(source: str, json_out: str | None, fmt: str = "table") -> int:
    cache = LookupCache(os.environ.get("TRUSTMAP_CACHE_DB", "trustmap.db"))
    findings = asyncio.run(
        scan(
            source,
            client=LiveModelClient(),
            cache=cache,
            hydrate_only=not is_website_source(source),
        )
    )
    if fmt == "sarif":
        from scanner.sarif import findings_to_sarif

        text = json.dumps(findings_to_sarif(findings), indent=2) + "\n"
        if json_out:
            Path(json_out).write_text(text)
        else:
            sys.stdout.write(text)
        return 0
    if fmt == "json":
        text = json.dumps([item.model_dump(mode="json") for item in findings], indent=2) + "\n"
        if json_out:
            Path(json_out).write_text(text)
        else:
            sys.stdout.write(text)
        return 0
    print(format_table(findings))
    if json_out:
        Path(json_out).write_text(
            json.dumps([item.model_dump(mode="json") for item in findings], indent=2)
            + "\n"
        )
    return 0


def _fix(args: argparse.Namespace) -> int:
    root = Path(args.repo_path).resolve()
    cache = LookupCache(os.environ.get("TRUSTMAP_CACHE_DB", "trustmap.db"))
    extracted = extract_scan(str(root))
    findings = asyncio.run(
        scan(
            str(root),
            client=LiveModelClient(),
            cache=cache,
            hydrate_only=True,
        )
    )
    plan = propose_fixes(findings, extracted.file_texts)
    title, body = write_pr_copy(plan, findings, client=LiveModelClient(), cache=cache)
    plan.title, plan.body = title, body
    apply_plan_to_repo(root, plan)
    print(plan.patch or "(no edits)")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {
                    "title": title,
                    "body": body,
                    "edits": [edit.__dict__ for edit in plan.edits],
                },
                indent=2,
            )
            + "\n"
        )
    if args.open_pr:
        url = open_pull_request(root, title, body)
        print(url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
