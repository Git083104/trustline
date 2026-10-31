from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from dotenv import load_dotenv

from scanner.llm import LiveModelClient
from scanner.lookups import LookupCache
from scanner.report import format_table, scan


def main(argv: list[str] | None = None) -> int:
    load_dotenv(Path(".env"), override=True)
    parser = argparse.ArgumentParser(prog="trustmap")
    parser.add_argument("source", help="local path or GitHub URL")
    parser.add_argument("--json", dest="json_out", help="write findings JSON")
    args = parser.parse_args(argv)
    cache = LookupCache(Path("trustmap.db"))
    findings = asyncio.run(scan(args.source, client=LiveModelClient(), cache=cache))
    print(format_table(findings))
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps([item.model_dump(mode="json") for item in findings], indent=2)
            + "\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
