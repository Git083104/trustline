from __future__ import annotations

import argparse
import asyncio
import json
import random
import tempfile
from pathlib import Path
from typing import Any, Callable, TextIO

from scanner.agent import has_hard_signal, precheck
from scanner.config import EVAL_SAMPLE_SEED, EVAL_TARGET_CAP
from scanner.extract import GITHUB_RE, extract, _clone_github
from scanner.lookups import LookupCache, consistent_evidence
from scanner.models import Classification, Investigation, Reference
from scanner.report import evidence_line
from scanner.tools import ToolContext

EVAL_DIR = Path(__file__).resolve().parent
REPOS_FILE = EVAL_DIR / "repos.txt"
LABELS_FILE = EVAL_DIR / "labels.jsonl"
SEVERITY_KEYS = {
    "c": "critical",
    "h": "high",
    "m": "medium",
    "l": "low",
    "i": "info",
    "s": "skip",
}


def is_bucket_ref(ref: Reference) -> bool:
    raw = ref.raw.lower()
    return (
        raw.startswith("s3://")
        or "amazonaws.com" in raw
        or "storage.googleapis.com" in raw
    )


def target_from_ref(ref: Reference) -> tuple[str, str]:
    if is_bucket_ref(ref):
        return ref.host_or_bucket, "bucket"
    return (ref.domain or ref.host_or_bucket), "domain"


def stub_classification(ref: Reference) -> Classification:
    return Classification(
        id="0",
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        type="bucket" if is_bucket_ref(ref) else "script",
        runs_in="deploy" if is_bucket_ref(ref) else "browser",
        blast_radius=0,
        confidence=0.0,
        reason="",
    )


def load_repos(path: Path = REPOS_FILE) -> list[str]:
    urls = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def load_labeled_keys(path: Path) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    if not path.is_file():
        return keys
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        keys.add((row["repo"], row["target"]))
    return keys


def append_label(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def three_line_context(root: Path, ref: Reference) -> str:
    path = root / ref.file
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ref.context
    index = ref.line - 1
    start = max(0, index - 1)
    end = min(len(lines), index + 2)
    out = []
    for pos in range(start, end):
        mark = ">" if pos == index else " "
        out.append(f"{mark} {pos + 1}\t{lines[pos]}")
    return "\n".join(out)


def select_groups(
    groups: list[dict[str, Any]],
    *,
    cap: int = EVAL_TARGET_CAP,
    seed: int = EVAL_SAMPLE_SEED,
) -> list[dict[str, Any]]:
    hard = [group for group in groups if has_hard_signal(group["evidence"])]
    rest = [group for group in groups if not has_hard_signal(group["evidence"])]
    if len(hard) >= cap:
        return hard[:cap]
    need = cap - len(hard)
    if not rest or need <= 0:
        return hard
    rng = random.Random(seed)
    sample = rng.sample(rest, min(need, len(rest)))
    return hard + sample


async def gather_groups(
    refs: list[Reference], ctx: ToolContext
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for ref in refs:
        if ref.filter_reason is not None:
            continue
        key, kind = target_from_ref(ref)
        cl = stub_classification(ref)
        evidence = await precheck(ref, cl, ctx)
        inv = Investigation(
            file=ref.file,
            line=ref.line,
            host_or_bucket=ref.host_or_bucket,
            status="done",
            evidence=evidence,
        )
        if key not in grouped:
            grouped[key] = {
                "target": key,
                "kind": kind,
                "rows": [],
                "evidence": {},
            }
            order.append(key)
        grouped[key]["rows"].append((ref, cl, inv))
        grouped[key]["evidence"].update(evidence)
        grouped[key]["evidence"] = consistent_evidence(grouped[key]["evidence"])
    return [grouped[key] for key in order]


def format_target(group: dict[str, Any], root: Path) -> str:
    lines = [f"target: {group['target']}"]
    for ref, _cl, _inv in group["rows"]:
        lines.append(f"  {ref.file}:{ref.line}  {ref.raw}")
        lines.append(three_line_context(root, ref))
    lines.append(evidence_line(group, include_runs_in=False))
    return "\n".join(lines)


def read_severity(
    input_fn: Callable[[str], str],
) -> tuple[str, str]:
    while True:
        raw = input_fn("severity [c/h/m/l/i/s]: ").strip().lower()
        if raw in SEVERITY_KEYS:
            note = input_fn("note (optional): ").strip()
            return SEVERITY_KEYS[raw], note
        print("enter c, h, m, l, i, or s")


def repo_name(source: str) -> str:
    match = GITHUB_RE.match(source.strip())
    if match:
        return f"{match.group(1)}/{match.group(2)}"
    return Path(source).name or source


def open_source(source: str) -> tuple[Path, list[Reference], Any]:
    path = Path(source)
    if path.exists():
        return path.resolve(), extract(str(path.resolve())), None
    tmp = tempfile.TemporaryDirectory()
    cloned = _clone_github(source.strip(), Path(tmp.name))
    return cloned, extract(str(cloned)), tmp


async def label_source(
    source: str,
    *,
    cache: LookupCache,
    labels_path: Path,
    ctx: ToolContext | None = None,
    input_fn: Callable[[str], str] = input,
    output: TextIO | None = None,
    repo_index: str = "",
) -> int:
    out = output
    done = load_labeled_keys(labels_path)
    root, refs, tmp = open_source(source)
    try:
        ctx = ctx or ToolContext(cache=cache)
        groups = await gather_groups(refs, ctx)
        selected = select_groups(groups)
        written = 0
        total = len(selected)
        prefix = f"repo {repo_index}{repo_name(source)}"
        for index, group in enumerate(selected, 1):
            if (source, group["target"]) in done:
                continue
            print(f"{prefix}: target {index} of {total}", file=out)
            print(format_target(group, root), file=out)
            severity, note = read_severity(input_fn)
            row = {
                "repo": source,
                "target": group["target"],
                "kind": group["kind"],
                "severity": severity,
                "note": note,
                "references": [
                    {"file": ref.file, "line": ref.line, "raw": ref.raw}
                    for ref, _cl, _inv in group["rows"]
                ],
                "evidence": group["evidence"],
            }
            append_label(labels_path, row)
            written += 1
        return written
    finally:
        if tmp is not None:
            tmp.cleanup()


def main(argv: list[str] | None = None) -> int:
    from dotenv import load_dotenv

    load_dotenv(Path(".env"), override=True)
    parser = argparse.ArgumentParser(prog="label")
    parser.add_argument(
        "source",
        nargs="?",
        help="local path or GitHub URL (default: eval/repos.txt)",
    )
    parser.add_argument("--labels", default=str(LABELS_FILE))
    parser.add_argument("--cache", default="trustmap.db")
    args = parser.parse_args(argv)
    sources = [args.source] if args.source else load_repos()
    cache = LookupCache(args.cache)
    labels_path = Path(args.labels)

    async def run() -> None:
        for i, source in enumerate(sources, 1):
            tag = f"{i}/{len(sources)} " if len(sources) > 1 else ""
            await label_source(
                source,
                cache=cache,
                labels_path=labels_path,
                repo_index=tag,
            )

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
