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
from scanner.report import evidence_line, is_claimable
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
DOCS_SUFFIXES = {".md", ".rst", ".txt", ".ipynb"}
DOCS_DIR_NAMES = {"docs", "doc", "tests"}
DOCS_FILE_STEMS = {"changelog", "license"}
HEALTHY_RDAP = frozenset({"registered", "unknown"})


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


def is_docs_test_path(file: str) -> bool:
    path = Path(file.replace("\\", "/"))
    parts = [part.lower() for part in path.parts]
    name = path.name.lower()
    stem = path.stem.lower()
    if path.suffix.lower() in DOCS_SUFFIXES:
        return True
    if any(part in DOCS_DIR_NAMES for part in parts[:-1]):
        return True
    if stem in DOCS_FILE_STEMS:
        return True
    if name.startswith("test_"):
        return True
    if stem.endswith("_test"):
        return True
    return False


def has_nxdomain(evidence: dict[str, Any]) -> bool:
    dns = (evidence or {}).get("dns") or {}
    return str(dns.get("status", "")).lower() == "nxdomain"


def is_healthy_unclaimable(group: dict[str, Any]) -> bool:
    evidence = consistent_evidence(group.get("evidence") or {})
    if is_claimable(evidence):
        return False
    if group.get("kind") == "bucket":
        status = str((evidence.get("bucket_probe") or {}).get("status", "")).lower()
        return status == "exists"
    dns = str((evidence.get("dns") or {}).get("status", "")).lower()
    rdap = str((evidence.get("rdap") or {}).get("status", "")).lower()
    return dns == "resolves" and rdap in HEALTHY_RDAP


def auto_severity(group: dict[str, Any]) -> str | None:
    refs = [ref for ref, _cl, _inv in group.get("rows") or []]
    docs_only = bool(refs) and all(is_docs_test_path(ref.file) for ref in refs)
    evidence = consistent_evidence(group.get("evidence") or {})
    risky = is_claimable(evidence) or has_nxdomain(evidence)
    if docs_only:
        return "low" if risky else "info"
    if is_healthy_unclaimable(group):
        return "info"
    return None


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


def label_row(
    source: str,
    group: dict[str, Any],
    *,
    severity: str,
    note: str,
    origin: str,
) -> dict[str, Any]:
    return {
        "repo": source,
        "target": group["target"],
        "kind": group["kind"],
        "severity": severity,
        "note": note,
        "source": origin,
        "references": [
            {"file": ref.file, "line": ref.line, "raw": ref.raw}
            for ref, _cl, _inv in group["rows"]
        ],
        "evidence": group["evidence"],
    }


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
    auto: bool = False,
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
        pending: list[tuple[int, dict[str, Any]]] = []
        auto_count = 0
        for index, group in enumerate(selected, 1):
            if (source, group["target"]) in done:
                continue
            guessed = auto_severity(group) if auto else None
            if guessed is not None:
                append_label(
                    labels_path,
                    label_row(
                        source, group, severity=guessed, note="", origin="auto"
                    ),
                )
                written += 1
                auto_count += 1
                done.add((source, group["target"]))
                continue
            pending.append((index, group))
        if auto:
            print(
                f"{prefix}: auto-labeled {auto_count}, {len(pending)} left for you",
                file=out,
            )
        for index, group in pending:
            print(f"{prefix}: target {index} of {total}", file=out)
            print(format_target(group, root), file=out)
            severity, note = read_severity(input_fn)
            append_label(
                labels_path,
                label_row(
                    source, group, severity=severity, note=note, origin="human"
                ),
            )
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
    parser.add_argument(
        "--auto",
        action="store_true",
        help="auto-label fact-decided targets, then prompt for the rest",
    )
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
                auto=args.auto,
            )

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
