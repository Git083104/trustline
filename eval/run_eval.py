from __future__ import annotations

import argparse
import asyncio
import json
from collections import defaultdict
from pathlib import Path

from scanner.config import EVAL_SCAN_COST_CAP_USD, EXPIRY_INVESTIGATE_DAYS
from scanner.llm import LiveModelClient
from scanner.lookups import LookupCache
from scanner.report import ScanOutcome, is_claimable, run_scan
from scanner.tools import ToolContext

EVAL_DIR = Path(__file__).resolve().parent
LABELS_FILE = EVAL_DIR / "labels.jsonl"
RESULTS_FILE = EVAL_DIR / "results.md"
GOLD_POS = frozenset({"critical", "high"})
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
ALL_SEVERITIES = ("critical", "high", "medium", "low", "info")


def load_labels(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("severity") == "skip":
            continue
        rows.append(row)
    return rows


def baseline_severity(evidence: dict) -> str:
    if is_claimable(evidence):
        return "critical"
    dns = evidence.get("dns") or {}
    rdap = evidence.get("rdap") or {}
    if str(dns.get("status", "")).lower() == "nxdomain":
        return "high"
    days = rdap.get("days_to_expiry")
    if isinstance(days, int) and days <= EXPIRY_INVESTIGATE_DAYS:
        return "high"
    return "low"


def precision_at_10(
    labeled: list[dict], pred: dict[str, str]
) -> float | None:
    if not labeled:
        return None
    ranked = sorted(
        labeled,
        key=lambda row: (
            SEVERITY_ORDER.get(pred.get(row["target"], "low"), 4),
            row["target"],
        ),
    )
    top = ranked[:10]
    hits = sum(1 for row in top if row["severity"] in GOLD_POS)
    return hits / len(top)


def recall_ch(labeled: list[dict], pred: dict[str, str]) -> float | None:
    gold = [row for row in labeled if row["severity"] in GOLD_POS]
    if not gold:
        return None
    hits = sum(
        1 for row in gold if pred.get(row["target"], "low") in GOLD_POS
    )
    return hits / len(gold)


def confusion(labeled: list[dict], pred: dict[str, str]) -> dict[str, dict[str, int]]:
    table = {gold: {pred_s: 0 for pred_s in ALL_SEVERITIES} for gold in ALL_SEVERITIES}
    for row in labeled:
        gold = row["severity"]
        guessed = pred.get(row["target"], "low")
        if gold not in table or guessed not in table[gold]:
            continue
        table[gold][guessed] += 1
    return table


def macro_mean(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    if not present:
        return None
    return sum(present) / len(present)


def fmt(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}"


def render_results(
    *,
    baseline_p: float | None,
    baseline_r: float | None,
    trustmap_p: float | None,
    trustmap_r: float | None,
    cost: float,
    baseline_conf: dict[str, dict[str, int]],
    trustmap_conf: dict[str, dict[str, int]],
    budget: list[str],
) -> str:
    lines = [
        "# Eval results",
        "",
        "| system | precision@10 | recall (critical/high) | cost_usd |",
        "|---|---|---|---|",
        f"| baseline | {fmt(baseline_p)} | {fmt(baseline_r)} | 0.00000000 |",
        f"| trustmap | {fmt(trustmap_p)} | {fmt(trustmap_r)} | {cost:.8f} |",
        "",
        "## Confusion (baseline, gold \\ predicted)",
        _conf_md(baseline_conf),
        "",
        "## Confusion (trustmap, gold \\ predicted)",
        _conf_md(trustmap_conf),
        "",
        "## Budget skips",
    ]
    if budget:
        lines.extend(f"- {item}" for item in budget)
    else:
        lines.append("- (none)")
    lines.append("")
    return "\n".join(lines)


def _conf_md(table: dict[str, dict[str, int]]) -> str:
    header = "| gold \\ pred | " + " | ".join(ALL_SEVERITIES) + " |"
    sep = "|" + "|".join(["---"] * 6) + "|"
    rows = [header, sep]
    for gold in ALL_SEVERITIES:
        cells = [gold] + [str(table[gold][pred]) for pred in ALL_SEVERITIES]
        rows.append("| " + " | ".join(cells) + " |")
    return "\n".join(rows)


async def scan_repos(
    repos: list[str],
    *,
    client,
    cache: LookupCache,
    ctx: ToolContext | None = None,
    cost_cap: float = EVAL_SCAN_COST_CAP_USD,
    scan_fn=run_scan,
) -> tuple[dict[str, ScanOutcome], float, list[str]]:
    outcomes: dict[str, ScanOutcome] = {}
    budget: list[str] = []
    total_cost = 0.0
    for repo in repos:
        outcome = await scan_fn(
            repo,
            client=client,
            cache=cache,
            ctx=ctx,
            hydrate_only=False,
            cost_cap=cost_cap,
        )
        outcomes[repo] = outcome
        total_cost += outcome.cost_usd
        for target in outcome.budget_targets:
            budget.append(f"{repo} {target}: not investigated (budget)")
    return outcomes, total_cost, budget


def _confusion_unique(
    labels: list[dict], pred: dict[tuple[str, str], str]
) -> dict[str, dict[str, int]]:
    table = {gold: {pred_s: 0 for pred_s in ALL_SEVERITIES} for gold in ALL_SEVERITIES}
    for row in labels:
        gold = row["severity"]
        guessed = pred.get((row["repo"], row["target"]), "low")
        if gold in table and guessed in table[gold]:
            table[gold][guessed] += 1
    return table


def evaluate(labels, outcomes, cost, budget) -> str:
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for row in labels:
        by_repo[row["repo"]].append(row)
    baseline_pred = {
        (row["repo"], row["target"]): baseline_severity(row.get("evidence") or {})
        for row in labels
    }
    trustmap_pred = {}
    for row in labels:
        outcome = outcomes.get(row["repo"])
        findings = {item.target: item.final_severity for item in (outcome.findings if outcome else [])}
        trustmap_pred[(row["repo"], row["target"])] = findings.get(row["target"], "low")

    def p_macro(pred: dict[tuple[str, str], str]) -> float | None:
        values = []
        for repo, rows in by_repo.items():
            mapped = {row["target"]: pred[(repo, row["target"])] for row in rows}
            values.append(precision_at_10(rows, mapped))
        return macro_mean(values)

    def rec(pred: dict[tuple[str, str], str]) -> float | None:
        gold = [row for row in labels if row["severity"] in GOLD_POS]
        if not gold:
            return None
        hits = sum(1 for row in gold if pred[(row["repo"], row["target"])] in GOLD_POS)
        return hits / len(gold)

    return render_results(
        baseline_p=p_macro(baseline_pred),
        baseline_r=rec(baseline_pred),
        trustmap_p=p_macro(trustmap_pred),
        trustmap_r=rec(trustmap_pred),
        cost=cost,
        baseline_conf=_confusion_unique(labels, baseline_pred),
        trustmap_conf=_confusion_unique(labels, trustmap_pred),
        budget=budget,
    )


async def run(
    *,
    labels_path: Path = LABELS_FILE,
    results_path: Path = RESULTS_FILE,
    cache: LookupCache | None = None,
    client=None,
    ctx: ToolContext | None = None,
    scan_fn=run_scan,
    cost_cap: float = EVAL_SCAN_COST_CAP_USD,
) -> str:
    labels = load_labels(labels_path)
    repos = sorted({row["repo"] for row in labels})
    cache = cache or LookupCache("trustmap.db")
    if client is None:
        client = LiveModelClient()
    outcomes, cost, budget = await scan_repos(
        repos, client=client, cache=cache, ctx=ctx, cost_cap=cost_cap, scan_fn=scan_fn
    )
    text = evaluate(labels, outcomes, cost, budget)
    results_path.write_text(text)
    return text


def main(argv: list[str] | None = None) -> int:
    from dotenv import load_dotenv

    load_dotenv(Path(".env"), override=True)
    parser = argparse.ArgumentParser(prog="run_eval")
    parser.add_argument("--labels", default=str(LABELS_FILE))
    parser.add_argument("--results", default=str(RESULTS_FILE))
    parser.add_argument("--cache", default="trustmap.db")
    args = parser.parse_args(argv)
    text = asyncio.run(
        run(
            labels_path=Path(args.labels),
            results_path=Path(args.results),
            cache=LookupCache(args.cache),
        )
    )
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
