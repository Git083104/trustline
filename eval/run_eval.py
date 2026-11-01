from __future__ import annotations

import argparse
import asyncio
import json
from collections import defaultdict
from pathlib import Path

from scanner.config import EVAL_SCAN_COST_CAP_USD
from scanner.llm import LiveModelClient
from scanner.lookups import LookupCache, consistent_evidence
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
    evidence = consistent_evidence(evidence)
    if is_claimable(evidence):
        return "critical"
    dns = evidence.get("dns") or {}
    rdap = evidence.get("rdap") or {}
    if str(dns.get("status", "")).lower() == "nxdomain":
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


def compact_evidence(evidence: dict | None) -> dict:
    out = {}
    for name, value in (evidence or {}).items():
        if not isinstance(value, dict):
            out[name] = value
            continue
        keep = {
            key: value[key]
            for key in (
                "status",
                "name",
                "provider",
                "host",
                "domain",
                "days_to_expiry",
                "http_status",
            )
            if key in value
        }
        out[name] = keep
    return out


def closest_finding_keys(target: str, findings) -> list[str]:
    keys = [item.target for item in findings]
    hits = [key for key in keys if target in key or key in target]
    if hits:
        return hits
    folded = target.casefold()
    return [key for key in keys if folded[:8] and folded[:8] in key.casefold()][:8]


def match_finding(row: dict, outcome: ScanOutcome | None):
    findings = list(outcome.findings) if outcome else []
    for item in findings:
        if item.target == row["target"]:
            return item
    return None


def debug_gold(labels: list[dict], outcomes: dict) -> str:
    lines = ["## Gold critical/high debug", ""]
    gold = [row for row in labels if row.get("severity") in GOLD_POS]
    if not gold:
        lines.append("(none)")
        lines.append("")
        return "\n".join(lines)
    for row in gold:
        outcome = outcomes.get(row["repo"])
        findings = list(outcome.findings) if outcome else []
        hit = match_finding(row, outcome)
        lines.append(f"### {row['repo']} `{row['target']}` gold={row['severity']}")
        lines.append(f"label_evidence: {json.dumps(compact_evidence(row.get('evidence')))}")
        if hit is None:
            closest = closest_finding_keys(row["target"], findings)
            lines.append("trustmap: NO MATCH")
            lines.append(f"closest_keys: {closest or [item.target for item in findings[:8]]}")
        else:
            lines.append(
                f"trustmap: target={hit.target} model_severity={hit.model_severity} "
                f"final_severity={hit.final_severity} floor_reason={hit.floor_reason or '(none)'}"
            )
            lines.append(f"finding_evidence: {json.dumps(compact_evidence(hit.evidence))}")
        lines.append("")
    return "\n".join(lines)


def flag_stats(
    labels: list[dict], pred: dict[tuple[str, str], str]
) -> dict[str, float | int | None]:
    gold = [row for row in labels if row["severity"] in GOLD_POS]
    gold_keys = {(row["repo"], row["target"]) for row in gold}
    flagged = [
        row
        for row in labels
        if pred.get((row["repo"], row["target"]), "low") in GOLD_POS
    ]
    true_pos = sum(1 for row in flagged if (row["repo"], row["target"]) in gold_keys)
    false_alarms = len(flagged) - true_pos
    return {
        "flagged": len(flagged),
        "true_pos": true_pos,
        "false_alarms": false_alarms,
        "flag_precision": (true_pos / len(flagged)) if flagged else None,
        "recall": (true_pos / len(gold)) if gold else None,
    }


def render_table(
    *,
    title: str,
    baseline_p: float | None,
    baseline_r: float | None,
    trustmap_p: float | None,
    trustmap_r: float | None,
    cost: float,
    baseline_conf: dict[str, dict[str, int]],
    trustmap_conf: dict[str, dict[str, int]],
    baseline_flags: dict[str, float | int | None],
    trustmap_flags: dict[str, float | int | None],
    include_cost: bool,
) -> str:
    if include_cost:
        header = (
            "| system | precision@10 | flag_precision | flagged_ch | gold_ch_caught | "
            "false_alarms | recall | cost_usd |"
        )
        sep = "|---|---|---|---|---|---|---|---|"
        b_cost = " 0.00000000 |"
        t_cost = f" {cost:.8f} |"
    else:
        header = (
            "| system | precision@10 | flag_precision | flagged_ch | gold_ch_caught | "
            "false_alarms | recall |"
        )
        sep = "|---|---|---|---|---|---|---|"
        b_cost = ""
        t_cost = ""

    def row(name: str, p, flags, cost_cell: str) -> str:
        return (
            f"| {name} | {fmt(p)} | {fmt(flags['flag_precision'])} | "
            f"{flags['flagged']} | {flags['true_pos']} | {flags['false_alarms']} | "
            f"{fmt(flags['recall'])} |{cost_cell}"
        )

    return "\n".join(
        [
            f"## {title}",
            "",
            "precision@10 ranks labeled targets only and is capped by the few gold "
            "critical/high labels per repo.",
            "",
            header,
            sep,
            row("baseline", baseline_p, baseline_flags, b_cost),
            row("trustmap", trustmap_p, trustmap_flags, t_cost),
            "",
            "### Confusion (baseline, gold \\ predicted)",
            _conf_md(baseline_conf),
            "",
            "### Confusion (trustmap, gold \\ predicted)",
            _conf_md(trustmap_conf),
        ]
    )


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
            hydrate_only=True,
            allow_partial_cache=True,
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


def _metrics(labels: list[dict], outcomes: dict, cost: float) -> dict:
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for row in labels:
        by_repo[row["repo"]].append(row)
    baseline_pred = {
        (row["repo"], row["target"]): baseline_severity(row.get("evidence") or {})
        for row in labels
    }
    trustmap_pred = {}
    for row in labels:
        hit = match_finding(row, outcomes.get(row["repo"]))
        trustmap_pred[(row["repo"], row["target"])] = (
            hit.final_severity if hit is not None else "low"
        )

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
        hits = sum(
            1 for row in gold if pred[(row["repo"], row["target"])] in GOLD_POS
        )
        return hits / len(gold)

    return {
        "baseline_p": p_macro(baseline_pred),
        "baseline_r": rec(baseline_pred),
        "trustmap_p": p_macro(trustmap_pred),
        "trustmap_r": rec(trustmap_pred),
        "cost": cost,
        "baseline_conf": _confusion_unique(labels, baseline_pred),
        "trustmap_conf": _confusion_unique(labels, trustmap_pred),
        "baseline_flags": flag_stats(labels, baseline_pred),
        "trustmap_flags": flag_stats(labels, trustmap_pred),
    }


def human_labels(labels: list[dict]) -> list[dict]:
    return [row for row in labels if row.get("source") != "auto"]


def evaluate(labels, outcomes, cost, budget) -> str:
    empty = {
        gold: {pred_s: 0 for pred_s in ALL_SEVERITIES} for gold in ALL_SEVERITIES
    }
    all_m = _metrics(labels, outcomes, cost)
    human = human_labels(labels)
    human_m = _metrics(human, outcomes, cost) if human else {
        "baseline_p": None,
        "baseline_r": None,
        "trustmap_p": None,
        "trustmap_r": None,
        "cost": cost,
        "baseline_conf": empty,
        "trustmap_conf": empty,
        "baseline_flags": flag_stats([], {}),
        "trustmap_flags": flag_stats([], {}),
    }
    lines = [
        "# Eval results",
        "",
        render_table(title="All labels", include_cost=True, **all_m),
        "",
        render_table(title="Human-labeled only", include_cost=False, **human_m),
        "",
        debug_gold(labels, outcomes).rstrip(),
        "",
        "## Budget skips",
    ]
    if budget:
        lines.extend(f"- {item}" for item in budget)
    else:
        lines.append("- (none)")
    lines.append("")
    return "\n".join(lines)


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
