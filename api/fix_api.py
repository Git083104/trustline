from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner.copy import assistant_prompt, decorate, issue_markdown
from scanner.fix import FixPlan, propose_fixes, write_pr_copy
from scanner.models import Finding, Severity

PAGES = Path(__file__).resolve().parent / "demo_pages.html"


def findings_from_public(rows: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    for row in rows:
        refs = row.get("references") or []
        locations = [item for item in refs if isinstance(item, dict)]
        strings = [item for item in refs if isinstance(item, str)]
        if not locations:
            for item in strings:
                file, _, line = str(item).rpartition(":")
                loc = {"file": file or str(item), "line": int(line) if line.isdigit() else 1}
                lowered = loc["file"].replace("\\", "/").lower()
                if ".github/workflows/" in lowered:
                    loc["runs_in"] = "ci"
                locations.append(loc)
        if not strings:
            strings = [
                f"{item.get('file', 'index.html')}:{item.get('line', 1)}"
                for item in locations
            ] or ["index.html:1"]
        severity = row.get("severity") or "info"
        out.append(
            decorate(Finding(
                target=row["target"],
                kind=row.get("kind") or "domain",
                references=strings,
                severity=severity,  # type: ignore[arg-type]
                model_severity=row.get("model_severity") or severity,  # type: ignore[arg-type]
                final_severity=severity,  # type: ignore[arg-type]
                classified_blast_radius=int(row.get("classified_blast_radius") or 0),
                ranked_blast_radius=int(row.get("blast_radius") or 0),
                risk=row.get("risk") or "",
                fix=row.get("fix") or "remove dead reference",
                evidence=row.get("evidence") or {},
                evidence_line=row.get("evidence_line") or "",
                locations=locations,
                action_ref=row.get("action_ref") or "",
                action_sha_pinned=row.get("action_sha_pinned"),
            ))
        )
    _ = Severity
    return out


def plan_for(
    findings: list[Finding],
    file_texts: dict[str, str],
    *,
    client: Any | None = None,
) -> FixPlan:
    plan = propose_fixes(findings, file_texts)
    title, body = write_pr_copy(plan, findings, client=client)
    plan.title = title
    plan.body = body
    return plan


def demo_file_texts() -> dict[str, str]:
    if PAGES.is_file():
        return {"index.html": PAGES.read_text()}
    return {}


def plan_to_dict(plan: FixPlan, findings: list[Finding] | None = None) -> dict[str, Any]:
    items = []
    for item in findings or []:
        if item.severity not in {"critical", "high"}:
            continue
        title, body = issue_markdown(item)
        items.append(
            {
                "target": item.target,
                "headline": item.headline or title,
                "steps": item.steps,
                "issue_title": title,
                "issue_body": body,
                "prompt": assistant_prompt(item),
            }
        )
    return {
        "title": plan.title,
        "body": plan.body,
        "patch": plan.patch,
        "edit_count": len(plan.edits),
        "items": items,
        "edits": [
            {
                "file": edit.file,
                "line": edit.line,
                "before": edit.before,
                "after": edit.after,
                "finding_id": edit.finding_id,
                "kind": edit.kind,
            }
            for edit in plan.edits
        ],
    }
