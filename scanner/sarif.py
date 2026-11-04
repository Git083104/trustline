"""SARIF 2.1.0 export. Facts stay on the Finding; this file only serializes them."""

from __future__ import annotations

from typing import Any

from scanner.copy import headline_for, risk_type
from scanner.models import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _uri_line(item: Finding) -> tuple[str, int]:
    for loc in item.locations or []:
        if isinstance(loc, dict) and loc.get("file"):
            return str(loc["file"]), int(loc.get("line") or 1)
    if item.references:
        ref = item.references[0]
        if isinstance(ref, str) and ":" in ref:
            path, _, rest = ref.partition(":")
            try:
                return path, int(rest.split(":")[0])
            except ValueError:
                return path, 1
    return "unknown", 1


def findings_to_sarif(findings: list[Finding]) -> dict[str, Any]:
    rules: dict[str, dict[str, str]] = {}
    results = []
    for item in findings:
        rule_id = (item.risk_type or risk_type(item) or "unregistered_host").replace(" ", "_")
        message = item.headline or headline_for(item)
        uri, line = _uri_line(item)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": message},
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": LEVEL.get(item.severity, "note"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": max(1, line)},
                        }
                    }
                ],
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Tether",
                        "informationUri": "https://github.com/Git083104/trustline",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
