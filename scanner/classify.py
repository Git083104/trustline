from __future__ import annotations

import json

from scanner.config import (
    CLASSIFY_BATCH_SIZE,
    CLASSIFY_MODEL,
    CLASSIFY_REASONING_EFFORT,
)
from scanner.extract import actionable
from scanner.llm import ModelClient, call_json, redact_secrets
from scanner.lookups import LookupCache
from scanner.models import (
    Classification,
    ClassificationBatch,
    ClassificationItem,
    CallLog,
    Reference,
)

CLASSIFY_SYSTEM_PROMPT = (
    "You classify outside infrastructure references found in a software repo. "
    "Return JSON only. Use each provided id exactly once. "
    "type must be one of: script, api, asset, config, bucket, ci, docs, test. "
    "runs_in must be one of: browser, server, build, ci, docs_only. "
    "blast_radius is 0-3. Do not invent hosts, dates, or counts."
)

_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "type": {
            "type": "string",
            "enum": ["script", "api", "asset", "config", "bucket", "ci", "docs", "test"],
        },
        "runs_in": {
            "type": "string",
            "enum": ["browser", "server", "build", "ci", "docs_only"],
        },
        "blast_radius": {"type": "integer", "minimum": 0, "maximum": 3},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reason": {"type": "string"},
    },
    "required": ["id", "type", "runs_in", "blast_radius", "confidence", "reason"],
    "additionalProperties": False,
}

CLASSIFY_JSON_SCHEMA = {
    "type": "object",
    "properties": {"items": {"type": "array", "items": _ITEM_SCHEMA}},
    "required": ["items"],
    "additionalProperties": False,
}


def classify(
    refs: list[Reference],
    *,
    client: ModelClient,
    include_filtered: bool = False,
    cache: LookupCache | None = None,
    logs: list[CallLog] | None = None,
) -> list[Classification]:
    chosen = refs if include_filtered else actionable(refs)
    results: list[Classification] = []
    for start in range(0, len(chosen), CLASSIFY_BATCH_SIZE):
        batch = chosen[start : start + CLASSIFY_BATCH_SIZE]
        results.extend(_classify_batch(batch, client=client, cache=cache, logs=logs))
    return results


def _classify_batch(
    batch: list[Reference],
    *,
    client: ModelClient,
    cache: LookupCache | None,
    logs: list[CallLog] | None,
) -> list[Classification]:
    items = []
    expected_ids: list[str] = []
    for index, ref in enumerate(batch):
        ref_id = str(index)
        expected_ids.append(ref_id)
        items.append(
            {
                "id": ref_id,
                "file": ref.file,
                "line": ref.line,
                "raw": ref.raw,
                "host_or_bucket": ref.host_or_bucket,
                "domain": ref.domain,
                "context": redact_secrets(ref.context),
            }
        )
    user = (
        "Classify each reference. Return one item per id.\n"
        + json.dumps({"references": items}, sort_keys=True)
    )

    def check_ids(parsed: ClassificationBatch) -> None:
        got = [item.id for item in parsed.items]
        if len(got) != len(expected_ids) or set(got) != set(expected_ids):
            raise ValueError(f"ids {got} != {expected_ids}")
        if len(set(got)) != len(got):
            raise ValueError("duplicate ids")

    parsed, log = call_json(
        CLASSIFY_MODEL,
        CLASSIFY_SYSTEM_PROMPT,
        user,
        ClassificationBatch,
        CLASSIFY_REASONING_EFFORT,
        client=client,
        json_schema=CLASSIFY_JSON_SCHEMA,
        schema_name="classification_batch",
        cache=cache,
        extra_check=check_ids,
    )
    if logs is not None:
        logs.append(log)
    by_id = {item.id: item for item in parsed.items}
    return [_merge(ref, by_id[str(index)]) for index, ref in enumerate(batch)]


def _merge(ref: Reference, item: ClassificationItem) -> Classification:
    return Classification(
        id=item.id,
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        type=item.type,
        runs_in=item.runs_in,
        blast_radius=item.blast_radius,
        confidence=item.confidence,
        reason=item.reason,
    )


def type_mismatch_table(
    got: list[Classification], expected: list[dict]
) -> list[tuple[str, int, str, str]]:
    by_loc = {(row.file, row.line): row for row in got}
    rows: list[tuple[str, int, str, str]] = []
    for exp in expected:
        key = (exp["file"], exp["line"])
        found = by_loc.get(key)
        got_type = found.type if found else "(missing)"
        if got_type != exp["type"]:
            rows.append((exp["file"], exp["line"], exp["type"], got_type))
    return rows
