from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from scanner.config import (
    CLASSIFY_BATCH_SIZE,
    CLASSIFY_CONCURRENCY,
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
    "blast_radius is 0-3. Do not invent hosts, dates, or counts. "
    "type is what the URL points to, not which file it sits in: "
    "script = downloaded and executed (JS, shell, Python). Example: "
    "<script src=\"https://cdn.example/app.js\"> or curl https://ci.example/tool.sh | sh; "
    "api = HTTP API base or endpoint. Example: const API = \"https://api.example.com/v1\"; "
    "asset = static file that is not executed (css, image, font). Example: "
    "<link href=\"https://cdn.example/app.css\">; "
    "bucket = object-storage name. Example: s3://my-bucket; "
    "docs_link = documentation, status, or handbook URL. Example: README link to "
    "https://docs.example/setup; "
    "other = anything else. Example: an unknown binary download URL. "
    "runs_in is when/where it is used: "
    "browser = loaded in the user's browser. Example: script src in HTML; "
    "server = used by backend at runtime. Example: BILLING_URL in settings.py; "
    "build = used while building an image or package. Example: ADD https://.../get-pip.py "
    "in a Dockerfile; "
    "deploy = named in deploy/infra config. Example: s3://bucket in infra.yaml; "
    "ci = used in CI workflows. Example: curl of a script in .github/workflows; "
    "test = used only in tests. Example: MOCK_HEALTH in tests/test_client.py; "
    "docs_only = comments, README, or docs. Example: a handbook link in README.md."
)

_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "type": {
            "type": "string",
            "enum": ["script", "api", "asset", "bucket", "docs_link", "other"],
        },
        "runs_in": {
            "type": "string",
            "enum": ["browser", "server", "build", "deploy", "ci", "test", "docs_only"],
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
    batches = [
        chosen[start : start + CLASSIFY_BATCH_SIZE]
        for start in range(0, len(chosen), CLASSIFY_BATCH_SIZE)
    ]
    # one log list per batch, merged in batch order, so costs never depend on timing
    batch_logs: list[list[CallLog]] = [[] for _ in batches]

    def run(index: int) -> list[Classification]:
        return _classify_batch(
            batches[index], client=client, cache=cache, logs=batch_logs[index]
        )

    workers = min(CLASSIFY_CONCURRENCY, len(batches))
    if workers <= 1:
        done = [run(index) for index in range(len(batches))]
    else:
        # A big repository is dozens of batches; one at a time they took longer
        # than a serverless request may run.
        with ThreadPoolExecutor(max_workers=workers) as pool:
            done = list(pool.map(run, range(len(batches))))
    if logs is not None:
        for bundle in batch_logs:
            logs.extend(bundle)
    return [item for batch in done for item in batch]


def set_aside(ref: Reference) -> Classification:
    """A label for a reference code filters already dropped; no later step reads it."""
    return Classification(
        id="set-aside",
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        type="other",
        runs_in="docs_only",
        blast_radius=0,
        confidence=0.0,
        reason=f"set aside by code: {ref.filter_reason}",
    )


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


def runs_in_mismatch_table(
    got: list[Classification], expected: list[dict]
) -> list[tuple[str, int, str, str]]:
    by_loc = {(row.file, row.line): row for row in got}
    rows: list[tuple[str, int, str, str]] = []
    for exp in expected:
        key = (exp["file"], exp["line"])
        found = by_loc.get(key)
        got_runs = found.runs_in if found else "(missing)"
        if got_runs != exp["runs_in"]:
            rows.append((exp["file"], exp["line"], exp["runs_in"], got_runs))
    return rows
