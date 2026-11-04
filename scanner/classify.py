from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scanner.config import (
    ALLOWLIST_DOMAINS,
    CLASSIFY_BATCH_SIZE,
    CLASSIFY_CONCURRENCY,
    CLASSIFY_MODEL,
    CLASSIFY_REASONING_EFFORT,
)
from scanner.deadline import ScanClock
from scanner.inert import is_inert_path
from scanner.extract import (
    actionable,
    is_bucket_ref,
    is_github_action_ref,
    is_github_owner_ref,
)
from scanner.llm import ModelClient, OverloadError, call_json, muse_overloaded, redact_secrets
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
    "link = opened or shared as a hyperlink, not downloaded. Example: "
    "<a href=\"https://example.com\"> or a markdown [text](https://example.com) link; "
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
            "enum": ["script", "api", "asset", "bucket", "docs_link", "link", "other"],
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

_SCRIPT_SUFFIXES = (
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".sh",
    ".bash",
    ".py",
)
_ASSET_SUFFIXES = (
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
)
_DOCKER_INSTR = re.compile(r"(?i)\b(FROM|ADD|COPY|curl|wget)\b")
_SCRIPT_TAG = re.compile(r"(?i)<script\b")
_LINK_TAG = re.compile(r"(?i)<link\b")
_A_HREF = re.compile(r"(?i)<a\b[^>]*\bhref\s*=")
_MD_LINK = re.compile(r"\[[^\]]*\]\(\s*https?://", re.IGNORECASE)
_SHARE_OPEN = re.compile(
    r"(?i)(window\.open\s*\(|location\.href\s*=|shareurl|share_url|openurl)"
)
SKIPPED_CLASSIFY = "not classified (deadline)"
UNKNOWN_POSITION = "unknown position"
log = logging.getLogger("trustmap")
_PACKAGE_HOSTS = (
    "npmjs.com",
    "npmjs.org",
    "unpkg.com",
    "jsdelivr.net",
    "pypi.org",
    "pythonhosted.org",
    "rubygems.org",
    "crates.io",
    "nuget.org",
    "maven.org",
    "pkg.go.dev",
    "proxy.golang.org",
)
_DOC_NAMES = (
    "readme",
    "changelog",
    "changes",
    "license",
    "copying",
    "authors",
    "contributing",
    "security",
    "code_of_conduct",
)


def _docs_only_file(path: str, name: str) -> bool:
    stem = name.split(".", 1)[0]
    if any(stem.startswith(prefix) for prefix in _DOC_NAMES):
        return True
    return "/docs/" in path or path.startswith("docs/")


def _package_registry(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == item or host.endswith("." + item) for item in _PACKAGE_HOSTS)


def _allowlisted_host(host: str, domain: str) -> bool:
    names = {host.lower().rstrip("."), domain.lower().rstrip(".")}
    for item in ALLOWLIST_DOMAINS:
        if item in names:
            return True
        if any(name.endswith("." + item) for name in names if name):
            return True
    return False


def _cloud_object_url(raw: str, host: str) -> bool:
    blob = f"{raw} {host}".lower()
    return (
        "s3.amazonaws.com" in blob
        or ".s3." in blob
        or "storage.googleapis.com" in blob
        or "blob.core.windows.net" in blob
        or blob.startswith("gs://")
        or blob.startswith("az://")
    )


def _url_in_comment(context: str, raw: str) -> bool:
    if not context or not raw:
        return False
    for line in context.splitlines():
        if raw not in line:
            continue
        before = line.split(raw, 1)[0].strip()
        return before.startswith(("//", "#", "/*", "*"))
    return False


def _config_source(name: str) -> bool:
    stem, _, suffix = name.partition(".")
    return stem == "config" and suffix in {
        "js",
        "mjs",
        "cjs",
        "ts",
        "tsx",
        "json",
    }


def _plain_link(ref: Reference, context: str, raw_l: str) -> bool:
    if ref.tag in {"script", "link", "img", "source", "iframe"}:
        return False
    if ref.tag in {"a", "markdown"}:
        return True
    blob = context or ""
    if _A_HREF.search(blob) or _MD_LINK.search(blob):
        return True
    if _SHARE_OPEN.search(blob):
        return True
    return False


def classify_by_rule(ref: Reference) -> Classification | None:
    path = ref.file.replace("\\", "/")
    lowered = path.lower()
    name = Path(path).name.lower()
    context = ref.context or ""
    raw_l = (ref.raw or "").lower()
    url_path = raw_l.split("?", 1)[0]
    host = (ref.domain or ref.host_or_bucket or "").lower()

    if is_inert_path(lowered) or _docs_only_file(lowered, name):
        runs = "test" if any(part in lowered.split("/") for part in ("tests", "test", "__tests__", "spec", "fixtures")) else "docs_only"
        return _rule(ref, "docs_link", runs, 0, "inert file")
    if _url_in_comment(context, ref.raw):
        return _rule(ref, "docs_link", "docs_only", 0, "comment URL")
    if is_bucket_ref(ref) or raw_l.startswith("s3://") or _cloud_object_url(raw_l, host):
        runs = "ci" if ".github/workflows/" in lowered else "deploy"
        return _rule(ref, "bucket", runs, 3, "object storage URL")
    if is_github_action_ref(ref) or (
        ".github/workflows/" in lowered and "uses:" in context.lower()
    ):
        return _rule(ref, "script", "ci", 2, "GitHub Actions uses:")
    if name == "dockerfile" and _DOCKER_INSTR.search(context):
        return _rule(ref, "script", "build", 2, "Dockerfile FROM/ADD")
    if _package_registry(host):
        runs = "build" if name in {
            "package.json",
            "requirements.txt",
            "pyproject.toml",
            "go.mod",
            "cargo.toml",
            "gemfile",
        } else "docs_only"
        return _rule(ref, "other", runs, 0 if runs == "docs_only" else 1, "package registry")
    html = name.endswith(".html") or name.endswith(".htm")
    if _plain_link(ref, context, raw_l):
        runs = "browser" if html or ref.tag in {"a", "markdown"} else "server"
        return _rule(ref, "link", runs, 1, "plain link")
    if is_github_owner_ref(ref) or "raw.githubusercontent.com" in raw_l:
        if ".github/workflows/" in lowered:
            return _rule(ref, "script", "ci", 2, "GitHub URL")
        return _rule(ref, "script", "server", 2, "GitHub URL")
    if host.endswith("github.io"):
        runs = "browser" if html or ref.tag == "script" else "server"
        return _rule(ref, "script", runs, 2, "GitHub Pages URL")
    if _allowlisted_host(host, ref.domain or "") or ref.filter_reason == "allowlisted":
        return _rule(ref, "docs_link", "docs_only", 0, "allowlisted host")
    if ".github/workflows/" in lowered:
        if any(url_path.endswith(suffix) for suffix in _SCRIPT_SUFFIXES):
            return _rule(ref, "script", "ci", 2, "CI script URL")
        if "curl" in context.lower() or "wget" in context.lower():
            return _rule(ref, "script", "ci", 2, "CI curl")
    if ref.tag == "script" or (
        html and _SCRIPT_TAG.search(context) and ref.tag not in {"link", "img", "source"}
    ):
        return _rule(ref, "script", "browser", 2, "script tag")
    if ref.tag == "link" or (
        html and _LINK_TAG.search(context) and ref.tag not in {"script", "img", "source"}
    ):
        return _rule(ref, "asset", "browser", 1, "link tag")
    if html and any(url_path.endswith(suffix) for suffix in _SCRIPT_SUFFIXES):
        return _rule(ref, "script", "browser", 2, "script tag")
    if html and (
        ref.tag in {"img", "source", "link"}
        or any(url_path.endswith(suffix) for suffix in _ASSET_SUFFIXES)
    ):
        return _rule(ref, "asset", "browser", 1, "static asset URL")
    if _config_source(name):
        if any(url_path.endswith(suffix) for suffix in _SCRIPT_SUFFIXES):
            return _rule(ref, "script", "browser", 2, "config script URL")
        if any(url_path.endswith(suffix) for suffix in _ASSET_SUFFIXES):
            return _rule(ref, "asset", "server", 1, "config asset URL")
        return _rule(ref, "api", "server", 2, "config URL")
    if html or name.endswith(".ejs") or name.endswith(".jsx") or name.endswith(".tsx"):
        if ref.tag not in {"script", "link", "img", "source", "iframe"}:
            if not _SCRIPT_TAG.search(context):
                return _rule(ref, "link", "browser", 1, "markup URL")
    return None


def _rule(
    ref: Reference, type_: str, runs_in: str, blast: int, reason: str
) -> Classification:
    return Classification(
        id="0",
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        type=type_,  # type: ignore[arg-type]
        runs_in=runs_in,  # type: ignore[arg-type]
        blast_radius=blast,
        confidence=1.0,
        reason=reason,
    )


def _unknown_position(ref: Reference, reason: str) -> Classification:
    return Classification(
        id="0",
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        type="other",
        runs_in="docs_only",
        blast_radius=0,
        confidence=0.0,
        reason=reason,
    )


def _deadline_classification(ref: Reference) -> Classification:
    return _unknown_position(ref, f"{UNKNOWN_POSITION} ({SKIPPED_CLASSIFY})")


def _fallback_classification(ref: Reference) -> Classification:
    ruled = classify_by_rule(ref)
    if ruled is not None:
        return ruled
    return _unknown_position(ref, f"{UNKNOWN_POSITION} (model timeout fallback)")


def classify(
    refs: list[Reference],
    *,
    client: ModelClient,
    include_filtered: bool = False,
    cache: LookupCache | None = None,
    logs: list[CallLog] | None = None,
    clock: ScanClock | None = None,
    skipped: list[str] | None = None,
    code_only_hosts: list[str] | None = None,
    code_only: bool = False,
) -> list[Classification]:
    chosen = refs if include_filtered else actionable(refs)
    results: list[Classification | None] = [None] * len(chosen)
    pending: list[int] = []
    for index, ref in enumerate(chosen):
        ruled = classify_by_rule(ref)
        if ruled is not None:
            results[index] = ruled
        else:
            pending.append(index)
    rule_n = len(chosen) - len(pending)
    model_n = len(pending)
    if clock is not None:
        clock.classify_rule_n = rule_n
        clock.classify_model_n = model_n
    log.info("classify rules=%s model=%s", rule_n, model_n)
    if code_only or muse_overloaded():
        if clock is not None:
            clock.classify_model_n = 0
        for index in pending:
            results[index] = _fallback_classification(chosen[index])
        return [item for item in results if item is not None]
    if not pending:
        return [item for item in results if item is not None]

    chunks = [
        pending[start : start + CLASSIFY_BATCH_SIZE]
        for start in range(0, len(pending), CLASSIFY_BATCH_SIZE)
    ]
    batch_logs: list[list[CallLog]] = [[] for _ in chunks]

    def work(batch_index: int) -> None:
        chunk = chunks[batch_index]
        if muse_overloaded():
            for index in chunk:
                results[index] = _fallback_classification(chosen[index])
            return
        if clock is not None and clock.expired():
            hosts = []
            for index in chunk:
                ref = chosen[index]
                results[index] = _fallback_classification(ref)
                hosts.append(ref.host_or_bucket)
                if code_only_hosts is not None:
                    code_only_hosts.append(ref.host_or_bucket)
            if clock is not None:
                clock.note_skip(
                    "classify",
                    "stage budget exhausted; used file-shape rules",
                    hosts,
                )
            return
        batch = [chosen[index] for index in chunk]
        timeout_s = clock.request_timeout() if clock is not None else None
        try:
            classified = _classify_batch(
                batch,
                client=client,
                cache=cache,
                logs=batch_logs[batch_index],
                timeout_s=timeout_s,
            )
        except (TimeoutError, OverloadError) as exc:
            hosts = []
            for index in chunk:
                ref = chosen[index]
                guessed = _fallback_classification(ref)
                results[index] = guessed
                hosts.append(ref.host_or_bucket)
                if code_only_hosts is not None:
                    code_only_hosts.append(ref.host_or_bucket)
            if hosts and clock is not None:
                clock.note_skip(
                    "classify",
                    f"model batch exceeded {timeout_s}s; used file-shape rules",
                    hosts,
                )
            else:
                log.warning("classify used file-shape fallback (%s)", type(exc).__name__)
            return
        for index, item in zip(chunk, classified, strict=True):
            results[index] = item

    workers = min(CLASSIFY_CONCURRENCY, len(chunks))
    if workers <= 1:
        work(0)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for future in [pool.submit(work, i) for i in range(len(chunks))]:
                future.result()
    if logs is not None:
        for bundle in batch_logs:
            logs.extend(bundle)
    return [item for item in results if item is not None]


def _classify_batch(
    batch: list[Reference],
    *,
    client: ModelClient,
    cache: LookupCache | None,
    logs: list[CallLog] | None,
    timeout_s: float | None = None,
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
        timeout_s=timeout_s,
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
