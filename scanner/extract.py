from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import tldextract

from scanner.config import (
    ALLOWLIST_DOMAINS,
    CONTEXT_LINES,
    GITHUB_CLONE_TIMEOUT_S,
    MAX_FILE_BYTES,
    MAX_SCAN_BYTES,
    MAX_SCAN_FILES,
    RFC2606_DOMAINS,
    RESERVED_TLDS,
    SKIP_DIR_NAMES,
    SKIP_FILE_NAMES,
    SKIP_NAME_SUFFIXES,
)
from scanner.models import Reference
from scanner.tools.github_owner import GITHUB_RESERVED

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False)

URL_RE = re.compile(r"https?://[^\s'\"<>\\)]+", re.IGNORECASE)
S3_SCHEME_RE = re.compile(
    r"s3://([A-Za-z0-9][A-Za-z0-9._-]{1,61}[A-Za-z0-9])", re.IGNORECASE
)
AZURE_BLOB_RE = re.compile(
    r"^([a-z0-9]{3,24})\.blob\.core\.windows\.net$", re.IGNORECASE
)
GH_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
PIPE_TO_SHELL_RE = re.compile(
    r"(?i)\b(?:curl|wget|iwr|invoke-webrequest|irm)\b.*\|\s*"
    r"(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*iex\b"
)
GITHUB_RE = re.compile(
    r"^https?://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?(?:/.*)?$", re.IGNORECASE
)
USES_RE = re.compile(
    r"""^\s*(?:-\s+)?uses:\s*['"]?([^'"\s#]+)['"]?\s*$""",
    re.IGNORECASE,
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TRAILING_JUNK = ".,;:)]}>'\""
HIGH_SUFFIXES = frozenset(
    {
        ".html",
        ".htm",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".json",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".env",
        ".tf",
        ".tfvars",
    }
)
SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".go",
        ".rs",
        ".java",
        ".rb",
        ".php",
        ".cs",
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".swift",
        ".kt",
        ".kts",
        ".scala",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".sql",
        ".vue",
        ".svelte",
        ".xml",
        ".gradle",
    }
)
DOC_SUFFIXES = frozenset({".md", ".rst", ".txt", ".adoc"})
DOC_NAMES = frozenset({"readme", "changelog", "license", "copying", "authors"})
HIGH_NAMES = frozenset(
    {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".env",
        ".env.local",
        ".env.example",
        ".env.production",
    }
)
BINARY_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".pyc",
        ".so",
        ".dylib",
        ".exe",
        ".bin",
        ".wasm",
        ".class",
        ".jar",
    }
)


@dataclass
class Coverage:
    files_scanned: int
    files_total: int
    truncated: bool
    reason: str = ""

    def as_dict(self) -> dict[str, int | bool | str]:
        return {
            "files_scanned": self.files_scanned,
            "files_total": self.files_total,
            "truncated": self.truncated,
            "reason": self.reason,
        }


@dataclass
class ExtractResult:
    references: list[Reference]
    coverage: Coverage


def _scan_file_cap() -> int:
    raw = os.environ.get("TRUSTMAP_MAX_SCAN_FILES", "")
    if raw.strip():
        return max(0, int(raw))
    return MAX_SCAN_FILES


def _scan_byte_cap() -> int:
    raw = os.environ.get("TRUSTMAP_MAX_SCAN_BYTES", "")
    if raw.strip():
        return max(0, int(raw))
    return MAX_SCAN_BYTES


def empty_coverage() -> Coverage:
    return Coverage(files_scanned=0, files_total=0, truncated=False, reason="")


def website_coverage() -> Coverage:
    return Coverage(files_scanned=1, files_total=1, truncated=False, reason="")


def actionable(refs: list[Reference]) -> list[Reference]:
    """Later phases skip anything with a filter_reason."""
    return [ref for ref in refs if ref.filter_reason is None]


def is_website_source(source: str) -> bool:
    text = source.strip()
    if not text.startswith(("http://", "https://")):
        return False
    if GITHUB_RE.match(text):
        return False
    if Path(text).exists():
        return False
    return True


def extract(source: str, *, clone_github=None) -> list[Reference]:
    return extract_scan(source, clone_github=clone_github).references


def extract_scan(source: str, *, clone_github=None) -> ExtractResult:
    path = Path(source)
    if path.exists():
        return _extract_dir(path.resolve())
    if GITHUB_RE.match(source.strip()):
        cloner = clone_github or _clone_github
        with tempfile.TemporaryDirectory() as tmp:
            return _extract_dir(cloner(source.strip(), Path(tmp)))
    raise FileNotFoundError(f"not a local path or GitHub URL: {source}")


def _clone_github(url: str, dest_parent: Path) -> Path:
    match = GITHUB_RE.match(url)
    if not match:
        raise ValueError(f"not a GitHub URL: {url}")
    owner, repo = match.group(1), match.group(2)
    dest = dest_parent / repo
    remote = f"https://github.com/{owner}/{repo}.git"
    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--filter=blob:limit=1m",
            "--quiet",
            remote,
            str(dest),
        ],
        check=True,
        timeout=GITHUB_CLONE_TIMEOUT_S,
    )
    return dest


def _extract_dir(root: Path) -> ExtractResult:
    found: dict[tuple[str, str, int], Reference] = {}
    candidates = _candidate_files(root)
    files_total = len(candidates)
    file_cap = _scan_file_cap()
    byte_cap = _scan_byte_cap()
    scanned = 0
    used_bytes = 0
    truncated = False
    reason = ""
    for path in candidates:
        size = _file_size(path)
        if size is None:
            continue
        if size > MAX_FILE_BYTES:
            continue
        if not _should_read(path):
            continue
        if scanned >= file_cap:
            truncated = True
            reason = "file_cap"
            break
        if used_bytes + size > byte_cap:
            truncated = True
            reason = "byte_cap"
            break
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        used_bytes += size
        scanned += 1
        _scan_text(rel, text, found)
    refs = sorted(found.values(), key=lambda ref: (ref.file, ref.line, ref.raw))
    return ExtractResult(
        references=refs,
        coverage=Coverage(
            files_scanned=scanned,
            files_total=files_total,
            truncated=truncated,
            reason=reason,
        ),
    )


def _candidate_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
        for name in filenames:
            path = Path(dirpath) / name
            lowered = name.lower()
            if lowered in SKIP_FILE_NAMES:
                continue
            if any(lowered.endswith(suffix) for suffix in SKIP_NAME_SUFFIXES):
                continue
            if path.suffix.lower() in BINARY_SUFFIXES:
                continue
            files.append(path)
    files.sort(key=lambda path: (_file_priority(path, root), path.as_posix()))
    return files


def _file_priority(path: Path, root: Path) -> int:
    rel = path.relative_to(root).as_posix().lower()
    name = path.name.lower()
    suffix = path.suffix.lower()
    if rel.startswith(".github/workflows/"):
        return 0
    if name in HIGH_NAMES or name.startswith("dockerfile"):
        return 0
    if suffix in HIGH_SUFFIXES or name.endswith(".env"):
        return 0
    if "/terraform/" in f"/{rel}/" or suffix in {".tf", ".tfvars"}:
        return 0
    if suffix in SOURCE_SUFFIXES:
        return 1
    if (
        suffix in DOC_SUFFIXES
        or name.split(".", 1)[0] in DOC_NAMES
        or rel.startswith("docs/")
    ):
        return 2
    return 3


def _file_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _should_read(path: Path) -> bool:
    name = path.name.lower()
    if name in SKIP_FILE_NAMES:
        return False
    if any(name.endswith(suffix) for suffix in SKIP_NAME_SUFFIXES):
        return False
    if path.suffix.lower() in BINARY_SUFFIXES:
        return False
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size > MAX_FILE_BYTES:
        return False
    try:
        with path.open("rb") as handle:
            chunk = handle.read(8192)
    except OSError:
        return False
    return b"\x00" not in chunk


def _scan_text(rel: str, text: str, found: dict[tuple[str, str, int], Reference]) -> None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        line_no = index + 1
        context = _context(lines, index)
        for host_or_bucket, raw, domain, reason in _find_on_line(line, rel):
            key = (host_or_bucket, rel, line_no)
            if key in found:
                continue
            found[key] = Reference(
                file=rel,
                line=line_no,
                raw=raw,
                host_or_bucket=host_or_bucket,
                domain=domain,
                context=context,
                filter_reason=reason,
            )
        if _is_workflow_or_action_file(rel):
            action = _action_from_uses(line)
            if action is not None:
                owner, repo, ref, sha_pinned, raw = action
                host = f"github.com/{owner}/{repo}"
                key = (host, rel, line_no)
                if key not in found:
                    found[key] = Reference(
                        file=rel,
                        line=line_no,
                        raw=raw,
                        host_or_bucket=host,
                        domain="",
                        context=context,
                        filter_reason=None,
                        action_owner=owner,
                        action_repo=repo,
                        action_ref=ref,
                        action_sha_pinned=sha_pinned,
                    )


def _context(lines: list[str], index: int) -> str:
    start = max(0, index - CONTEXT_LINES // 2)
    end = min(len(lines), start + CONTEXT_LINES)
    start = max(0, end - CONTEXT_LINES)
    return "\n".join(lines[start:end])


def _find_on_line(
    line: str, rel: str = ""
) -> list[tuple[str, str, str, str | None]]:
    hits: list[tuple[str, str, str, str | None]] = []
    for match in S3_SCHEME_RE.finditer(line):
        name = match.group(1)
        hits.append((name, match.group(0), "", _filter_reason("", "", name, True)))
    for match in URL_RE.finditer(line):
        raw = match.group(0).rstrip(TRAILING_JUNK)
        parsed = _classify_http_url(raw, line, rel)
        if parsed is None:
            continue
        hits.append(parsed)
    return hits


def _classify_http_url(
    raw: str, line: str = "", rel: str = ""
) -> tuple[str, str, str, str | None] | None:
    parsed = urlparse(raw)
    host = _host_from_netloc(parsed.netloc)
    if not host:
        return None
    path = parsed.path.lstrip("/")
    first = path.split("/", 1)[0] if path else ""
    host_l = host.lower()

    bucket = _bucket_from_http(host, host_l, first)
    if bucket:
        domain = _registrable(host)
        return bucket, raw, domain, _filter_reason(host, domain, bucket, True)

    owner_hit = _github_owner_target(host_l, path, raw, line, rel)
    if owner_hit is not None:
        return owner_hit

    domain = _registrable(host)
    return host, raw, domain, _filter_reason(host, domain, host, False)


def is_bucket_ref(ref: Reference) -> bool:
    raw = (ref.raw or "").strip()
    lowered = raw.lower()
    if lowered.startswith("s3://"):
        return True
    if not lowered.startswith("http"):
        return False
    parsed = urlparse(raw)
    host = _host_from_netloc(parsed.netloc)
    path = parsed.path.lstrip("/")
    first = path.split("/", 1)[0] if path else ""
    return _bucket_from_http(host, host.lower(), first) is not None


def _bucket_from_http(host: str, host_l: str, first: str) -> str | None:
    if host_l == "storage.googleapis.com" and first:
        return first
    if host_l == "s3.amazonaws.com" and first:
        return first
    region_path = re.fullmatch(r"s3\.[a-z0-9-]+\.amazonaws\.com", host_l)
    if region_path and first:
        return first
    virtual = re.fullmatch(
        r"(.+)\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com", host, flags=re.IGNORECASE
    )
    if virtual:
        return virtual.group(1)
    azure = AZURE_BLOB_RE.fullmatch(host_l)
    if azure:
        return azure.group(1)
    return None


def is_github_action_ref(ref: Reference) -> bool:
    return bool(ref.action_owner and ref.action_repo)


def is_github_owner_ref(ref: Reference) -> bool:
    if is_github_action_ref(ref):
        return False
    return github_login(ref) is not None and ref.host_or_bucket.lower().startswith(
        "github.com/"
    )


def github_login(ref: Reference) -> str | None:
    if ref.action_owner:
        return (
            ref.action_owner.lower()
            if _valid_github_owner(ref.action_owner)
            else None
        )
    host = ref.host_or_bucket.lower()
    if host.startswith("github.com/"):
        owner = host.split("/", 1)[1]
        return owner if _valid_github_owner(owner) else None
    if host.endswith(".github.io") and host != "github.io":
        owner = host.split(".", 1)[0]
        return owner if _valid_github_owner(owner) else None
    return None


def _valid_github_owner(owner: str) -> bool:
    return bool(GH_OWNER_RE.match(owner)) and owner.lower() not in GITHUB_RESERVED


def _is_workflow_or_action_file(rel: str) -> bool:
    path = rel.replace("\\", "/").lower()
    name = path.rsplit("/", 1)[-1]
    if path.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
        return True
    return name in {"action.yml", "action.yaml"}


def _action_from_uses(
    line: str,
) -> tuple[str, str, str, bool, str] | None:
    match = USES_RE.match(line)
    if not match:
        return None
    spec = match.group(1).strip()
    if spec.startswith("./") or spec.startswith("docker://"):
        return None
    if "@" not in spec:
        return None
    name, ref = spec.rsplit("@", 1)
    parts = [part for part in name.split("/") if part]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if not _valid_github_owner(owner):
        return None
    sha_pinned = bool(SHA_RE.fullmatch(ref.lower()))
    return owner.lower(), repo.lower(), ref, sha_pinned, spec


def _github_owner_target(
    host_l: str, path: str, raw: str, line: str, rel: str
) -> tuple[str, str, str, str | None] | None:
    segs = [part for part in path.split("/") if part]
    owner = None
    if host_l in {"github.com", "www.github.com"} and len(segs) >= 2:
        if not _is_ci_pipe_to_shell(rel, line):
            return None
        owner = segs[0]
    elif host_l == "raw.githubusercontent.com" and segs:
        owner = segs[0]
    if owner and _valid_github_owner(owner):
        return f"github.com/{owner.lower()}", raw, "", None
    return None


def _is_ci_pipe_to_shell(rel: str, line: str) -> bool:
    path = rel.replace("\\", "/").lower()
    if not path.startswith(".github/workflows/"):
        return False
    return PIPE_TO_SHELL_RE.search(line) is not None


def _host_from_netloc(netloc: str) -> str:
    if not netloc:
        return ""
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[-1]
    if netloc.startswith("["):
        end = netloc.find("]")
        return netloc[1:end] if end != -1 else netloc
    return netloc.rsplit(":", 1)[0]


def _registrable(host: str) -> str:
    parts = _EXTRACT(host)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}".lower()
    return host.lower()


_PLACEHOLDER_CHARS = frozenset("{}<>$")


def _filter_reason(
    host: str, domain: str, host_or_bucket: str, is_bucket: bool
) -> str | None:
    if is_bucket:
        if _is_placeholder(host_or_bucket):
            return "placeholder"
        return None
    if _is_ip(host):
        return "ip_address"
    if _is_placeholder(host) or _is_placeholder(host_or_bucket):
        return "placeholder"
    psl_suffix = _suffix(host)
    last_label = host.rsplit(".", 1)[-1].lower() if host else ""
    if psl_suffix in RESERVED_TLDS or last_label in RESERVED_TLDS:
        return "reserved_tld"
    if domain.lower() in RFC2606_DOMAINS:
        return "reserved_domain"
    if not psl_suffix:
        return "no_public_suffix"
    if domain.lower() in ALLOWLIST_DOMAINS or host.lower() in ALLOWLIST_DOMAINS:
        return "allowlisted"
    return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _is_placeholder(value: str) -> bool:
    return any(char in value for char in _PLACEHOLDER_CHARS)


def _suffix(host: str) -> str:
    parts = _EXTRACT(host)
    return (parts.suffix or "").lower()
