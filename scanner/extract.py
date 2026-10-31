from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import tldextract

from scanner.config import (
    ALLOWLIST_DOMAINS,
    CONTEXT_LINES,
    GITHUB_CLONE_TIMEOUT_S,
    MAX_FILE_BYTES,
    SKIP_DIR_NAMES,
)
from scanner.models import Reference

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False)

URL_RE = re.compile(r"https?://[^\s'\"<>\\)]+", re.IGNORECASE)
S3_SCHEME_RE = re.compile(
    r"s3://([A-Za-z0-9][A-Za-z0-9._-]{1,61}[A-Za-z0-9])", re.IGNORECASE
)
GITHUB_RE = re.compile(
    r"^https?://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?(?:/.*)?$", re.IGNORECASE
)
TRAILING_JUNK = ".,;:)]}>'\""
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


def extract(source: str, *, clone_github=None) -> list[Reference]:
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
        ["git", "clone", "--depth", "1", "--quiet", remote, str(dest)],
        check=True,
        timeout=GITHUB_CLONE_TIMEOUT_S,
    )
    return dest


def _extract_dir(root: Path) -> list[Reference]:
    found: dict[tuple[str, str, int], Reference] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
        for name in filenames:
            path = Path(dirpath) / name
            if not _should_read(path):
                continue
            rel = path.relative_to(root).as_posix()
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            _scan_text(rel, text, found)
    return sorted(found.values(), key=lambda ref: (ref.file, ref.line, ref.raw))


def _should_read(path: Path) -> bool:
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
        for host_or_bucket, raw, domain in _find_on_line(line):
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
            )


def _context(lines: list[str], index: int) -> str:
    start = max(0, index - CONTEXT_LINES // 2)
    end = min(len(lines), start + CONTEXT_LINES)
    start = max(0, end - CONTEXT_LINES)
    return "\n".join(lines[start:end])


def _find_on_line(line: str) -> list[tuple[str, str, str]]:
    hits: list[tuple[str, str, str]] = []
    for match in S3_SCHEME_RE.finditer(line):
        name = match.group(1)
        hits.append((name, match.group(0), ""))
    for match in URL_RE.finditer(line):
        raw = match.group(0).rstrip(TRAILING_JUNK)
        parsed = _classify_http_url(raw)
        if parsed is None:
            continue
        hits.append(parsed)
    return hits


def _classify_http_url(raw: str) -> tuple[str, str, str] | None:
    parsed = urlparse(raw)
    host = _host_from_netloc(parsed.netloc)
    if not host:
        return None
    path = parsed.path.lstrip("/")
    first = path.split("/", 1)[0] if path else ""
    host_l = host.lower()

    bucket = _bucket_from_http(host, host_l, first)
    if bucket:
        return bucket, raw, _registrable(host)

    domain = _registrable(host)
    if domain in ALLOWLIST_DOMAINS or host_l in ALLOWLIST_DOMAINS:
        return None
    return host, raw, domain


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
    return None


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
