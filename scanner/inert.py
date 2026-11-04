"""Inert paths and .tether.yml ignore globs. Never executing for floors or patches."""

from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml

INERT_DIR_NAMES = frozenset(
    {
        "tests",
        "test",
        "__tests__",
        "spec",
        "fixtures",
        "testdata",
        "__snapshots__",
        "mocks",
        "docs",
        "design",
        "examples",
    }
)
INERT_NAME_MARKERS = ("expected", "snapshot", "recording", "demo_scan")
SOURCE_SUFFIXES = frozenset(
    {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
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
        ".vue",
        ".svelte",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
    }
)
CONFIG_OK = frozenset(
    {
        "package.json",
        "manifest.json",
        "action.yml",
        "action.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    }
)
DATA_SUFFIXES = frozenset({".json", ".csv", ".jsonl", ".ndjson"})


def _posix(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def is_config_file(path: str) -> bool:
    posix = _posix(path)
    name = posix.rsplit("/", 1)[-1].lower()
    if name in CONFIG_OK:
        return True
    if ".config." in name or name.endswith(".config.js") or name.endswith(".config.ts"):
        return True
    orig = path.replace("\\", "/")
    if ".github/workflows/" in orig and name.endswith((".yml", ".yaml")):
        return True
    if name.startswith("docker-compose.") or name.startswith("_config.") or name.startswith("config."):
        return True
    return False


def is_data_file(path: str) -> bool:
    if is_config_file(path):
        return False
    posix = _posix(path).lower()
    name = posix.rsplit("/", 1)[-1]
    suffix = Path(name).suffix.lower()
    if name.endswith(".jsonl") or name.endswith(".ndjson"):
        return True
    return suffix in DATA_SUFFIXES


def is_inert_path(path: str) -> bool:
    posix = _posix(path).lower()
    name = posix.rsplit("/", 1)[-1]
    if is_config_file(path) and not _in_inert_dir(posix):
        return False
    if is_data_file(path):
        return True
    if posix.endswith(".md"):
        return True
    if name == "demo_scan.json" or posix.endswith("/demo_scan.json"):
        return True
    if any(marker in name for marker in INERT_NAME_MARKERS):
        return True
    if name.startswith("test_") and name.endswith(".py"):
        return True
    stem, _, suffix = name.partition(".")
    if name.endswith((".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx")):
        return True
    if ".test." in name or name.endswith("_test.py") or name.endswith("_test.go"):
        return True
    if _in_inert_dir(posix):
        return True
    return False


def _in_inert_dir(posix: str) -> bool:
    parts = [part for part in posix.split("/") if part]
    return any(part in INERT_DIR_NAMES for part in parts[:-1])


def is_source_code(path: str) -> bool:
    posix = _posix(path)
    name = posix.rsplit("/", 1)[-1].lower()
    if is_config_file(path):
        return False
    suffix = Path(name).suffix.lower()
    if name in {"dockerfile"} or posix.lower().endswith("/dockerfile"):
        return False
    return suffix in SOURCE_SUFFIXES


def load_ignore_globs(root: Path) -> list[str]:
    path = root / ".tether.yml"
    if not path.is_file():
        return []
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception:
        return []
    raw = data.get("ignore") or []
    return [str(item) for item in raw if str(item).strip()]


def ignored_by_globs(rel: str, globs: list[str]) -> bool:
    posix = _posix(rel)
    for pattern in globs:
        pat = pattern.replace("\\", "/")
        if fnmatch.fnmatch(posix, pat):
            return True
        if pat.endswith("/**") and (posix.startswith(pat[:-3]) or posix == pat[:-3].rstrip("/")):
            return True
    return False
