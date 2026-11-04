from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from scanner.extract import GITHUB_RE, GH_OWNER_RE
from scanner.tools.github_owner import GITHUB_RESERVED


PROFILE_MSG = (
    "That's a GitHub profile. Paste a repository, e.g. github.com/<owner>/<repo>."
)

_GITHUB_HOST = re.compile(r"^(?:www\.)?github\.com$", re.IGNORECASE)


class TargetError(ValueError):
    def __init__(self, status_code: int, body: dict[str, str]):
        super().__init__(body.get("error", "bad target"))
        self.status_code = status_code
        self.body = body


def _canonical_github(target: str) -> str:
    raw = target.strip()
    if re.match(r"^github\.com/", raw, re.IGNORECASE):
        raw = "https://" + raw
    parts = urlsplit(raw)
    if not _GITHUB_HOST.match(parts.netloc):
        return raw
    path = parts.path or "/"
    return f"https://github.com{path}"


def github_url_kind(target: str) -> str | None:
    """Return 'repo', 'profile', or None if this is not a github.com URL."""
    raw = _canonical_github(target)
    parts = urlsplit(raw)
    if not _GITHUB_HOST.match(parts.netloc):
        return None
    if GITHUB_RE.match(raw.rstrip("/")) or GITHUB_RE.match(raw):
        segs = [seg for seg in (parts.path or "").split("/") if seg]
        if len(segs) >= 2 and segs[0].lower() not in GITHUB_RESERVED:
            return "repo"
    segs = [seg for seg in (parts.path or "").split("/") if seg]
    if len(segs) >= 2 and segs[0].lower() not in GITHUB_RESERVED:
        repo = segs[1].removesuffix(".git")
        if repo and GH_OWNER_RE.match(segs[0]):
            return "repo"
    return "profile"


def is_listable_github_owner(name: str) -> bool:
    return bool(GH_OWNER_RE.match(name)) and name.lower() not in GITHUB_RESERVED


def github_profile_owner(target: str) -> str | None:
    if github_url_kind(target) != "profile":
        return None
    raw = _canonical_github(target)
    segs = [seg for seg in (urlsplit(raw).path or "").split("/") if seg]
    if len(segs) == 1 and segs[0].lower() not in GITHUB_RESERVED and GH_OWNER_RE.match(segs[0]):
        return segs[0]
    return None


def infer_kind(target: str) -> str:
    if github_url_kind(target) == "repo":
        return "repo"
    if Path(target).exists():
        return "path"
    if target.startswith("http://") or target.startswith("https://"):
        return "website"
    return "path"


def classify_target(target: str, kind: str | None = None) -> tuple[str, str]:
    raw = target.strip()
    if not raw:
        raise TargetError(400, {"error": "target required"})
    if github_url_kind(raw) == "profile":
        raise TargetError(400, {"error": PROFILE_MSG})
    inferred = kind or infer_kind(raw)
    if inferred == "website":
        if github_url_kind(raw) == "profile":
            raise TargetError(400, {"error": PROFILE_MSG})
        if not raw.startswith(("http://", "https://")):
            raise TargetError(400, {"error": "not a website URL", "kind": "website"})
        return "website", raw
    if inferred == "repo":
        canonical = _canonical_github(raw)
        if not GITHUB_RE.match(canonical) and not GITHUB_RE.match(canonical.rstrip("/")):
            raise TargetError(400, {"error": "not a GitHub URL", "kind": "repo"})
        return "repo", canonical
    if inferred == "path":
        path = Path(raw)
        if not path.exists():
            raise TargetError(400, {"error": "path not found", "kind": "path"})
        return "path", str(path)
    raise TargetError(400, {"error": "unknown kind", "kind": inferred})
