from __future__ import annotations

from pathlib import Path

from scanner.extract import GITHUB_RE


class TargetError(ValueError):
    def __init__(self, status_code: int, body: dict[str, str]):
        super().__init__(body.get("error", "bad target"))
        self.status_code = status_code
        self.body = body


def infer_kind(target: str) -> str:
    if GITHUB_RE.match(target):
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
    inferred = kind or infer_kind(raw)
    if inferred == "website":
        if not raw.startswith(("http://", "https://")):
            raise TargetError(400, {"error": "not a website URL", "kind": "website"})
        return "website", raw
    if inferred == "repo":
        if not GITHUB_RE.match(raw):
            raise TargetError(400, {"error": "not a GitHub URL", "kind": "repo"})
        return "repo", raw
    if inferred == "path":
        path = Path(raw)
        if not path.exists():
            raise TargetError(400, {"error": "path not found", "kind": "path"})
        return "path", str(path)
    raise TargetError(400, {"error": "unknown kind", "kind": inferred})
