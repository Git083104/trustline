"""Code-written headlines, steps, issue text, and assistant prompts."""

from __future__ import annotations

from typing import Any

from scanner.compromised import compromised_status
from scanner.inert import is_inert_path, name_is_owned
from scanner.models import Finding

OWNED_COPY = (
    "This is yours: renew the domain / re-create the bucket or account in your own "
    "cloud account before someone else does."
)
_owned_names: list[str] = []


def set_owned_names(names: list[str] | None) -> None:
    global _owned_names
    _owned_names = [str(item) for item in (names or []) if str(item).strip()]

PROVEN_TIP = (
    "Proven: checked directly, e.g. the registry says no one owns this domain"
)
LIKELY_TIP = (
    "Likely: the lookups point to a problem, but a human should confirm the dates"
)

HEADLINES = {
    "unregistered_script": "Your website loads code from a domain anyone can register",
    "missing_github_ci": "Your CI runs a script from a GitHub account that no longer exists",
    "missing_github_pages": "Your site loads a script from a GitHub Pages account that no longer exists",
    "nosuchbucket": "Your deploy downloads files from a storage bucket that no longer exists",
    "compromised_cdn": "Your site loads a script from a CDN known to have served malware",
    "unregistered_host": "Your project still talks to a domain anyone can register",
    "nxdomain": "Your project still names a host that no longer resolves",
    "inert_mention": "This name only appears in docs or tests",
}

WHY = {
    "unregistered_script": "Anyone who registers that domain could run their code in visitors' browsers.",
    "missing_github_ci": "Anyone who creates that GitHub account could change the script your CI downloads and runs.",
    "missing_github_pages": "Anyone who recreates that GitHub account could publish a script your pages would load.",
    "nosuchbucket": "Anyone who creates that bucket could serve files your deploy trusts.",
    "compromised_cdn": "That CDN has been used to ship malware; pages that load it inherit that risk.",
    "unregistered_host": "Anyone who registers the name could answer requests your software still makes.",
    "nxdomain": "The name no longer points anywhere, so a later owner could take it over.",
    "inert_mention": "It is not loaded at runtime from this file, so it is notes rather than an active foot-gun.",
}


def _loc_priority(loc: dict[str, Any]) -> int:
    from scanner.inert import is_config_file, is_inert_path

    path = str(loc.get("file") or "")
    runs = str(loc.get("runs_in") or "")
    if is_inert_path(path) or runs in {"test", "docs_only"}:
        return 2
    if is_config_file(path):
        return 1
    return 0


def _first_loc(item: Finding) -> str:
    locs = [loc for loc in item.locations or [] if isinstance(loc, dict) and loc.get("file")]
    locs.sort(key=_loc_priority)
    for loc in locs:
        line = loc.get("line") or 1
        return f"{loc['file']}:{line}"
    if item.references:
        ref = item.references[0]
        if isinstance(ref, str):
            return ref
    return "the scanned file"


def _runs(item: Finding) -> set[str]:
    out = set()
    for loc in item.locations or []:
        if isinstance(loc, dict) and loc.get("runs_in"):
            out.add(str(loc["runs_in"]))
    return out


def risk_type(item: Finding) -> str:
    evidence = item.evidence or {}
    locs = [loc for loc in (item.locations or []) if isinstance(loc, dict)]
    only_inert = bool(locs) and all(is_inert_path(str(loc.get("file") or "")) for loc in locs)
    if only_inert:
        return "inert_mention"
    status = compromised_status(item.target, "")
    has_script = any(str(loc.get("tag") or "") == "script" or loc.get("runs_in") == "browser" for loc in locs)
    if status == "compromised" and has_script:
        return "compromised_cdn"
    bucket = evidence.get("bucket_probe") or {}
    if bucket.get("status") == "NoSuchBucket":
        return "nosuchbucket"
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() == "missing":
        runs = _runs(item)
        files = " ".join(str(loc.get("file") or "") for loc in locs).replace("\\", "/").lower()
        if "ci" in runs or ".github/workflows/" in files:
            return "missing_github_ci"
        return "missing_github_pages"
    rdap = evidence.get("rdap") or {}
    if str(rdap.get("status", "")).lower() == "unregistered" and has_script:
        return "unregistered_script"
    dns = evidence.get("dns") or {}
    if str(dns.get("status", "")).lower() == "nxdomain":
        return "nxdomain"
    return "unregistered_host"


def steps_for(item: Finding) -> list[str]:
    loc = _first_loc(item)
    kind = risk_type(item)
    if kind == "compromised_cdn":
        return [
            f"Open {loc} and find the script or stylesheet URL.",
            "Replace it with a maintained CDN you control, or pin a subresource integrity hash.",
            "Do not register or claim the old name.",
        ]
    if kind == "unregistered_script":
        return [
            f"Open {loc} and remove or replace the script tag.",
            "Point it at a host you control, or drop the dependency.",
            "Do not register the abandoned domain yourself from this tool.",
        ]
    if kind == "missing_github_ci":
        return [
            f"Open {loc} and disable or delete that CI step.",
            "Replace the download with a script from a repository you still own.",
            "Do not create the missing GitHub account from this tool.",
        ]
    if kind == "missing_github_pages":
        return [
            f"Open {loc} and remove the script tag.",
            "Host the widget from a Pages site you control.",
            "Do not create the missing GitHub account from this tool.",
        ]
    if kind == "nosuchbucket":
        return [
            f"Open {loc} and stop pointing deploys at that bucket.",
            "Use a bucket in an account you still own.",
            "Do not create the missing bucket from this tool.",
        ]
    if kind == "inert_mention":
        return [
            f"Optionally delete the mention at {loc}.",
            "No runtime change is required.",
        ]
    return [
        f"Open {loc} and remove or replace the reference.",
        "Use a name you still control.",
        "Do not register or claim the abandoned name from this tool.",
    ]


def headline_for(item: Finding) -> str:
    if name_is_owned(item.target, _owned_names):
        return OWNED_COPY
    return HEADLINES.get(risk_type(item), HEADLINES["unregistered_host"])


def why_for(item: Finding) -> str:
    kind = risk_type(item)
    model = (item.risk or "").strip()
    if item.explained_by == "model" and model and "is at least" not in model.lower():
        return model.split("\n", 1)[0][:280]
    return WHY.get(kind, WHY["unregistered_host"])


def decorate(item: Finding) -> Finding:
    kind = risk_type(item)
    update = {
        "headline": headline_for(item),
        "why": why_for(item),
        "steps": steps_for(item),
        "risk_type": kind,
    }
    if name_is_owned(item.target, _owned_names):
        update["headline"] = OWNED_COPY
        update["fix"] = OWNED_COPY
    return item.model_copy(update=update)


def issue_markdown(item: Finding) -> tuple[str, str]:
    loc = _first_loc(item)
    title = f"Tether: {headline_for(item)}"
    steps = "\n".join(f"{index}. {step}" for index, step in enumerate(steps_for(item), 1))
    body = (
        f"## What's wrong\n\n{headline_for(item)} (`{item.target}`).\n\n"
        f"## Why it matters\n\n{why_for(item)}\n\n"
        f"## What to do\n\n{steps}\n\n"
        f"## Evidence\n\n{item.evidence_line}\n\n"
        f"First seen at `{loc}`.\n\n"
        "Do not register, claim, or write to the abandoned name.\n"
    )
    return title, body


def assistant_prompt(item: Finding) -> str:
    loc = _first_loc(item)
    steps = " ".join(steps_for(item))
    return (
        f"In {loc}, {headline_for(item).lower()} ({item.target}). "
        f"{why_for(item)} {steps} "
        "Make the smallest safe edit. Do not register, claim, or write to any "
        "bucket, domain, or GitHub account."
    )
