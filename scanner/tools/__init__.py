from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from scanner.lookups import (
    bucket_probe as lookup_bucket,
    cert_history as lookup_certs,
    dns as lookup_dns,
    github_owner as lookup_github_owner,
    platform_takeover as lookup_platform,
    rdap as lookup_rdap,
    wayback as lookup_wayback,
)
from scanner.tools import (
    bucket_probe,
    cert_history,
    dns,
    done,
    github_owner,
    platform_takeover,
    rdap,
    wayback,
)

_MODULES = {
    rdap.NAME: rdap,
    dns.NAME: dns,
    bucket_probe.NAME: bucket_probe,
    cert_history.NAME: cert_history,
    wayback.NAME: wayback,
    platform_takeover.NAME: platform_takeover,
    github_owner.NAME: github_owner,
    done.NAME: done,
}


@dataclass
class ToolContext:
    cache: Any
    rdap: Callable = lookup_rdap
    dns: Callable = lookup_dns
    bucket_probe: Callable = lookup_bucket
    cert_history: Callable = lookup_certs
    wayback: Callable = lookup_wayback
    platform_takeover: Callable = lookup_platform
    github_owner: Callable = lookup_github_owner


def definitions() -> list[dict[str, Any]]:
    return [mod.definition() for mod in _MODULES.values()]


async def run(name: str, args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    if name not in _MODULES:
        raise KeyError(name)
    return await _MODULES[name].run(args, ctx)
