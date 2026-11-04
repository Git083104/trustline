from __future__ import annotations

from typing import Any

NAME = "platform_takeover"

# Ported from jwang2007/trustline app/platforms.py (read-only reference).
PLATFORMS = [
    {
        "name": "GitHub Pages",
        "suffixes": ["github.io"],
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "isn&#39;t a GitHub Pages site here",
        ],
        "a_records": [
            "185.199.108.153",
            "185.199.109.153",
            "185.199.110.153",
            "185.199.111.153",
        ],
        "aaaa_records": [
            "2606:50c0:8000::153",
            "2606:50c0:8001::153",
            "2606:50c0:8002::153",
            "2606:50c0:8003::153",
        ],
        "takeover": "vulnerable",
    },
    {
        "name": "Heroku",
        "suffixes": ["herokuapp.com", "herokudns.com", "herokussl.com"],
        "fingerprints": ["No such app", "no-such-app.html"],
        "takeover": "edge case",
    },
    {
        "name": "Azure App Service",
        "suffixes": ["azurewebsites.net"],
        "nxdomain": True,
        "takeover": "vulnerable",
    },
    {
        "name": "Azure Cloud Service",
        "suffixes": ["cloudapp.net", "cloudapp.azure.com"],
        "nxdomain": True,
        "takeover": "vulnerable",
    },
    {
        "name": "Azure Traffic Manager",
        "suffixes": ["trafficmanager.net"],
        "nxdomain": True,
        "takeover": "vulnerable",
    },
    {
        "name": "Azure CDN",
        "suffixes": ["azureedge.net"],
        "nxdomain": True,
        "takeover": "vulnerable",
    },
    {
        "name": "AWS Elastic Beanstalk",
        "suffixes": ["elasticbeanstalk.com"],
        "nxdomain": True,
        "takeover": "vulnerable",
    },
    {
        "name": "Surge.sh",
        "suffixes": ["surge.sh"],
        "fingerprints": ["project not found"],
        "takeover": "vulnerable",
    },
    {
        "name": "Bitbucket",
        "suffixes": ["bitbucket.io"],
        "fingerprints": ["Repository not found"],
        "takeover": "vulnerable",
    },
    {
        "name": "Pantheon",
        "suffixes": ["pantheonsite.io"],
        "fingerprints": ["The gods are wise", "404 error unknown site"],
        "takeover": "vulnerable",
    },
    {
        "name": "Ghost",
        "suffixes": ["ghost.io"],
        "fingerprints": [
            "Domain error",
            "Failed to resolve DNS path for this host",
        ],
        "takeover": "vulnerable",
    },
    {
        "name": "WordPress.com",
        "suffixes": ["wordpress.com"],
        "fingerprints": ["Do you want to register"],
        "takeover": "vulnerable",
    },
    {
        "name": "Netlify",
        "suffixes": ["netlify.app", "netlify.com"],
        "fingerprints": ["Not Found - Request ID"],
        "takeover": "edge case",
    },
    {
        "name": "Vercel",
        "suffixes": ["vercel.app", "now.sh"],
        "fingerprints": [
            "DEPLOYMENT_NOT_FOUND",
            "The deployment could not be found",
        ],
        "takeover": "edge case",
    },
    {
        "name": "Firebase Hosting",
        "suffixes": ["firebaseapp.com", "web.app"],
        "fingerprints": ["Site Not Found"],
        "takeover": "edge case",
    },
    {
        "name": "Shopify",
        "suffixes": ["myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable"],
        "takeover": "edge case",
    },
    {
        "name": "Fly.io",
        "suffixes": ["fly.dev"],
        "nxdomain": True,
        "takeover": "edge case",
    },
]


def platform_for(host: str) -> dict[str, Any] | None:
    host = (host or "").lower().rstrip(".")
    for platform in PLATFORMS:
        for suffix in platform["suffixes"]:
            if host.endswith("." + suffix):
                return platform
    return None


def matching_platform(
    host: str,
    cnames: list[str] | None = None,
    addresses: list[str] | None = None,
) -> dict[str, Any] | None:
    found = platform_for(host)
    if found:
        return found
    for cname in cnames or []:
        found = platform_for(cname)
        if found:
            return found
    addrs = {(item or "").lower().rstrip(".") for item in (addresses or [])}
    if not addrs:
        return None
    for platform in PLATFORMS:
        documented = {
            item.lower()
            for item in list(platform.get("a_records") or [])
            + list(platform.get("aaaa_records") or [])
        }
        if addrs & documented:
            return platform
    return None


def dns_points_to_platform(
    platform: dict[str, Any],
    host: str,
    cnames: list[str] | None = None,
    addresses: list[str] | None = None,
) -> bool:
    """Hostname, CNAME chain, or documented A/AAAA records must point at the platform."""
    if (platform_for(host) or {}).get("name") == platform.get("name"):
        return True
    for cname in cnames or []:
        hit = platform_for(cname)
        if hit and hit.get("name") == platform.get("name"):
            return True
    addrs = {(item or "").lower().rstrip(".") for item in (addresses or [])}
    documented = {
        item.lower()
        for item in list(platform.get("a_records") or [])
        + list(platform.get("aaaa_records") or [])
    }
    return bool(addrs & documented)


def takeover_is_proven(evidence: dict[str, Any]) -> bool:
    platform = evidence.get("platform_takeover") or {}
    if str(platform.get("status", "")).lower() != "unclaimed":
        return False
    if platform.get("dns_proof"):
        return True
    host = str(platform.get("host") or "")
    dns = evidence.get("dns") or {}
    hit = matching_platform(
        host or str(dns.get("host") or ""),
        list(dns.get("cnames") or []),
        list(dns.get("addresses") or []),
    )
    if not hit:
        return False
    return dns_points_to_platform(
        hit,
        host or str(dns.get("host") or ""),
        cnames=list(dns.get("cnames") or []),
        addresses=list(dns.get("addresses") or []),
    )


def definition() -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": NAME,
            "description": (
                "GET-only hosting-platform takeover fingerprints. "
                "Only probes hosts whose suffix or CNAME matches a listed platform. "
                "Never creates or claims anything."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "cnames": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "dns_status": {"type": "string"},
                    "addresses": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["host"],
                "additionalProperties": False,
            },
        },
    }


async def run(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    result = await ctx.platform_takeover(
        args["host"],
        cnames=list(args.get("cnames") or []),
        dns_status=args.get("dns_status"),
        addresses=list(args.get("addresses") or []),
        cache=ctx.cache,
    )
    return result.model_dump(mode="json")
