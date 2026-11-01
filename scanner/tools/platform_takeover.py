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


def matching_platform(host: str, cnames: list[str] | None = None) -> dict[str, Any] | None:
    found = platform_for(host)
    if found:
        return found
    for cname in cnames or []:
        found = platform_for(cname)
        if found:
            return found
    return None


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
        cache=ctx.cache,
    )
    return result.model_dump(mode="json")
