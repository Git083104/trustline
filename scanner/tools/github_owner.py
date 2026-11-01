from __future__ import annotations

from typing import Any

NAME = "github_owner"

GITHUB_RESERVED = frozenset(
    {
        "about",
        "account",
        "apps",
        "blog",
        "collections",
        "contact",
        "customer-stories",
        "dashboard",
        "enterprise",
        "events",
        "explore",
        "features",
        "github",
        "issues",
        "join",
        "login",
        "logout",
        "marketplace",
        "new",
        "notifications",
        "orgs",
        "organizations",
        "pricing",
        "pulls",
        "readme",
        "search",
        "security",
        "settings",
        "site",
        "sponsors",
        "team",
        "topics",
        "trending",
        "codespaces",
        "copilot",
        "solutions",
        "resources",
        "advisories",
        "home",
        "premium-support",
        "users",
        "repos",
        "watching",
        "stars",
        "discussions",
        "signup",
    }
)


def definition() -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": NAME,
            "description": (
                "Check whether a GitHub user or org exists. GET only. "
                "A missing owner is claimable-now. Never creates an account."
            ),
            "parameters": {
                "type": "object",
                "properties": {"owner": {"type": "string"}},
                "required": ["owner"],
                "additionalProperties": False,
            },
        },
    }


async def run(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    result = await ctx.github_owner(args["owner"], cache=ctx.cache)
    return result.model_dump(mode="json")
