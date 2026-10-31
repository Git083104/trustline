from __future__ import annotations

from typing import Any

NAME = "wayback"


def definition() -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": NAME,
            "description": "Wayback Machine first and last snapshot for a URL.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
                "additionalProperties": False,
            },
        },
    }


async def run(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    result = await ctx.wayback(args["url"], cache=ctx.cache)
    return result.model_dump(mode="json")
