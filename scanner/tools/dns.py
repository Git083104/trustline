from __future__ import annotations

from typing import Any

NAME = "dns"


def definition() -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": NAME,
            "description": "DNS lookup for a full host, including CNAME chain.",
            "parameters": {
                "type": "object",
                "properties": {"host": {"type": "string"}},
                "required": ["host"],
                "additionalProperties": False,
            },
        },
    }


async def run(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    result = await ctx.dns(args["host"], cache=ctx.cache)
    return result.model_dump(mode="json")
