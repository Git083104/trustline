from __future__ import annotations

from typing import Any

NAME = "rdap"


def definition() -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": NAME,
            "description": "RDAP whois for a registrable domain. Use domain, not a hostname.",
            "parameters": {
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
                "additionalProperties": False,
            },
        },
    }


async def run(args: dict[str, Any], ctx: Any) -> dict[str, Any]:
    result = await ctx.rdap(args["domain"], cache=ctx.cache)
    return result.model_dump(mode="json")
